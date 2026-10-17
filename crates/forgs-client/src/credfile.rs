//! Persist a credential to a private file (Unix only).
//!
//! Meant for the long-lived, **non-rotating** refresh token a CLI or agent
//! keeps between runs: forgs-client does no storage of its own, and every
//! consumer would otherwise hand-roll the same file handling. Std only (no
//! libc, no tokio `fs`), so it builds for armv7-musl unchanged.
//!
//! * The directory is created `0700` and must stay private: an existing
//!   directory that is a symlink, is group/world accessible, or is owned by
//!   another user is refused with [`io::ErrorKind::PermissionDenied`], never
//!   silently chmod-ed.
//! * Writes are atomic: a fresh `0600` temp file in the same directory,
//!   `fsync`, `rename` over the final name, then `fsync` of the directory.
//!   A reader sees the old credential or the new one, never half of either.
//! * Reads refuse a file that is not a regular `0600`-ish file owned by the
//!   directory's owner.
//! * [`remove_credential`] is the logout counterpart.
//!
//! The functions block; the file is well under a KiB, so call them directly
//! even from async code.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::secret::Secret;

/// Largest credential file [`read_credential`] accepts.
const MAX_LEN: u64 = 64 * 1024;
/// Attempts at a fresh temp name before giving up.
const TEMP_ATTEMPTS: u32 = 8;

/// Atomically write `secret` to `dir/name`, creating `dir` (`0700`) if needed.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] for a bad `name` (empty, `.`/`..`, a `/`
/// or NUL, or a leading `.`, which is reserved for temp files);
/// [`io::ErrorKind::PermissionDenied`] if `dir` is not a private directory
/// owned by the calling user; otherwise the underlying I/O error.
pub fn write_credential(dir: &Path, name: &str, secret: &Secret) -> io::Result<()> {
    check_name(name)?;
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let dir_meta = private_dir(dir)?;

    let (tmp, mut file) = create_temp(dir, name)?;
    let result = (|| {
        // A file we just created is owned by our effective uid: comparing it
        // with the directory's owner is the libc-free `getuid` check.
        if file.metadata()?.uid() != dir_meta.uid() {
            return Err(denied(dir, "is owned by another user"));
        }
        file.write_all(secret.expose().as_bytes())?;
        file.sync_all()?;
        drop(file);
        // `rename` replaces a symlink at the final name rather than
        // following it.
        fs::rename(&tmp, dir.join(name))?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Read the credential at `dir/name`; `Ok(None)` if there is none.
///
/// # Errors
///
/// As [`write_credential`] for the name and directory, plus
/// [`io::ErrorKind::PermissionDenied`] for a file that is a symlink, not a
/// regular file, group/world accessible or owned by someone other than the
/// directory's owner, and [`io::ErrorKind::InvalidData`] for one over 64 KiB
/// or not UTF-8.
pub fn read_credential(dir: &Path, name: &str) -> io::Result<Option<Secret>> {
    check_name(name)?;
    let dir_meta = match private_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    let path = dir.join(name);
    let meta = match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    check_file(&path, &meta, &dir_meta)?;
    let file = File::open(&path)?;
    // Re-check the opened file: the name may have been swapped since.
    check_file(&path, &file.metadata()?, &dir_meta)?;

    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_LEN + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is larger than {MAX_LEN} bytes", path.display()),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not UTF-8", path.display()),
        )
    })?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    Ok(Some(Secret::from(text)))
}

/// Delete the credential at `dir/name`. A missing file (or directory) is
/// success, so logout can call this unconditionally.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] for a bad `name`, else the underlying I/O
/// error.
pub fn remove_credential(dir: &Path, name: &str) -> io::Result<()> {
    check_name(name)?;
    match fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        other => other?,
    }
    match File::open(dir).and_then(|d| d.sync_all()) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.starts_with('.') || name.contains(['/', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential name must be non-empty, not start with `.`, and contain no `/` or NUL",
        ));
    }
    Ok(())
}

/// `dir` must be a real directory (not a symlink) with no group/world bits.
fn private_dir(dir: &Path) -> io::Result<fs::Metadata> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() {
        return Err(denied(dir, "is not a directory (or is a symlink)"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(denied(dir, "is accessible by group or others (want 0700)"));
    }
    Ok(meta)
}

fn check_file(path: &Path, meta: &fs::Metadata, dir_meta: &fs::Metadata) -> io::Result<()> {
    if !meta.file_type().is_file() {
        return Err(denied(path, "is not a regular file (or is a symlink)"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(denied(path, "is accessible by group or others (want 0600)"));
    }
    if meta.uid() != dir_meta.uid() {
        return Err(denied(path, "is not owned by the directory's owner"));
    }
    Ok(())
}

/// Create `dir/.{name}.tmp.{pid}.{nanos}.{attempt}` exclusively, mode `0600`.
///
/// `create_new` is `O_CREAT | O_EXCL`, which POSIX requires to fail on *any*
/// existing path, a symlink (dangling or not) included: that is the
/// no-follow guarantee, so `O_NOFOLLOW` (and libc) is not needed.
fn create_temp(dir: &Path, name: &str) -> io::Result<(PathBuf, File)> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let pid = std::process::id();
    let mut last = None;
    for attempt in 0..TEMP_ATTEMPTS {
        let tmp = dir.join(format!(".{name}.tmp.{pid}.{nanos}.{attempt}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)))
}

fn denied(path: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refusing {}: it {why}", path.display()),
    )
}
