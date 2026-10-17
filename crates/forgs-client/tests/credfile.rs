//! `credfile`: private, atomic credential files.
#![cfg(unix)]

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use forgs_client::credfile::{read_credential, remove_credential, write_credential};
use forgs_client::Secret;

/// A fresh, not-yet-existing directory path under the target tmpdir.
fn scratch(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "credfile-{}-{tag}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

fn mode(p: &std::path::Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn round_trip_with_private_modes() {
    let dir = scratch("rt").join("nested").join("creds");
    write_credential(&dir, "refresh", &Secret::new("tok-1")).unwrap();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("refresh")), 0o600);
    let got = read_credential(&dir, "refresh").unwrap().unwrap();
    assert_eq!(got.expose(), "tok-1");
}

#[test]
fn overwrite_replaces_and_leaves_no_temp_files() {
    let dir = scratch("ow").join("c");
    write_credential(&dir, "refresh", &Secret::new("old")).unwrap();
    write_credential(&dir, "refresh", &Secret::new("new")).unwrap();
    assert_eq!(
        read_credential(&dir, "refresh").unwrap().unwrap().expose(),
        "new"
    );
    let names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["refresh"]);
}

#[test]
fn trailing_newline_is_trimmed() {
    let dir = scratch("nl").join("c");
    write_credential(&dir, "refresh", &Secret::new("x")).unwrap();
    fs::write(dir.join("refresh"), "tok\r\n").unwrap();
    assert_eq!(
        read_credential(&dir, "refresh").unwrap().unwrap().expose(),
        "tok"
    );
}

#[test]
fn open_directory_is_refused() {
    let dir = scratch("open").join("c");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let e = write_credential(&dir, "refresh", &Secret::new("t")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert_eq!(
        read_credential(&dir, "refresh").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "nothing written");
}

#[test]
fn symlinked_directory_is_refused() {
    let root = scratch("dirlink");
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.join("link");
    symlink(&real, &link).unwrap();
    let e = write_credential(&link, "refresh", &Secret::new("t")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn readable_file_is_refused() {
    let dir = scratch("644").join("c");
    write_credential(&dir, "refresh", &Secret::new("t")).unwrap();
    fs::set_permissions(dir.join("refresh"), fs::Permissions::from_mode(0o644)).unwrap();
    let e = read_credential(&dir, "refresh").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn symlinked_file_is_refused_on_read() {
    let root = scratch("filelink");
    let outside = root.join("outside");
    fs::write(&outside, "planted").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    let dir = root.join("c");
    write_credential(&dir, "other", &Secret::new("t")).unwrap();
    symlink(&outside, dir.join("refresh")).unwrap();
    let e = read_credential(&dir, "refresh").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn write_replaces_a_symlink_without_following_it() {
    let root = scratch("wlink");
    let outside = root.join("outside");
    fs::write(&outside, "untouched").unwrap();
    let dir = root.join("c");
    write_credential(&dir, "other", &Secret::new("t")).unwrap();
    symlink(&outside, dir.join("refresh")).unwrap();
    write_credential(&dir, "refresh", &Secret::new("fresh")).unwrap();
    assert_eq!(fs::read_to_string(&outside).unwrap(), "untouched");
    assert!(fs::symlink_metadata(dir.join("refresh"))
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(
        read_credential(&dir, "refresh").unwrap().unwrap().expose(),
        "fresh"
    );
}

#[test]
fn bad_names_are_invalid_input() {
    let dir = scratch("names").join("c");
    for name in ["", ".", "..", ".hidden", "a/b", "nul\0"] {
        let e = write_credential(&dir, name, &Secret::new("t")).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name:?}");
        assert_eq!(
            read_credential(&dir, name).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            remove_credential(&dir, name).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
}

#[test]
fn missing_is_none() {
    let root = scratch("missing");
    assert!(read_credential(&root.join("absent"), "refresh")
        .unwrap()
        .is_none());
    let dir = root.join("c");
    write_credential(&dir, "other", &Secret::new("t")).unwrap();
    assert!(read_credential(&dir, "refresh").unwrap().is_none());
}

#[test]
fn remove_is_idempotent() {
    let root = scratch("rm");
    let dir = root.join("c");
    write_credential(&dir, "refresh", &Secret::new("t")).unwrap();
    remove_credential(&dir, "refresh").unwrap();
    remove_credential(&dir, "refresh").unwrap();
    remove_credential(&root.join("absent"), "refresh").unwrap();
    assert!(read_credential(&dir, "refresh").unwrap().is_none());
}
