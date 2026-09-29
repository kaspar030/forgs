//! Std-only helpers for a login CLI: browser launch, TTL parsing, and turning
//! a [`ClientError`] into remediation text. No argument parser, no printing.

use forgs::api::error_code;

use crate::error::ClientError;

/// Whether opening a browser is plausible here.
///
/// Over SSH, or on Linux with no display, `xdg-open` opens a browser on the
/// wrong machine or nowhere; the printed code is the real interface there.
#[must_use]
pub fn should_try_browser() -> bool {
    if std::env::var_os("SSH_CONNECTION").is_some() {
        return false;
    }
    if cfg!(target_os = "linux") {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    } else {
        true
    }
}

/// Best-effort browser launch, detached and silenced (a browser's chatter on
/// our stderr would bury the code the user needs to read). Returns whether a
/// launcher was spawned; the caller has already printed the URL either way.
#[must_use = "a false return means no browser was opened"]
pub fn try_open_browser(url: &str) -> bool {
    let (program, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[])
    } else if cfg!(target_os = "windows") {
        ("cmd", &["/C", "start", ""])
    } else {
        ("xdg-open", &[])
    };
    std::process::Command::new(program)
        .args(args)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Why [`parse_ttl`] refused its input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TtlError {
    /// Empty input.
    #[error("the TTL is empty; try `24h`")]
    Empty,
    /// `0` / `never`: keys minted over the API must expire.
    #[error("a key minted over the API must expire: pass a TTL like `24h`")]
    NeverExpires,
    /// Not a number with an optional `s`/`m`/`h`/`d` suffix.
    #[error("`{0}` is not a duration; try `30m`, `24h` or `7d`")]
    Invalid(String),
    /// Overflows `u64` seconds.
    #[error("the TTL is absurdly large")]
    TooLarge,
}

/// Parse a key TTL: `3600`, `90s`, `30m`, `12h`, `7d` → seconds.
///
/// Zero and `never` are refused locally, since the server refuses them anyway
/// and saying so here names the flag the user typed.
///
/// # Errors
///
/// See [`TtlError`].
pub fn parse_ttl(raw: &str) -> Result<u64, TtlError> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err(TtlError::Empty);
    }
    if s == "never" {
        return Err(TtlError::NeverExpires);
    }
    let (digits, multiplier) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3_600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        _ => (s.as_str(), 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TtlError::Invalid(raw.trim().to_owned()));
    }
    let value: u64 = digits.parse().map_err(|_| TtlError::TooLarge)?;
    let secs = value.checked_mul(multiplier).ok_or(TtlError::TooLarge)?;
    if secs == 0 {
        return Err(TtlError::NeverExpires);
    }
    Ok(secs)
}

/// One line of remediation text for a failed request. `doing` names the
/// action, e.g. `"revoking the key"`.
///
/// The server's errors are deliberately coarse (no oracle), so the advice is
/// by code, not by cause.
#[must_use]
pub fn describe(err: &ClientError, doing: &str) -> String {
    match err {
        ClientError::Rejected { code, status } => match code.as_str() {
            error_code::INVALID_GRANT | error_code::UNAUTHORIZED => format!(
                "{doing} failed: your credentials were not accepted (expired or revoked); \
                 run login again"
            ),
            error_code::FORBIDDEN => {
                format!("{doing} failed: you are not allowed to do that in this namespace")
            }
            error_code::NOT_FOUND => {
                format!("{doing} failed: no such target (or it is not visible to you)")
            }
            error_code::AMBIGUOUS_PREFIX => format!(
                "{doing} failed: the prefix matches more than one key; list the keys and use a \
                 longer prefix"
            ),
            error_code::INVALID_REQUEST => {
                format!("{doing} failed: the server refused the request as invalid")
            }
            other => format!("{doing} failed: the server answered {status} ({other})"),
        },
        ClientError::Transport(e) => format!("{doing} failed: could not reach the server: {e}"),
        ClientError::Url(e) => format!("{doing} failed: {e}"),
        ClientError::Malformed(e) => {
            format!("{doing} failed: the server's response was not understood ({e})")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttls() {
        assert_eq!(parse_ttl("3600"), Ok(3600));
        assert_eq!(parse_ttl("90s"), Ok(90));
        assert_eq!(parse_ttl("90m"), Ok(5400));
        assert_eq!(parse_ttl(" 12H "), Ok(43_200));
        assert_eq!(parse_ttl("30d"), Ok(2_592_000));
        assert_eq!(parse_ttl(""), Err(TtlError::Empty));
        assert_eq!(parse_ttl("0"), Err(TtlError::NeverExpires));
        assert_eq!(parse_ttl("0h"), Err(TtlError::NeverExpires));
        assert_eq!(parse_ttl("never"), Err(TtlError::NeverExpires));
        for bad in ["h", "1w", "-1", "+5", "1.5h", "abc"] {
            assert!(matches!(parse_ttl(bad), Err(TtlError::Invalid(_))), "{bad}");
        }
        assert_eq!(parse_ttl("18446744073709551615d"), Err(TtlError::TooLarge));
        assert_eq!(parse_ttl("99999999999999999999"), Err(TtlError::TooLarge));
    }

    #[test]
    fn descriptions() {
        let rej = |code: &str| ClientError::Rejected {
            status: 400,
            code: code.to_owned(),
        };
        assert!(describe(&rej("invalid_grant"), "x").contains("login again"));
        assert!(describe(&rej("unauthorized"), "x").contains("login again"));
        assert!(describe(&rej("ambiguous_prefix"), "revoking").contains("longer prefix"));
        assert!(describe(&rej("forbidden"), "x").contains("not allowed"));
        assert!(describe(&rej("not_found"), "x").contains("no such"));
        assert!(describe(&rej("weird"), "x").contains("400 (weird)"));
        assert!(describe(&ClientError::Transport("refused".into()), "x").contains("reach"));
    }
}
