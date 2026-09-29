//! Cookies, CSRF, and sealed flow cookies.
//!
//! # Cookies
//!
//! Two carry a login, set together and cleared together:
//!
//! * `{brand}_session` — the session token itself, byte-for-byte the bearer
//!   credential. `HttpOnly`, so a single XSS cannot exfiltrate it; the CSRF
//!   machinery below is the price of that.
//! * `{brand}_csrf` — the double-submit token, deliberately **not**
//!   `HttpOnly`: the page reads it and echoes it in the CSRF header (or a
//!   hidden form field on forgs' own no-JS pages).
//!
//! Both carry the same `Max-Age`, derived from the session's `expires`, so
//! the CSRF cookie cannot outlive the credential it is derived from.
//!
//! **`Secure` is unconditional.** Browsers treat `http://localhost` and
//! `http://127.0.0.1` as secure contexts, so local development still works;
//! any other plain-HTTP deployment is unsupported rather than silently
//! downgraded. Please do not make this conditional on the scheme — that is
//! the obvious "fix" and it would hand every session to anyone on the path.
//!
//! # CSRF
//!
//! `csrf = hex(HMAC-SHA256(k_csrf, session_token_hash))`, keyed by the app's
//! injected secret ([`crate::CsrfKey`]). Keyed off the token's *hash*, so
//! nothing derived from the credential itself is handed to JavaScript.
//! [`csrf_ok`] is the one enforcement point, and it is constant-time: a
//! timing oracle on an HMAC is a forgery oracle. forgs emits **no CORS
//! headers anywhere**, which makes the mandatory custom header a second,
//! independent control (a custom header cannot be sent cross-origin without
//! a preflight, and the preflight fails).
//!
//! # Sealed flow cookies
//!
//! The in-flight login (`{brand}_oauth`) and the pending-signup ticket
//! (`{brand}_signup`) are `MACed` with a separate key and bound to their
//! cookie name and an expiry. `HttpOnly` + `SameSite=Lax` already stop a
//! cross-site page reading or sending them; the seal additionally stops a
//! sibling origin that can *write* cookies for this host (cookie tossing)
//! from planting a login state, a link intent or a ticket.

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use subtle::ConstantTimeEq as _;

use crate::context::{hmac256, AuthContext};

/// Read one cookie's value from the `Cookie` header(s).
///
/// Hand-rolled: `split(';')`, `split_once('=')` and a charset check. A
/// missing or garbage cookie is simply "no credential" — never an error and
/// never a 500: a caller with a mangled cookie jar must get the same answer
/// as a caller with none, or the shape of the failure is itself an oracle.
#[must_use]
pub fn cookie_value<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty() && v.bytes().all(is_cookie_byte))
}

/// The cookie-value charset accepted (and emitted).
///
/// RFC 6265's `cookie-octet` minus everything no value forgs issues
/// contains. Not decoration: every value read is fed to a token parser, an
/// HMAC comparison or a seal check, and a permissive charset would let a
/// caller smuggle a `;` or a quote into one.
fn is_cookie_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Build one `Set-Cookie` value.
///
/// `Secure` is unconditional (see the module docs). **Invariant: `value` is
/// in the [`is_cookie_byte`] charset** — a `;` would not escape the header,
/// it would end the value and start an *attribute*. Every value forgs writes
/// is minted here (a token, hex, base64url), so it holds by construction; a
/// violation is refused (empty value) rather than emitted.
#[must_use]
pub fn set_cookie(name: &str, value: &str, max_age: u64, http_only: bool) -> String {
    let value = if value.bytes().all(is_cookie_byte) {
        value
    } else {
        ""
    };
    let mut out = format!("{name}={value}; Secure; SameSite=Lax; Path=/; Max-Age={max_age}");
    if http_only {
        out.push_str("; HttpOnly");
    }
    out
}

/// The `Set-Cookie` that erases `name`.
#[must_use]
pub fn clear_cookie(name: &str, http_only: bool) -> String {
    set_cookie(name, "", 0, http_only)
}

/// The pair of cookies that log a browser in, for a session token
/// `token` expiring at `expires`.
#[must_use]
pub fn session_cookies(ctx: &AuthContext, token: &str, expires: u64) -> Vec<String> {
    let max_age = expires.saturating_sub(ctx.now());
    let hash = ctx
        .format()
        .parse(token)
        .map(|t| t.hash().as_str().to_owned())
        .unwrap_or_default();
    vec![
        set_cookie(&ctx.cookies().session, token, max_age, true),
        set_cookie(&ctx.cookies().csrf, &csrf_token(ctx, &hash), max_age, false),
    ]
}

/// The pair of cookies that log a browser out.
#[must_use]
pub fn cleared_session_cookies(ctx: &AuthContext) -> Vec<String> {
    vec![
        clear_cookie(&ctx.cookies().session, true),
        clear_cookie(&ctx.cookies().csrf, false),
    ]
}

/// Attach `Set-Cookie` headers to a response.
#[must_use]
pub fn with_cookies(mut response: Response, cookies: &[String]) -> Response {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            response.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    response
}

/// A redirect to a same-origin `location` carrying `cookies`: `303 See
/// Other` (so a form POST becomes a GET), `302` otherwise.
#[must_use]
pub fn redirect(location: &str, cookies: &[String], after_post: bool) -> Response {
    let status = if after_post {
        StatusCode::SEE_OTHER
    } else {
        StatusCode::FOUND
    };
    let mut r = status.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    with_cookies(r, cookies)
}

/// The CSRF token for a session, given the **hash** of its token.
#[must_use]
pub fn csrf_token(ctx: &AuthContext, session_token_hash: &str) -> String {
    hex(&hmac256(
        ctx.keys().csrf(),
        &[session_token_hash.as_bytes()],
    ))
}

/// Whether `offered` is the CSRF token for `session_token_hash`.
/// Constant-time.
#[must_use]
pub fn csrf_matches(ctx: &AuthContext, session_token_hash: &str, offered: &str) -> bool {
    let expected = csrf_token(ctx, session_token_hash);
    constant_time_eq(offered.as_bytes(), expected.as_bytes())
}

/// Whether a mutating request authenticated by cookie carries the right CSRF
/// header. Always `true` for a header-authenticated request: that
/// credential is not ambient, so there is nothing to forge.
#[must_use]
pub fn csrf_ok(
    ctx: &AuthContext,
    headers: &HeaderMap,
    session_token_hash: &str,
    by_cookie: bool,
) -> bool {
    if !by_cookie {
        return true;
    }
    headers
        .get(ctx.csrf_header())
        .and_then(|v| v.to_str().ok())
        .is_some_and(|offered| csrf_matches(ctx, session_token_hash, offered))
}

/// Constant-time byte comparison, for values an attacker chooses one side of.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Seal `fields` into a cookie value bound to `cookie_name` and valid until
/// `expires`: `b64url(expires \n fields…) . hex(mac)`.
pub(crate) fn seal(ctx: &AuthContext, cookie_name: &str, expires: u64, fields: &[&str]) -> String {
    let mut payload = expires.to_string();
    for f in fields {
        payload.push('\n');
        payload.push_str(f);
    }
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let mac = hmac256(
        ctx.keys().flow(),
        &[cookie_name.as_bytes(), b"\0", body.as_bytes()],
    );
    format!("{body}.{}", hex(&mac))
}

/// Open a value made by [`seal`]: the MAC must verify for `cookie_name`, the
/// expiry must be in the future, and exactly `n` fields must be present.
pub(crate) fn unseal(
    ctx: &AuthContext,
    cookie_name: &str,
    value: &str,
    n: usize,
) -> Option<Vec<String>> {
    let (body, mac) = value.split_once('.')?;
    let expected = hex(&hmac256(
        ctx.keys().flow(),
        &[cookie_name.as_bytes(), b"\0", body.as_bytes()],
    ));
    if !constant_time_eq(mac.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()?;
    let payload = String::from_utf8(payload).ok()?;
    let mut parts = payload.split('\n');
    let expires: u64 = parts.next()?.parse().ok()?;
    if expires <= ctx.now() {
        return None;
    }
    let fields: Vec<String> = parts.map(str::to_owned).collect();
    (fields.len() == n).then_some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        h
    }

    #[test]
    fn cookie_parsing_finds_a_value_among_others() {
        let h = headers_with("a=1; frg_session=frgs1_abc-_; other=x");
        assert_eq!(cookie_value(&h, "frg_session"), Some("frgs1_abc-_"));
        assert_eq!(cookie_value(&h, "a"), Some("1"));
        assert_eq!(cookie_value(&h, "missing"), None);
    }

    #[test]
    fn garbage_cookies_are_simply_absent() {
        for raw in [
            "",
            "novalue",
            "frg_session=",
            "frg_session=a\"b",
            "frg_session=a,b",
        ] {
            assert_eq!(
                cookie_value(&headers_with(raw), "frg_session"),
                None,
                "{raw}"
            );
        }
        assert_eq!(cookie_value(&HeaderMap::new(), "x"), None);
    }

    #[test]
    fn set_cookie_is_always_secure_and_lax() {
        let c = set_cookie("n", "v", 60, true);
        assert_eq!(c, "n=v; Secure; SameSite=Lax; Path=/; Max-Age=60; HttpOnly");
        let c = set_cookie("n", "v", 60, false);
        assert!(!c.contains("HttpOnly"));
        assert!(clear_cookie("n", true).contains("Max-Age=0"));
    }

    #[test]
    fn the_cookie_charset_rejects_attribute_injection() {
        let c = set_cookie("n", "x; Path=/evil; HttpOnly=0", 5, true);
        assert!(c.starts_with("n=; Secure"), "{c}");
        assert!(!c.contains("evil"));
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0, 0xab, 0x0f]), "00ab0f");
    }
}
