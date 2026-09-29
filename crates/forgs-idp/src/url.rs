//! URL and form helpers (pure).
//!
//! Hand-rolled rather than pulled from `url` / `percent-encoding`: forgs'
//! client side cross-compiles to armv7-musl and the workspace keeps its
//! dependency graph small. `url` alone drags in `idna` and the `icu_*` unicode
//! stack; encoding a form value and sanity-checking an endpoint is a page.

use crate::identity::IdpError;

/// Percent-encode one `application/x-www-form-urlencoded` (or query) *value*.
///
/// Everything outside RFC 3986's unreserved set is escaped, which is stricter
/// than necessary but never wrong. Notably that covers `:` and `/` in a
/// redirect URI and any `&`/`=` in an opaque value, which would otherwise let
/// the value inject extra parameters.
///
/// Spaces become `%20` rather than `+`; both are accepted for form bodies, and
/// `%20` is the one that is also correct in a query string, so there is a
/// single rule to remember.
#[must_use]
pub fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(*byte));
            }
            other => {
                out.push('%');
                out.push(char::from(HEX[usize::from(other >> 4)]));
                out.push(char::from(HEX[usize::from(other & 0x0f)]));
            }
        }
    }
    out
}

/// Build a form body (or query string) from known-good key names and opaque
/// values.
#[must_use]
pub fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Append `pairs` as query parameters to `url`.
///
/// A GHES or stub endpoint may already carry a query string; the separator
/// has to follow, or the first parameter is swallowed into the last value.
#[must_use]
pub fn append_query(url: &str, pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return url.to_owned();
    }
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{}", form_body(pairs))
}

/// Hosts for which plain `http` is accepted: loopback only.
///
/// Exists so a stub server in tests (or a developer's local `IdP`) works
/// without an "insecure" switch that a production config could also set.
/// Matched against the parsed host literal, never by string prefix, so
/// `http://localhost.evil.example` is refused.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "[::1]"
}

/// Check that `url` is usable as a provider endpoint.
///
/// It must be an absolute `https://` URL with a host, no userinfo and no
/// fragment. Plain `http://` is accepted **only** for a loopback host
/// (`localhost`, `127.0.0.1`, `[::1]`). Called when a provider is constructed
/// and on every endpoint a discovery document names, so a document cannot
/// downgrade the token exchange to cleartext.
///
/// # Errors
///
/// Returns [`IdpError::Url`] describing the first problem found.
pub fn check_endpoint_url(url: &str) -> Result<(), IdpError> {
    let bad = |why: &str| Err(IdpError::Url(format!("{why}: `{url}`")));
    if url.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return bad("endpoint URL is empty or contains whitespace");
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return bad("endpoint URL is not absolute");
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return bad("endpoint URL scheme must be https");
    }
    if rest.contains('#') {
        return bad("endpoint URL must not carry a fragment");
    }
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        return bad("endpoint URL must not carry userinfo");
    }
    let (host, port) = if authority.starts_with('[') {
        let Some(close) = authority.find(']') else {
            return bad("endpoint URL has an unterminated IPv6 literal");
        };
        let (host, tail) = authority.split_at(close + 1);
        match tail {
            "" => (host, None),
            _ => match tail.strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None => return bad("endpoint URL has a malformed authority"),
            },
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || host == "[]" {
        return bad("endpoint URL has no host");
    }
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            return bad("endpoint URL has an invalid port");
        }
    }
    if scheme == "http" && !is_loopback_host(host) {
        return bad("plain http is only allowed for a loopback host");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoder_escapes_form_metacharacters() {
        assert_eq!(
            percent_encode("urn:ietf:params:oauth:grant-type:device_code"),
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(
            percent_encode("read:user user:email"),
            "read%3Auser%20user%3Aemail"
        );
        assert_eq!(percent_encode("aZ0-._~"), "aZ0-._~");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn form_body_joins_pairs() {
        assert_eq!(
            form_body(&[("client_id", "Iv1.abc"), ("scope", "read:user")]),
            "client_id=Iv1.abc&scope=read%3Auser"
        );
    }

    #[test]
    fn append_query_picks_the_separator() {
        assert_eq!(
            append_query("https://a/b", &[("x", "1")]),
            "https://a/b?x=1"
        );
        assert_eq!(
            append_query("https://a/b?t=e", &[("x", "1"), ("y", "a b")]),
            "https://a/b?t=e&x=1&y=a%20b"
        );
        assert_eq!(append_query("https://a/b", &[]), "https://a/b");
    }

    #[test]
    fn endpoint_urls_must_be_https_except_on_loopback() {
        for ok in [
            "https://github.com/login/oauth/authorize",
            "https://ghes.example:8443/api/v3",
            "https://codeberg.org/",
            "https://a.example?x=1",
            "http://127.0.0.1:1234/token",
            "http://localhost/x",
            "http://LOCALHOST:80",
            "http://[::1]:9/jwks",
            "https://[2001:db8::1]/x",
        ] {
            assert!(check_endpoint_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "github.com/login",
            "ftp://example.com/",
            "http://example.com/",
            "http://localhost.evil.example/",
            "http://127.0.0.1.evil.example/",
            "http://evil.example/127.0.0.1",
            "http://127.0.0.1@evil.example/",
            "https://user:pw@example.com/",
            "https://example.com/#frag",
            "https:///path",
            "https://:443/",
            "https://example.com:99999/",
            "https://example.com:x/",
            "https://exa mple.com/",
            "https://[::1/",
        ] {
            assert!(
                matches!(check_endpoint_url(bad), Err(IdpError::Url(_))),
                "{bad:?} should be refused"
            );
        }
    }
}
