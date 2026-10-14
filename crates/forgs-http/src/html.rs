//! Minimal server-rendered pages: login, signup, device verification, and a
//! result page. No JavaScript, no external resources.
//!
//! Every dynamic value goes through [`escape`], and every page is served
//! with a strict CSP (`default-src 'none'`: no scripts, styles, images or
//! frames of any origin; forms may only post back to this origin), plus
//! `X-Frame-Options: DENY` against clickjacking the approve button,
//! `Referrer-Policy: same-origin` so a code in the URL never leaks to another
//! origin (while same-origin form posts still carry a real `Origin`), and
//! `Cache-Control: no-store`.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// The CSP every page carries.
pub const CSP: &str =
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// HTML-escape text for element content and double-quoted attributes.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A page with the security headers. `body` must already be escaped.
#[must_use]
pub fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width\">\
         <title>{}</title></head><body>\n<h1>{}</h1>\n{body}\n</body></html>\n",
        escape(title),
        escape(title)
    );
    let mut r = (status, html).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// A message page.
#[must_use]
pub fn message(status: StatusCode, title: &str, text: &str) -> Response {
    page(status, title, &format!("<p>{}</p>", escape(text)))
}

/// The provider list. `start` maps a provider name to its start URL.
#[must_use]
pub fn login(names: &[&str], start: impl Fn(&str) -> String, lead: &str) -> Response {
    let mut body = format!("<p>{}</p>\n<ul>\n", escape(lead));
    for n in names {
        use std::fmt::Write as _;
        let _ = writeln!(
            body,
            "<li><a href=\"{}\">Log in with {}</a></li>",
            escape(&start(n)),
            escape(n)
        );
    }
    body.push_str("</ul>");
    if names.is_empty() {
        "<p>No login providers are configured.</p>".clone_into(&mut body);
    }
    page(StatusCode::OK, "Log in", &body)
}

/// The username form.
#[must_use]
pub fn signup(action: &str, suggestion: &str, error: Option<&str>, status: StatusCode) -> Response {
    let err = error
        .map(|e| format!("<p role=\"alert\"><strong>{}</strong></p>\n", escape(e)))
        .unwrap_or_default();
    let body = format!(
        "{err}<p>This is your first login. Choose a username; it is your public handle \
         and the name of your personal namespace.</p>\n\
         <form method=\"post\" action=\"{}\">\n\
         <label>Username <input name=\"username\" value=\"{}\" required \
         autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\"></label>\n\
         <button type=\"submit\">Create account</button>\n</form>",
        escape(action),
        escape(suggestion)
    );
    page(status, "Choose a username", &body)
}

/// The device-verification form for a logged-in user.
#[must_use]
pub fn device_form(action: &str, username: &str, code: &str, csrf: &str) -> Response {
    let body = format!(
        "<p>You are logged in as <strong>{}</strong>.</p>\n\
         <p>A device is asking to log in <strong>as you</strong>. Only continue if you \
         started this yourself and the code below matches the one it shows.</p>\n\
         <form method=\"post\" action=\"{}\">\n\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\n\
         <label>Code <input name=\"code\" value=\"{}\" required autocomplete=\"off\" \
         autocapitalize=\"characters\" spellcheck=\"false\"></label>\n\
         <button type=\"submit\" name=\"action\" value=\"approve\">Approve</button>\n\
         <button type=\"submit\" name=\"action\" value=\"deny\">Deny</button>\n</form>",
        escape(username),
        escape(action),
        escape(csrf),
        escape(code)
    );
    page(StatusCode::OK, "Confirm device login", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_covers_the_dangerous_five() {
        assert_eq!(
            escape(r#"<a href="x" onclick='y'>&</a>"#),
            "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
        );
    }

    #[test]
    fn pages_carry_the_security_headers() {
        let r = message(StatusCode::OK, "t", "<script>");
        let h = r.headers();
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }
}
