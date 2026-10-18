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

use std::fmt::Write as _;

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

/// The device-verification form for a logged-in user: an empty code field.
/// It is never pre-filled, so the user must type what their device shows.
#[must_use]
pub fn device_form(action: &str, username: &str, csrf: &str) -> Response {
    let body = format!(
        "<p>You are logged in as <strong>{}</strong>.</p>\n\
         <p>A device is asking to log in <strong>as you</strong>. Type the code your \
         device shows. Never enter a code someone sent you.</p>\n\
         <form method=\"post\" action=\"{}\">\n\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\n\
         <label>Code <input name=\"code\" value=\"\" required autocomplete=\"off\" \
         autocapitalize=\"characters\" spellcheck=\"false\"></label>\n\
         <button type=\"submit\" name=\"action\" value=\"review\">Continue</button>\n</form>",
        escape(username),
        escape(action),
        escape(csrf),
    );
    page(StatusCode::OK, "Confirm device login", &body)
}

/// The review step: what is asking, from where and when, then Approve/Deny.
#[must_use]
pub fn device_confirm(
    action: &str,
    username: &str,
    info: &crate::device::DeviceInfo,
    csrf: &str,
) -> Response {
    let what = if info.is_app {
        "A machine is asking for approval"
    } else {
        "A device is asking to log in"
    };
    let body = format!(
        "<p>You are logged in as <strong>{}</strong>.</p>\n\
         <p>{} <strong>as you</strong> with code <strong>{}</strong>. It asked at \
         <strong>{}</strong> from <strong>{}</strong>.</p>\n\
         <p>Only approve if you started this yourself, just now, on that device.</p>\n\
         <form method=\"post\" action=\"{}\">\n\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\n\
         <input type=\"hidden\" name=\"code\" value=\"{}\">\n\
         <button type=\"submit\" name=\"action\" value=\"approve\">Approve</button>\n\
         <button type=\"submit\" name=\"action\" value=\"deny\">Deny</button>\n</form>",
        escape(username),
        escape(what),
        escape(&info.display_code),
        escape(&utc(info.created_at)),
        escape(info.source_ip.as_deref().unwrap_or("an unknown address")),
        escape(action),
        escape(csrf),
        escape(&info.display_code),
    );
    page(StatusCode::OK, "Confirm device login", &body)
}

/// After an approval: a way to take it back before the device redeems it.
#[must_use]
pub fn device_approved(action: &str, code: &str, csrf: &str) -> Response {
    let body = format!(
        "<p>The device is now logged in. You can return to your terminal.</p>\n\
         <form method=\"post\" action=\"{}\">\n\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\n\
         <input type=\"hidden\" name=\"code\" value=\"{}\">\n\
         <p>Not you? <button type=\"submit\" name=\"action\" value=\"deny\">Cancel this \
         approval</button></p>\n</form>",
        escape(action),
        escape(csrf),
        escape(code),
    );
    page(StatusCode::OK, "Device approved", &body)
}

/// After a signup (or a login) under an approval policy: the account
/// exists but waits for an administrator.
#[must_use]
pub fn pending_approval() -> Response {
    message(
        StatusCode::OK,
        "Waiting for approval",
        "Your account is waiting for approval by an administrator. You can log in once it \
         has been approved.",
    )
}

/// The pending-signup review page: one row per user, each with an approve
/// and a reject button (CSRF-checked form POSTs to `action`).
#[must_use]
pub fn signup_review(
    action: &str,
    csrf: &str,
    users: &[forgs::api::PendingUserInfo],
    notice: Option<&str>,
) -> Response {
    let mut body = String::new();
    if let Some(n) = notice {
        let _ = writeln!(body, "<p><strong>{}</strong></p>", escape(n));
    }
    if users.is_empty() {
        body.push_str("<p>No signups are waiting for approval.</p>");
        return page(StatusCode::OK, "Pending signups", &body);
    }
    body.push_str("<table>\n<tr><th>Username</th><th>Email</th><th>Signed up</th><th></th></tr>\n");
    for u in users {
        let _ = writeln!(
            body,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>\
             <form method=\"post\" action=\"{}\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <input type=\"hidden\" name=\"user_id\" value=\"{}\">\
             <button type=\"submit\" name=\"action\" value=\"approve\">Approve</button> \
             <button type=\"submit\" name=\"action\" value=\"reject\">Reject</button>\
             </form></td></tr>",
            escape(&u.username),
            escape(&u.emails.join(", ")),
            escape(&utc(u.created_at)),
            escape(action),
            escape(csrf),
            escape(&u.user_id),
        );
    }
    body.push_str("</table>");
    page(StatusCode::OK, "Pending signups", &body)
}

/// Epoch seconds as `YYYY-MM-DD HH:MM:SS UTC`.
#[must_use]
pub fn utc(epoch: u64) -> String {
    let days = epoch / 86_400;
    let rem = epoch % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`, for days since 1970-01-01 (>= 0).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
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

    #[test]
    fn utc_formats_epoch_seconds() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(1_792_186_285), "2026-10-16 21:31:25 UTC");
        assert_eq!(utc(4_107_542_399), "2100-02-28 23:59:59 UTC");
    }
}
