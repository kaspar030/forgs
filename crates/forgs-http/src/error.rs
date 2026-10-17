//! The single error shape.
//!
//! Every failure this crate produces is an [`ErrorResponse`] with a code from
//! [`forgs::api::error_code`]. Bodies are deliberately coarse: "unknown" and
//! "expired" are never distinguished (no oracle), and a store error's message
//! is logged, never echoed.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use forgs::api::{error_code as code, ErrorResponse};
use forgs_store::StoreError;

/// The one rejection body. `pub` so an app's own routes answer in the same
/// shape: two rejection shapes on one server tell a caller which module
/// answered it.
#[must_use]
pub fn reject(status: StatusCode, error: &str) -> Response {
    let body = serde_json::to_vec(&ErrorResponse {
        error: error.to_owned(),
    })
    .unwrap_or_default();
    let mut r = (status, body).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// A failure of an auth service function.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// `401 unauthorized`: the bearer credential was rejected.
    #[error("unauthorized")]
    Unauthorized,
    /// `401 invalid_grant`: a credential in the body was rejected.
    #[error("invalid grant")]
    InvalidGrant,
    /// `403 forbidden`: not allowed, or the target does not exist (no oracle).
    #[error("forbidden")]
    Forbidden,
    /// `404 not_found`.
    #[error("not found")]
    NotFound,
    /// `400 invalid_request`.
    #[error("invalid request")]
    BadRequest,
    /// `500 server_error`. The cause has been logged.
    #[error("server error")]
    Internal,
    /// Any other status and code.
    #[error("{1}")]
    Code(StatusCode, &'static str),
}

impl ApiError {
    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::Unauthorized | ApiError::InvalidGrant => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Code(s, _) => *s,
        }
    }

    /// The machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::Unauthorized => code::UNAUTHORIZED,
            ApiError::InvalidGrant => code::INVALID_GRANT,
            ApiError::Forbidden => code::FORBIDDEN,
            ApiError::NotFound => code::NOT_FOUND,
            ApiError::BadRequest => code::INVALID_REQUEST,
            ApiError::Internal => code::SERVER_ERROR,
            ApiError::Code(_, c) => c,
        }
    }

    /// `409 username_taken` — taken and tombstoned are deliberately the same.
    pub const USERNAME_TAKEN: ApiError = ApiError::Code(StatusCode::CONFLICT, code::USERNAME_TAKEN);
    /// `400 username_invalid`.
    pub const USERNAME_INVALID: ApiError =
        ApiError::Code(StatusCode::BAD_REQUEST, code::USERNAME_INVALID);
    /// `410 ticket_expired`.
    pub const TICKET_EXPIRED: ApiError = ApiError::Code(StatusCode::GONE, code::TICKET_EXPIRED);
    /// `409 email_in_use`.
    pub const EMAIL_IN_USE: ApiError = ApiError::Code(StatusCode::CONFLICT, code::EMAIL_IN_USE);
    /// `409 identity_taken`.
    pub const IDENTITY_TAKEN: ApiError = ApiError::Code(StatusCode::CONFLICT, code::IDENTITY_TAKEN);
    /// `409 conflict`.
    pub const CONFLICT: ApiError = ApiError::Code(StatusCode::CONFLICT, code::CONFLICT);
    /// `403 namespace_limit`.
    pub const NAMESPACE_LIMIT: ApiError =
        ApiError::Code(StatusCode::FORBIDDEN, code::NAMESPACE_LIMIT);
    /// `409 not_empty`.
    pub const NOT_EMPTY: ApiError = ApiError::Code(StatusCode::CONFLICT, code::NOT_EMPTY);
    /// `409 last_admin`.
    pub const LAST_ADMIN: ApiError = ApiError::Code(StatusCode::CONFLICT, code::LAST_ADMIN);
    /// `409 ambiguous_prefix`.
    pub const AMBIGUOUS_PREFIX: ApiError =
        ApiError::Code(StatusCode::CONFLICT, code::AMBIGUOUS_PREFIX);
    /// `503 workload_unconfigured`.
    pub const WORKLOAD_UNCONFIGURED: ApiError =
        ApiError::Code(StatusCode::SERVICE_UNAVAILABLE, code::WORKLOAD_UNCONFIGURED);
    /// `404 unknown_provider`.
    pub const UNKNOWN_PROVIDER: ApiError =
        ApiError::Code(StatusCode::NOT_FOUND, code::UNKNOWN_PROVIDER);
    /// `502 upstream_error`.
    pub const UPSTREAM: ApiError = ApiError::Code(StatusCode::BAD_GATEWAY, code::UPSTREAM_ERROR);
    /// `403 no_verified_email`.
    pub const NO_VERIFIED_EMAIL: ApiError =
        ApiError::Code(StatusCode::FORBIDDEN, code::NO_VERIFIED_EMAIL);
    /// `409 last_identity`.
    pub const LAST_IDENTITY: ApiError = ApiError::Code(StatusCode::CONFLICT, code::LAST_IDENTITY);
    /// `403 reauth_required`.
    pub const REAUTH_REQUIRED: ApiError =
        ApiError::Code(StatusCode::FORBIDDEN, code::REAUTH_REQUIRED);
    /// `503 temporarily_unavailable`.
    pub const UNAVAILABLE: ApiError = ApiError::Code(
        StatusCode::SERVICE_UNAVAILABLE,
        code::TEMPORARILY_UNAVAILABLE,
    );
    /// `429 rate_limited`.
    pub const RATE_LIMITED: ApiError =
        ApiError::Code(StatusCode::TOO_MANY_REQUESTS, code::RATE_LIMITED);
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        reject(self.status(), self.code())
    }
}

impl From<StoreError> for ApiError {
    /// Name errors map to their own codes; a tombstoned name is reported
    /// exactly like a taken one. Anything unexpected is a logged 500 whose
    /// message never reaches the body.
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NameTaken | StoreError::NameTombstoned => ApiError::USERNAME_TAKEN,
            StoreError::Name(_) | StoreError::NotUserNameable => ApiError::USERNAME_INVALID,
            StoreError::NotFound => ApiError::NotFound,
            StoreError::EmailTaken => ApiError::EMAIL_IN_USE,
            StoreError::IdentityTaken => ApiError::IDENTITY_TAKEN,
            StoreError::BadRole | StoreError::BadPrefix => ApiError::BadRequest,
            StoreError::PersonalNode | StoreError::HasChildren => ApiError::CONFLICT,
            StoreError::OwnedLimit => ApiError::NAMESPACE_LIMIT,
            StoreError::LastIdentity => ApiError::LAST_IDENTITY,
            StoreError::ReleaseLimited => ApiError::RATE_LIMITED,
            other => {
                tracing::warn!(error = %other, "store operation failed");
                ApiError::Internal
            }
        }
    }
}

/// Log a store failure with context and turn it into an [`ApiError`].
pub(crate) fn store_err(what: &'static str) -> impl Fn(StoreError) -> ApiError {
    move |e| {
        tracing::debug!(error = %e, %what, "store error");
        ApiError::from(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejections_are_nosniff_json() {
        let r = reject(StatusCode::FORBIDDEN, "forbidden");
        let h = r.headers();
        assert_eq!(h[header::CONTENT_TYPE], "application/json");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn store_errors_map_without_echoing() {
        assert_eq!(
            ApiError::from(StoreError::NameTaken),
            ApiError::USERNAME_TAKEN
        );
        assert_eq!(
            ApiError::from(StoreError::NameTombstoned),
            ApiError::USERNAME_TAKEN
        );
        assert_eq!(
            ApiError::from(StoreError::Name(forgs::NameError::Empty)),
            ApiError::USERNAME_INVALID
        );
        assert_eq!(ApiError::from(StoreError::NotFound), ApiError::NotFound);
        assert_eq!(
            ApiError::from(StoreError::EmailTaken),
            ApiError::EMAIL_IN_USE
        );
        assert_eq!(
            ApiError::from(StoreError::CorruptRow("secret detail".into())),
            ApiError::Internal
        );
        assert_eq!(
            ApiError::from(StoreError::OwnedLimit),
            ApiError::NAMESPACE_LIMIT
        );
        assert_eq!(
            ApiError::from(StoreError::LastIdentity),
            ApiError::LAST_IDENTITY
        );
        assert_eq!(
            ApiError::from(StoreError::ReleaseLimited),
            ApiError::RATE_LIMITED
        );
        assert_eq!(ApiError::LAST_IDENTITY.status(), StatusCode::CONFLICT);
        assert_eq!(ApiError::REAUTH_REQUIRED.status(), StatusCode::FORBIDDEN);
        assert_eq!(ApiError::REAUTH_REQUIRED.code(), "reauth_required");
        assert_eq!(ApiError::NAMESPACE_LIMIT.status(), StatusCode::FORBIDDEN);
        assert_eq!(ApiError::NOT_EMPTY.status(), StatusCode::CONFLICT);
        assert_eq!(ApiError::Internal.code(), "server_error");
        assert_eq!(ApiError::TICKET_EXPIRED.status(), StatusCode::GONE);
    }
}
