//! [`forgs::TokenStore`] over the forgs tables.
//!
//! Every method is a lookup by **token hash**; secrets are never stored.
//! Expiry is **not** filtered here (except where noted): `forgs::verify`
//! compares it against the clock, so an expired credential is
//! `AuthError::Expired` rather than the indistinguishable `Unknown` — the
//! difference between an operator diagnosing a long job and hunting a phantom
//! revocation. Negative stored times clamp to 0, i.e. expired.
//!
//! Apps with their own token kinds (fleet: nodes) wrap [`Store`] and delegate
//! the core lookups to it, overriding `lookup_app`.

use async_trait::async_trait;
use forgs::store::{
    ApiKeyRecord, DeviceSecretRecord, RefreshRecord, SessionRecord, WorkloadRecord,
};
use forgs::{ApiKeyId, NsNodeId, PendingId, SubjectKey, TokenHash, TokenStore, UserId};

use crate::error::{from_ts, parse_id, StoreError};
use crate::Store;

fn err(e: impl Into<StoreError>) -> String {
    e.into().to_string()
}

#[async_trait]
impl TokenStore for Store {
    async fn lookup_session(&self, hash: &TokenHash) -> Result<Option<SessionRecord>, String> {
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT user_id, expires FROM forgs_session WHERE token_hash = ?1")
                .bind(hash.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(err)?;
        row.map(|(user, expires)| {
            Ok(SessionRecord {
                user_id: parse_id!(UserId, user).map_err(err)?,
                expires: from_ts(expires),
            })
        })
        .transpose()
    }

    async fn lookup_refresh_token(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<RefreshRecord>, String> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT user_id, expires FROM forgs_refresh_token WHERE token_hash = ?1",
        )
        .bind(hash.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(err)?;
        row.map(|(user, expires)| {
            Ok(RefreshRecord {
                user_id: parse_id!(UserId, user).map_err(err)?,
                expires: from_ts(expires),
            })
        })
        .transpose()
    }

    /// A consumed key is `None` (it no longer exists as a credential); an
    /// expired one is returned and `verify_api_key` rejects it.
    async fn lookup_api_key(&self, hash: &TokenHash) -> Result<Option<ApiKeyRecord>, String> {
        type Row = (
            String,
            String,
            String,
            bool,
            Option<i64>,
            Option<String>,
            Option<String>,
        );
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, ns_node_id, purpose, single_use, expires, subject_name, created_by
               FROM forgs_api_key WHERE key_hash = ?1 AND consumed_at IS NULL",
        )
        .bind(hash.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(err)?;
        row.map(
            |(id, ns, purpose, single_use, expires, subject_name, created_by)| {
                Ok(ApiKeyRecord {
                    id: parse_id!(ApiKeyId, id).map_err(err)?,
                    ns: parse_id!(NsNodeId, ns).map_err(err)?,
                    purpose,
                    single_use,
                    expires: expires.map(from_ts),
                    subject_name,
                    created_by: created_by
                        .map(|u| parse_id!(UserId, u))
                        .transpose()
                        .map_err(err)?,
                })
            },
        )
        .transpose()
    }

    /// A stored subject that does not parse resolves to `None` — **fails
    /// closed**. Widening it into some default subject is the one outcome that
    /// must never happen, since that subject would then be matched against
    /// grants.
    async fn lookup_workload(&self, hash: &TokenHash) -> Result<Option<WorkloadRecord>, String> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT subject, expires FROM forgs_workload_token WHERE token_hash = ?1",
        )
        .bind(hash.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(err)?;
        let Some((subject, expires)) = row else {
            return Ok(None);
        };
        let Some(subject) = SubjectKey::parse_with(&subject, &self.app_subject_kinds) else {
            return Ok(None);
        };
        Ok(Some(WorkloadRecord {
            subject,
            expires: from_ts(expires),
        }))
    }

    /// Only rows still awaiting redemption (pending or approved, not
    /// consumed or denied) resolve.
    async fn lookup_device_secret(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<DeviceSecretRecord>, String> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT id, expires FROM forgs_pending_device WHERE device_hash = ?1 AND consumed_at IS NULL",
        )
        .bind(hash.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(err)?;
        row.map(|(id, expires)| {
            Ok(DeviceSecretRecord {
                id: parse_id!(PendingId, id).map_err(err)?,
                expires: from_ts(expires),
            })
        })
        .transpose()
    }
}
