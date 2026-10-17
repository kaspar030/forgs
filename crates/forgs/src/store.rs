//! The storage seam token verification sits on.
//!
//! [`TokenStore`] is implemented by `forgs-store` over its `SQLite` handle (and
//! extended by apps for their own token kinds via [`TokenStore::lookup_app`]).
//! Keeping it a trait means [`crate::verify`] is unit-testable against an
//! in-memory fake, and — more importantly — that this crate never learns how
//! anything is stored.
//!
//! Every lookup is keyed by [`TokenHash`], never by the token: the secret is not
//! persisted anywhere.

use async_trait::async_trait;

use crate::ids::{ApiKeyId, NsNodeId, PendingId, SshKeyId, UserId};
use crate::ssh::SshFingerprint;
use crate::subject::SubjectKey;
use crate::token::{AppKind, TokenHash};

/// A user session row.
///
/// Not bound to any namespace: the request names the namespace it acts in,
/// and authz checks membership there (docs/design.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// The user this session belongs to.
    pub user_id: UserId,
    /// Expiry, epoch seconds.
    pub expires: u64,
}

/// A user's refresh-token row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    /// The user this refresh token belongs to.
    pub user_id: UserId,
    /// Expiry, epoch seconds. Always set.
    pub expires: u64,
}

/// An API key row (fleet's auth key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRecord {
    /// The key's id.
    pub id: ApiKeyId,
    /// The namespace the key is scoped to.
    pub ns: NsNodeId,
    /// What the key is for. App-defined; redemption dispatches on it.
    pub purpose: String,
    /// Whether redeeming the key consumes it.
    pub single_use: bool,
    /// Expiry, epoch seconds; `None` means no expiry (never over the API).
    pub expires: Option<u64>,
    /// A stable identity name that survives rotation, or `None` for
    /// "no name" (`NULL`, never `''`).
    pub subject_name: Option<String>,
    /// The user who minted it, or `None` for a shell-minted key.
    pub created_by: Option<UserId>,
}

/// A CI workload token row.
///
/// Deliberately **not** namespace-scoped: a workload belongs to no tenant. Its
/// subject is `<issuer label>/workload:id:<owner_id>/<repo_id>` for the OIDC
/// path, or a namespace-scoped `<ns>/workload:agent:<name>` for a named API
/// key. It reaches resources only through grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRecord {
    /// The subject the token speaks as. A store must drop a row whose stored
    /// subject does not parse **closed** (return `None`), never guess.
    pub subject: SubjectKey,
    /// Expiry, epoch seconds. Always set: a workload token is per job.
    pub expires: u64,
}

/// A pending device approval's poll secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSecretRecord {
    /// The pending row.
    pub id: PendingId,
    /// Expiry, epoch seconds.
    pub expires: u64,
}

/// A row of an app-registered token kind (fleet: a node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRecord {
    /// The subject the token speaks as.
    pub subject: SubjectKey,
    /// Expiry, epoch seconds; `None` for a credential that does not expire
    /// (e.g. one that rotates instead).
    pub expires: Option<u64>,
    /// When the current token was issued (epoch seconds), for a rotation
    /// policy ([`crate::rotation`]).
    pub issued_at: Option<u64>,
}

/// Read access to the credential tables.
///
/// Errors are returned as `String` rather than a concrete error type so this
/// crate does not depend on a storage error enum or on `sqlx`; the caller maps
/// them back. Every error fails closed ([`crate::verify::AuthError::Store`]).
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Look up a session by its token hash.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_session(&self, hash: &TokenHash) -> Result<Option<SessionRecord>, String>;

    /// Look up a refresh token by its hash **without** consuming it.
    ///
    /// There is deliberately no consume counterpart: redemption is
    /// non-rotating (see [`crate::token::TokenKind::Refresh`]).
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_refresh_token(&self, hash: &TokenHash)
        -> Result<Option<RefreshRecord>, String>;

    /// Look up an API key by its hash **without** consuming it.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_api_key(&self, hash: &TokenHash) -> Result<Option<ApiKeyRecord>, String>;

    /// Look up a CI workload token by its hash.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_workload(&self, hash: &TokenHash) -> Result<Option<WorkloadRecord>, String>;

    /// Look up a pending device approval by its poll secret's hash.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_device_secret(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<DeviceSecretRecord>, String>;

    /// Look up a token of an app-registered kind.
    ///
    /// The default knows no app kinds and answers `Ok(None)` (so an app token
    /// is [`crate::verify::AuthError::Unknown`]). Apps that register kinds
    /// override this.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_app(
        &self,
        kind: AppKind,
        hash: &TokenHash,
    ) -> Result<Option<AppRecord>, String> {
        let _ = (kind, hash);
        Ok(None)
    }
}

/// A registered SSH public key, found by fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyRecord {
    /// The key's id.
    pub id: SshKeyId,
    /// The user who registered it.
    pub user_id: UserId,
    /// Expiry, epoch seconds; `None` for a key that does not expire.
    pub expires: Option<u64>,
}

/// Lookup of registered SSH public keys, for [`crate::ssh::authenticate_ssh_key`].
///
/// Separate from [`TokenStore`] because an SSH key is not a bearer token: it
/// is found by its public fingerprint, and holding it proves nothing until
/// the SSH server has checked a signature. Errors fail closed, as there.
#[async_trait]
pub trait SshKeyStore: Send + Sync {
    /// The key with this fingerprint, if registered to a user who may log
    /// in. Expiry is **not** filtered: the caller reports it.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_ssh_key(
        &self,
        fingerprint: &SshFingerprint,
    ) -> Result<Option<SshKeyRecord>, String>;

    /// Record that key `id` was used at `now` (best-effort, may be
    /// throttled). The default does nothing.
    ///
    /// # Errors
    ///
    /// Returns a storage error description; callers ignore it.
    async fn touch_ssh_key(&self, id: SshKeyId, now: u64) -> Result<(), String> {
        let _ = (id, now);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory [`TokenStore`] used by this crate's own tests.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{
        ApiKeyRecord, AppRecord, DeviceSecretRecord, RefreshRecord, SessionRecord, TokenStore,
        WorkloadRecord,
    };
    use crate::token::{AppKind, TokenHash};
    use async_trait::async_trait;

    #[derive(Default)]
    pub(crate) struct FakeStore {
        sessions: Mutex<HashMap<String, SessionRecord>>,
        refresh_tokens: Mutex<HashMap<String, RefreshRecord>>,
        api_keys: Mutex<HashMap<String, ApiKeyRecord>>,
        workloads: Mutex<HashMap<String, WorkloadRecord>>,
        device_secrets: Mutex<HashMap<String, DeviceSecretRecord>>,
        apps: Mutex<HashMap<(&'static str, String), AppRecord>>,
    }

    fn put<V>(map: &Mutex<HashMap<String, V>>, hash: &TokenHash, v: V) {
        map.lock().unwrap().insert(hash.as_str().to_owned(), v);
    }

    fn get<V: Clone>(map: &Mutex<HashMap<String, V>>, hash: &TokenHash) -> Option<V> {
        map.lock().unwrap().get(hash.as_str()).cloned()
    }

    impl FakeStore {
        pub(crate) fn with_session(self, hash: &TokenHash, r: SessionRecord) -> Self {
            put(&self.sessions, hash, r);
            self
        }
        pub(crate) fn with_refresh_token(self, hash: &TokenHash, r: RefreshRecord) -> Self {
            put(&self.refresh_tokens, hash, r);
            self
        }
        pub(crate) fn with_api_key(self, hash: &TokenHash, r: ApiKeyRecord) -> Self {
            put(&self.api_keys, hash, r);
            self
        }
        pub(crate) fn with_workload(self, hash: &TokenHash, r: WorkloadRecord) -> Self {
            put(&self.workloads, hash, r);
            self
        }
        pub(crate) fn with_device_secret(self, hash: &TokenHash, r: DeviceSecretRecord) -> Self {
            put(&self.device_secrets, hash, r);
            self
        }
        pub(crate) fn with_app(self, kind: AppKind, hash: &TokenHash, r: AppRecord) -> Self {
            self.apps
                .lock()
                .unwrap()
                .insert((kind.label(), hash.as_str().to_owned()), r);
            self
        }
    }

    #[async_trait]
    impl TokenStore for FakeStore {
        async fn lookup_session(&self, h: &TokenHash) -> Result<Option<SessionRecord>, String> {
            Ok(get(&self.sessions, h))
        }
        async fn lookup_refresh_token(
            &self,
            h: &TokenHash,
        ) -> Result<Option<RefreshRecord>, String> {
            Ok(get(&self.refresh_tokens, h))
        }
        async fn lookup_api_key(&self, h: &TokenHash) -> Result<Option<ApiKeyRecord>, String> {
            Ok(get(&self.api_keys, h))
        }
        async fn lookup_workload(&self, h: &TokenHash) -> Result<Option<WorkloadRecord>, String> {
            Ok(get(&self.workloads, h))
        }
        async fn lookup_device_secret(
            &self,
            h: &TokenHash,
        ) -> Result<Option<DeviceSecretRecord>, String> {
            Ok(get(&self.device_secrets, h))
        }
        async fn lookup_app(
            &self,
            kind: AppKind,
            h: &TokenHash,
        ) -> Result<Option<AppRecord>, String> {
            Ok(self
                .apps
                .lock()
                .unwrap()
                .get(&(kind.label(), h.as_str().to_owned()))
                .cloned())
        }
    }

    /// A store that panics on any access: proves a code path never reaches
    /// storage.
    pub(crate) struct PanicStore;

    #[async_trait]
    impl TokenStore for PanicStore {
        async fn lookup_session(&self, _: &TokenHash) -> Result<Option<SessionRecord>, String> {
            panic!("store accessed")
        }
        async fn lookup_refresh_token(
            &self,
            _: &TokenHash,
        ) -> Result<Option<RefreshRecord>, String> {
            panic!("store accessed")
        }
        async fn lookup_api_key(&self, _: &TokenHash) -> Result<Option<ApiKeyRecord>, String> {
            panic!("store accessed")
        }
        async fn lookup_workload(&self, _: &TokenHash) -> Result<Option<WorkloadRecord>, String> {
            panic!("store accessed")
        }
        async fn lookup_device_secret(
            &self,
            _: &TokenHash,
        ) -> Result<Option<DeviceSecretRecord>, String> {
            panic!("store accessed")
        }
        async fn lookup_app(&self, _: AppKind, _: &TokenHash) -> Result<Option<AppRecord>, String> {
            panic!("store accessed")
        }
    }

    /// A store whose every lookup fails.
    pub(crate) struct BrokenStore;

    #[async_trait]
    impl TokenStore for BrokenStore {
        async fn lookup_session(&self, _: &TokenHash) -> Result<Option<SessionRecord>, String> {
            Err("disk on fire".into())
        }
        async fn lookup_refresh_token(
            &self,
            _: &TokenHash,
        ) -> Result<Option<RefreshRecord>, String> {
            Err("disk on fire".into())
        }
        async fn lookup_api_key(&self, _: &TokenHash) -> Result<Option<ApiKeyRecord>, String> {
            Err("disk on fire".into())
        }
        async fn lookup_workload(&self, _: &TokenHash) -> Result<Option<WorkloadRecord>, String> {
            Err("disk on fire".into())
        }
        async fn lookup_device_secret(
            &self,
            _: &TokenHash,
        ) -> Result<Option<DeviceSecretRecord>, String> {
            Err("disk on fire".into())
        }
    }
}
