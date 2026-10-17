//! Expiry sweep.
//!
//! **Hygiene, not the security boundary**: expiry and single use are enforced
//! at verification and by the conditional consume statements regardless. The
//! sweep only keeps tables from growing. There is no background task here;
//! the app drives [`Store::sweep`] on its own timer.

use crate::error::{ts, Result};
use crate::Store;

/// Rows removed by one [`Store::sweep`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepCounts {
    /// Expired sessions.
    pub sessions: u64,
    /// Expired refresh tokens.
    pub refresh_tokens: u64,
    /// Expired workload tokens.
    pub workload_tokens: u64,
    /// Expired or consumed API keys.
    pub api_keys: u64,
    /// Expired pending signups.
    pub pending_signups: u64,
    /// Expired or consumed (redeemed or denied) device approvals.
    pub pending_devices: u64,
}

impl Store {
    /// Delete every credential row that expired at or before `now`
    /// (`expires <= now`, matching verification's exclusive expiry), consumed
    /// single-use API keys no live workload token still references, and
    /// decided device approvals.
    ///
    /// Workload tokens are swept before API keys, so a consumed key whose
    /// tokens all just expired goes in the same pass. A consumed key is kept
    /// while one of its tokens lives: it is how disabling or removing its
    /// creator finds that token.
    ///
    /// # Errors
    ///
    /// A database error; statements already run stay applied.
    pub async fn sweep(&self, now: u64) -> Result<SweepCounts> {
        let now = ts(now)?;
        let run = |sql: &'static str| {
            let pool = &self.pool;
            async move {
                Ok::<u64, crate::StoreError>(
                    sqlx::query(sql)
                        .bind(now)
                        .execute(pool)
                        .await?
                        .rows_affected(),
                )
            }
        };
        Ok(SweepCounts {
            sessions: run("DELETE FROM forgs_session WHERE expires <= ?1").await?,
            refresh_tokens: run("DELETE FROM forgs_refresh_token WHERE expires <= ?1").await?,
            workload_tokens: run("DELETE FROM forgs_workload_token WHERE expires <= ?1").await?,
            api_keys: run("DELETE FROM forgs_api_key WHERE expires <= ?1
                     OR (consumed_at IS NOT NULL AND NOT EXISTS (
                         SELECT 1 FROM forgs_workload_token w
                          WHERE w.api_key_id = forgs_api_key.id))")
            .await?,
            pending_signups: run("DELETE FROM forgs_pending_signup WHERE expires <= ?1").await?,
            pending_devices: run(
                "DELETE FROM forgs_pending_device WHERE expires <= ?1 OR consumed_at IS NOT NULL",
            )
            .await?,
        })
    }
}
