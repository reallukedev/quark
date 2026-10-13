//! FAST tokens (XEP-0484): after one full sign-in, a device reconnects with a single round trip
//! and no password hashing. Tokens are per device, expire, and rotate.

use base64::Engine;
use rand::RngCore;

use crate::db::{params, Db, Migration};

pub static MIGRATION: Migration = Migration {
    module: "fast",
    steps: &["CREATE TABLE fast_tokens (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        agent TEXT NOT NULL,
        mechanism TEXT NOT NULL,
        token BLOB NOT NULL,
        expires INTEGER NOT NULL,
        previous BLOB,
        previous_expires INTEGER,
        PRIMARY KEY (host, user, agent),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID"],
};

/// How long a token stays valid.
pub const LIFETIME_MS: i64 = 30 * 86_400_000;
/// How long the previous token keeps working after a new one is issued, in case the device
/// didn't get the new one.
const OVERLAP_MS: i64 = 86_400_000;

#[derive(Clone)]
pub struct FastTokens {
    db: Db,
}

impl FastTokens {
    pub fn new(db: Db) -> Self {
        FastTokens { db }
    }

    /// Issues a new token for a device, keeping the current one as `previous` for a day.
    /// Returns (token, expiry).
    pub async fn issue(&self, host: &str, user: &str, agent: &str, mechanism: &str) -> Result<(String, i64), crate::db::DbError> {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let now = quark_core::time::now_ms();
        let expires = now + LIFETIME_MS;
        let (h, u, a, m, t) = (host.to_string(), user.to_string(), agent.to_string(), mechanism.to_string(), token.clone());
        self.db
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO fast_tokens (host, user, agent, mechanism, token, expires) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(host, user, agent) DO UPDATE SET previous = token, previous_expires = MIN(expires, ?7),
                        token = excluded.token, expires = excluded.expires, mechanism = excluded.mechanism",
                    params![h, u, a, m, t.as_bytes(), expires, now + OVERLAP_MS],
                )
            })
            .await?;
        Ok((token, expires))
    }

    /// Forgets a device's tokens (`<fast invalidate='true'/>`).
    pub async fn revoke(&self, host: &str, user: &str, agent: &str) -> Result<(), crate::db::DbError> {
        let (h, u, a) = (host.to_string(), user.to_string(), agent.to_string());
        self.db
            .write(move |tx| tx.execute("DELETE FROM fast_tokens WHERE host = ?1 AND user = ?2 AND agent = ?3", params![h, u, a]))
            .await
            .map(|_| ())
    }

    /// Forgets every token of an account (password change, account turned off).
    pub async fn revoke_all(&self, host: &str, user: &str) -> Result<(), crate::db::DbError> {
        let (h, u) = (host.to_string(), user.to_string());
        self.db.write(move |tx| tx.execute("DELETE FROM fast_tokens WHERE host = ?1 AND user = ?2", params![h, u])).await.map(|_| ())
    }
}

#[async_trait::async_trait]
impl crate::sasl::TokenCheck for FastTokens {
    async fn tokens(&self, host: &str, user: &str, mechanism: &str) -> Vec<Vec<u8>> {
        let (h, u, m) = (host.to_string(), user.to_string(), mechanism.to_string());
        let now = quark_core::time::now_ms();
        self.db
            .read(move |c| {
                let mut st = c.prepare_cached(
                    "SELECT token, expires, previous, previous_expires FROM fast_tokens WHERE host = ?1 AND user = ?2 AND mechanism = ?3",
                )?;
                let rows = st.query_map(params![h, u, m], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<Vec<u8>>>(2)?, r.get::<_, Option<i64>>(3)?))
                })?;
                let mut out = Vec::new();
                for row in rows {
                    let (t, e, p, pe) = row?;
                    if e > now {
                        out.push(t);
                    }
                    if let (Some(p), Some(pe)) = (p, pe) {
                        if pe > now {
                            out.push(p);
                        }
                    }
                }
                Ok(out)
            })
            .await
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sasl::TokenCheck;

    async fn store() -> FastTokens {
        let db = Db::memory().unwrap();
        db.migrate(&[&crate::accounts::MIGRATION, &MIGRATION]).unwrap();
        crate::accounts::Accounts::new(db.clone()).create("a.test", "sam", "password1", crate::accounts::Role::Member).await.unwrap();
        FastTokens::new(db)
    }

    #[tokio::test]
    async fn rotation_keeps_previous_token_valid() {
        let s = store().await;
        let (t1, _) = s.issue("a.test", "sam", "phone", "HT-SHA-256-NONE").await.unwrap();
        let (t2, _) = s.issue("a.test", "sam", "phone", "HT-SHA-256-NONE").await.unwrap();
        let valid = s.tokens("a.test", "sam", "HT-SHA-256-NONE").await;
        assert!(valid.contains(&t1.into_bytes()));
        assert!(valid.contains(&t2.into_bytes()));
    }

    #[tokio::test]
    async fn revoke_all_clears_tokens() {
        let s = store().await;
        s.issue("a.test", "sam", "phone", "HT-SHA-256-NONE").await.unwrap();
        s.revoke_all("a.test", "sam").await.unwrap();
        assert!(s.tokens("a.test", "sam", "HT-SHA-256-NONE").await.is_empty());
    }
}
