//! Accounts and their credentials. Passwords are never stored: only SCRAM keys (RFC 5802) for
//! SHA-1, SHA-256 and SHA-512, derived once with PBKDF2, which also serve PLAIN sign-ins.

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::db::{params, Db, DbError, Migration, OptionalExtension};

pub static MIGRATION: Migration = Migration {
    module: "accounts",
    steps: &["CREATE TABLE accounts (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'member',
        enabled INTEGER NOT NULL DEFAULT 1,
        created INTEGER NOT NULL,
        password_changed INTEGER NOT NULL,
        last_active INTEGER,
        salt BLOB NOT NULL,
        iterations INTEGER NOT NULL,
        sha1_stored BLOB NOT NULL, sha1_server BLOB NOT NULL,
        sha256_stored BLOB NOT NULL, sha256_server BLOB NOT NULL,
        sha512_stored BLOB NOT NULL, sha512_server BLOB NOT NULL,
        PRIMARY KEY (host, user)
    ) WITHOUT ROWID"],
};

/// PBKDF2 rounds for new passwords. Clients cache the salted password, so this is paid once per
/// device, not per sign-in.
pub const ITERATIONS: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Member,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Admin => "admin",
        }
    }
    fn parse(s: &str) -> Role {
        if s == "admin" {
            Role::Admin
        } else {
            Role::Member
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramHash {
    Sha1,
    Sha256,
    Sha512,
}

impl ScramHash {
    pub fn mechanism(self) -> &'static str {
        match self {
            ScramHash::Sha1 => "SCRAM-SHA-1",
            ScramHash::Sha256 => "SCRAM-SHA-256",
            ScramHash::Sha512 => "SCRAM-SHA-512",
        }
    }

    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! mac {
            ($h:ty) => {{
                let mut m = <Hmac<$h> as Mac>::new_from_slice(key).expect("HMAC takes keys of any length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            ScramHash::Sha1 => mac!(Sha1),
            ScramHash::Sha256 => mac!(Sha256),
            ScramHash::Sha512 => mac!(Sha512),
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            ScramHash::Sha1 => Sha1::digest(data).to_vec(),
            ScramHash::Sha256 => Sha256::digest(data).to_vec(),
            ScramHash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn salted_password(self, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        match self {
            ScramHash::Sha1 => pbkdf2::pbkdf2_hmac_array::<Sha1, 20>(password, salt, iterations).to_vec(),
            ScramHash::Sha256 => pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password, salt, iterations).to_vec(),
            ScramHash::Sha512 => pbkdf2::pbkdf2_hmac_array::<Sha512, 64>(password, salt, iterations).to_vec(),
        }
    }

    /// (StoredKey, ServerKey) for a salted password.
    pub fn keys(self, salted: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let client_key = self.hmac(salted, b"Client Key");
        (self.hash(&client_key), self.hmac(salted, b"Server Key"))
    }
}

/// What SCRAM needs to check a client without the password.
#[derive(Debug, Clone)]
pub struct ScramCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub user: String,
    pub role: Role,
    pub enabled: bool,
    pub created: i64,
    pub password_changed: i64,
    pub last_active: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("There's already an account called {0}.")]
    Exists(String),
    #[error("{0} doesn't exist.")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

struct Derived {
    salt: Vec<u8>,
    keys: [(Vec<u8>, Vec<u8>); 3],
}

const HASHES: [ScramHash; 3] = [ScramHash::Sha1, ScramHash::Sha256, ScramHash::Sha512];

fn derive(password: &str) -> Derived {
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let pw = saslprep(password);
    let keys = HASHES.map(|h| h.keys(&h.salted_password(pw.as_bytes(), &salt, ITERATIONS)));
    Derived { salt, keys }
}

/// SASLprep (RFC 4013) when the password needs it; plain ASCII passes through untouched.
pub fn saslprep(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return std::borrow::Cow::Borrowed(s);
    }
    stringprep::saslprep(s).unwrap_or(std::borrow::Cow::Borrowed(s))
}

/// Usernames people can type: lowercase letters, digits, `.`, `_`, `-`, up to 64.
pub fn valid_username(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}

pub fn check_password(p: &str) -> Result<(), AccountError> {
    if p.chars().count() < 8 {
        return Err(AccountError::Invalid("Passwords are at least 8 characters.".into()));
    }
    if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
        return Err(AccountError::Invalid("That password has characters chat apps can't send.".into()));
    }
    Ok(())
}

#[derive(Clone)]
pub struct Accounts {
    db: Db,
}

impl Accounts {
    pub fn new(db: Db) -> Self {
        Accounts { db }
    }

    pub async fn create(&self, host: &str, user: &str, password: &str, role: Role) -> Result<(), AccountError> {
        if !valid_username(user) {
            return Err(AccountError::Invalid(
                "Usernames use lowercase letters, numbers, dots, dashes or underscores, starting with a letter or number.".into(),
            ));
        }
        check_password(password)?;
        let pw = password.to_string();
        let d = tokio::task::spawn_blocking(move || derive(&pw)).await.map_err(|e| DbError::Join(e.to_string()))?;
        let (host, user) = (host.to_string(), user.to_string());
        let jid = format!("{user}@{host}");
        let now = quark_core::time::now_ms();
        let inserted = self
            .db
            .write(move |t| {
                t.execute(
                    "INSERT INTO accounts (host, user, role, enabled, created, password_changed, salt, iterations,
                        sha1_stored, sha1_server, sha256_stored, sha256_server, sha512_stored, sha512_server)
                     VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT DO NOTHING",
                    params![
                        host,
                        user,
                        role.as_str(),
                        now,
                        d.salt,
                        ITERATIONS,
                        d.keys[0].0,
                        d.keys[0].1,
                        d.keys[1].0,
                        d.keys[1].1,
                        d.keys[2].0,
                        d.keys[2].1
                    ],
                )
            })
            .await?;
        if inserted == 0 {
            return Err(AccountError::Exists(jid));
        }
        Ok(())
    }

    pub async fn exists(&self, host: &str, user: &str) -> Result<bool, DbError> {
        let (h, u) = (host.to_string(), user.to_string());
        self.db
            .read(move |c| {
                c.query_row("SELECT 1 FROM accounts WHERE host = ?1 AND user = ?2", params![h, u], |_| Ok(()))
                    .optional()
                    .map(|r| r.is_some())
            })
            .await
    }

    pub async fn info(&self, host: &str, user: &str) -> Result<Option<AccountInfo>, DbError> {
        let (h, u) = (host.to_string(), user.to_string());
        self.db
            .read(move |c| {
                c.query_row(
                    "SELECT user, role, enabled, created, password_changed, last_active FROM accounts WHERE host = ?1 AND user = ?2",
                    params![h, u],
                    row_info,
                )
                .optional()
            })
            .await
    }

    pub async fn list(&self, host: &str) -> Result<Vec<AccountInfo>, DbError> {
        let h = host.to_string();
        self.db
            .read(move |c| {
                let mut st = c.prepare_cached(
                    "SELECT user, role, enabled, created, password_changed, last_active FROM accounts WHERE host = ?1 ORDER BY user",
                )?;
                let rows = st.query_map([h], row_info)?;
                rows.collect()
            })
            .await
    }

    pub async fn count(&self, host: &str) -> Result<u64, DbError> {
        let h = host.to_string();
        self.db
            .read(move |c| c.query_row("SELECT COUNT(*) FROM accounts WHERE host = ?1", [h], |r| r.get::<_, i64>(0)).map(|n| n as u64))
            .await
    }

    pub async fn scram(&self, host: &str, user: &str, hash: ScramHash) -> Result<Option<(ScramCredentials, bool)>, DbError> {
        let (h, u) = (host.to_string(), user.to_string());
        let cols = match hash {
            ScramHash::Sha1 => "sha1_stored, sha1_server",
            ScramHash::Sha256 => "sha256_stored, sha256_server",
            ScramHash::Sha512 => "sha512_stored, sha512_server",
        };
        let sql = format!("SELECT salt, iterations, {cols}, enabled FROM accounts WHERE host = ?1 AND user = ?2");
        self.db
            .read(move |c| {
                c.query_row(&sql, params![h, u], |r| {
                    Ok((
                        ScramCredentials { salt: r.get(0)?, iterations: r.get(1)?, stored_key: r.get(2)?, server_key: r.get(3)? },
                        r.get::<_, bool>(4)?,
                    ))
                })
                .optional()
            })
            .await
    }

    /// Checks a password (PLAIN, in-band password change). Constant time in the comparison.
    pub async fn verify_password(&self, host: &str, user: &str, password: &str) -> Result<bool, DbError> {
        let Some((cred, enabled)) = self.scram(host, user, ScramHash::Sha256).await? else {
            return Ok(false);
        };
        if !enabled {
            return Ok(false);
        }
        let pw = password.to_string();
        tokio::task::spawn_blocking(move || {
            let h = ScramHash::Sha256;
            let (stored, _) = h.keys(&h.salted_password(saslprep(&pw).as_bytes(), &cred.salt, cred.iterations));
            bool::from(stored.ct_eq(&cred.stored_key))
        })
        .await
        .map_err(|e| DbError::Join(e.to_string()))
    }

    pub async fn set_password(&self, host: &str, user: &str, password: &str) -> Result<(), AccountError> {
        check_password(password)?;
        let pw = password.to_string();
        let d = tokio::task::spawn_blocking(move || derive(&pw)).await.map_err(|e| DbError::Join(e.to_string()))?;
        let (h, u) = (host.to_string(), user.to_string());
        let now = quark_core::time::now_ms();
        let n = self
            .db
            .write(move |t| {
                t.execute(
                    "UPDATE accounts SET salt = ?3, iterations = ?4, sha1_stored = ?5, sha1_server = ?6, sha256_stored = ?7, sha256_server = ?8,
                        sha512_stored = ?9, sha512_server = ?10, password_changed = ?11 WHERE host = ?1 AND user = ?2",
                    params![h, u, d.salt, ITERATIONS, d.keys[0].0, d.keys[0].1, d.keys[1].0, d.keys[1].1, d.keys[2].0, d.keys[2].1, now],
                )
            })
            .await?;
        if n == 0 {
            return Err(AccountError::NotFound(format!("{user}@{host}")));
        }
        Ok(())
    }

    pub async fn set_role(&self, host: &str, user: &str, role: Role) -> Result<(), AccountError> {
        self.update(host, user, "role", role.as_str().to_string()).await
    }

    pub async fn set_enabled(&self, host: &str, user: &str, enabled: bool) -> Result<(), AccountError> {
        self.update(host, user, "enabled", enabled).await
    }

    async fn update<V: rusqlite::ToSql + Send + 'static>(
        &self,
        host: &str,
        user: &str,
        col: &'static str,
        v: V,
    ) -> Result<(), AccountError> {
        let (h, u) = (host.to_string(), user.to_string());
        let sql = format!("UPDATE accounts SET {col} = ?3 WHERE host = ?1 AND user = ?2");
        let n = self.db.write(move |t| t.execute(&sql, params![h, u, v])).await?;
        if n == 0 {
            return Err(AccountError::NotFound(format!("{user}@{host}")));
        }
        Ok(())
    }

    pub async fn touch(&self, host: &str, user: &str, at: i64) -> Result<(), DbError> {
        let (h, u) = (host.to_string(), user.to_string());
        self.db
            .write(move |t| t.execute("UPDATE accounts SET last_active = ?3 WHERE host = ?1 AND user = ?2", params![h, u, at]))
            .await
            .map(|_| ())
    }

    /// Deletes the account; tables that reference it go with it (`ON DELETE CASCADE`).
    pub async fn delete(&self, host: &str, user: &str) -> Result<bool, DbError> {
        let (h, u) = (host.to_string(), user.to_string());
        self.db.write(move |t| t.execute("DELETE FROM accounts WHERE host = ?1 AND user = ?2", params![h, u])).await.map(|n| n > 0)
    }
}

fn row_info(r: &rusqlite::Row<'_>) -> rusqlite::Result<AccountInfo> {
    Ok(AccountInfo {
        user: r.get(0)?,
        role: Role::parse(&r.get::<_, String>(1)?),
        enabled: r.get(2)?,
        created: r.get(3)?,
        password_changed: r.get(4)?,
        last_active: r.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn accounts() -> Accounts {
        let db = Db::memory().unwrap();
        db.migrate(&[&MIGRATION]).unwrap();
        Accounts::new(db)
    }

    #[tokio::test]
    async fn create_verify_and_change_password() {
        let a = accounts().await;
        a.create("a.test", "sam", "correct horse", Role::Member).await.unwrap();
        assert!(a.verify_password("a.test", "sam", "correct horse").await.unwrap());
        assert!(!a.verify_password("a.test", "sam", "wrong horse!").await.unwrap());
        a.set_password("a.test", "sam", "battery staple").await.unwrap();
        assert!(a.verify_password("a.test", "sam", "battery staple").await.unwrap());
    }

    #[tokio::test]
    async fn duplicate_is_refused() {
        let a = accounts().await;
        a.create("a.test", "sam", "correct horse", Role::Member).await.unwrap();
        assert!(matches!(a.create("a.test", "sam", "correct horse", Role::Member).await, Err(AccountError::Exists(_))));
    }

    #[tokio::test]
    async fn disabled_account_fails_password_check() {
        let a = accounts().await;
        a.create("a.test", "sam", "correct horse", Role::Member).await.unwrap();
        a.set_enabled("a.test", "sam", false).await.unwrap();
        assert!(!a.verify_password("a.test", "sam", "correct horse").await.unwrap());
    }

    #[test]
    fn usernames() {
        assert!(valid_username("sam.r-2_x"));
        assert!(!valid_username("Sam"));
        assert!(!valid_username(".sam"));
        assert!(!valid_username(""));
    }

    #[test]
    fn scram_sha1_matches_rfc5802_vector() {
        // RFC 5802 §5: user "user", password "pencil".
        let salt = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, "QSXCR+Q6sek8bf92").unwrap();
        let h = ScramHash::Sha1;
        let salted = h.salted_password(b"pencil", &salt, 4096);
        let (_, server_key) = h.keys(&salted);
        let auth = "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j";
        let sig = h.hmac(&server_key, auth.as_bytes());
        assert_eq!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig), "rmF9pqV8S7suAoZWja4dJRkFsKQ=");
    }
}
