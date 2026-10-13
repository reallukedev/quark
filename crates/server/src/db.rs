//! SQLite storage. One writer connection and a few readers in WAL mode, used from blocking
//! threads so the async runtime never waits on disk. Each feature owns its tables and brings its
//! own migrations (see [`Migration`]).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags};

pub use rusqlite::{params, OptionalExtension};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database task failed: {0}")]
    Join(String),
    #[error("database lock poisoned")]
    Poisoned,
}

/// A feature's schema history: `steps[n]` takes the schema from version n to n+1. Never edit a
/// released step; add a new one.
pub struct Migration {
    pub module: &'static str,
    pub steps: &'static [&'static str],
}

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    writer: Mutex<Connection>,
    /// Empty for in-memory databases, which have only the writer.
    readers: Vec<Mutex<Connection>>,
    next: AtomicUsize,
}

const READERS: usize = 4;

fn tune(c: &Connection) -> rusqlite::Result<()> {
    c.busy_timeout(std::time::Duration::from_secs(10))?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    // Prepared statements are cached per connection; the hot queries stay compiled.
    c.set_prepared_statement_cache_capacity(128);
    Ok(())
}

impl Db {
    pub fn open(path: &Path) -> Result<Db, DbError> {
        let writer = Connection::open(path)?;
        writer.pragma_update(None, "journal_mode", "WAL")?;
        tune(&writer)?;
        let mut readers = Vec::with_capacity(READERS);
        for _ in 0..READERS {
            let r = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
            tune(&r)?;
            readers.push(Mutex::new(r));
        }
        Ok(Db { inner: Arc::new(Inner { writer: Mutex::new(writer), readers, next: AtomicUsize::new(0) }) })
    }

    /// A private in-memory database, for tests.
    pub fn memory() -> Result<Db, DbError> {
        let writer = Connection::open_in_memory()?;
        tune(&writer)?;
        Ok(Db { inner: Arc::new(Inner { writer: Mutex::new(writer), readers: Vec::new(), next: AtomicUsize::new(0) }) })
    }

    /// Brings every feature's tables up to date, each in its own transaction.
    pub fn migrate(&self, migrations: &[&Migration]) -> Result<(), DbError> {
        let mut c = self.inner.writer.lock().map_err(|_| DbError::Poisoned)?;
        c.execute_batch("CREATE TABLE IF NOT EXISTS schema_versions (module TEXT PRIMARY KEY, version INTEGER NOT NULL)")?;
        for m in migrations {
            let have: usize = c
                .query_row("SELECT version FROM schema_versions WHERE module = ?1", [m.module], |r| r.get::<_, i64>(0))
                .optional()?
                .map_or(0, |v| usize::try_from(v).unwrap_or(0));
            for (i, step) in m.steps.iter().enumerate().skip(have) {
                let tx = c.transaction()?;
                tx.execute_batch(step)?;
                tx.execute(
                    "INSERT INTO schema_versions (module, version) VALUES (?1, ?2) ON CONFLICT(module) DO UPDATE SET version = excluded.version",
                    params![m.module, (i + 1) as i64],
                )?;
                tx.commit()?;
                tracing::debug!(module = m.module, version = i + 1, "migrated");
            }
        }
        Ok(())
    }

    /// Runs `f` on a read-only connection.
    pub async fn read<T, F>(&self, f: F) -> Result<T, DbError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let slot = if inner.readers.is_empty() {
                &inner.writer
            } else {
                &inner.readers[inner.next.fetch_add(1, Ordering::Relaxed) % inner.readers.len()]
            };
            let c = slot.lock().map_err(|_| DbError::Poisoned)?;
            f(&c).map_err(DbError::from)
        })
        .await
        .map_err(|e| DbError::Join(e.to_string()))?
    }

    /// Runs `f` inside a write transaction, committed when it returns Ok.
    pub async fn write<T, F>(&self, f: F) -> Result<T, DbError>
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T> + Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = inner.writer.lock().map_err(|_| DbError::Poisoned)?;
            let tx = c.transaction()?;
            let out = f(&tx)?;
            tx.commit()?;
            Ok(out)
        })
        .await
        .map_err(|e| DbError::Join(e.to_string()))?
    }

    /// Synchronous write for startup and tests (not from async code).
    pub fn write_blocking<T>(&self, f: impl FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T>) -> Result<T, DbError> {
        let mut c = self.inner.writer.lock().map_err(|_| DbError::Poisoned)?;
        let tx = c.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static M: Migration = Migration { module: "t", steps: &["CREATE TABLE a (x INTEGER)", "ALTER TABLE a ADD COLUMN y TEXT"] };

    #[tokio::test]
    async fn migrations_apply_once_and_in_order() {
        let db = Db::memory().unwrap();
        db.migrate(&[&M]).unwrap();
        db.migrate(&[&M]).unwrap();
        db.write(|t| t.execute("INSERT INTO a (x, y) VALUES (1, 'z')", [])).await.unwrap();
        let y: String = db.read(|c| c.query_row("SELECT y FROM a", [], |r| r.get(0))).await.unwrap();
        assert_eq!(y, "z");
    }

    #[tokio::test]
    async fn file_database_reads_see_writes() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("q.db")).unwrap();
        db.migrate(&[&M]).unwrap();
        db.write(|t| t.execute("INSERT INTO a (x) VALUES (7)", [])).await.unwrap();
        let x: i64 = db.read(|c| c.query_row("SELECT x FROM a", [], |r| r.get(0))).await.unwrap();
        assert_eq!(x, 7);
    }
}
