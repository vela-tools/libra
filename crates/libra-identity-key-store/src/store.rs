//! Opening the store.

use crate::error::StoreError;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::Path, time::Duration};

/// How long a write waits for another writer before failing.
///
/// The proxy only reads and renews its lease; the command line writes rarely. A writer that has to
/// wait longer than this is stuck, and failing is better than stalling a request behind it.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections held open. Reads are concurrent under WAL; writes are serialized by SQLite anyway.
const MAX_CONNECTIONS: u32 = 4;

/// The principals, keys and lease of one deployment.
#[derive(Debug, Clone)]
pub struct ApiKeyStore {
    pool: SqlitePool,
}

impl ApiKeyStore {
    /// Opens the database at `path`, creating it if it does not exist, and brings its schema up to
    /// date.
    ///
    /// Foreign keys are switched on explicitly: removing a principal has to remove its keys, and
    /// SQLite enforces nothing unless told to.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the file cannot be opened and
    /// [`StoreError::Migration`] if the schema cannot be migrated.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(BUSY_TIMEOUT);

        let pool = SqlitePoolOptions::new().max_connections(MAX_CONNECTIONS).connect_with(options).await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    /// The connection pool, for the operations defined beside each record type.
    pub(crate) const fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Closes every connection, waiting for those in use.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    #[tokio::test]
    async fn opening_twice_keeps_the_data_and_the_journal_is_write_ahead() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("keys.db");

        let first = ApiKeyStore::open(&path).await.unwrap();
        sqlx::query("INSERT INTO principals (id, name, created_at) VALUES (zeroblob(16), 'ingest', 0)")
            .execute(first.pool())
            .await
            .unwrap();
        first.close().await;

        let second = ApiKeyStore::open(&path).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM principals").fetch_one(second.pool()).await.unwrap();
        let journal: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(second.pool()).await.unwrap();

        assert_eq!(count, 1);
        assert_eq!(journal, "wal");
    }

    #[tokio::test]
    async fn a_row_naming_a_principal_that_does_not_exist_is_refused() {
        let directory = TempDir::new().unwrap();
        let store = ApiKeyStore::open(&directory.path().join("keys.db")).await.unwrap();

        let orphan = sqlx::query("INSERT INTO principal_groups (principal, name) VALUES (zeroblob(16), 'fleet')")
            .execute(store.pool())
            .await;

        assert!(orphan.is_err());
    }
}
