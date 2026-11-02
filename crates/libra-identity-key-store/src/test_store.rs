//! A fresh store in a temporary directory, for tests.

use crate::store::ApiKeyStore;
use tempfile::TempDir;

/// Opens a store in a new temporary directory. The directory is returned so it outlives the store.
pub async fn store() -> (TempDir, ApiKeyStore) {
    let directory = TempDir::new().unwrap();
    let store = ApiKeyStore::open(&directory.path().join("keys.db")).await.unwrap();

    (directory, store)
}
