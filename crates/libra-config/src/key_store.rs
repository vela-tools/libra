//! `[key-store]`: where principals and API key verifiers are kept.
//!
//! On by default, so a deployment configured by environment variables alone can issue API keys. A
//! deployment that accepts JWTs only turns it off, and then accepts no API key and holds no lease.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The key store configuration.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct KeyStore {
    /// Whether Libra keeps a key store and accepts the API keys in it.
    pub enabled: bool,

    /// The SQLite database file, created if it does not exist.
    ///
    /// Whoever can write this file can issue keys, so it deserves the same protection as the
    /// policy directory.
    pub path: PathBuf,
}

impl KeyStore {
    /// The database file, if the key store is on.
    #[must_use]
    pub fn enabled_path(&self) -> Option<&Path> {
        self.enabled.then_some(self.path.as_path())
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self {
            enabled: true,
            path: PathBuf::from("/var/lib/libra/keys.db"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigError, pending::PendingConfig};
    use pretty_assertions::assert_eq;

    fn section(text: &str) -> Result<KeyStore, ConfigError> {
        PendingConfig::from_toml_with_broker(text).map(|pending| pending.config().key_store.clone())
    }

    #[test]
    fn the_key_store_is_on_by_default_under_var_lib_libra() {
        let store = section("").unwrap();

        assert_eq!(store.enabled_path(), Some(Path::new("/var/lib/libra/keys.db")));
    }

    #[test]
    fn the_section_names_the_database_file() {
        let store = section("[key-store]\npath = \"/srv/libra/keys.db\"").unwrap();

        assert_eq!(store.enabled_path(), Some(Path::new("/srv/libra/keys.db")));
    }

    #[test]
    fn a_disabled_key_store_names_no_file() {
        let store = section("[key-store]\nenabled = false").unwrap();

        assert_eq!(store.enabled_path(), None);
    }

    #[test]
    fn the_section_is_read_by_every_build_rather_than_left_unclaimed() {
        let pending = PendingConfig::from_toml_with_broker("[key-store]\npath = \"keys.db\"").unwrap();

        assert!(pending.finish().is_ok());
    }

    #[test]
    fn a_mistyped_key_is_refused() {
        assert!(section("[key-store]\nfile = \"keys.db\"").is_err());
        assert!(section("[key-store]\npath = \"keys.db\"\ndatabase-path = \"keys.db\"").is_err());
    }
}
