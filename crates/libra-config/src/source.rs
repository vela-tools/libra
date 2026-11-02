//! Where the configuration file comes from.

use std::path::{Path, PathBuf};

/// Well-known configuration file paths, checked in order when `LIBRA__CONFIG_FILE` is not set.
pub const DEFAULT_CONFIG_PATHS: [&str; 2] = ["/etc/libra.toml", "config/libra.toml"];

/// Where the configuration file was resolved from.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfigSource {
    /// `LIBRA__CONFIG_FILE` was set and the file exists.
    Explicit(PathBuf),
    /// A well-known path was found.
    Discovered(PathBuf),
    /// `LIBRA__CONFIG_FILE` was set but the file does not exist. Fatal.
    Missing(PathBuf),
    /// No configuration file was found anywhere; defaults overlaid with environment only.
    None,
}

/// Decides which configuration file to load.
///
/// An explicit `LIBRA__CONFIG_FILE` wins and must exist. Otherwise the first existing well-known
/// path is used. Resolution deliberately does not depend on container detection: the heuristic
/// misreports under Kubernetes and Podman, and a mounted `/etc/libra.toml` would then be silently
/// ignored in favour of built-in defaults.
pub fn resolve_config_source(explicit: Option<PathBuf>, exists: impl Fn(&Path) -> bool) -> ConfigSource {
    if let Some(path) = explicit {
        return if exists(&path) {
            ConfigSource::Explicit(path)
        } else {
            ConfigSource::Missing(path)
        };
    }

    DEFAULT_CONFIG_PATHS
        .into_iter()
        .map(Path::new)
        .find(|candidate| exists(candidate))
        .map_or(ConfigSource::None, |candidate| ConfigSource::Discovered(candidate.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn resolves_explicit_when_present() {
        let source = resolve_config_source(Some(PathBuf::from("/custom/libra.toml")), |path| path == Path::new("/custom/libra.toml"));
        assert_eq!(source, ConfigSource::Explicit(PathBuf::from("/custom/libra.toml")));
    }

    #[test]
    fn explicit_missing_is_hard_error() {
        let source = resolve_config_source(Some(PathBuf::from("/missing.toml")), |_| false);
        assert_eq!(source, ConfigSource::Missing(PathBuf::from("/missing.toml")));
    }

    #[test]
    fn discovers_etc_even_outside_docker() {
        // Under Kubernetes and Podman, Docker detection returns false, but
        // /etc/libra.toml mounted into a container must still be loaded.
        let source = resolve_config_source(None, |path| path == Path::new("/etc/libra.toml"));
        assert_eq!(source, ConfigSource::Discovered(PathBuf::from("/etc/libra.toml")));
    }

    #[test]
    fn prefers_etc_over_local_config() {
        let source = resolve_config_source(None, |_| true);
        assert_eq!(source, ConfigSource::Discovered(PathBuf::from("/etc/libra.toml")));
    }

    #[test]
    fn falls_back_to_local_config() {
        let source = resolve_config_source(None, |path| path == Path::new("config/libra.toml"));
        assert_eq!(source, ConfigSource::Discovered(PathBuf::from("config/libra.toml")));
    }

    #[test]
    fn none_when_no_file_exists() {
        let source = resolve_config_source(None, |_| false);
        assert_eq!(source, ConfigSource::None);
    }
}
