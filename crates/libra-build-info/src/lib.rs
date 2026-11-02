//! Build-time metadata: what this binary is, and which commit it came from.
//!
//! An operator running a security proxy has to be able to say exactly what is deployed. The same
//! constants back `--version`, the info endpoint, and the panic report.

use axum::{Json, Router, routing::get};
use human_panic::Metadata;
use iri_rs::{Iri, iri};
use serde::Serialize;
use std::future::ready;

shadow_rs::shadow!(build);

/// The product name. A literal rather than the crate name, because the crate that carries the
/// build script is not the product.
pub const NAME: &str = "libra";

/// Where a user goes for help, quoted in the panic report.
pub static HOMEPAGE: Iri<&str> = iri!("https://github.com/vela-tools/libra");

// A panic report must never carry a personal identifier. `human-panic` fills its authors field
// from CARGO_PKG_AUTHORS, so the guarantee is that the manifest has no `authors` key at all. This
// fails the build rather than the code review if one is ever added.
const _: () = assert!(
    env!("CARGO_PKG_AUTHORS").is_empty(),
    "libra manifests must not carry an authors field: it is printed to users by the panic handler"
);

/// Version and build metadata, as served by the info endpoint.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BuildInfo {
    /// Product name.
    pub name: &'static str,
    /// Package version.
    pub version: &'static str,
    /// When the binary was built.
    pub build_time: &'static str,
    /// Target triple it was built for.
    pub target: &'static str,
    /// Short git commit hash.
    pub commit: &'static str,
    /// Git branch.
    pub branch: &'static str,
}

impl Default for BuildInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildInfo {
    /// The metadata baked into this binary.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            name: NAME,
            version: build::PKG_VERSION,
            build_time: build::BUILD_TIME,
            target: build::BUILD_TARGET,
            commit: build::SHORT_COMMIT,
            branch: build::BRANCH,
        }
    }
}

/// The long version string, for `--version`.
#[must_use]
pub const fn long_version() -> &'static str {
    build::CLAP_LONG_VERSION
}

/// Metadata for the panic handler.
///
/// Carries no authors field: a panic report is printed to whoever is running the binary, and a
/// personal identifier does not belong in it.
#[must_use]
pub fn panic_metadata() -> Metadata {
    Metadata::new(NAME, build::PKG_VERSION).homepage(HOMEPAGE.as_str())
}

/// The info endpoint.
///
/// Mounted behind the management-API privilege gate by the composition root. Which commit a
/// gateway is running is exactly the fact an attacker needs to know which advisories apply to it,
/// so it is not served to whoever asks by default.
pub fn router() -> Router {
    // `ready` rather than an `async fn`: the handler awaits nothing, and axum accepts any function
    // returning a future.
    Router::new().route("/ngsi-ld/auth/info", get(|| ready(Json(BuildInfo::new()))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_version_and_a_commit() {
        let info = BuildInfo::new();

        assert_eq!(info.name, "libra");
        assert_ne!(info.version, "");
        assert!(!info.commit.is_empty(), "the build must know which commit it came from");
    }

    #[test]
    fn serialises_for_the_info_endpoint() {
        let payload = serde_json::to_value(BuildInfo::new()).unwrap();

        for field in ["name", "version", "build_time", "target", "commit", "branch"] {
            assert!(payload.get(field).is_some(), "info payload is missing {field}");
        }
    }

    #[test]
    fn the_panic_report_carries_no_personal_identifier() {
        // The const assertion above is the real guard; this pins the intent in a readable place.
        assert_eq!(env!("CARGO_PKG_AUTHORS"), "");
        let _metadata = panic_metadata();
    }
}
