//! Typed configuration model for Libra.
//!
//! Configuration is layered: built-in defaults, then a TOML file, then `LIBRA__*` environment
//! variables. One module per `[section]` of that file, named after the section so the mapping from
//! a deployed `libra.toml` to the type that reads it is mechanical.
//!
//! This crate is a leaf: it depends on nothing else in the workspace except `libra-kebab-name` and
//! `libra-via-pseudonym`, which are themselves leaves, and models no domain behaviour. Values that
//! mean something to another crate (the default policy effect, the JWT signing algorithm) are
//! declared here as plain configuration enums and converted by the crate that owns the concept.
//! A value that is a URL, a path, or an HTTP method is read straight into its type, so a file that
//! names none is refused with the key it was written under rather than on the first request.
//! That keeps `libra-config` free of the security model rather than making
//! the security model depend on how it happens to be configured.
//!
//! There is no global singleton. The composition root loads the configuration once and passes it
//! where it is needed.
//!
//! The sections defined here are the ones every build reads. A crate that adds behaviour to a build
//! owns its own section through [`section::ConfigSection`], claims it from the [`pending::PendingConfig`]
//! that loading returns, and the load is not finished until every section in the file has been
//! claimed by someone.

pub mod aggregation;
pub mod allow_list;
pub mod audience;
pub mod audit;
pub mod authz;
pub mod broker;
pub mod cors;
pub mod helmet;
pub mod hex_secret;
pub mod issuer;
pub mod jsonld;
pub mod jwt;
pub mod key_store;
pub mod libra;
pub mod limits;
pub mod listen_host;
pub mod log_file_prefix;
pub mod logging;
pub mod management_api;
pub mod metrics_path;
pub mod multitenancy;
pub mod payload;
pub mod pending;
pub mod prometheus;
pub mod proxy;
pub mod representation;
pub mod section;
pub mod source;
pub mod template;
pub mod timeout;
pub mod validate;

use crate::{
    aggregation::Aggregation,
    audit::Audit,
    authz::Authz,
    broker::Broker,
    cors::Cors,
    helmet::Helmet,
    jsonld::JsonLd,
    jwt::Jwt,
    key_store::KeyStore,
    libra::Libra,
    limits::Limits,
    logging::Logging,
    management_api::ManagementApi,
    multitenancy::Multitenancy,
    payload::Payload,
    pending::PendingConfig,
    prometheus::Prometheus,
    proxy::Proxy,
    representation::RepresentationStrictness,
    section::SectionName,
    source::{ConfigSource, resolve_config_source},
    timeout::Timeout,
    validate::InvalidConfig,
};
use figment2::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;
use std::{
    env,
    path::{Path, PathBuf},
};

/// Everything Libra reads out of its configuration file.
///
/// Every name in the file is kebab-case, sections and keys alike, with no accepted alternative
/// spelling. One spelling means a key either matches or fails loudly; two spellings mean a
/// deployment can write the one that does not match and get defaults in silence, which for
/// `[management-api]` is `admin-users` and both privilege gates reverting without a line in the log.
///
/// `deny_unknown_fields` is the other half of that guard: a mistyped name is a startup error, not a
/// section that quietly does not apply.
#[derive(Deserialize, Debug)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub libra: Libra,
    /// `[broker]`, required: there is no broker Libra could assume.
    pub broker: Broker,
    #[serde(default)]
    pub proxy: Proxy,
    #[serde(default)]
    pub multitenancy: Multitenancy,
    /// `[jwt]`, absent when the deployment accepts no JWT.
    pub jwt: Option<Jwt>,
    #[serde(default)]
    pub key_store: KeyStore,
    #[serde(default)]
    pub jsonld: JsonLd,
    #[serde(default)]
    pub authz: Authz,
    #[serde(default)]
    pub aggregation: Aggregation,
    #[serde(default)]
    pub audit: Audit,
    #[serde(default)]
    pub payload: Payload,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub timeout: Timeout,
    #[serde(default)]
    pub logging: Logging,
    #[serde(default)]
    pub cors: Cors,
    #[serde(default)]
    pub prometheus: Prometheus,
    #[serde(default)]
    pub management_api: ManagementApi,
    #[serde(default)]
    pub helmet: Helmet,
    #[serde(default)]
    pub representation: RepresentationStrictness,
}

/// What went wrong while loading the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `LIBRA__CONFIG_FILE` named a file that does not exist. Deliberately fatal: a missing file
    /// that silently fell back to defaults would start the proxy with a different security posture
    /// than the operator wrote down.
    #[error("LIBRA__CONFIG_FILE is set to '{}' but no such file exists", path.display())]
    MissingConfigFile { path: PathBuf },

    /// A value in the file or the environment did not fit the model.
    #[error("failed to load Libra configuration")]
    Extract(#[from] Box<figment2::Error>),

    /// A value loaded and cannot work.
    #[error(transparent)]
    Invalid(#[from] InvalidConfig),

    /// The configuration has sections that nothing in this build reads.
    ///
    /// Either a misspelling of a section that is read, or a section for a build that has more in it.
    /// Starting anyway would leave an operator believing a setting was in force that nothing reads.
    #[error("these configuration sections are not read by anything in this build: {}", .names.join(", "))]
    UnclaimedSections {
        /// The sections, as the file spells them. Text rather than [`SectionName`]: a misspelled
        /// section need not be a valid name, and the operator is shown what they wrote.
        names: Vec<String>,
    },

    /// An extension asked for a section that [`Config`] defines.
    #[error("section '{name}' is defined by Libra itself and cannot be claimed by an extension")]
    ReservedSection {
        /// The section.
        name: SectionName,
    },

    /// Two extensions asked for one section.
    #[error("section '{name}' was claimed twice")]
    SectionClaimedTwice {
        /// The section.
        name: SectionName,
    },
}

/// The configuration and the file it came from.
#[derive(Debug)]
pub struct Loaded {
    pub config: Config,
    pub source: ConfigSource,
}

impl Config {
    /// Loads the configuration from a TOML file and `LIBRA__*` environment variables, over the
    /// defaults each section declares.
    ///
    /// The file is the one named by `LIBRA__CONFIG_FILE` if that is set, and otherwise the first
    /// of [`source::DEFAULT_CONFIG_PATHS`] that exists. Resolution deliberately does not depend on
    /// container detection, which is unreliable under Kubernetes and Podman: a misdetected container
    /// would ignore a mounted `/etc/libra.toml` in favour of built-in defaults.
    ///
    /// The resolved source is returned rather than logged, because logging is configured from the
    /// result and is therefore not running yet.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingConfigFile`] if `LIBRA__CONFIG_FILE` names a file that does
    /// not exist, and [`ConfigError::Extract`] if a value does not fit the model or a required one,
    /// such as `[broker] url`, is set nowhere.
    ///
    /// What comes back is not yet a [`Loaded`]: sections that [`Config`] does not define are still
    /// waiting to be claimed, and [`PendingConfig::finish`] is where one nobody claimed is refused.
    pub fn load() -> Result<PendingConfig, ConfigError> {
        let explicit = env::var("LIBRA__CONFIG_FILE").ok().filter(|value| !value.trim().is_empty()).map(PathBuf::from);
        let source = resolve_config_source(explicit, Path::exists);

        let mut figment = Figment::new();

        let source = match source {
            ConfigSource::Missing(path) => return Err(ConfigError::MissingConfigFile { path }),
            present @ (ConfigSource::Explicit(_) | ConfigSource::Discovered(_) | ConfigSource::None) => present,
        };

        match &source {
            ConfigSource::Explicit(path) | ConfigSource::Discovered(path) => {
                figment = figment.merge(Toml::file(path));
            }
            ConfigSource::Missing(_) | ConfigSource::None => {}
        }

        let figment = figment.merge(
            Env::prefixed("LIBRA__")
                // The double underscore keeps the variables a Kubernetes cluster injects for a
                // Service named `libra` (`LIBRA_PORT`, `LIBRA_SERVICE_HOST`, `LIBRA_PORT_5667_TCP_ADDR`)
                // from matching the prefix, and with them every other name that is not a section
                // and a key. `CONFIG_FILE` is read directly above to find this file; it is not a
                // key in it, and left in it would be reported as a section nothing reads.
                .ignore(&["CONFIG_FILE"])
                .split("__")
                .map(|key| environment_path(key.as_str()).into()),
        );

        PendingConfig::from_figment(&figment, source)
    }
}

/// The path inside the configuration that an environment variable's name, less its `LIBRA__`
/// prefix and with `.` in place of the `__` between the section and the key, refers to.
///
/// The file is kebab-case and environment variables are uppercase, so a single `_` becomes the
/// `-` inside a name: `LIBRA__MANAGEMENT_API__ADMIN_USERS` sets `[management-api] admin-users`.
/// The same rule reaches a section another crate owns, so `LIBRA__CACHE__MAX_ENTRIES` sets
/// `[cache] max-entries` once something claims `[cache]`.
fn environment_path(name: &str) -> String {
    name.replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{listen_host::ListenHost, management_api::ManagementAccess};
    use libra_policy_model::identity::{RoleName, Username};
    use pretty_assertions::assert_eq;
    use std::{
        error::Error,
        iter::successors,
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
    };

    #[test]
    fn an_environment_name_maps_to_a_kebab_case_section_and_key() {
        // The separator between the section and the key has already become `.` when this mapping
        // runs, so only the underscore inside a name is rewritten.
        assert_eq!(environment_path("MANAGEMENT_API.ADMIN_USERS").to_lowercase(), "management-api.admin-users");
        assert_eq!(environment_path("CACHE.MAX_ENTRIES").to_lowercase(), "cache.max-entries");
        assert_eq!(environment_path("BROKER.URL").to_lowercase(), "broker.url");
    }

    #[test]
    fn defaults_are_complete() {
        let config = from_toml("").expect("a broker and nothing else should load");

        assert_eq!(config.libra.port, 5667);
        assert_eq!(config.authz.default_effect, authz::DefaultEffect::Deny);
        assert!(config.limits.enabled);
        assert_eq!(config.limits.max_in_flight_requests, 256);
    }

    #[test]
    fn the_limits_section_loads_under_its_kebab_case_name() {
        // The ceiling decides how many requests may pin memory and broker connections at once, so
        // a key that does not match would leave the default in force without a word.
        let config = from_toml("[limits]\nenabled = true\nmax-in-flight-requests = 32").expect("the section should load");

        assert!(config.limits.enabled);
        assert_eq!(config.limits.max_in_flight_requests, 32);
    }

    #[test]
    fn default_paths_prefer_etc() {
        assert_eq!(source::DEFAULT_CONFIG_PATHS[0], "/etc/libra.toml");
    }

    /// Loads a configuration from TOML text over a broker, the way `load` reads a file, and accepts
    /// it only if every section in it is one `Config` defines.
    fn from_toml(source: &str) -> Result<Config, ConfigError> {
        PendingConfig::from_toml_with_broker(source)?.finish().map(|loaded| loaded.config)
    }

    /// Every message in the chain of a refusal, as an operator would read it in the startup log.
    fn reported(refused: &ConfigError) -> String {
        successors(Some(refused as &(dyn Error + 'static)), |&cause| cause.source())
            .map(|cause| format!("{cause} {cause:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_configuration_that_names_no_broker_is_refused_with_the_missing_section() {
        // Any address assumed in its place would receive every request Libra accepts.
        let refused = PendingConfig::from_toml("[libra]\nport = 8080").map(|_| ()).unwrap_err();

        assert!(matches!(refused, ConfigError::Extract(..)), "{refused:?}");
        assert!(reported(&refused).contains("broker"), "{}", reported(&refused));
    }

    #[test]
    fn a_broker_section_without_a_url_is_refused_with_the_missing_key() {
        let refused = PendingConfig::from_toml("[broker]").map(|_| ()).unwrap_err();

        assert!(matches!(refused, ConfigError::Extract(..)), "{refused:?}");
        assert!(reported(&refused).contains("url"), "{}", reported(&refused));
    }

    #[test]
    fn a_section_written_in_part_keeps_the_defaults_of_the_keys_it_leaves_out() {
        let config = from_toml("[libra]\nport = 8080\n\n[logging.console]\nlevel = \"debug\"").expect("a partial section should load");

        assert_eq!(config.libra.port, 8080);
        assert_eq!(config.libra.host, libra::Libra::default().host);
        assert_eq!(config.libra.shutdown_grace_seconds, 25);
        assert_eq!(config.logging.console.level, logging::LogLevel::Debug);
        assert_eq!(config.logging.console.enabled, logging::ConsoleLogging::default().enabled);
    }

    #[test]
    fn the_management_api_section_loads_under_its_kebab_case_name() {
        // The section that decides who may read and write policy. A section name that does not
        // match parses into nothing and leaves every key at its default, so this is the one place
        // where getting the spelling wrong changes the security posture without saying anything.
        let config = from_toml(
            r#"
            [management-api]
            admin-users = ["ops"]
            admin-roles = ["realm:policy-admin"]
            metrics-access = "privileged"
            "#,
        )
        .expect("the section should load");

        assert_eq!(config.management_api.admin_users, [Username::new("ops").unwrap()]);
        assert_eq!(config.management_api.admin_roles, [RoleName::new("realm:policy-admin").unwrap()]);
        assert_eq!(config.management_api.metrics_access, ManagementAccess::Privileged);
    }

    #[test]
    fn a_mistyped_key_inside_a_section_is_a_startup_error_too() {
        // The same failure one level down. A misspelled `admin-users` would otherwise leave the
        // list at its default, which is a different set of people with management access.
        let mistyped = from_toml(
            r#"
            [management-api]
            admin_users = ["ops"]
            "#,
        );

        assert!(mistyped.is_err(), "an unknown key inside a section must not be ignored");
    }

    #[test]
    fn a_mistyped_audit_key_is_refused_without_being_repeated_in_the_startup_error() {
        let refused = from_toml("[audit]\ntoken-fingerprint-key = \"00ff10ee0d0c0b0a090807060504030z\"")
            .map(|_| ())
            .unwrap_err();
        let reported = reported(&refused);

        assert!(reported.contains("hexadecimal"), "{reported}");
        assert!(!reported.contains("00ff10ee"), "{reported}");
    }

    #[test]
    fn a_mistyped_section_is_a_startup_error_rather_than_a_silent_default() {
        // A mistyped name that is silently ignored looks like it took effect.
        for wrong in ["[managment-api]\nadmin-users = [\"ops\"]", "[management_api]\nadmin-users = [\"ops\"]"] {
            assert!(
                from_toml(wrong).is_err(),
                "a name that is not the one Libra reads must fail rather than be ignored: {wrong}"
            );
        }
    }

    #[test]
    fn every_section_loads_under_its_own_name() {
        // One assertion per section: a multi-word section whose name does not map to its key would load
        // as defaults without a word.
        let config = from_toml(
            r#"
            [libra]
            host = "127.0.0.1"
            port = 8080

            [broker]
            url = "http://broker.test:9090"

            [jwt]
            jwks-url = "https://idp.test/certs"
            issuer = "https://idp.test"
            audience = "ngsi-client"

            [key-store]
            path = "/var/lib/libra/keys.db"

            [authz]
            policies-dir = "/policies"
            default-effect = "allow"

            [jsonld]
            allow-remote = false

            [multitenancy]
            policy = "require-header"
            "#,
        )
        .expect("every section should load");

        assert_eq!(config.libra.host, ListenHost::from_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(config.libra.port, 8080);
        assert_eq!(config.broker.url.as_str(), "http://broker.test:9090/");
        assert_eq!(config.jwt.as_ref().map(|jwt| jwt.jwks_url.as_str()), Some("https://idp.test/certs"));
        assert_eq!(config.jwt.as_ref().map(|jwt| jwt.audience.as_str()), Some("ngsi-client"));
        assert_eq!(config.key_store.enabled_path(), Some(Path::new("/var/lib/libra/keys.db")));
        assert_eq!(config.authz.policies_dir, PathBuf::from("/policies"));
        assert_eq!(config.authz.default_effect, authz::DefaultEffect::Allow);
        assert!(!config.jsonld.allow_remote);
        assert_eq!(config.multitenancy.policy, multitenancy::MissingTenantHeaderPolicy::RequireHeader);
    }

    #[test]
    fn a_representation_section_defaults_to_forwarding() {
        // Reading the `Accept` header must not by itself change what a deployment answers, so a
        // file that says nothing about it leaves the broker deciding.
        let defaults = from_toml("").expect("an empty file should load");

        assert_eq!(defaults.representation.unsatisfiable_accept, representation::UnsatisfiableAccept::Forward);
        assert_eq!(defaults.representation.contradictory_options, representation::ContradictoryOptions::Forward);

        let strict = from_toml(
            r#"
            [representation]
            unsatisfiable-accept = "refuse"
            contradictory-options = "refuse"
            "#,
        )
        .expect("the section should load");

        assert_eq!(strict.representation.unsatisfiable_accept, representation::UnsatisfiableAccept::Refuse);
        assert_eq!(strict.representation.contradictory_options, representation::ContradictoryOptions::Refuse);
    }
}
