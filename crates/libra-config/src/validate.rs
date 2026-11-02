//! Values that parse and still cannot work.
//!
//! A type check cannot say that a timeout of zero fails every request, that a metrics path on a
//! route Libra serves itself collides with it, or that plain-http key fetching was an accident
//! rather than a decision. Each is cheap to refuse while the file and the key are still known, and expensive to
//! discover as a crash on the first request or as a signing key delivered over a channel anyone on
//! the path can rewrite.

use crate::{
    Config,
    jwt::{JwksTransport, Jwt},
    metrics_path::MetricsPath,
};
use thiserror::Error;
use url::Url;

/// The routes Libra serves itself under `/ngsi-ld/auth/`, which the metrics path must not take.
const RESERVED_PATHS: [&str; 3] = ["/ngsi-ld/auth/health", "/ngsi-ld/auth/ready", "/ngsi-ld/auth/info"];

/// The most clock skew tolerated on `exp` and `nbf`, in seconds.
///
/// The tolerance extends every token's life by that much, so a large one turns the expiry check
/// off without saying so. Five minutes is the customary ceiling for clocks kept by NTP.
const MAX_CLOCK_SKEW_SECONDS: u64 = 300;

/// The longest a fetched key set may be used before it is fetched again, in seconds.
///
/// A key the identity provider withdrew keeps verifying until the next fetch, so this bounds how
/// long a revoked signing key is still trusted.
const MAX_JWKS_CACHE_SECONDS: u64 = 86_400;

/// A configuration that loads and cannot be run.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidConfig {
    /// The key set address is neither http nor https.
    #[error("jwt.jwks-url '{url}' must be an http or https URL")]
    JwksScheme {
        /// The value written.
        url: Url,
    },

    /// The key set would be fetched over plain http without the operator saying that is intended.
    ///
    /// Whoever can alter that response chooses which keys Libra trusts, and so which tokens it
    /// accepts.
    #[error("jwt.jwks-url '{url}' is not https; set jwt.jwks-transport = \"insecure-http\" if fetching signing keys over plain http is intended")]
    JwksNotHttps {
        /// The value written.
        url: Url,
    },

    /// A number that must be positive is zero.
    #[error("{key} must be greater than zero")]
    Zero {
        /// The key, as written in the file.
        key: &'static str,
    },

    /// A number is past the largest value Libra accepts for it.
    #[error("{key} must be at most {maximum}")]
    TooLarge {
        /// The key, as written in the file.
        key: &'static str,
        /// The largest value accepted.
        maximum: u64,
    },

    /// The metrics path is one Libra serves for something else.
    #[error("prometheus.path '{path}' is a route Libra serves itself")]
    ReservedMetricsPath {
        /// The value written.
        path: MetricsPath,
    },
}

impl Config {
    /// Checks the values that cannot be checked by their type.
    ///
    /// # Errors
    ///
    /// Returns the first [`InvalidConfig`] found.
    pub fn validate(&self) -> Result<(), InvalidConfig> {
        if let Some(jwt) = &self.jwt {
            validate_jwks(jwt)?;
            if jwt.jwks_cache_duration == 0 {
                return Err(InvalidConfig::Zero {
                    key: "jwt.jwks-cache-duration",
                });
            }
            for (key, value, maximum) in [
                ("jwt.jwks-cache-duration", jwt.jwks_cache_duration, MAX_JWKS_CACHE_SECONDS),
                ("jwt.clock-skew-seconds", jwt.clock_skew_seconds, MAX_CLOCK_SKEW_SECONDS),
            ] {
                if value > maximum {
                    return Err(InvalidConfig::TooLarge { key, maximum });
                }
            }
        }

        for (key, value) in [
            ("timeout.upstream-timeout-seconds", self.timeout.upstream_timeout_seconds),
            ("proxy.connect-timeout-seconds", self.proxy.connect_timeout_seconds),
            ("jsonld.fetch-timeout-seconds", self.jsonld.fetch_timeout_seconds),
            ("libra.shutdown-grace-seconds", self.libra.shutdown_grace_seconds),
            ("libra.header-read-timeout-seconds", self.libra.header_read_timeout_seconds),
        ] {
            if value == 0 {
                return Err(InvalidConfig::Zero { key });
            }
        }
        for (key, value) in [
            ("payload.max-body-size-bytes", self.payload.max_body_size_bytes),
            ("jsonld.max-context-bytes", self.jsonld.max_context_bytes),
            ("limits.max-in-flight-requests", self.limits.max_in_flight_requests),
        ] {
            if value == 0 {
                return Err(InvalidConfig::Zero { key });
            }
        }

        if self.prometheus.enabled {
            let path = &self.prometheus.path;
            if RESERVED_PATHS.contains(&path.as_str()) {
                return Err(InvalidConfig::ReservedMetricsPath { path: path.clone() }); // the error owns the path, the configuration keeps its own
            }
        }

        Ok(())
    }
}

/// Checks the key set address against the transport the operator chose.
fn validate_jwks(jwt: &Jwt) -> Result<(), InvalidConfig> {
    let url = &jwt.jwks_url;

    match (url.scheme(), jwt.jwks_transport) {
        ("https", JwksTransport::HttpsOnly | JwksTransport::InsecureHttp) | ("http", JwksTransport::InsecureHttp) => Ok(()),
        ("http", JwksTransport::HttpsOnly) => Err(InvalidConfig::JwksNotHttps { url: url.clone() }), // the error owns the url, the configuration keeps its own
        (_, JwksTransport::HttpsOnly | JwksTransport::InsecureHttp) => Err(InvalidConfig::JwksScheme { url: url.clone() }), // the error owns the url, the configuration keeps its own
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::PendingConfig;
    use pretty_assertions::assert_eq;

    fn invalid(source: &str) -> InvalidConfig {
        match PendingConfig::from_toml_with_broker(source) {
            Err(crate::ConfigError::Invalid(error)) => error,
            other => panic!("expected an invalid configuration, got {other:?}"),
        }
    }

    #[test]
    fn the_defaults_can_run() {
        assert!(PendingConfig::from_toml_with_broker("").is_ok());
    }

    /// A `[jwt]` section fetching its keys from `url`, with the rest of the section filled in.
    fn jwt_section(url: &str) -> String {
        format!("[jwt]\njwks-url = \"{url}\"\nissuer = \"https://idp.test\"\naudience = \"ngsi-client\"")
    }

    #[test]
    fn plain_http_key_fetching_needs_the_operator_to_say_so() {
        let http = jwt_section("http://idp.test/certs");

        assert!(matches!(invalid(&http), InvalidConfig::JwksNotHttps { .. }));
        assert!(PendingConfig::from_toml_with_broker(&format!("{http}\njwks-transport = \"insecure-http\"")).is_ok());
        assert!(PendingConfig::from_toml_with_broker(&jwt_section("https://idp.test/certs")).is_ok());
    }

    #[test]
    fn a_key_set_address_that_is_not_http_at_all_is_refused_even_with_the_opt_in() {
        let ftp = format!("{}\njwks-transport = \"insecure-http\"", jwt_section("ftp://idp.test/certs"));

        assert!(matches!(invalid(&ftp), InvalidConfig::JwksScheme { .. }));
    }

    #[test]
    fn a_key_set_that_would_be_fetched_on_every_request_is_refused() {
        let zero = format!("{}\njwks-cache-duration = 0", jwt_section("https://idp.test/certs"));

        assert_eq!(
            invalid(&zero),
            InvalidConfig::Zero {
                key: "jwt.jwks-cache-duration"
            }
        );
    }

    #[test]
    fn a_clock_skew_that_would_switch_off_expiry_is_refused() {
        let at_maximum = format!("{}\nclock-skew-seconds = 300", jwt_section("https://idp.test/certs"));
        let past_maximum = format!("{}\nclock-skew-seconds = 301", jwt_section("https://idp.test/certs"));

        assert!(PendingConfig::from_toml_with_broker(&at_maximum).is_ok());
        assert_eq!(
            invalid(&past_maximum),
            InvalidConfig::TooLarge {
                key: "jwt.clock-skew-seconds",
                maximum: 300
            }
        );
    }

    #[test]
    fn a_key_set_kept_longer_than_a_day_is_refused() {
        let at_maximum = format!("{}\njwks-cache-duration = 86400", jwt_section("https://idp.test/certs"));
        let past_maximum = format!("{}\njwks-cache-duration = 86401", jwt_section("https://idp.test/certs"));

        assert!(PendingConfig::from_toml_with_broker(&at_maximum).is_ok());
        assert_eq!(
            invalid(&past_maximum),
            InvalidConfig::TooLarge {
                key: "jwt.jwks-cache-duration",
                maximum: 86_400
            }
        );
    }

    /// The message of the error a file is refused with while it is being read into the model.
    fn refused_while_reading(source: &str) -> String {
        match PendingConfig::from_toml_with_broker(source) {
            Err(crate::ConfigError::Extract(error)) => error.to_string(),
            other => panic!("expected the file to be refused while it is read, got {other:?}"),
        }
    }

    #[test]
    fn a_value_that_is_not_the_type_of_its_key_is_refused_naming_the_key() {
        for (source, key) in [
            (
                "[jwt]\njwks-url = \"not a url\"\nissuer = \"https://idp.test\"\naudience = \"a\"",
                "jwt.jwks-url",
            ),
            ("[broker]\nurl = \"scorpio\"", "broker.url"),
            ("[jsonld]\ncore-context = \"not a url\"", "jsonld.core-context"),
            ("[jsonld]\nallowed-contexts = [\"not a url\"]", "jsonld.allowed-contexts"),
            ("[prometheus]\npath = \"metrics\"", "prometheus.path"),
            ("[prometheus]\npath = \"/ngsi-ld/v1/entities\"", "prometheus.path"),
            ("[libra]\nhost = \"\"", "libra.host"),
            ("[libra]\nhost = \"two words\"", "libra.host"),
            ("[proxy]\nvia-pseudonym = \"libra, 1.1 elsewhere\"", "proxy.via-pseudonym"),
            (
                "[jwt]\njwks-url = \"https://idp.test/certs\"\nissuer = \"https://idp.test\"\naudience = \"\"",
                "jwt.audience",
            ),
            ("[jwt]\njwks-url = \"https://idp.test/certs\"\nissuer = \"idp\"\naudience = \"a\"", "jwt.issuer"),
            ("[key-store]\npath = 1", "key-store.path"),
            ("[logging.file]\nfile-prefix = \"../escape\"", "logging.file.file-prefix"),
            ("[cors]\nallow-methods = [\"NOT A METHOD\"]", "cors.allow-methods"),
            ("[cors]\nallow-headers = [\"not a header\"]", "cors.allow-headers"),
            ("[cors]\nexpose-headers = [\"not a header\"]", "cors.expose-headers"),
            ("[cors]\nallow-origins = [\"https://bad\\u007f.test\"]", "cors.allow-origins"),
        ] {
            let message = refused_while_reading(source);

            assert!(message.contains(key), "the refusal of {source:?} must name {key}: {message}");
        }
    }

    #[test]
    fn a_zero_that_would_fail_every_request_is_refused_at_startup() {
        for (source, key) in [
            ("[timeout]\nupstream-timeout-seconds = 0", "timeout.upstream-timeout-seconds"),
            ("[payload]\nmax-body-size-bytes = 0", "payload.max-body-size-bytes"),
            ("[proxy]\nconnect-timeout-seconds = 0", "proxy.connect-timeout-seconds"),
            ("[jsonld]\nfetch-timeout-seconds = 0", "jsonld.fetch-timeout-seconds"),
            ("[libra]\nshutdown-grace-seconds = 0", "libra.shutdown-grace-seconds"),
            ("[libra]\nheader-read-timeout-seconds = 0", "libra.header-read-timeout-seconds"),
            ("[jsonld]\nmax-context-bytes = 0", "jsonld.max-context-bytes"),
            ("[limits]\nmax-in-flight-requests = 0", "limits.max-in-flight-requests"),
        ] {
            assert_eq!(invalid(source), InvalidConfig::Zero { key }, "{source}");
        }
    }

    #[test]
    fn a_metrics_path_on_a_route_libra_serves_is_refused() {
        // Axum panics while building the router for a path that an existing route already owns.
        for reserved in RESERVED_PATHS {
            assert!(
                matches!(
                    invalid(&format!("[prometheus]\npath = \"{reserved}\"")),
                    InvalidConfig::ReservedMetricsPath { .. }
                ),
                "{reserved}"
            );
        }
        assert!(
            PendingConfig::from_toml_with_broker("[prometheus]\nenabled = false\npath = \"/ngsi-ld/auth/health\"").is_ok(),
            "a path nothing mounts cannot collide"
        );
    }
}
