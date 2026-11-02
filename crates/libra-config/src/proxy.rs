//! `[proxy]`: how Libra connects to the broker.
//!
//! These are the settings of the one connection pool Libra keeps to the upstream. They are here
//! rather than left at their defaults because a proxy that cannot be tuned to its broker is a
//! proxy that queues behind it: too few idle connections and every request pays a handshake, too
//! long a connect timeout and a broker that is down holds requests open until something else gives
//! up on them.

use libra_forwarding::inbound_scheme::InboundScheme;
use libra_via_pseudonym::ViaPseudonym;
use serde::{Deserialize, Serialize};

/// Upstream connection configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Proxy {
    /// How long an idle connection is kept before it is closed, in seconds.
    pub pool_idle_timeout_seconds: u64,

    /// How many idle connections to keep to the broker.
    pub pool_max_idle_per_host: usize,

    /// How long to wait for a connection to be established, in seconds.
    ///
    /// Distinct from `[timeout] upstream-timeout-seconds`, which bounds the whole request. This one
    /// bounds only reaching the broker at all, and should be much shorter: a broker that is not
    /// answering its port is not going to answer this request either.
    pub connect_timeout_seconds: u64,

    /// Whether to disable Nagle's algorithm on upstream connections.
    ///
    /// On by default. NGSI-LD requests are small and latency-sensitive, which is exactly the shape
    /// Nagle delays.
    pub tcp_nodelay: bool,

    /// The name Libra gives itself in the `Via` header it adds. Required: startup refuses without
    /// one.
    ///
    /// A pseudonym rather than a hostname: RFC 9110 allows either, and a hostname tells whoever
    /// reads the response something about the deployment's topology. There is no default, because
    /// brokers in a federation compare `Via` entries against the aliases of context sources (NGSI-LD
    /// clause 5.2.40) to detect loops, and every installation answering to one shared name would make
    /// two different deployments look like the same hop. Held as an `Option` only so that the
    /// section's other settings can keep their defaults; absent is refused where the proxy is built.
    pub via_pseudonym: Option<ViaPseudonym>,

    /// The scheme clients use to reach Libra, reported to the broker in `X-Forwarded-Proto`.
    ///
    /// `https` when a TLS terminator sits in front of Libra and the peer is not itself a trusted
    /// proxy that already said so; Libra's own listener is plain HTTP.
    pub inbound_scheme: InboundScheme,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            pool_idle_timeout_seconds: 60,
            pool_max_idle_per_host: 32,
            connect_timeout_seconds: 10,
            tcp_nodelay: true,
            via_pseudonym: None,
            inbound_scheme: InboundScheme::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeout::Timeout;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_connect_timeout_is_much_shorter_than_the_request_timeout() {
        // A broker that is not answering its port will not answer this request either, and holding
        // the caller open for the full request budget only delays the refusal.
        assert!(Proxy::default().connect_timeout_seconds < Timeout::default().upstream_timeout_seconds);
    }

    #[test]
    fn no_pseudonym_is_assumed_when_none_is_configured() {
        assert_eq!(Proxy::default().via_pseudonym, None);
    }

    #[test]
    fn the_configured_pseudonym_is_read() {
        let proxy: Proxy = serde_json::from_str(
            r#"{"pool-idle-timeout-seconds":60,"pool-max-idle-per-host":32,"connect-timeout-seconds":10,"tcp-nodelay":true,"via-pseudonym":"gateway-a","inbound-scheme":"http"}"#,
        )
        .unwrap();

        assert_eq!(proxy.via_pseudonym, Some(ViaPseudonym::new("gateway-a".to_owned()).unwrap()));
    }

    #[test]
    fn clients_are_assumed_to_reach_libra_over_plain_http() {
        assert_eq!(Proxy::default().inbound_scheme, InboundScheme::Http);
    }

    #[test]
    fn the_inbound_scheme_is_read_in_kebab_case() {
        let proxy: Proxy = serde_json::from_str(
            r#"{"pool-idle-timeout-seconds":60,"pool-max-idle-per-host":32,"connect-timeout-seconds":10,"tcp-nodelay":true,"via-pseudonym":"libra","inbound-scheme":"https"}"#,
        )
        .unwrap();

        assert_eq!(proxy.inbound_scheme, InboundScheme::Https);
    }

    #[test]
    fn an_inbound_scheme_that_is_not_http_or_https_is_refused() {
        let outcome = serde_json::from_str::<Proxy>(
            r#"{"pool-idle-timeout-seconds":60,"pool-max-idle-per-host":32,"connect-timeout-seconds":10,"tcp-nodelay":true,"via-pseudonym":"libra","inbound-scheme":"ftp"}"#,
        );

        assert!(outcome.is_err());
    }
}
