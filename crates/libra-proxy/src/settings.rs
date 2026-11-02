//! What the proxy needs to know, and what it assumes when not told.

use libra_forwarding::{inbound_scheme::InboundScheme, trusted_proxies::TrustedProxies};
use libra_via_pseudonym::ViaPseudonym;
use std::time::Duration;
use url::Url;

/// How the proxy reaches the upstream broker.
///
/// Every field except `upstream` has a default, so a caller writes
/// `ProxySettings { pool_max_idle_per_host: 8, ..ProxySettings::new(upstream, via_pseudonym) }` and overrides only
/// what a deployment actually tunes. There is no `Default`: a proxy with no upstream has nowhere
/// to forward to, and inventing one would point it at a broker nobody named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySettings {
    /// Base URL of the broker: scheme, authority, and optionally a path prefix.
    ///
    /// A request's own path and query are appended to it verbatim. A trailing `/` is trimmed, so
    /// `http://broker:9090` and `http://broker:9090/` are the same upstream.
    pub upstream: Url,

    /// How long an idle pooled connection is kept.
    pub pool_idle_timeout: Duration,

    /// How many idle connections the pool keeps per upstream host.
    ///
    /// One pool serves the whole proxy, so this is the real ceiling. A client per registered route
    /// would give each route its own pool of this size, and the broker would see a multiple of the idle
    /// connections the operator configured.
    pub pool_max_idle_per_host: usize,

    /// How long to wait for the TCP connection to the broker.
    ///
    /// This is not the request timeout. A slow broker is somebody else's layer to give up on; this
    /// only bounds how long a connection attempt to an unreachable host can sit.
    pub connect_timeout: Duration,

    /// Whether to disable Nagle's algorithm on upstream connections.
    ///
    /// On by default: NGSI-LD requests are small and latency-sensitive, and waiting to coalesce
    /// them with a following write only adds delay.
    pub tcp_nodelay: bool,

    /// The scheme clients use to reach Libra, reported in `X-Forwarded-Proto`.
    pub inbound_scheme: InboundScheme,

    /// The peers whose forwarding headers are passed on to the broker as sent.
    ///
    /// For every other peer, `X-Forwarded-*`, `Forwarded` and `X-Real-IP` are replaced or removed.
    /// Empty by default, which trusts nobody.
    pub trusted_proxies: TrustedProxies,

    /// The name Libra gives itself in `Via`, per RFC 9110 section 7.6.3.
    ///
    /// A pseudonym rather than a host name by default: `Via` is returned to the client, and the
    /// internal name of the host answering is not something a deployment should have to publish
    /// to keep its proxy chain honest.
    pub via_pseudonym: ViaPseudonym,
}

impl ProxySettings {
    /// Settings for `upstream`, with every other field at its default.
    #[must_use]
    pub fn new(upstream: Url, via_pseudonym: ViaPseudonym) -> ProxySettings {
        ProxySettings {
            upstream,
            pool_idle_timeout: Duration::from_secs(90),
            pool_max_idle_per_host: 32,
            connect_timeout: Duration::from_secs(5),
            tcp_nodelay: true,
            inbound_scheme: InboundScheme::Http,
            trusted_proxies: TrustedProxies::default(),
            via_pseudonym,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_defaults_describe_one_shared_pool() {
        let pseudonym = ViaPseudonym::new("gateway-a".to_owned()).expect("a pseudonym");
        let settings = ProxySettings::new(Url::parse("http://broker.test:9090").expect("a URL"), pseudonym);

        assert_eq!(settings.pool_max_idle_per_host, 32);
        assert!(settings.tcp_nodelay);
        assert_eq!(settings.via_pseudonym.header_value(), "gateway-a");
        assert_eq!(settings.inbound_scheme, InboundScheme::Http);
        assert_eq!(settings.trusted_proxies, TrustedProxies::default());
    }
}
