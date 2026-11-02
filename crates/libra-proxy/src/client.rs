//! The one HTTP client the proxy uses for every upstream request.
//!
//! One is the whole point. A client per registered route would give each route its own connection
//! pool: a connection warmed by a request to `/entities` could not be reused by a request to
//! `/subscriptions`, the broker would see a multiple of the configured idle connections, and the
//! pool setting in the configuration file would describe none of it. The client built here is cloned
//! into every service, and a clone shares the pool rather than copying it.

use crate::{error::ProxyError, settings::ProxySettings};
use axum::body::Body;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use rustls::crypto::aws_lc_rs;

/// The client type every [`ProxyService`](crate::layer::ProxyService) holds a clone of.
pub type UpstreamClient = Client<HttpsConnector<HttpConnector>, Body>;

/// Builds the shared client.
///
/// # Errors
///
/// Returns [`ProxyError::Tls`] if rustls will not accept the crypto provider and the Mozilla root
/// set together.
pub fn build(settings: &ProxySettings) -> Result<UpstreamClient, ProxyError> {
    let mut http = HttpConnector::new();

    // The TLS connector wraps this one, so it has to be willing to hand it an https URI.
    http.enforce_http(false);
    http.set_nodelay(settings.tcp_nodelay);
    http.set_connect_timeout(Some(settings.connect_timeout));

    // The provider is named rather than left to rustls' process default. Left implicit, the choice
    // depends on which crypto features the rest of the workspace happens to enable, and rustls
    // resolves "neither or both" by panicking on the first connection rather than at startup.
    let https = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(aws_lc_rs::default_provider())
        .map_err(|error| ProxyError::Tls { reason: error.to_string() })?
        // A broker on the same network is usually plain HTTP, so https is offered rather than
        // required; which one is used follows the scheme the operator configured.
        .https_or_http()
        // ALPN offers `h2` before `http/1.1`, and `Client` reads back what was negotiated: over
        // TLS a broker that speaks HTTP/2 gets one multiplexed connection instead of a pool
        // bounded by `pool_max_idle_per_host`, and one that does not falls back to HTTP/1.1 in the
        // same handshake. Cleartext upstreams stay HTTP/1.1: there is no ALPN to negotiate with,
        // and h2c would have to be asserted rather than agreed.
        .enable_all_versions()
        .wrap_connector(http);

    Ok(Client::builder(TokioExecutor::new())
        .pool_idle_timeout(settings.pool_idle_timeout)
        .pool_max_idle_per_host(settings.pool_max_idle_per_host)
        // Without a timer the idle timeout above is silently inert.
        .pool_timer(TokioTimer::new())
        .timer(TokioTimer::new())
        // The proxy removes the caller's `Host`, which names Libra, so the client writes the
        // broker's: HTTP/1.1 requires one on every request (RFC 9112 section 3.2).
        .set_host(true)
        .build(https))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_via_pseudonym::ViaPseudonym;
    use url::Url;

    #[test]
    fn the_shared_client_builds_with_the_default_settings() {
        // The whole chain is fallible at run time rather than at compile time: naming the crypto
        // provider, loading the Mozilla roots, and setting the ALPN list all happen here. A build
        // that fails would fail on the first request instead.
        assert!(build(&ProxySettings::new(Url::parse("http://broker.test:9090").expect("a URL"), pseudonym())).is_ok());
    }

    /// The name the proxy under test gives itself in `Via`.
    fn pseudonym() -> ViaPseudonym {
        ViaPseudonym::new("gateway-a".to_owned()).expect("a pseudonym")
    }

    #[test]
    fn a_client_is_built_for_an_https_upstream_too() {
        let settings = ProxySettings::new(Url::parse("https://broker.test:9090").expect("a URL"), pseudonym());

        assert!(build(&settings).is_ok());
    }
}
