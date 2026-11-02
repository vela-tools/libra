//! Binding, serving, and stopping.

use crate::{
    connections::{self, ConnectionSettings},
    cors::{self, CorsError},
    extensions::{GatedRoutes, OuterLayer},
    lease::LeaseKeeper,
    management_routes,
    request_id,
    router::{self, EnforcementLayers},
    startup::{Background, RequestPath, SigningKeys},
};
use axum::Router;
use libra_config::{Config, listen_host::ListenHost};
use libra_enforcement_scope::layer::ScopeEnforcementLayer;
use libra_enforcement_time::layer::TimeEnforcementLayer;
use libra_enforcement_type::layer::TypeEnforcementLayer;
use libra_entity_preflight::{error::PreflightError, preflight::Preflight};
use libra_health::HealthState;
use libra_proxy::{error::ProxyError, layer::ProxyLayer, settings::ProxySettings};
use std::{io, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing::{info, warn};
use url::Host;

/// Anything that stops Libra once startup has succeeded.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The proxy could not be built from the broker configuration.
    #[error(transparent)]
    Proxy(#[from] ProxyError),

    /// The client the scope and type layers ask the broker with could not be built.
    #[error(transparent)]
    Preflight(#[from] PreflightError),

    /// The `[cors]` section does not describe a usable policy.
    #[error(transparent)]
    Cors(#[from] CorsError),

    /// `[proxy] via-pseudonym` is not set.
    ///
    /// There is no default name: every installation answering to the same one would make two
    /// deployments look like one hop to the brokers that detect loops from `Via`.
    #[error("[proxy] via-pseudonym is required: choose a name unique to this deployment")]
    NoViaPseudonym,

    /// The listening address is unusable, or serving failed.
    #[error("could not serve on {host}:{port}: {source}")]
    Serve {
        /// The host Libra tried to bind, which displays an IPv6 address in brackets.
        host: Host<String>,
        /// The port Libra tried to bind.
        port: u16,
        /// What the operating system said.
        #[source]
        source: io::Error,
    },
}

/// Serves until the process is asked to stop.
///
/// # Errors
///
/// Returns [`ServeError`] if the proxy cannot be built or the address cannot be served.
pub async fn serve(
    config: &Config,
    request_path: &RequestPath,
    background: &Background,
    outer: Vec<OuterLayer>,
    extra: Vec<GatedRoutes>,
) -> Result<(), ServeError> {
    let router = assemble(config, request_path, background.signing_keys.as_ref(), outer, extra)?;

    let listener = match bind(&config.libra.host, config.libra.port).await {
        Ok(listener) => listener,
        Err(source) => {
            return Err(ServeError::Serve {
                // Cloned because the error outlives the borrowed configuration.
                host: config.libra.host.host().clone(),
                port: config.libra.port,
                source,
            });
        }
    };

    // Started once binding has succeeded, so that no way out of this function leaves it running.
    let refresh = background
        .signing_keys
        .as_ref()
        .map(|signing| signing.keys.clone().start_refresh_task(signing.refresh_period)); // the task owns a handle to the shared key set
    let keeper = background.key_store.as_ref().map(LeaseKeeper::start);
    let stop_requests = keeper.as_ref().map(LeaseKeeper::stop_requests).unwrap_or_default();

    info!(host = %config.libra.host.host(), port = config.libra.port, "libra is listening");

    let settings = ConnectionSettings {
        header_read_timeout: Duration::from_secs(config.libra.header_read_timeout_seconds),
        shutdown_grace: Duration::from_secs(config.libra.shutdown_grace_seconds),
    };
    connections::serve(listener, router, settings, stop_requests).await;

    if let Some(refresh) = refresh {
        refresh.abort();
    }
    if let Some(keeper) = keeper {
        keeper.stop();
    }

    Ok(())
}

/// Builds every route Libra serves, with the layers that apply to each.
fn assemble(
    config: &Config,
    request_path: &RequestPath,
    signing_keys: Option<&SigningKeys>,
    outer: Vec<OuterLayer>,
    extra: Vec<GatedRoutes>,
) -> Result<Router, ServeError> {
    let proxy = ProxyLayer::new(proxy_settings(config)?)?;
    let upstream = proxy.service();

    // The type and scope layers reach the broker to ask what an entity is, through one client and
    // its one connection pool. Built here rather than in the router, which does no I/O and cannot
    // fail.
    let preflight = Arc::new(Preflight::new(config.broker.url.clone(), config.payload.max_body_size_bytes)?); // the client owns its address, the configuration is borrowed
    let layers = EnforcementLayers {
        time: TimeEnforcementLayer::new(config.payload.max_body_size_bytes),
        scope: ScopeEnforcementLayer::new(Arc::clone(&preflight), config.payload.max_body_size_bytes),
        entity_type: TypeEnforcementLayer::new(preflight, config.payload.max_body_size_bytes),
    };

    let health = health_routes(config, signing_keys);

    let metrics = libra_metrics::build(&config.prometheus);

    let proxied = router::build(config, request_path, upstream, layers, outer);

    // The probes are mounted bare and everything else that is not proxied carries the listener
    // protections. The probes are the deliberate exception: a readiness check has to answer when
    // the identity provider does not, so it carries nothing that could refuse it.
    let mut router = Router::new().merge(health).merge(management_routes::build(
        config,
        request_path,
        metrics.as_ref().map(|metrics| metrics.router.clone()), // a router is a shared handle; the metrics layer is mounted from the original
        extra,
    ));

    router = router.merge(proxied);

    if let Some(metrics) = metrics {
        // Outermost, so a measurement covers the time every other layer spent.
        router = router.layer(metrics.layer);
    }

    let router = request_id::apply(router);

    Ok(if let Some(layer) = cors::layer(&config.cors)? {
        info!(mode = ?config.cors.enabled, "CORS is on");
        router.layer(layer)
    } else {
        info!("CORS is disabled");
        router
    })
}

/// The liveness and readiness routes, or none when the probe cannot be built.
fn health_routes(config: &Config, signing_keys: Option<&SigningKeys>) -> Router {
    let keys = signing_keys.map(|signing| signing.keys.clone()); // the probe owns a handle to the shared key set
    HealthState::new(keys, config.broker.url.clone()).map_or_else(
        // the probe state owns its address
        |error| {
            // A probe that cannot be built would answer failure forever and take a working proxy out
            // of rotation. Its absence is reported here instead, and the routes are left off.
            warn!(error = %error, "health probes are unavailable");
            Router::new()
        },
        libra_health::router,
    )
}

/// The broker connection settings, from the `[proxy]` section.
fn proxy_settings(config: &Config) -> Result<ProxySettings, ServeError> {
    let via_pseudonym = config.proxy.via_pseudonym.clone().ok_or(ServeError::NoViaPseudonym)?; // ProxySettings owns its pseudonym, the configuration is borrowed

    Ok(ProxySettings {
        pool_idle_timeout: Duration::from_secs(config.proxy.pool_idle_timeout_seconds),
        pool_max_idle_per_host: config.proxy.pool_max_idle_per_host,
        connect_timeout: Duration::from_secs(config.proxy.connect_timeout_seconds),
        tcp_nodelay: config.proxy.tcp_nodelay,
        inbound_scheme: config.proxy.inbound_scheme,
        trusted_proxies: config.libra.trusted_proxies.clone(), // the proxy owns a handle to the shared list, the configuration is borrowed
        ..ProxySettings::new(config.broker.url.clone(), via_pseudonym)  // ProxySettings owns its address, the configuration is borrowed
    })
}

/// Binds the listener.
///
/// The host and the port are passed as two values. Joined into one string, an IPv6 host such as
/// `::1` read as an address with a very long host part and no port.
async fn bind(host: &ListenHost, port: u16) -> io::Result<TcpListener> {
    match host.host() {
        Host::Domain(name) => TcpListener::bind((name.as_str(), port)).await,
        Host::Ipv4(address) => TcpListener::bind((*address, port)).await,
        Host::Ipv6(address) => TcpListener::bind((*address, port)).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(text: &str) -> ListenHost {
        ListenHost::new(text.to_owned()).expect("the test host is a host")
    }

    #[test]
    fn an_ipv6_host_is_bracketed_in_the_address_shown_to_the_operator() {
        let refusal = |text: &str, port: u16| {
            ServeError::Serve {
                // Cloned out of a temporary `ListenHost`, which the error cannot borrow from.
                host: host(text).host().clone(),
                port,
                source: io::Error::from(io::ErrorKind::AddrInUse),
            }
            .to_string()
        };

        assert!(refusal("::1", 5667).starts_with("could not serve on [::1]:5667: "));
        assert!(refusal("0.0.0.0", 5667).starts_with("could not serve on 0.0.0.0:5667: "));
        assert!(refusal("libra.internal", 80).starts_with("could not serve on libra.internal:80: "));
    }

    #[tokio::test]
    async fn an_ipv6_host_can_be_bound() {
        // Skipped quietly on a machine with no IPv6 loopback, which is the machine's property and
        // not the code's.
        if let Ok(listener) = bind(&host("::1"), 0).await {
            assert!(listener.local_addr().is_ok_and(|address| address.is_ipv6()));
        }
    }
}
