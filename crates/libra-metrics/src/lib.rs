//! The Prometheus metrics layer and its endpoint.
//!
//! Metrics are cheap to expose and awkward to expose safely: the series names and label values a
//! proxy emits describe the traffic through it, and the endpoint itself is a route like any other.
//! Both concerns are settled here rather than in the composition root, so there is one answer to
//! where metrics are served and one answer to what is excluded from them.

use axum::{Router, routing::get};
use axum_prometheus::{EndpointLabel, GenericMetricLayer, Handle, PrometheusMetricLayerBuilder, metrics_exporter_prometheus::PrometheusHandle};
use libra_config::prometheus::Prometheus;
use std::future::ready;

/// The label every request that matched no route of Libra's own is measured under.
///
/// Everything NGSI-LD reaches the proxy through the fallback, so it has no matched path. Labelling
/// it with the request path made each entity id its own series, and the recorder never evicts one:
/// an unauthenticated client asking for `/x1`, `/x2` and so on grew memory without bound.
const PROXIED_ENDPOINT: &str = "proxied";

/// The layer that measures requests, and the router that serves what it measured.
pub struct Metrics {
    /// Applied outermost, so a measurement covers the time every other layer spent.
    pub layer: GenericMetricLayer<'static, PrometheusHandle, Handle>,
    /// Mounted at the configured path.
    pub router: Router,
}

/// Builds the metrics layer and endpoint, if the deployment wants them.
///
/// Returns `None` when metrics are switched off, so the composition root has nothing to remember
/// to check.
#[must_use]
pub fn build(config: &Prometheus) -> Option<Metrics> {
    if !config.enabled {
        return None;
    }

    // The probes and the metrics endpoint itself are excluded, by the configured path rather than a
    // literal `/metrics`; otherwise the endpoint would measure itself and every scrape would add a
    // request to the series it was scraping.
    // The layer holds its exclusion list for the life of the process, so the list has to outlive
    // this function. Leaked deliberately: it is built once, at startup, from configuration that
    // does not change, and the alternative is threading a lifetime through the composition root.
    let excluded: Vec<&'static str> = vec![
        "/ngsi-ld/auth/health",
        "/ngsi-ld/auth/ready",
        "/ngsi-ld/auth/info",
        config.path.as_str().to_owned().leak(),
    ];

    let (layer, handle) = PrometheusMetricLayerBuilder::new()
        .with_ignore_patterns(excluded.leak())
        .with_endpoint_label_type(EndpointLabel::MatchedPathWithFallbackFn(|_unmatched_path| PROXIED_ENDPOINT.to_owned()))
        .with_default_metrics()
        .build_pair();

    let router = Router::new().route(config.path.as_str(), get(move || ready(handle.render())));

    Some(Metrics { layer, router })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn metrics_can_be_switched_off_entirely() {
        let off = Prometheus {
            enabled: false,
            ..Prometheus::default()
        };

        assert!(build(&off).is_none(), "a disabled deployment must expose no endpoint at all");
    }

    #[tokio::test]
    async fn requests_for_unmatched_paths_share_one_label_instead_of_one_series_each() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::{Service, ServiceExt};

        let metrics = build(&Prometheus::default()).expect("metrics are on by default");
        let path = Prometheus::default().path;
        let mut app = metrics.router.fallback(|| async { "broker" }).layer(metrics.layer);

        for uri in ["/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1", "/x1", "/x2"] {
            let response = ServiceExt::<Request<Body>>::ready(&mut app)
                .await
                .expect("the router is ready")
                .call(Request::builder().uri(uri).body(Body::empty()).expect("a request"))
                .await
                .expect("the fallback answers");
            assert!(response.status().is_success());
        }

        let scrape = app
            .oneshot(Request::builder().uri(path.as_str()).body(Body::empty()).expect("a request"))
            .await
            .expect("the endpoint answers");
        let text = String::from_utf8(scrape.into_body().collect().await.expect("a body").to_bytes().to_vec()).expect("text");

        assert!(text.contains("endpoint=\"proxied\""), "{text}");
        assert!(!text.contains("/x1") && !text.contains("urn:ngsi-ld"), "a raw path became a label: {text}");
    }

    #[test]
    fn the_endpoint_is_served_where_the_configuration_says() {
        // The default is under the proxy's own management prefix, not the conventional `/metrics`,
        // because everything Libra serves that is not NGSI-LD lives under one prefix.
        assert_eq!(Prometheus::default().path.as_str(), "/ngsi-ld/auth/metrics");
    }
}
