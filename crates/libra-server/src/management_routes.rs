//! The management endpoints, assembled.
//!
//! These are the routes that describe Libra rather than the broker: which commit is running, what
//! the metrics layer has collected, and whatever a binary adds, such as a policy API. Nothing here
//! is proxied, so none of it passes through the stack in [`crate::router`], which sits behind
//! `Router::fallback_service` and therefore only ever sees a request no route matched.
//!
//! Protections inside the fallback cover proxied traffic and nothing else. The management routes
//! carry their own, so a refused management request leaves an audit record, a management request
//! body has a size to exceed, and a client-supplied `X-Auth-*` header is swept here as it is on the
//! way to the broker. Nothing reads those headers except identity propagation on the proxied
//! path, so the sweep guards a latent weakness rather than a live one, but "no handler happens to read it"
//! is a fact about the current handlers, not an invariant, and the sweep is what makes it one.
//!
//! # What is shared, and what is not
//!
//! Shared with the proxied path: everything that is about the listener. The audit layer, the
//! payload limit, the identity-header sweep and the security headers, in that order, which is the
//! order they have on the proxied path. The layers are built from the same values the proxied stack
//! uses.
//!
//! Not shared: the upstream timeout, because it names an upstream that a management route does not
//! have, and a 504 saying the upstream did not answer would be describing something that was never
//! asked. Nor the in-flight ceiling, because these routes are admin-authenticated and a shared
//! ceiling would lock the operator out of the one place that could widen it during exactly the
//! incident the ceiling exists for. Nor the proxy's authentication, tenant resolution or
//! authorization: these routes carry [`ManagementAuthLayer`] instead, which is a different question
//! with a different answer. The error handler is absent for the same reason it would be inert:
//! every layer here renders its own RFC 9457 refusal, so there is no error left to convert.
//!
//! # Why the probes are not here
//!
//! The liveness and readiness probes are mounted bare by the composition root. A readiness probe
//! answers without a token so that it still works when the identity provider does not.

use crate::{
    extensions::GatedRoutes,
    management::ManagementAuthLayer,
    startup::{CallerAuthentication, RequestPath},
};
use axum::Router;
use libra_audit::AuditLayer;
use libra_build_info::router as build_info_router;
use libra_config::Config;
use libra_hardening::{identity_headers::IdentityHeaderStripLayer, payload::PayloadLimitLayer, security_headers::security_headers_layer};
use libra_management_auth::PrivilegeSettings;
use std::sync::Arc;
use tower::ServiceBuilder;

/// Builds the management routes, each behind its own privilege gate and all behind the listener
/// protections.
///
/// `metrics` is the endpoint [`libra_metrics::build`] produced, absent when the deployment has
/// switched metrics off. The measuring layer is not this module's business: it is applied
/// outermost, to every route, by the composition root. `extra` is whatever the binary mounts
/// beyond the routes every build has.
pub fn build(config: &Config, request_path: &RequestPath, metrics: Option<Router>, extra: Vec<GatedRoutes>) -> Router {
    let authentication = &request_path.authentication;

    // What commit is running, behind its own gate. Deliberately not part of the health router: a
    // liveness probe has to answer without a token, and this must not.
    let mut router = build_info_router().layer(gate(authentication, PrivilegeSettings::for_build_info(&config.management_api)));

    if let Some(metrics) = metrics {
        // Gated on `metrics-access`, which is this endpoint's own key. Metrics
        // describe the traffic through the proxy (the tenants in use, the routes exercised, the
        // error rates), which is not something to serve to whoever asks.
        router = router.merge(metrics.layer(gate(authentication, PrivilegeSettings::for_metrics(&config.management_api))));
    }

    // Each extra group carries its own privilege settings, because "who may call this" is a
    // property of the route and not of the proxy.
    for GatedRoutes { privilege, routes } in extra {
        router = router.merge(routes(request_path).layer(gate(authentication, privilege)));
    }

    // `route_layer` rather than `layer`: these protections belong to the routes above, and the
    // fallback they would otherwise also wrap is the proxied stack, which has its own copy in its
    // own documented position. Layering it twice would audit a proxied request twice and sweep its
    // identity headers twice.
    router.route_layer(
        ServiceBuilder::new()
            // Outermost and above everything that can refuse, as on the proxied path, so a refused
            // management request is on the record and the gate can say who it was.
            .layer(AuditLayer::new())
            .option_layer(config.payload.enabled.then(|| PayloadLimitLayer::new(config.payload.max_body_size_bytes)))
            // Before any handler could read one. No management handler does; the sweep keeps that from
            // being the only thing holding the guarantee up.
            .layer(IdentityHeaderStripLayer::new())
            .option_layer(security_headers_layer(&config.helmet)),
    )
}

/// The privilege gate for one group of routes.
fn gate(authentication: &CallerAuthentication, settings: PrivilegeSettings) -> ManagementAuthLayer {
    ManagementAuthLayer::new(Arc::clone(&authentication.authenticators), settings, authentication.fingerprint.clone())
}
