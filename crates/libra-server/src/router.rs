//! The request path, assembled.
//!
//! Order is the security-relevant part of this file. A cache or deduplicator above authentication
//! answers a hit without authentication running: an expired token would keep working for the
//! cache's lifetime, and two concurrent reads with different tokens would collapse into one, with the
//! second caller receiving the first caller's body. Anything of that kind is added below
//! authorization, where a hit has already been authorised and the decision is part of the key.
//!
//! Reading the stack: `ServiceBuilder` applies layers outermost-first, so the first `.layer()` call
//! below sees a request first and the proxy sees it last.

use crate::{
    extensions::{Enforcement, OuterLayer, wrap},
    startup::RequestPath,
};
use axum::Router;
use libra_audit::AuditLayer;
use libra_config::Config;
use libra_enforcement_aggregation::layer::AggregationEnforcementLayer;
use libra_enforcement_attribute::layer::AttributeFilterLayer;
use libra_enforcement_scope::layer::ScopeEnforcementLayer;
use libra_enforcement_time::layer::TimeEnforcementLayer;
use libra_enforcement_type::layer::TypeEnforcementLayer;
use libra_hardening::{
    identity_headers::IdentityHeaderStripLayer,
    in_flight::InFlightLimitLayer,
    method_override::MethodOverrideRefusalLayer,
    payload::PayloadLimitLayer,
    security_headers::security_headers_layer,
};
use libra_identity_layer::IdentityLayer;
use libra_identity_propagation::PropagationLayer;
use libra_jsonld_context_layer::ContextLayer;
use libra_linked_entity_layer::layer::LinkedEntityLayer;
use libra_ngsi_ld_operation_layer::layer::OperationLayer;
use libra_ngsi_ld_query_layer::layer::QueryLayer;
use libra_ngsi_ld_representation_layer::RepresentationLayer;
use libra_policy_layer::AuthzLayer;
use libra_problem_details::layer::ErrorHandlerLayer;
use libra_proxy::layer::ProxyService;
use libra_registration_disclosure::RegistrationDisclosureLayer;
use libra_tenant_layer::TenantLayer;
use libra_upstream_deadlines::timeout::UpstreamTimeoutLayer;
use std::{sync::Arc, time::Duration};
use tower::{ServiceBuilder, util::BoxCloneSyncService};

/// The enforcement layers below authorization, built by the composition root because the scope and
/// type layers need the broker's address and can fail to build.
pub struct EnforcementLayers {
    /// Temporal window narrowing.
    pub time: TimeEnforcementLayer,
    /// Hierarchical scope restrictions.
    pub scope: ScopeEnforcementLayer,
    /// Entity type restrictions.
    pub entity_type: TypeEnforcementLayer,
}

/// The layers below authorization, with the binary's own layers wrapped around them.
///
/// `outer` layers are outermost first. They are still below authorization, which is the placement
/// that matters: a layer that answers from memory, such as a cache, has to run after the request
/// was authorised, with the decision that authorised it available to key on. An expired token must
/// not keep working for a cache's lifetime, and two concurrent reads with different tokens must
/// not collapse into one.
fn enforcement(config: &Config, upstream: ProxyService, layers: EnforcementLayers, outer: Vec<OuterLayer>) -> Enforcement {
    let core = BoxCloneSyncService::new(
        ServiceBuilder::new()
            // A registration reader who may not write registrations is not shown what a
            // registration carries for its source.
            .layer(RegistrationDisclosureLayer::new(config.payload.max_body_size_bytes))
            // Each of these narrows the request under the decision above, and refuses what the
            // decision does not cover.
            .layer(AggregationEnforcementLayer::new(&config.aggregation))
            .layer(layers.time)
            .layer(AttributeFilterLayer::new(config.payload.max_body_size_bytes))
            .layer(layers.scope)
            .layer(layers.entity_type)
            // Innermost before the broker: the only place an X-Auth-* header is written.
            .layer(PropagationLayer::new())
            .service(upstream),
    );

    wrap(core, outer)
}

/// Builds the router the server serves.
pub fn build(config: &Config, request_path: &RequestPath, upstream: ProxyService, layers: EnforcementLayers, outer: Vec<OuterLayer>) -> Router {
    let enforcement = enforcement(config, upstream, layers, outer);

    let stack = ServiceBuilder::new()
        // Outermost, above everything that can refuse, so a 401, a 403 or a 413 is recorded as well
        // as a success. The layers below tell it who the caller was through the slot it inserts.
        .layer(AuditLayer::new())
        // Everything below may refuse by returning an error, and this is what turns one into an
        // RFC 9457 response. Nothing below has to know how a refusal is rendered.
        .layer(ErrorHandlerLayer::new())
        // Immediately after the error handler, so a refusal over the ceiling renders as a problem
        // response, and before everything that reads a body or waits on the broker, so the ceiling
        // bounds exactly the memory and broker pins a request costs. It stays off the management
        // routes, which are admin-authenticated: a shared ceiling would lock the operator out of
        // the one place that could widen it during the incident the ceiling exists for.
        .option_layer(config.limits.enabled.then(|| InFlightLimitLayer::new(config.limits.max_in_flight_requests)))
        .layer(UpstreamTimeoutLayer::new(Duration::from_secs(config.timeout.upstream_timeout_seconds)))
        .option_layer(config.payload.enabled.then(|| PayloadLimitLayer::new(config.payload.max_body_size_bytes)))
        // Before anything reads or writes an X-Auth-* header. A forged one must not survive to the
        // point where something downstream could believe it.
        .layer(IdentityHeaderStripLayer::new())
        // Before anything classifies the request by its method.
        .layer(MethodOverrideRefusalLayer::new())
        .option_layer(security_headers_layer(&config.helmet))
        // Which tenant, and whether the request may be anonymous at all.
        .layer(TenantLayer::new(config.multitenancy.clone())) // the layer owns its settings, the configuration is borrowed
        // Who the caller is, from whichever authenticator recognizes the credential.
        .layer(IdentityLayer::new(
            Arc::clone(&request_path.authentication.authenticators),
            request_path.authentication.fingerprint.clone(),
        ))
        // What the request is and what its query string says, each resolved once and read from the
        // extensions by everything below. Below identity, so a caller with no acceptable credential
        // learns nothing about which paths exist. Nothing unclassifiable passes this point, and a
        // layer that narrows the query writes the stored parameters and the target together.
        .layer(OperationLayer::new())
        .layer(QueryLayer::new())
        // Resolved once, here, and read from the extensions by everything below. Two resolutions of
        // one request can disagree, and then one layer authorizes against a meaning a later layer
        // does not share.
        .layer(ContextLayer::new(Arc::clone(&request_path.resolver), config.payload.max_body_size_bytes))
        // The other thing resolved once and read from the extensions: what the answer will look
        // like. The cache keys on it, the deduplicator coalesces on it, and the attribute filter
        // rewrites bodies under it, so two readings of one `Accept` header would be two layers
        // describing different answers to the same request.
        .layer(RepresentationLayer::new(config.representation))
        // The third thing resolved once: what the request asks for in Linked Entity Retrieval, from
        // its query string, a `Query` body or a subscription. Authorization weighs a join as
        // touching every type, and every enforcement layer judges a join answer by it, so it sits
        // directly above the first of them.
        .layer(LinkedEntityLayer::new())
        // Below this layer everything reads the decision it produced.
        .layer(AuthzLayer::new(Arc::clone(&request_path.store)));

    Router::new().fallback_service(stack.service(enforcement))
}
