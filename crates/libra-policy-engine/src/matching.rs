//! Whether one policy applies to one request.
//!
//! Every field is an allow list and an absent field matches everything, except `resources`, whose
//! absence on an allow means entity data only: see `matches_resources`. The other place the rule needs care
//! is a condition the request cannot answer: see `matches_entity_types`.

use crate::request::{EvaluationRequest, RequestedTypes};
use libra_policy_model::{condition::CompiledCondition, effect::Effect, identity::IdentityName};

/// Whether every present condition is satisfied.
#[must_use]
pub fn matches(condition: &CompiledCondition, effect: Effect, request: &EvaluationRequest<'_>) -> bool {
    matches_user(condition, request)
        && matches_principal(condition, request)
        && matches_groups(condition, request)
        && matches_roles(condition, request)
        && matches_tenants(condition, request)
        && matches_operations(condition, request)
        && matches_resources(condition, effect, request)
        && matches_entity_types(condition, effect, request)
        && matches_queries(condition, request)
        && matches_time_interval(condition, request)
}

/// A policy naming users is satisfied only by an account of one of those names.
///
/// Not by a request with no caller: anonymous access is allowed by a policy that names nobody,
/// which is a thing an operator writes on purpose. Not by a principal either, whatever its name:
/// a principal is defined in Libra and an account by the identity provider, and neither may stand
/// in for the other.
fn matches_user(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    match (&condition.users, request.name) {
        (None, _) => true,
        (Some(users), Some(IdentityName::Account(user))) => users.contains(user),
        (Some(_), Some(IdentityName::Principal(_)) | None) => false,
    }
}

/// A policy naming principals is satisfied only by a principal of one of those names.
fn matches_principal(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    match (&condition.principals, request.name) {
        (None, _) => true,
        (Some(principals), Some(IdentityName::Principal(principal))) => principals.contains(principal),
        (Some(_), Some(IdentityName::Account(_)) | None) => false,
    }
}

fn matches_groups(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    condition
        .groups
        .as_ref()
        .is_none_or(|groups| request.groups.iter().any(|held| groups.contains(held)))
}

fn matches_roles(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    condition
        .roles
        .as_ref()
        .is_none_or(|roles| request.roles.iter().any(|held| roles.contains(held)))
}

fn matches_tenants(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    condition.tenants.as_ref().is_none_or(|tenants| tenants.contains(request.tenant))
}

fn matches_operations(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    condition.operations.as_ref().is_none_or(|operations| operations.contains(&request.operation))
}

/// A policy naming resources is about those. One naming none is about entity data alone when it
/// allows, and about every family when it denies.
///
/// The two effects need opposite answers, as for entity types. An allow that names no resources
/// must not come to cover registrations, the broker's context cache or snapshots, which reach
/// further than entity data. A deny that names none must not leave those open: `users = ["x"]`
/// with `effect = "deny"` reads as "refuse x", and a deny that stood aside for subscriptions or
/// registrations would let x through wherever another policy names them.
fn matches_resources(condition: &CompiledCondition, effect: Effect, request: &EvaluationRequest<'_>) -> bool {
    match (&condition.resources, effect) {
        (Some(resources), Effect::Allow | Effect::Deny) => resources.contains(&request.resource),
        (None, Effect::Allow) => request.resource.is_covered_by_default(),
        (None, Effect::Deny) => true,
    }
}

/// Whether the request touches the types this policy is about.
///
/// The two effects need opposite answers when the request does not bound what it touches. An allow
/// is a restriction, so it applies only to a request that names types and names nothing outside its
/// list: `?type=Vehicle,Secret` is not covered by an allow for `Vehicle`, because the broker would
/// answer with `Secret` entities too. A deny is a refusal, so it applies when the request names any
/// type in its list, and also when its types are unbounded: a read by id, a batch body or a
/// subscription touches types the query string does not reveal, a Linked Entity Retrieval returns
/// entities of types it never named, and a deny that stood aside for them would be bypassed by
/// asking differently. The precise tool for narrowing such a request is the entity type
/// restriction, which looks at what the broker returns.
fn matches_entity_types(condition: &CompiledCondition, effect: Effect, request: &EvaluationRequest<'_>) -> bool {
    let Some(types) = condition.entity_types.as_ref() else {
        return true;
    };

    match (effect, request.entity_types) {
        (Effect::Allow, RequestedTypes::Unbounded) => false,
        (Effect::Allow, RequestedTypes::Named(named)) => !named.is_empty() && named.iter().all(|name| types.contains(name)),
        (Effect::Deny, RequestedTypes::Unbounded) => true,
        (Effect::Deny, RequestedTypes::Named(named)) => named.iter().any(|name| types.contains(name)),
    }
}

fn matches_queries(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    match (&condition.queries, request.query) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(queries), Some(query)) => queries.contains(query),
    }
}

fn matches_time_interval(condition: &CompiledCondition, request: &EvaluationRequest<'_>) -> bool {
    condition.time_interval.as_ref().is_none_or(|interval| interval.contains(request.now))
}
