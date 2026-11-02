//! Checking and narrowing what a request carries or asks for.
//!
//! Where a scope can be found differs by operation, and getting that mapping wrong leaves holes in an otherwise working
//! restriction. There are four
//! places, and all four are covered here:
//!
//! * A collection read names its scopes in `scopeQ`, which is narrowed.
//! * A batch query names them in its body, which is narrowed too.
//! * A create or a batch write names them in the entities it carries. A write that may change an
//!   entity already stored is also judged by the scopes it is stored in, which
//!   [`libra_enforcement_member::batch`] pre-flights.
//! * A request that names one entity names no scope at all: not in the path, not in the query,
//!   and for an attribute write or a delete not in the body either. Those are pre-flighted.
//!
//! The rule for the last case is one line and covers every method, though what it asks differs by
//! mode: a read is allowed when any one of the entity's scopes is allowed and the response is then
//! reduced to the allowed scopes, while a write needs every scope the entity carries to be allowed.
//! If [`Resource::entity_id`](libra_ngsi_ld_operation::resource::Resource::entity_id) is `Some`, the entity is fetched and its scope checked, whatever the method.
//! Appending `scopeQ=` to `GET /entities/{id}` instead would not work: NGSI-LD does not define that
//! parameter for retrieve-by-id, so brokers would ignore it and any entity would be readable by id
//! whatever its scope.
//!
//! What a request asks for in Linked Entity Retrieval (in its query string, a `Query` body or a
//! subscription's notification) is resolved above authorization and judged in the layer, not here.

use crate::{document, error::ScopeError, expression::ScopeExpression};
use axum::{body::Body, extract::Request, http::request::Parts};
use libra_enforcement_member::{batch, location::Location, query_parameter::take_parameter, unnarrowable::Unnarrowable};
use libra_entity_preflight::preflight::{EntityEndpoint, Preflight};
use libra_json_body::{narrowing::Narrowing, request_body::RequestBody};
use libra_ngsi_ld_operation::{
    operation::{Mode, Operation},
    target::EntityTarget,
};
use libra_ngsi_ld_query::parameter_name::ParameterName;
use libra_ngsi_ld_query_layer::parsed::{parameters, replace_query};
use libra_policy_model::{member_on_write::MemberOnWrite, scope::ScopeRestriction};
use tracing::debug;

/// What a query string that names no scope is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unnamed {
    /// The policy's restriction, written in as the scope filter.
    Restriction,
    /// Nothing: the scope filter lives somewhere other than the query string.
    Nothing,
}

/// Whether the response to this operation has to be filtered to the allowed scopes.
///
/// Every read that returns entities does: a by-id read and a collection or batch query each hand
/// back an entity's whole `scope` member, which may name scopes the restriction does not cover.
#[must_use]
pub const fn filters_response(operation: &Operation) -> bool {
    matches!(operation.mode, Mode::Read)
        && matches!(
            EntityTarget::of(operation),
            EntityTarget::SingleEntity | EntityTarget::CollectionQuery | EntityTarget::BatchQuery
        )
}

/// Applies the restriction to whichever part of the request carries scopes.
///
/// Bodies are read from the parse the context layer left in the request extensions, never from the
/// bytes.
///
/// # Errors
///
/// Returns [`ScopeError`] if the request carries or asks for scopes outside the restriction, carries a
/// body or query this layer cannot read, or reached this layer with no body read above it.
pub async fn enforce(request: Request, operation: &Operation, restriction: &ScopeRestriction, preflight: &Preflight) -> Result<Request, ScopeError> {
    match EntityTarget::of(operation) {
        EntityTarget::SingleEntity => single_entity(request, operation, restriction, preflight).await,
        EntityTarget::CollectionQuery => narrow_query(request, restriction),
        EntityTarget::CollectionWrite | EntityTarget::BatchCreate => check_body(request, restriction, restriction.scope_on_write),
        EntityTarget::TemporalCollectionWrite => overwrite(request, restriction, preflight, EntityEndpoint::Temporal).await,
        EntityTarget::BatchOverwrite => overwrite(request, restriction, preflight, EntityEndpoint::Current).await,
        EntityTarget::BatchQuery => narrow_query_body(request, restriction),
        EntityTarget::BatchDelete => {
            let (parts, body) = request.into_parts();
            batch::check_deleted(&parts, preflight, |id, answer| document::check_existing(answer, restriction, Mode::Write, id)).await?;

            Ok(Request::from_parts(parts, body))
        }
        EntityTarget::SubscriptionCreate => narrow_subscription(request, restriction),
        EntityTarget::ExistingSubscriptions => Err(Unnarrowable::ExistingSubscriptions.into()),
        EntityTarget::Untouched => Ok(request),
    }
}

/// Checks a write that may change entities already stored: the scopes its body declares, then the
/// scopes each entity it names is stored in.
///
/// The body is checked first, so a body declaring a forbidden scope is refused without asking the
/// broker anything.
async fn overwrite(request: Request, restriction: &ScopeRestriction, preflight: &Preflight, endpoint: EntityEndpoint) -> Result<Request, ScopeError> {
    let (parts, body) = check_body(request, restriction, restriction.scope_on_write)?.into_parts();

    batch::check_stored(&parts, preflight, endpoint, |id, stored| {
        document::check_existing(Ok(stored), restriction, Mode::Write, id)
    })
    .await?;

    Ok(Request::from_parts(parts, body))
}

/// Checks a request that names exactly one entity.
///
/// One pre-flight, whatever the method. A read is checked because appending a parameter the broker
/// ignores would not restrict it; a write is checked because its body carries attributes rather
/// than a scope, so judging the payload alone would read it as one that left the scope out and
/// refuse every attribute write under `scope-on-write`.
async fn single_entity(request: Request, operation: &Operation, restriction: &ScopeRestriction, preflight: &Preflight) -> Result<Request, ScopeError> {
    let Some(id) = operation.resource.entity_id() else {
        // Unreachable through `EntityTarget`, which chose this arm because there is an identifier.
        return Ok(request);
    };

    let answer = preflight.entity(id, EntityEndpoint::for_resource(&operation.resource), request.headers()).await;
    document::check_existing(answer, restriction, operation.mode, id)?;

    debug!(entity = %id, "the addressed entity is inside the allowed scopes");

    // A body addressed to one attribute is that attribute's value (NGSI-LD 6.7.3.1, 6.7.3.3,
    // 6.22.3.1), so a `scope` member in it is a sub-attribute, never the entity's scope, and it
    // cannot move the entity.
    if matches!(operation.mode, Mode::Read) || operation.resource.attribute().is_some() {
        return Ok(request);
    }

    // A write may also move the entity. The pre-flight said where it is; the payload says where it
    // is going, and a scope it may not write is refused even though the entity it started in was
    // one it may.
    check_body(request, restriction, MemberOnWrite::Optional)
}

/// Narrows the `scopeQ` parameter, injecting the policy's own restriction if the caller named none.
fn narrow_query(request: Request, restriction: &ScopeRestriction) -> Result<Request, ScopeError> {
    let (mut parts, body) = request.into_parts();

    apply_to_query(&mut parts, restriction, Unnamed::Restriction)?;

    Ok(Request::from_parts(parts, body))
}

/// Narrows whatever scope filter the query string carries.
///
/// `unnamed` says what a query that names no scope is given. A collection read gets the policy's
/// restriction; a batch query gets nothing, because its filter belongs in the body and adding a
/// parameter the specification does not define there would be Libra inventing a request.
fn apply_to_query(parts: &mut Parts, restriction: &ScopeRestriction, unnamed: Unnamed) -> Result<(), ScopeError> {
    // Cloned because the narrowed copy is written back over the stored one.
    let mut parameters = parameters(&parts.extensions)?.clone();

    // Whatever the caller spelled it, so no second, unchecked filter is left behind for a lenient
    // broker to read instead of the narrowed one.
    let expression = match (take_parameter(&mut parameters, &ParameterName::SCOPE_Q)?, unnamed) {
        (Some(filter), Unnamed::Restriction | Unnamed::Nothing) => ScopeExpression::parse(&filter)?.narrow(&restriction.allowed)?,
        (None, Unnamed::Restriction) => ScopeExpression::any_of(&restriction.allowed).ok_or(ScopeError::EmptyAllowList)?,
        (None, Unnamed::Nothing) => return Ok(()),
    };

    parameters.set(ParameterName::SCOPE_Q, expression.to_string());

    replace_query(parts, parameters).map_err(|_| ScopeError::Unrebuildable)?;

    Ok(())
}

/// Narrows the scope filter a batch query carries in its body.
fn narrow_query_body(request: Request, restriction: &ScopeRestriction) -> Result<Request, ScopeError> {
    let (mut parts, body) = request.into_parts();

    // A batch query may still carry a `scopeQ` in the URL. It is narrowed if it is there, and not
    // invented if it is not: a broker that honours it would otherwise apply a filter nobody
    // checked.
    apply_to_query(&mut parts, restriction, Unnamed::Nothing)?;

    narrow_scope_filter(parts, body, restriction, "a Query object")
}

/// Narrows the scope filter a subscription carries in its body.
///
/// A subscription (NGSI-LD 5.2.12) has a `scopeQ` member of its own, and the broker delivers its
/// notifications on a channel Libra never sees. The restriction therefore has to be written into the
/// subscription itself: one that named a wider scope, or none at all, would otherwise notify on
/// entities outside the caller's restriction. A subscription that named no scope is given the restriction, and
/// one that named a scope has it narrowed to within the restriction. Both are bounded by it, so a
/// caller can never widen past it.
fn narrow_subscription(request: Request, restriction: &ScopeRestriction) -> Result<Request, ScopeError> {
    let (parts, body) = request.into_parts();

    narrow_scope_filter(parts, body, restriction, "a Subscription object")
}

/// Narrows the `scopeQ` member of the body a request carries.
///
/// A body whose filter was inside the restriction as written is forwarded as the caller's bytes;
/// one that was narrowed is printed again, with its length.
fn narrow_scope_filter(mut parts: Parts, body: Body, restriction: &ScopeRestriction, expected: &'static str) -> Result<Request, ScopeError> {
    let mut document = RequestBody::take_document(&mut parts)?.ok_or(ScopeError::MalformedBody { expected })?;

    let body = match document::narrow_query_document(&mut document, &restriction.allowed)? {
        Narrowing::Unchanged => {
            RequestBody::restore(&mut parts, document);
            body
        }
        Narrowing::Narrowed => RequestBody::replace(&mut parts, document),
    };

    Ok(Request::from_parts(parts, body))
}

/// Checks the scopes a write payload carries.
fn check_body(request: Request, restriction: &ScopeRestriction, on_write: MemberOnWrite) -> Result<Request, ScopeError> {
    let (parts, body) = request.into_parts();

    match (RequestBody::document_in(&parts)?, on_write) {
        (None, MemberOnWrite::Required) => return Err(ScopeError::MissingScope { at: Location::Payload }),
        (None, MemberOnWrite::Optional) => {}
        (Some(document), MemberOnWrite::Required | MemberOnWrite::Optional) => document::check_write_body(document, restriction, on_write)?,
    }

    Ok(Request::from_parts(parts, body))
}
