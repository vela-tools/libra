//! Checking and narrowing what a request carries or asks for.
//!
//! Four places name an entity type, and all four are covered:
//!
//! * A collection read names them in `type`, which is checked and, if the caller named none,
//!   filled in with the restriction.
//! * A batch query names them in the `entities` selectors of its body.
//! * A create or a batch write names them in the entities it carries. A write that may change an
//!   entity already stored is also judged by the types it is stored under, which
//!   [`libra_enforcement_member::batch`] pre-flights.
//! * A request that names one entity does not name a type at all. Those are pre-flighted.
//!
//! What a request asks for in Linked Entity Retrieval (in its query string, a `Query` body or a
//! subscription's notification) is resolved above authorization and judged in the layer, not here.

use crate::{document, error::TypeError, names};
use axum::{body::Body, extract::Request, http::request::Parts};
use libra_enforcement_member::{batch, location::Location, query_parameter::take_parameter, unnarrowable::Unnarrowable};
use libra_entity_preflight::preflight::{EntityEndpoint, Preflight};
use libra_json_body::{narrowing::Narrowing, request_body::RequestBody};
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_ngsi_ld_operation::{
    operation::{Mode, Operation},
    target::EntityTarget,
};
use libra_ngsi_ld_query::{parameter_name::ParameterName, type_selection::TypeSelection};
use libra_ngsi_ld_query_layer::parsed::{parameters, replace_query};
use libra_policy_model::{entity_type::CompiledTypeRestriction, member_on_write::MemberOnWrite};
use tracing::debug;

/// What a query string that names no type is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unnamed {
    /// The policy's restriction, written in as the type selection.
    Restriction,
    /// Nothing: the type filter lives somewhere other than the query string.
    Nothing,
}

/// Applies the restriction to whichever part of the request carries types.
///
/// Bodies are read from the parse the context layer left in the request extensions, never from the
/// bytes.
///
/// # Errors
///
/// Returns [`TypeError`] if the request carries or asks for entity types outside the policy restriction,
/// if request bodies or query parameters cannot be processed, or if no layer above read the body.
pub async fn enforce(
    request: Request,
    operation: &Operation,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    preflight: &Preflight,
) -> Result<Request, TypeError> {
    match EntityTarget::of(operation) {
        EntityTarget::SingleEntity => single_entity(request, operation, restriction, context, preflight).await,
        EntityTarget::CollectionQuery => narrow_query(request, restriction, context),
        EntityTarget::CollectionWrite | EntityTarget::BatchCreate => check_body(request, restriction, context, restriction.on_write()),
        EntityTarget::TemporalCollectionWrite => overwrite(request, restriction, context, preflight, EntityEndpoint::Temporal).await,
        EntityTarget::BatchOverwrite => overwrite(request, restriction, context, preflight, EntityEndpoint::Current).await,
        EntityTarget::BatchQuery => narrow_query_body(request, restriction, context),
        EntityTarget::BatchDelete => {
            let (parts, body) = request.into_parts();
            batch::check_deleted(&parts, preflight, |id, answer| document::check_stored(answer, restriction, context, id)).await?;

            Ok(Request::from_parts(parts, body))
        }
        EntityTarget::SubscriptionCreate => {
            let (parts, body) = request.into_parts();

            narrow_selectors(parts, body, restriction, context, "a Subscription object")
        }
        EntityTarget::ExistingSubscriptions => Err(Unnarrowable::ExistingSubscriptions.into()),
        EntityTarget::Untouched => Ok(request),
    }
}

/// Checks a write that may change entities already stored: the types its body declares, then the
/// types each entity it names is stored under.
///
/// The body is checked first, so a body declaring a forbidden type is refused without asking the
/// broker anything.
async fn overwrite(
    request: Request,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    preflight: &Preflight,
    endpoint: EntityEndpoint,
) -> Result<Request, TypeError> {
    let (parts, body) = check_body(request, restriction, context, restriction.on_write())?.into_parts();

    batch::check_stored(&parts, preflight, endpoint, |id, stored| {
        document::check_stored(Ok(stored), restriction, context, id)
    })
    .await?;

    Ok(Request::from_parts(parts, body))
}

/// Checks a request that names exactly one entity.
///
/// One pre-flight, whatever the method. `PATCH /entities/{id}` is the case that makes this
/// necessary: a merge patch carries no type by design, so under `type-on-write` it looked
/// exactly like a payload that had left the type out, and every merge was refused.
async fn single_entity(
    request: Request,
    operation: &Operation,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    preflight: &Preflight,
) -> Result<Request, TypeError> {
    let Some(id) = operation.resource.entity_id() else {
        // Unreachable through `EntityTarget`, which chose this arm because there is an identifier.
        return Ok(request);
    };

    let answer = preflight.entity(id, EntityEndpoint::for_resource(&operation.resource), request.headers()).await;
    document::check_stored(answer, restriction, context, id)?;

    debug!(entity = %id, "the addressed entity is of an allowed type");

    // A body addressed to one attribute is that attribute's value (NGSI-LD 6.7.3.1, 6.7.3.3,
    // 6.22.3.1), so its `type` is `Property` or `Relationship`, never the entity's, and it cannot
    // change what the pre-flight found.
    if matches!(operation.mode, Mode::Read) || operation.resource.attribute().is_some() {
        return Ok(request);
    }

    // A replace may also change the type. The pre-flight said what the entity is; the payload says
    // what it is about to become, and a type it may not write is refused even though the type it
    // started as was one it may.
    check_body(request, restriction, context, MemberOnWrite::Optional)
}

/// Narrows the `type` parameter, injecting the policy's own restriction if the caller named none.
fn narrow_query(request: Request, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<Request, TypeError> {
    let (mut parts, body) = request.into_parts();

    apply_to_query(&mut parts, restriction, context, Unnamed::Restriction)?;

    Ok(Request::from_parts(parts, body))
}

/// Narrows whatever type selection the query string carries to the allowed types.
///
/// A selection the restriction covers in full is forwarded as the caller wrote it; one it covers in part
/// is rewritten to the part it covers. `unnamed` says what a query that names no type is given. A
/// collection read gets the policy's restriction; a batch query gets nothing, because its selectors
/// belong in the body.
fn apply_to_query(parts: &mut Parts, restriction: &CompiledTypeRestriction, context: &ResolvedContext, unnamed: Unnamed) -> Result<(), TypeError> {
    // Cloned because the narrowed copy is written back over the stored one.
    let mut parameters = parameters(&parts.extensions)?.clone();

    // Whatever the caller spelled it, so no second, unchecked selection is left behind for a lenient
    // broker to read instead of the narrowed one.
    let selected = take_parameter(&mut parameters, &ParameterName::TYPE)?;

    let value = match (selected, unnamed) {
        (Some(selection), Unnamed::Restriction | Unnamed::Nothing) => {
            // Parsed, not split. An expression Libra cannot read is one whose type references it
            // cannot check, while the broker would apply it whole.
            let parsed = TypeSelection::parse(&selection)?;
            let narrowed = names::narrow_selection(&parsed, restriction, context)?;
            if narrowed == parsed { selection } else { narrowed.to_string() }
        }
        (None, Unnamed::Restriction) => names::allowed_selector(restriction)?,
        (None, Unnamed::Nothing) => return Ok(()),
    };

    parameters.set(ParameterName::TYPE, value);

    replace_query(parts, parameters).map_err(|_| TypeError::Unrebuildable)?;

    Ok(())
}

/// Checks and narrows the entity selectors a batch query carries in its body.
fn narrow_query_body(request: Request, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<Request, TypeError> {
    let (mut parts, body) = request.into_parts();

    // A batch query may still carry a `type` in the URL. It is checked if it is there, and not
    // invented if it is not: the selectors in the body are where this endpoint's filter lives.
    apply_to_query(&mut parts, restriction, context, Unnamed::Nothing)?;

    narrow_selectors(parts, body, restriction, context, "a Query object")
}

/// Narrows the `entities` selectors of the body a request carries.
///
/// A body whose selectors were inside the restriction as written is forwarded as the caller's
/// bytes; one that was narrowed is printed again, with its length.
fn narrow_selectors(
    mut parts: Parts,
    body: Body,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    expected: &'static str,
) -> Result<Request, TypeError> {
    let mut document = RequestBody::take_document(&mut parts)?.ok_or(TypeError::MalformedBody { expected })?;

    let body = match document::narrow_query_document(&mut document, restriction, context)? {
        Narrowing::Unchanged => {
            RequestBody::restore(&mut parts, document);
            body
        }
        Narrowing::Narrowed => RequestBody::replace(&mut parts, document),
    };

    Ok(Request::from_parts(parts, body))
}

/// Checks the types a write payload carries.
fn check_body(request: Request, restriction: &CompiledTypeRestriction, context: &ResolvedContext, on_write: MemberOnWrite) -> Result<Request, TypeError> {
    let (parts, body) = request.into_parts();

    match (RequestBody::document_in(&parts)?, on_write) {
        (None, MemberOnWrite::Required) => return Err(TypeError::MissingType { at: Location::Payload }),
        (None, MemberOnWrite::Optional) => {}
        (Some(document), MemberOnWrite::Required | MemberOnWrite::Optional) => document::check_write_body(document, restriction, context, on_write)?,
    }

    Ok(Request::from_parts(parts, body))
}
