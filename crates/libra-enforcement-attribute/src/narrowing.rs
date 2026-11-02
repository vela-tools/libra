//! Narrowing an outgoing request to what an attribute restriction allows, and deciding what is
//! done with its answer.
//!
//! The request is narrowed before it reaches the broker so it does not ask for what the caller may
//! not see; the plan returned with it says how the answer is filtered, because `attrs` is a hint a
//! broker may ignore and "everything except these" cannot be written as a selector at all.

use crate::{
    error::FilterError,
    filters::check_filters,
    query_body::narrow_query_body,
    registration,
    request::{check_path_attribute, check_write, narrow_selectors},
    route::refuse_route,
    subscription,
};
use axum::{
    body::Body,
    extract::Request,
    http::{header::ACCEPT_ENCODING, request::Parts},
};
use libra_json_body::request_body::RequestBody;
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_linked_entity_layer::servable::{LinkedFilterJudgement, servable_join};
use libra_ngsi_ld_operation::{operation::Mode, resource::Resource, target::EntityTarget};
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_query::linked_entity::{Join, JoinMode};
use libra_ngsi_ld_query_layer::parsed::{parameters, replace_query};
use libra_policy_model::attribute::CompiledAttributeRestriction;

/// What is done with the response once the narrowed request has been forwarded.
pub(crate) enum ResponsePlan {
    /// Leave the response untouched. A write answers with identifiers rather than attribute values.
    Passthrough,
    /// Filter the response attribute by attribute, as the document says.
    Document(DocumentPlan),
    /// Filter the response as context source registrations (NGSI-LD 5.2.9), whose structure is not
    /// attributes and whose registered attribute names are. Carries the resource the request
    /// addressed, which says whether a withheld answer was a retrieval.
    Registration(Resource),
}

/// How an answer whose members are attributes is filtered.
pub(crate) enum DocumentPlan {
    /// Filter the response as an entity document.
    Entity {
        /// The join the answer holds linked entities for, which are filtered as entities too.
        join: Option<JoinMode>,
    },
    /// Filter the response as a type/attribute metadata index (NGSI-LD 5.2.24 to 5.2.28).
    MetadataIndex,
}

/// Checks and narrows the outgoing request.
pub(crate) fn narrow(request: Request, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(Request, ResponsePlan), FilterError> {
    let (mut parts, body) = request.into_parts();

    // Cloned because the operation travels in the parts that are narrowed and moved while it is
    // still read.
    let operation = operation(&parts.extensions)?.clone();
    let mode = operation.mode;

    refuse_route(&parts.method, &operation, parameters(&parts.extensions)?, restriction.action())?;

    if operation.resource.is_context_source_registration() {
        // A registration is not an entity: only the attribute names it registers are this
        // restriction's business.
        let request = registration::check_request(Request::from_parts(parts, body), mode, restriction, context)?;
        let plan = match mode {
            Mode::Read => ResponsePlan::Registration(operation.resource),
            Mode::Write => ResponsePlan::Passthrough,
        };

        return Ok((request, plan));
    }

    if EntityTarget::of(&operation) == EntityTarget::SubscriptionCreate {
        // Creating a subscription carries its attribute selectors in the body, not in `attrs`/`q`,
        // and the data it discloses arrives out of band. It is narrowed as a whole rather than run
        // through the entity-query narrowing below. Anything a notification asks for in Linked
        // Entity Retrieval reaches the endpoint without passing back through Libra, so it is
        // refused rather than narrowed.
        servable_join(&parts.extensions, LinkedFilterJudgement::CheckedByCaller)?;

        return narrow_subscription(parts, body, restriction, context);
    }

    if matches!(mode, Mode::Read) && operation.resource.is_metadata_index() {
        // A metadata index (NGSI-LD 5.7.5 to 5.7.10) carries no `attrs`, `q` or `geoQ`; the only
        // request-side check is the path attribute of `/attributes/{attr}`, refused here. The
        // disclosure it can carry is in the response, which is filtered as an index rather than as
        // an entity. `Accept-Encoding` is dropped for the same reason it is for an entity read: a
        // compressed body cannot be filtered.
        check_path_attribute(operation.resource.attribute(), restriction, context)?;
        parts.headers.remove(ACCEPT_ENCODING);

        return Ok((Request::from_parts(parts, body), ResponsePlan::Document(DocumentPlan::MetadataIndex)));
    }

    narrow_entity_request(parts, body, operation.resource.attribute(), mode, restriction, context)
}

/// Narrows a request about entities: the attribute its path names, what it filters and ranks by,
/// what it projects, and the query or the entities its body carries.
fn narrow_entity_request(
    mut parts: Parts,
    body: Body,
    path_attribute: Option<&Term>,
    mode: Mode,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
) -> Result<(Request, ResponsePlan), FilterError> {
    check_path_attribute(path_attribute, restriction, context)?;

    // Cloned because the narrowed copy is written back over the stored one.
    let mut parameters = parameters(&parts.extensions)?.clone();

    // Linked Entity Retrieval (NGSI-LD 4.5.23) answers with entities the request narrowing never
    // reached. They are filtered as entities on the way back; a linked projection term whose
    // Relationship is allowed is kept by the narrowing below, and the names inside it are
    // filtered in the answer.
    let join = match mode {
        Mode::Read => servable_join(&parts.extensions, LinkedFilterJudgement::CheckedByCaller)?.map(Join::mode),
        Mode::Write => None,
    };

    check_filters(&parameters, restriction, context)?;
    narrow_selectors(&mut parameters, restriction, context)?;
    replace_query(&mut parts, parameters).map_err(|_| FilterError::Unfilterable {
        reason: "the narrowed request could not be rebuilt",
    })?;

    // Asked for before the request goes upstream, because a compressed response cannot be
    // filtered, and returning it unfiltered, or giving up on it silently, would leak what the
    // restriction hides.
    parts.headers.remove(ACCEPT_ENCODING);

    // A read can carry a body too. `POST /entityOperations/query` is the specification's own way of
    // sending a query too long for a URL, and it carries the same selectors that are checked above
    // in the query string, so a filter refused as `?q=location!=null` would otherwise be forwarded
    // verbatim as `{"q": "location!=null"}`.
    match mode {
        Mode::Read => {
            let body = narrow_read_body(&mut parts, body, restriction, context)?;

            Ok((Request::from_parts(parts, body), ResponsePlan::Document(DocumentPlan::Entity { join })))
        }
        Mode::Write => {
            match RequestBody::document_in(&parts)? {
                // A path that names a single attribute (`/entities/{id}/attrs/{attr}`) carries that
                // attribute's own value representation in the body (`value`, `unitCode`, `object`,
                // sub-attributes), not a set of attribute names. The attribute itself was already
                // checked from the path above; walking the value members as if they were attribute
                // names would refuse a legitimate update of an allowed attribute under a pick policy.
                Some(_) if path_attribute.is_some() => {}
                Some(document) => check_write(document, restriction, context)?,
                None => {}
            }

            // A write's response carries the identifiers it touched, not attribute values.
            Ok((Request::from_parts(parts, body), ResponsePlan::Passthrough))
        }
    }
}

/// Narrows the query a read carries in its body, and returns the body to forward.
///
/// A read with no body is forwarded with the body it has.
fn narrow_read_body(parts: &mut Parts, body: Body, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<Body, FilterError> {
    let Some(mut document) = RequestBody::take_document(parts)? else {
        return Ok(body);
    };

    narrow_query_body(&mut document, restriction, context)?;

    Ok(RequestBody::replace(parts, document))
}

/// Narrows a subscription create and puts it back on the request.
///
/// The body is rewritten so the notification can only disclose allowed attributes, and
/// [`RequestBody::replace`] restates `Content-Length` with it. The response is not filtered (a
/// subscription create answers with a location, not entity data), so this returns
/// [`ResponsePlan::Passthrough`].
fn narrow_subscription(
    mut parts: Parts,
    body: Body,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
) -> Result<(Request, ResponsePlan), FilterError> {
    let Some(mut document) = RequestBody::take_document(&mut parts)? else {
        // A subscription with no body is invalid; the broker will refuse it. There is nothing to
        // narrow.
        return Ok((Request::from_parts(parts, body), ResponsePlan::Passthrough));
    };

    subscription::enforce(&mut document, restriction, context)?;
    let body = RequestBody::replace(&mut parts, document);

    Ok((Request::from_parts(parts, body), ResponsePlan::Passthrough))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{context, omitting};
    use axum::http::Method;
    use libra_ngsi_ld_operation_layer::layer::classify;
    use libra_ngsi_ld_query::{linked_entity::LinkedEntityRequest, parameters::QueryParameters};
    use libra_ngsi_ld_query_layer::layer::read_query;

    fn narrowed(method: Method, uri: &str, body: &'static str) -> Result<(Request, ResponsePlan), FilterError> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(ACCEPT_ENCODING, "gzip")
            .body(Body::from(body))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request
            .extensions_mut()
            .insert(RequestBody::read(body.as_bytes()).expect("the test body is readable"));
        let (mut parts, body) = request.into_parts();
        classify(&mut parts).unwrap();
        read_query(&mut parts).unwrap();

        narrow(Request::from_parts(parts, body), &omitting(&["location"]), &context())
    }

    #[test]
    fn a_metadata_index_read_is_filtered_as_an_index_and_asked_for_uncompressed() {
        let (request, plan) = narrowed(Method::GET, "/ngsi-ld/v1/attributes", "").unwrap();

        assert!(matches!(plan, ResponsePlan::Document(DocumentPlan::MetadataIndex)));
        assert!(request.headers().get(ACCEPT_ENCODING).is_none());
    }

    #[test]
    fn a_write_is_judged_by_its_attributes_and_its_answer_passed_through() {
        assert!(matches!(
            narrowed(Method::POST, "/ngsi-ld/v1/entities", r#"{"id":"urn:e:1","type":"Vehicle","speed":1}"#),
            Ok((_, ResponsePlan::Passthrough))
        ));
        assert!(matches!(
            narrowed(Method::POST, "/ngsi-ld/v1/entities", r#"{"id":"urn:e:1","type":"Vehicle","location":1}"#),
            Err(FilterError::AttributeDenied { .. })
        ));
    }

    #[test]
    fn a_refused_route_is_refused_before_anything_is_narrowed() {
        assert!(matches!(
            narrowed(Method::DELETE, "/ngsi-ld/v1/entities/urn:e:1", ""),
            Err(FilterError::WholeEntityRefused)
        ));
    }

    #[test]
    fn the_selectors_are_read_from_the_stored_query_not_from_the_request_target() {
        let (mut parts, body) = Request::builder()
            .uri("/ngsi-ld/v1/entities?attrs=speed")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        parts.extensions.insert(RequestBody::Empty);
        classify(&mut parts).unwrap();
        parts.extensions.insert(QueryParameters::parse("attrs=location").unwrap());
        parts.extensions.insert(LinkedEntityRequest::NOTHING);

        let narrowed = narrow(Request::from_parts(parts, body), &omitting(&["location"]), &context());

        assert_eq!(narrowed.err(), Some(FilterError::NothingAllowed));
    }
}
