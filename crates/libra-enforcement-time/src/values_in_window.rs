//! Serving a current-state read under `current-state = "values-in-window"`.
//!
//! The request goes out nearly as written; what changes is the answer. Three things have to hold
//! for that answer to be judged, and a request that breaks one is refused rather than forwarded:
//!
//! * Every attribute instance carries its metadata. `keyValues` (NGSI-LD 4.5.4) replaces an
//!   attribute by its value, and a `GeoJSON` `geometry` (4.5.16) copies one attribute's value
//!   without it, so neither can be dated.
//! * The answer is entities. Only `/entities`, `/entities/{id}` and a batch query answer with them.
//! * Nothing selects entities by a value the answer will not show. A `q` or geospatial filter is
//!   evaluated against the current values whatever their age, so which entities come back would
//!   disclose a value outside the window.
//!
//! `options=sysAttrs` is added when the caller did not ask for it, so an instance without
//! `observedAt` can be dated by `modifiedAt`, and the system attributes are stripped from the answer
//! again. A join answer's linked entities are filtered the same way as the queried ones.

use crate::{
    current_state::{AddedSystemAttributes, TooDeep, filter_entity},
    error::TimeError,
    window::Window,
};
use axum::{
    body::Body,
    extract::Request,
    http::{header::ACCEPT_ENCODING, request::Parts},
    response::Response,
};
use jstrict::Value;
use libra_json_body::request_body::RequestBody;
use libra_linked_entity_layer::servable::{LinkedFilterJudgement, servable_join};
use libra_ngsi_ld_entity_document::{
    entities::for_each_entity,
    linked::{Visibility, judge_linked},
    unwalkable::Unwalkable,
};
use libra_ngsi_ld_operation::resource::{BatchAction, Resource};
use libra_ngsi_ld_query::{
    linked_entity::{Join, JoinMode},
    parameter_name::ParameterName,
    parameters::QueryParameters,
};
use libra_ngsi_ld_query_layer::parsed::replace_query;
use libra_ngsi_ld_representation::{
    accept::MediaType,
    representation::{Representation, SystemAttributes},
};
use libra_ngsi_ld_representation_layer::RequestRepresentation;
use libra_response_json::{error::RewriteError, rewrite::rewrite};
use tracing::debug;

/// The query parameters that select or rank entities by an attribute's value.
const VALUE_PARAMETERS: [ParameterName; 3] = [ParameterName::Q, ParameterName::GEOREL, ParameterName::ORDER_BY];

/// The members of a `Query` body (NGSI-LD 5.2.23) that select or rank entities by an attribute's
/// value. Clause 5.2.43 puts `orderBy` in `ordering`; a top-level `orderBy` is refused too, because a
/// broker that reads one there ranks by it.
const VALUE_MEMBERS: [&str; 4] = ["q", "geoQ", "ordering", "orderBy"];

/// How a current-state answer is to be filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValuesInWindow {
    window: Window,
    added: AddedSystemAttributes,
    join: Option<JoinMode>,
}

/// Checks a current-state read and prepares it for its answer to be filtered to `window`.
///
/// # Errors
///
/// Returns [`TimeError::CurrentStateUnjudgeable`] for a request whose answer cannot be dated,
/// [`TimeError::CurrentStateFilter`] for one that filters or orders on attribute values,
/// [`TimeError::LinkedEntity`] for a join that cannot be served, and the errors reading the query
/// string or a batch query body produce.
pub fn prepare(
    mut parts: Parts,
    body: Body,
    mut parameters: QueryParameters,
    resource: &Resource,
    window: Window,
) -> Result<(Request, ValuesInWindow), TimeError> {
    let batch_query = matches!(resource, Resource::EntityBatch { action: BatchAction::Query });
    if !(batch_query || matches!(resource, Resource::Entities | Resource::Entity { .. })) {
        return Err(TimeError::CurrentStateUnjudgeable {
            reason: "the answer to this resource is not an entity",
        });
    }

    let system_attributes = judgeable_representation(&parts)?;
    let join = servable_join(&parts.extensions, LinkedFilterJudgement::Refused)?.map(Join::mode);

    if VALUE_PARAMETERS.iter().any(|name| parameters.contains(name)) {
        return Err(TimeError::CurrentStateFilter);
    }

    let added = match system_attributes {
        SystemAttributes::Included => AddedSystemAttributes::Keep,
        SystemAttributes::Omitted => {
            let options = adding_system_attributes(parameters.get(&ParameterName::OPTIONS));
            parameters.set(ParameterName::OPTIONS, options);
            replace_query(&mut parts, parameters).map_err(|_| TimeError::Unrewritable)?;

            AddedSystemAttributes::Strip
        }
    };

    // A compressed body cannot be filtered.
    parts.headers.remove(ACCEPT_ENCODING);

    if batch_query {
        refuse_body_filters(&parts)?;
    }

    Ok((Request::from_parts(parts, body), ValuesInWindow { window, added, join }))
}

/// The system attributes the caller asked for, once the representation is known to keep attribute
/// metadata.
fn judgeable_representation(parts: &Parts) -> Result<SystemAttributes, TimeError> {
    let representation = match parts.extensions.get::<RequestRepresentation>() {
        None => return Err(TimeError::Unresolved),
        Some(RequestRepresentation::Unresolvable(_)) => {
            return Err(TimeError::CurrentStateUnjudgeable {
                reason: "the request names no representation whose attributes can be dated",
            });
        }
        Some(RequestRepresentation::Resolved(representation)) => representation,
    };

    match (representation.representation(), representation.media_type()) {
        (Representation::Simplified, _) => Err(TimeError::CurrentStateUnjudgeable {
            reason: "the keyValues representation carries no attribute metadata to date a value by",
        }),
        (Representation::Normalized | Representation::Concise, MediaType::GeoJson) => Err(TimeError::CurrentStateUnjudgeable {
            reason: "a GeoJSON geometry carries no attribute metadata to date a value by",
        }),
        (Representation::Normalized | Representation::Concise, MediaType::Json | MediaType::JsonLd) => Ok(representation.system_attributes()),
    }
}

/// Refuses a batch query body that filters or orders on attribute values.
///
/// The body is read from the parse the context layer above made of it, and is forwarded as it is.
/// A filter member named twice is refused as malformed rather than judged by one occurrence: the
/// broker may apply the other.
fn refuse_body_filters(parts: &Parts) -> Result<(), TimeError> {
    let query = match RequestBody::document_in(parts)? {
        None | Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_)) => return Ok(()),
        Some(Value::Object(query)) => query,
    };

    for member in VALUE_MEMBERS {
        let value = query.get_unique(member).map_err(|_| TimeError::MalformedBody {
            reason: "it names a filter member more than once",
        })?;

        if value.is_some_and(|value| !value.is_null()) {
            return Err(TimeError::CurrentStateFilter);
        }
    }

    Ok(())
}

/// Removes from a current-state answer every attribute instance outside the window.
///
/// # Errors
///
/// Returns [`TimeError::Unfilterable`] when the body cannot be read, is `GeoJSON`, nests too deeply,
/// or is a join answer whose linked entities cannot be walked.
pub async fn filter_response(response: Response, plan: ValuesInWindow, max_body_bytes: usize) -> Result<Response, TimeError> {
    rewrite(response, max_body_bytes, |document, media_type| filter_document(document, media_type, plan))
        .await
        .map_err(|error| TimeError::Unfilterable {
            reason: match error {
                RewriteError::Unreadable(unreadable) => unreadable.reason(),
                RewriteError::Edit(reason) => reason,
            },
        })
}

/// The `options` value that also asks for the system attributes, keeping every option the caller
/// named.
fn adding_system_attributes(options: Option<&str>) -> String {
    match options.map(str::trim).filter(|options| !options.is_empty()) {
        Some(options) => format!("{options},{}", SystemAttributes::TOKEN),
        None => SystemAttributes::TOKEN.to_owned(),
    }
}

/// Filters one answer document, or says why it cannot be.
fn filter_document(document: &mut Value, media_type: MediaType, plan: ValuesInWindow) -> Result<(), &'static str> {
    if media_type == MediaType::GeoJson {
        return Err("a GeoJSON geometry carries no attribute metadata to date a value by");
    }

    let mut removed = 0;
    let mut too_deep = None;

    let mut unwalkable = None;

    for_each_entity(document, media_type, |mut entity| match entity.members() {
        Ok(Some(members)) => match filter_entity(members, plan.window, plan.added) {
            Ok(count) => removed += count,
            Err(error) => too_deep = Some(error),
        },
        Ok(None) => {}
        Err(error) => unwalkable = Some(error),
    })
    .map_err(Unwalkable::reason)?;

    if let Some(error) = unwalkable {
        return Err(error.reason());
    }

    if let Some(mode) = plan.join {
        judge_linked(document, media_type, mode, |mut entity| {
            match entity
                .members()
                .map(|members| members.map(|members| filter_entity(members, plan.window, plan.added)))
            {
                Ok(Some(Ok(count))) => {
                    removed += count;
                    Visibility::Show
                }
                // An entity that cannot be walked cannot be shown to hold only what the window allows.
                Ok(Some(Err(TooDeep)) | None) | Err(_) => Visibility::Withhold,
            }
        })
        .map_err(Unwalkable::reason)?;
    }

    if let Some(error) = too_deep {
        debug!(%error, "a current-state answer could not be filtered");
        return Err("the answer nests deeper than it can be walked");
    }

    debug!(removed, "removed the attribute instances outside the allowed window");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use libra_json_body::error::DocumentError;
    use libra_log_capture::captured;
    use pretty_assertions::assert_eq;

    fn plan(join: Option<JoinMode>) -> ValuesInWindow {
        ValuesInWindow {
            window: Window::new("2026-05-31T12:00:00Z".parse().unwrap(), "2026-06-01T12:00:00Z".parse().unwrap()),
            added: AddedSystemAttributes::Strip,
            join,
        }
    }

    #[test]
    fn a_join_answer_has_its_linked_entities_filtered_too() {
        let mut document = json!([{ "id": "urn:v:1", "type": "Vehicle",
            "isParked": { "type": "Relationship", "object": "urn:p:1", "observedAt": "2026-06-01T10:00:00Z",
                "entity": { "id": "urn:p:1", "type": "Parking",
                    "name": { "type": "Property", "value": "Old", "modifiedAt": "2020-01-01T00:00:00Z" },
                    "free": { "type": "Property", "value": 3, "observedAt": "2026-06-01T11:00:00Z", "modifiedAt": "2026-06-01T11:00:00Z" } } } }]);

        assert_eq!(filter_document(&mut document, MediaType::Json, plan(Some(JoinMode::Inline))), Ok(()));
        assert_eq!(
            document,
            json!([{ "id": "urn:v:1", "type": "Vehicle",
                "isParked": { "type": "Relationship", "object": "urn:p:1", "observedAt": "2026-06-01T10:00:00Z",
                    "entity": { "id": "urn:p:1", "type": "Parking",
                        "free": { "type": "Property", "value": 3, "observedAt": "2026-06-01T11:00:00Z" } } } }])
        );
    }

    #[test]
    fn a_geojson_answer_is_not_filtered() {
        let mut document = json!({ "type": "FeatureCollection", "features": [] });

        assert!(filter_document(&mut document, MediaType::GeoJson, plan(None)).is_err());
    }

    fn parts(body: Option<RequestBody>) -> Parts {
        let (mut parts, _body) = Request::new(Body::empty()).into_parts();
        if let Some(body) = body {
            parts.extensions.insert(body);
        }
        parts
    }

    #[test]
    fn a_batch_query_body_that_filters_or_orders_on_values_is_refused() {
        let filtering = parts(Some(RequestBody::Json(json!({ "type": "Query", "q": "speed>40" }))));
        let plain = parts(Some(RequestBody::Json(
            json!({ "type": "Query", "q": null, "entities": [{ "type": "Vehicle" }] }),
        )));

        let ordering = parts(Some(RequestBody::Json(json!({ "type": "Query", "ordering": { "orderBy": "speed" } }))));
        let top_level_order = parts(Some(RequestBody::Json(json!({ "type": "Query", "orderBy": "speed" }))));

        assert_eq!(refuse_body_filters(&filtering), Err(TimeError::CurrentStateFilter));
        assert_eq!(refuse_body_filters(&ordering), Err(TimeError::CurrentStateFilter));
        assert_eq!(refuse_body_filters(&top_level_order), Err(TimeError::CurrentStateFilter));
        assert_eq!(refuse_body_filters(&plain), Ok(()));
        assert_eq!(refuse_body_filters(&parts(Some(RequestBody::Empty))), Ok(()));
    }

    #[test]
    fn a_batch_query_body_that_repeats_a_filter_member_is_refused_as_malformed() {
        // One `geoQ` is null and the other is not; which the broker applies is not Libra's to guess.
        let repeated = parts(Some(RequestBody::Json(json!({ "type": "Query", "geoQ": null, "geoQ": { "georel": "near" } }))));

        assert_eq!(
            refuse_body_filters(&repeated),
            Err(TimeError::MalformedBody {
                reason: "it names a filter member more than once"
            })
        );
    }

    #[test]
    fn a_batch_query_body_that_is_not_json_or_was_not_read_is_refused() {
        assert_eq!(
            refuse_body_filters(&parts(Some(RequestBody::NotJson))),
            Err(TimeError::Body(DocumentError::NotJson))
        );
        assert_eq!(refuse_body_filters(&parts(None)), Err(TimeError::Body(DocumentError::Unread)));
    }

    #[test]
    fn the_system_attributes_are_asked_for_beside_every_option_the_caller_named() {
        assert_eq!(adding_system_attributes(Some("concise")), "concise,sysAttrs");
        assert_eq!(adding_system_attributes(Some(" ")), "sysAttrs");
        assert_eq!(adding_system_attributes(None), "sysAttrs");
    }

    #[tokio::test]
    async fn the_debug_log_counts_the_instances_removed_from_queried_and_linked_entities() {
        let mut document = json!([{ "id": "urn:v:1", "type": "Vehicle",
            "colour": { "type": "Property", "value": "red", "observedAt": "2020-01-01T00:00:00Z" },
            "isParked": { "type": "Relationship", "object": "urn:p:1", "observedAt": "2026-06-01T10:00:00Z",
                "entity": { "id": "urn:p:1", "type": "Parking",
                    "name": { "type": "Property", "value": "Old", "modifiedAt": "2020-01-01T00:00:00Z" } } } }]);

        let (filtered, records) = captured(async { filter_document(&mut document, MediaType::Json, plan(Some(JoinMode::Inline))) }).await;

        assert_eq!(filtered, Ok(()));
        // One instance outside the window on the queried entity, one on the linked one.
        let removed = records
            .iter()
            .find(|record| record.message() == "removed the attribute instances outside the allowed window")
            .and_then(|record| record.field("removed"));
        assert_eq!(removed, Some("2"));
    }
}
