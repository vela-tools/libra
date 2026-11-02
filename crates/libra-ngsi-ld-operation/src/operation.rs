//! Turning a method and a path into the one description everything else reads.

use crate::{
    error::OperationError,
    path::{PathSegment, Segments},
    resource::{BatchAction, Resource, ResourceId},
};
use http::Method;
use libra_jsonld_term_expansion::name::Term;

/// Whether a request observes state or changes it.
///
/// The coarse distinction policies are written in. It is derived from the method *and* the
/// resource, because NGSI-LD has reads that arrive as `POST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The request only observes.
    Read,
    /// The request may change state.
    Write,
}

/// A classified NGSI-LD request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// What the request addresses.
    pub resource: Resource,
    /// Whether it reads or writes.
    pub mode: Mode,
}

impl Operation {
    /// Classifies a request by method and path.
    ///
    /// Returns `Ok(None)` when the path is not under the NGSI-LD API root: a health probe, the
    /// management API, anything the router handles itself.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] when the method has no NGSI-LD meaning, or when the path could
    /// be segmented differently by another hop. See [`crate::path`] for why those are refusals
    /// rather than best-effort readings.
    pub fn classify(method: &Method, path: &str) -> Result<Option<Self>, OperationError> {
        let Some(segments) = Segments::parse(path)? else {
            return Ok(None);
        };

        let resource = classify_resource(&segments);
        let mode = classify_mode(method, &resource)?;

        Ok(Some(Self { resource, mode }))
    }

    /// Whether this request only observes state.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        matches!(self.mode, Mode::Read)
    }
}

/// Derives the mode from the method, given what the request addresses.
fn classify_mode(method: &Method, resource: &Resource) -> Result<Mode, OperationError> {
    // Refused rather than classified. `TRACE` echoes the request back with its headers, and by the
    // time a request reaches the broker Libra has added identity headers of its own; a reflected
    // response hands those to whoever asked. `CONNECT` asks the proxy to open a tunnel, which
    // would carry traffic past every layer below this one.
    if method == Method::TRACE || method == Method::CONNECT {
        // Cloned because the error owns its method and the caller keeps the request's.
        return Err(OperationError::MethodNotAllowed { method: method.clone() });
    }

    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return Ok(Mode::Read);
    }

    if method == Method::POST {
        // The two operations that are reads wearing a write's method. Their filter does not fit in
        // a URL, which is the only reason they are not `GET`.
        let reads = match resource {
            Resource::EntityBatch { action } => action.is_read(),
            Resource::TemporalBatchQuery => true,
            // Everything else that arrives as a POST changes state. Listed rather than defaulted:
            // a read-shaped endpoint added later must be named here, or a policy restricting
            // writes will catch it and one restricting reads will not.
            Resource::Entities
            | Resource::Entity { .. }
            | Resource::EntityAttributes { .. }
            | Resource::EntityAttribute { .. }
            | Resource::TemporalEntities
            | Resource::TemporalEntity { .. }
            | Resource::TemporalEntityAttributes { .. }
            | Resource::TemporalEntityAttribute { .. }
            | Resource::TemporalEntityAttributeInstance { .. }
            | Resource::Subscriptions
            | Resource::Subscription { .. }
            | Resource::ContextSourceRegistrations
            | Resource::ContextSourceRegistration { .. }
            | Resource::ContextSourceSubscriptions
            | Resource::ContextSourceSubscription { .. }
            | Resource::EntityTypes
            | Resource::EntityType { .. }
            | Resource::Attributes
            | Resource::Attribute { .. }
            | Resource::EntityMaps
            | Resource::EntityMap { .. }
            | Resource::JsonLdContexts
            | Resource::JsonLdContext { .. }
            | Resource::TemporalEntityMaps
            | Resource::Snapshots
            | Resource::Snapshot { .. }
            | Resource::SnapshotClone { .. }
            | Resource::SourceIdentity
            | Resource::Unrecognised => false,
        };
        return Ok(if reads { Mode::Read } else { Mode::Write });
    }

    if method == Method::PUT || method == Method::PATCH || method == Method::DELETE {
        return Ok(Mode::Write);
    }

    // Cloned for the same reason as above.
    Err(OperationError::MethodNotAllowed { method: method.clone() })
}

/// Names the resource a path addresses.
fn classify_resource(segments: &Segments) -> Resource {
    match segments.as_slice() {
        [] => Resource::Unrecognised,
        [head, tail @ ..] => match head.as_str() {
            "entities" => classify_entities(tail),
            "entityOperations" => classify_entity_operations(tail),
            "temporal" => classify_temporal(tail),
            "subscriptions" => match tail {
                [] => Resource::Subscriptions,
                [id] => Resource::Subscription {
                    id: ResourceId::new(id.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "csourceRegistrations" => match tail {
                [] => Resource::ContextSourceRegistrations,
                [id] => Resource::ContextSourceRegistration {
                    id: ResourceId::new(id.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "csourceSubscriptions" => match tail {
                [] => Resource::ContextSourceSubscriptions,
                [id] => Resource::ContextSourceSubscription {
                    id: ResourceId::new(id.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "types" => match tail {
                [] => Resource::EntityTypes,
                [entity_type] => Resource::EntityType {
                    entity_type: Term::new(entity_type.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "attributes" => match tail {
                [] => Resource::Attributes,
                [attribute] => Resource::Attribute {
                    attribute: Term::new(attribute.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "entityMaps" => match tail {
                [] => Resource::EntityMaps,
                [id] => Resource::EntityMap {
                    id: ResourceId::new(id.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "jsonldContexts" => match tail {
                [] => Resource::JsonLdContexts,
                [id] => Resource::JsonLdContext {
                    id: ResourceId::new(id.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "snapshots" => match tail {
                [] => Resource::Snapshots,
                [id] => Resource::Snapshot {
                    id: ResourceId::new(id.as_str()),
                },
                [id, clone] if clone.as_str() == "clone" => Resource::SnapshotClone {
                    id: ResourceId::new(id.as_str()),
                },
                _ => Resource::Unrecognised,
            },
            "info" => match tail {
                [identity] if identity.as_str() == "sourceIdentity" => Resource::SourceIdentity,
                _ => Resource::Unrecognised,
            },
            _ => Resource::Unrecognised,
        },
    }
}

/// `/entities/...`
fn classify_entities(tail: &[PathSegment]) -> Resource {
    match tail {
        [] => Resource::Entities,
        [id] => Resource::Entity {
            id: ResourceId::new(id.as_str()),
        },
        [id, attrs] if attrs.as_str() == "attrs" => Resource::EntityAttributes {
            id: ResourceId::new(id.as_str()),
        },
        [id, attrs, attribute] if attrs.as_str() == "attrs" => Resource::EntityAttribute {
            id: ResourceId::new(id.as_str()),
            attribute: Term::new(attribute.as_str()),
        },
        _ => Resource::Unrecognised,
    }
}

/// `/entityOperations/...`
fn classify_entity_operations(tail: &[PathSegment]) -> Resource {
    let [action] = tail else {
        return Resource::Unrecognised;
    };

    let action = match action.as_str() {
        "create" => BatchAction::Create,
        "update" => BatchAction::Update,
        "upsert" => BatchAction::Upsert,
        "delete" => BatchAction::Delete,
        "merge" => BatchAction::Merge,
        "query" => BatchAction::Query,
        _ => return Resource::Unrecognised,
    };

    Resource::EntityBatch { action }
}

/// `/temporal/...`
fn classify_temporal(tail: &[PathSegment]) -> Resource {
    match tail {
        [head, rest @ ..] if head.as_str() == "entities" => match rest {
            [] => Resource::TemporalEntities,
            [id] => Resource::TemporalEntity {
                id: ResourceId::new(id.as_str()),
            },
            [id, attrs] if attrs.as_str() == "attrs" => Resource::TemporalEntityAttributes {
                id: ResourceId::new(id.as_str()),
            },
            [id, attrs, attribute] if attrs.as_str() == "attrs" => Resource::TemporalEntityAttribute {
                id: ResourceId::new(id.as_str()),
                attribute: Term::new(attribute.as_str()),
            },
            [id, attrs, attribute, instance] if attrs.as_str() == "attrs" => Resource::TemporalEntityAttributeInstance {
                id: ResourceId::new(id.as_str()),
                attribute: Term::new(attribute.as_str()),
                instance: ResourceId::new(instance.as_str()),
            },
            _ => Resource::Unrecognised,
        },
        [head, rest @ ..] if head.as_str() == "entityOperations" => match rest {
            [action] if action.as_str() == "query" => Resource::TemporalBatchQuery,
            _ => Resource::Unrecognised,
        },
        [head] if head.as_str() == "entityMaps" => Resource::TemporalEntityMaps,
        _ => Resource::Unrecognised,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn classify(method: &Method, path: &str) -> Operation {
        Operation::classify(method, path)
            .expect("the request should classify")
            .expect("the path should be under the API root")
    }

    #[test]
    fn an_entity_collection_read_is_named() {
        assert_eq!(
            classify(&Method::GET, "/ngsi-ld/v1/entities?type=Vehicle"),
            Operation {
                resource: Resource::Entities,
                mode: Mode::Read,
            },
            "the query string is not part of the path and must not change the resource"
        );
    }

    #[test]
    fn an_entity_attribute_carries_both_names() {
        let operation = classify(&Method::PATCH, "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed");

        assert_eq!(operation.mode, Mode::Write);
        assert_eq!(
            operation.resource,
            Resource::EntityAttribute {
                id: ResourceId::new("urn:ngsi-ld:Vehicle:1"),
                attribute: Term::new("speed"),
            }
        );
    }

    #[test]
    fn a_batch_query_is_a_read_despite_being_a_post() {
        // The single most consequential classification in this file: a policy that restricts
        // writes must not catch `entityOperations/query`, and one that restricts reads must.
        let operation = classify(&Method::POST, "/ngsi-ld/v1/entityOperations/query");

        assert_eq!(operation.mode, Mode::Read);
        assert_eq!(operation.resource, Resource::EntityBatch { action: BatchAction::Query });
    }

    #[test]
    fn the_other_batch_operations_are_writes() {
        for action in ["create", "update", "upsert", "delete", "merge"] {
            let path = format!("/ngsi-ld/v1/entityOperations/{action}");

            assert_eq!(classify(&Method::POST, &path).mode, Mode::Write, "{action} changes state");
        }
    }

    #[test]
    fn a_temporal_batch_query_is_also_a_read() {
        assert_eq!(
            classify(&Method::POST, "/ngsi-ld/v1/temporal/entityOperations/query"),
            Operation {
                resource: Resource::TemporalBatchQuery,
                mode: Mode::Read,
            }
        );
    }

    #[test]
    fn temporal_resources_are_recognised_as_temporal() {
        assert!(
            classify(&Method::GET, "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1")
                .resource
                .is_temporal()
        );
        assert!(!classify(&Method::GET, "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1").resource.is_temporal());
    }

    #[test]
    fn registrations_and_context_source_subscriptions_are_told_apart() {
        for path in ["/ngsi-ld/v1/csourceRegistrations", "/ngsi-ld/v1/csourceRegistrations/urn:r:1"] {
            let resource = classify(&Method::GET, path).resource;
            assert!(resource.is_context_source_registration(), "{path}");
            assert!(!resource.is_context_source_subscription(), "{path}");
        }

        for path in ["/ngsi-ld/v1/csourceSubscriptions", "/ngsi-ld/v1/csourceSubscriptions/urn:s:1"] {
            let resource = classify(&Method::GET, path).resource;
            assert!(resource.is_context_source_subscription(), "{path}");
            assert!(!resource.is_context_source_registration(), "{path}");
        }
    }

    #[test]
    fn a_temporal_attribute_instance_keeps_all_three_names() {
        assert_eq!(
            classify(&Method::DELETE, "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1/attrs/speed/instance-7").resource,
            Resource::TemporalEntityAttributeInstance {
                id: ResourceId::new("urn:ngsi-ld:Vehicle:1"),
                attribute: Term::new("speed"),
                instance: ResourceId::new("instance-7"),
            }
        );
    }

    #[test]
    fn trace_and_connect_are_refused() {
        // `TRACE` would reflect the identity headers this proxy adds; `CONNECT` would tunnel past
        // every layer below.
        for method in [Method::TRACE, Method::CONNECT] {
            let refused = Operation::classify(&method, "/ngsi-ld/v1/entities");

            assert!(
                matches!(refused, Err(OperationError::MethodNotAllowed { .. })),
                "{method} must be refused, got {refused:?}"
            );
        }
    }

    #[test]
    fn an_unknown_path_under_the_root_is_named_unrecognised_not_guessed() {
        assert_eq!(classify(&Method::GET, "/ngsi-ld/v1/somethingNew").resource, Resource::Unrecognised);
        assert_eq!(
            classify(&Method::GET, "/ngsi-ld/v1/entities/one/two/three/four").resource,
            Resource::Unrecognised
        );
    }

    #[test]
    fn a_type_name_arrives_as_a_term_not_a_resource_id() {
        // `/types/{type}` names a type, and a type is a term: `Vehicle` here means whatever the
        // request context says it means, exactly as it would in a `?type=` filter.
        assert_eq!(
            classify(&Method::GET, "/ngsi-ld/v1/types/Vehicle").resource,
            Resource::EntityType {
                entity_type: Term::new("Vehicle")
            }
        );
    }

    #[test]
    fn the_source_identity_is_a_read_of_info() {
        assert_eq!(
            classify(&Method::GET, "/ngsi-ld/v1/info/sourceIdentity"),
            Operation {
                resource: Resource::SourceIdentity,
                mode: Mode::Read,
            }
        );
    }

    #[test]
    fn another_info_path_is_unrecognised() {
        assert_eq!(classify(&Method::GET, "/ngsi-ld/v1/info/other").resource, Resource::Unrecognised);
    }

    #[test]
    fn snapshots_are_named_by_collection_by_id_and_by_clone() {
        assert_eq!(classify(&Method::POST, "/ngsi-ld/v1/snapshots").resource, Resource::Snapshots);
        assert_eq!(classify(&Method::DELETE, "/ngsi-ld/v1/snapshots").mode, Mode::Write);
        assert_eq!(
            classify(&Method::GET, "/ngsi-ld/v1/snapshots/urn:s:1"),
            Operation {
                resource: Resource::Snapshot {
                    id: ResourceId::new("urn:s:1")
                },
                mode: Mode::Read,
            }
        );
        assert_eq!(classify(&Method::PATCH, "/ngsi-ld/v1/snapshots/urn:s:1").mode, Mode::Write);
        assert_eq!(classify(&Method::DELETE, "/ngsi-ld/v1/snapshots/urn:s:1").mode, Mode::Write);
        assert_eq!(
            classify(&Method::POST, "/ngsi-ld/v1/snapshots/urn:s:1/clone"),
            Operation {
                resource: Resource::SnapshotClone {
                    id: ResourceId::new("urn:s:1")
                },
                mode: Mode::Write,
            }
        );
    }

    #[test]
    fn temporal_entity_maps_are_entity_maps() {
        let operation = classify(&Method::GET, "/ngsi-ld/v1/temporal/entityMaps");

        assert_eq!(operation.resource, Resource::TemporalEntityMaps);
        assert!(operation.resource.is_entity_map());
        assert_eq!(classify(&Method::POST, "/ngsi-ld/v1/temporal/entityMaps").mode, Mode::Write);
    }
}
