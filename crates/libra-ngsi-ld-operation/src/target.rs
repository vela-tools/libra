//! Where an operation names the entities it touches.
//!
//! An entity type or scope restriction is enforced wherever the request says which entities it is
//! about, and that place differs by operation: the path, the query string, a body of entities, a
//! body of identifiers, or a subscription's selectors. Every layer that judges entities by their
//! own members asks this one question and gets the same answer.

use crate::{
    operation::{Mode, Operation},
    resource::{BatchAction, Resource},
};

/// Where the entities of one operation are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityTarget {
    /// The path names one entity, whose type and scope only the broker knows.
    SingleEntity,
    /// A read of `/entities` or `/temporal/entities` (clauses 5.7.2 and 5.7.4): a filter in the
    /// query string on the way in, a list of entities on the way out.
    CollectionQuery,
    /// A write to `/entities` (clauses 5.6.1 and 5.6.21): the entity it creates is in the body, and
    /// a create never overwrites a stored entity.
    CollectionWrite,
    /// A write to `/temporal/entities` (clause 5.6.11): the entity is in the body, and the write
    /// adds to the stored temporal evolution of an entity of the same identifier if there is one.
    TemporalCollectionWrite,
    /// `/entityOperations/query` or `/temporal/entityOperations/query`: the filter is a `Query`
    /// body, and the answer is a list of entities.
    BatchQuery,
    /// `/entityOperations/delete` (clause 5.6.10): the body is a list of identifiers.
    BatchDelete,
    /// `/entityOperations/create` (clause 5.6.7): the body is entities, none of which may exist.
    BatchCreate,
    /// `/entityOperations/upsert`, `update` and `merge` (clauses 5.6.8, 5.6.9 and 5.6.20): the body
    /// is entities, each of which may already be stored and is then changed.
    BatchOverwrite,
    /// `POST /subscriptions` (clause 5.8.1): the selectors of the subscription it creates are in the
    /// body.
    SubscriptionCreate,
    /// Any other request on `/subscriptions` or `/subscriptions/{id}` (clauses 5.8.2 to 5.8.5):
    /// subscriptions that already exist, read, changed or deleted.
    ExistingSubscriptions,
    /// Nothing that names entities.
    Untouched,
}

impl EntityTarget {
    /// Where `operation` names its entities.
    ///
    /// Listed exhaustively: a resource added later has to be given an answer here, and the wrong
    /// default is the one where a new endpoint that names entities is judged as naming none.
    #[must_use]
    pub const fn of(operation: &Operation) -> Self {
        match (&operation.resource, operation.mode) {
            (
                Resource::Entity { .. }
                | Resource::EntityAttributes { .. }
                | Resource::EntityAttribute { .. }
                | Resource::TemporalEntity { .. }
                | Resource::TemporalEntityAttributes { .. }
                | Resource::TemporalEntityAttribute { .. }
                | Resource::TemporalEntityAttributeInstance { .. },
                Mode::Read | Mode::Write,
            ) => Self::SingleEntity,
            (Resource::Entities | Resource::TemporalEntities, Mode::Read) => Self::CollectionQuery,
            (Resource::Entities, Mode::Write) => Self::CollectionWrite,
            (Resource::TemporalEntities, Mode::Write) => Self::TemporalCollectionWrite,
            (Resource::EntityBatch { action }, Mode::Read | Mode::Write) => match action {
                BatchAction::Query => Self::BatchQuery,
                BatchAction::Delete => Self::BatchDelete,
                BatchAction::Create => Self::BatchCreate,
                BatchAction::Update | BatchAction::Upsert | BatchAction::Merge => Self::BatchOverwrite,
            },
            (Resource::TemporalBatchQuery, Mode::Read | Mode::Write) => Self::BatchQuery,
            (Resource::Subscriptions, Mode::Write) => Self::SubscriptionCreate,
            (Resource::Subscriptions, Mode::Read) | (Resource::Subscription { .. }, Mode::Read | Mode::Write) => Self::ExistingSubscriptions,
            (
                Resource::ContextSourceRegistrations
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
                | Resource::Unrecognised,
                Mode::Read | Mode::Write,
            ) => Self::Untouched,
        }
    }

    /// Whether the answer to this operation is a list of entities, each of which is judged on the
    /// way back.
    #[must_use]
    pub const fn answers_with_entities(self) -> bool {
        matches!(self, Self::CollectionQuery | Self::BatchQuery)
    }
}

#[cfg(test)]
mod tests {
    use crate::{operation::Operation, target::EntityTarget};
    use http::Method;
    use pretty_assertions::assert_eq;

    fn target(method: &Method, path: &str) -> EntityTarget {
        let operation = Operation::classify(method, path).unwrap().unwrap();

        EntityTarget::of(&operation)
    }

    #[test]
    fn a_by_id_request_names_a_single_entity() {
        for (method, path) in [
            (Method::GET, "/ngsi-ld/v1/entities/urn:e"),
            (Method::PATCH, "/ngsi-ld/v1/entities/urn:e/attrs"),
            (Method::DELETE, "/ngsi-ld/v1/entities/urn:e/attrs/speed"),
            (Method::GET, "/ngsi-ld/v1/temporal/entities/urn:e"),
            (Method::PATCH, "/ngsi-ld/v1/temporal/entities/urn:e/attrs/speed/urn:i"),
        ] {
            assert_eq!(target(&method, path), EntityTarget::SingleEntity, "{method} {path}");
        }
    }

    #[test]
    fn collection_reads_are_queries_and_collection_writes_are_told_apart_by_store() {
        assert_eq!(target(&Method::GET, "/ngsi-ld/v1/entities"), EntityTarget::CollectionQuery);
        assert_eq!(target(&Method::GET, "/ngsi-ld/v1/temporal/entities"), EntityTarget::CollectionQuery);
        assert_eq!(target(&Method::POST, "/ngsi-ld/v1/entities"), EntityTarget::CollectionWrite);
        assert_eq!(target(&Method::POST, "/ngsi-ld/v1/temporal/entities"), EntityTarget::TemporalCollectionWrite);
    }

    #[test]
    fn batch_operations_are_told_apart_by_whether_they_can_change_a_stored_entity() {
        assert_eq!(target(&Method::POST, "/ngsi-ld/v1/entityOperations/query"), EntityTarget::BatchQuery);
        assert_eq!(target(&Method::POST, "/ngsi-ld/v1/temporal/entityOperations/query"), EntityTarget::BatchQuery);
        assert_eq!(target(&Method::POST, "/ngsi-ld/v1/entityOperations/delete"), EntityTarget::BatchDelete);
        assert_eq!(target(&Method::POST, "/ngsi-ld/v1/entityOperations/create"), EntityTarget::BatchCreate);
        for action in ["update", "upsert", "merge"] {
            assert_eq!(
                target(&Method::POST, &format!("/ngsi-ld/v1/entityOperations/{action}")),
                EntityTarget::BatchOverwrite,
                "{action}"
            );
        }
    }

    #[test]
    fn only_creating_a_subscription_is_a_create() {
        assert_eq!(target(&Method::POST, "/ngsi-ld/v1/subscriptions"), EntityTarget::SubscriptionCreate);
        for (method, path) in [
            (Method::GET, "/ngsi-ld/v1/subscriptions"),
            (Method::GET, "/ngsi-ld/v1/subscriptions/urn:s"),
            (Method::PATCH, "/ngsi-ld/v1/subscriptions/urn:s"),
            (Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:s"),
        ] {
            assert_eq!(target(&method, path), EntityTarget::ExistingSubscriptions, "{method} {path}");
        }
    }

    #[test]
    fn only_lists_of_entities_are_judged_on_the_way_back() {
        assert!(EntityTarget::CollectionQuery.answers_with_entities());
        assert!(EntityTarget::BatchQuery.answers_with_entities());
        assert!(!EntityTarget::SingleEntity.answers_with_entities());
        assert!(!EntityTarget::BatchOverwrite.answers_with_entities());
    }

    #[test]
    fn registrations_maps_and_indexes_name_no_entities_here() {
        for path in [
            "/ngsi-ld/v1/csourceRegistrations",
            "/ngsi-ld/v1/csourceSubscriptions",
            "/ngsi-ld/v1/entityMaps",
            "/ngsi-ld/v1/types",
            "/ngsi-ld/v1/attributes",
        ] {
            assert_eq!(target(&Method::GET, path), EntityTarget::Untouched, "{path}");
        }
    }
}
