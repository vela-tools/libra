//! What a request is addressing, named rather than pattern-matched.
//!
//! The alternative (asking `path.starts_with("/ngsi-ld/v1/entities")` at each layer that cares)
//! spreads the same parsing across a dozen files and lets them drift. Every layer that needs to
//! know what a request touches reads this enum, so there is one answer per request.

use derive_more::Display;
use libra_jsonld_term_expansion::name::Term;

/// The identifier of an addressed resource, as it appeared in the path.
///
/// Not validated against the specification's URI requirement. The broker decides what a legal
/// identifier is; Libra's job is to carry it faithfully so a policy and a cache key are written
/// about the same string the broker sees.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display)]
#[display("{_0}")]
pub struct ResourceId(String);

impl ResourceId {
    /// Records an identifier taken from a request path.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as it appeared.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The batch operations defined on `/entityOperations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchAction {
    /// `POST /entityOperations/create`.
    Create,
    /// `POST /entityOperations/update`.
    Update,
    /// `POST /entityOperations/upsert`.
    Upsert,
    /// `POST /entityOperations/delete`.
    Delete,
    /// `POST /entityOperations/merge`.
    Merge,
    /// `POST /entityOperations/query`: a read, despite the method.
    Query,
}

impl BatchAction {
    /// Whether this batch operation only reads.
    ///
    /// `query` is a `POST` because its filter does not fit in a URL, not because it changes
    /// anything. A policy that restricts writes must not catch it, and a cache may serve it.
    #[must_use]
    pub const fn is_read(self) -> bool {
        matches!(self, Self::Query)
    }
}

/// The resource a request addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    /// `/entities`: the entity collection.
    Entities,
    /// `/entities/{id}`.
    Entity {
        /// The addressed entity.
        id: ResourceId,
    },
    /// `/entities/{id}/attrs`.
    EntityAttributes {
        /// The addressed entity.
        id: ResourceId,
    },
    /// `/entities/{id}/attrs/{attr}`.
    EntityAttribute {
        /// The addressed entity.
        id: ResourceId,
        /// The attribute name, as authored. Still a term: it needs the request context to mean
        /// anything.
        attribute: Term,
    },
    /// `/entityOperations/{action}`.
    EntityBatch {
        /// Which batch operation.
        action: BatchAction,
    },
    /// `/temporal/entities`.
    TemporalEntities,
    /// `/temporal/entities/{id}`.
    TemporalEntity {
        /// The addressed entity.
        id: ResourceId,
    },
    /// `/temporal/entities/{id}/attrs`.
    TemporalEntityAttributes {
        /// The addressed entity.
        id: ResourceId,
    },
    /// `/temporal/entities/{id}/attrs/{attr}`.
    TemporalEntityAttribute {
        /// The addressed entity.
        id: ResourceId,
        /// The attribute name, as authored.
        attribute: Term,
    },
    /// `/temporal/entities/{id}/attrs/{attr}/{instanceId}`.
    TemporalEntityAttributeInstance {
        /// The addressed entity.
        id: ResourceId,
        /// The attribute name, as authored.
        attribute: Term,
        /// The addressed attribute instance.
        instance: ResourceId,
    },
    /// `/temporal/entityOperations/query`.
    TemporalBatchQuery,
    /// `/subscriptions`.
    Subscriptions,
    /// `/subscriptions/{id}`.
    Subscription {
        /// The addressed subscription.
        id: ResourceId,
    },
    /// `/csourceRegistrations`.
    ContextSourceRegistrations,
    /// `/csourceRegistrations/{id}`.
    ContextSourceRegistration {
        /// The addressed registration.
        id: ResourceId,
    },
    /// `/csourceSubscriptions`.
    ContextSourceSubscriptions,
    /// `/csourceSubscriptions/{id}`.
    ContextSourceSubscription {
        /// The addressed context source subscription.
        id: ResourceId,
    },
    /// `/types`.
    EntityTypes,
    /// `/types/{type}`.
    EntityType {
        /// The entity type, as authored.
        entity_type: Term,
    },
    /// `/attributes`.
    Attributes,
    /// `/attributes/{attr}`.
    Attribute {
        /// The attribute name, as authored.
        attribute: Term,
    },
    /// `/entityMaps`.
    EntityMaps,
    /// `/entityMaps/{id}`.
    EntityMap {
        /// The addressed entity map.
        id: ResourceId,
    },
    /// `/jsonldContexts`.
    JsonLdContexts,
    /// `/jsonldContexts/{id}`.
    JsonLdContext {
        /// The addressed cached context.
        id: ResourceId,
    },
    /// `/temporal/entityMaps` (NGSI-LD 6.35): an entity map built from a temporal query.
    TemporalEntityMaps,
    /// `/snapshots` (NGSI-LD 6.36).
    Snapshots,
    /// `/snapshots/{id}` (NGSI-LD 6.37).
    Snapshot {
        /// The addressed snapshot.
        id: ResourceId,
    },
    /// `/snapshots/{id}/clone` (NGSI-LD 6.38).
    SnapshotClone {
        /// The snapshot being cloned.
        id: ResourceId,
    },
    /// `/info/sourceIdentity` (NGSI-LD 6.33): the identity of the context source behind the API.
    SourceIdentity,
    /// A path under the API root that this version does not recognise.
    ///
    /// Kept as a variant rather than an error because brokers grow endpoints faster than proxies
    /// do. The caller decides what to do with it; the composition root's answer is to refuse,
    /// since a resource Libra cannot name is one no policy was written about.
    Unrecognised,
}

impl Resource {
    /// The entity this request is about, when the path names one.
    ///
    /// A batch operation names its entities in the body rather than the path, so this is `None`
    /// for those even though they clearly concern entities.
    ///
    /// Listed exhaustively rather than with a wildcard: a resource added later has to be given an
    /// answer here, and the wrong default is the one where a new by-id endpoint quietly reports no
    /// entity and skips every check that needs one.
    #[must_use]
    pub const fn entity_id(&self) -> Option<&ResourceId> {
        match self {
            Self::Entity { id }
            | Self::EntityAttributes { id }
            | Self::EntityAttribute { id, .. }
            | Self::TemporalEntity { id }
            | Self::TemporalEntityAttributes { id }
            | Self::TemporalEntityAttribute { id, .. }
            | Self::TemporalEntityAttributeInstance { id, .. } => Some(id),
            Self::Entities
            | Self::EntityBatch { .. }
            | Self::TemporalEntities
            | Self::TemporalBatchQuery
            | Self::Subscriptions
            | Self::Subscription { .. }
            | Self::ContextSourceRegistrations
            | Self::ContextSourceRegistration { .. }
            | Self::ContextSourceSubscriptions
            | Self::ContextSourceSubscription { .. }
            | Self::EntityTypes
            | Self::EntityType { .. }
            | Self::Attributes
            | Self::Attribute { .. }
            | Self::EntityMaps
            | Self::EntityMap { .. }
            | Self::JsonLdContexts
            | Self::JsonLdContext { .. }
            | Self::TemporalEntityMaps
            | Self::Snapshots
            | Self::Snapshot { .. }
            | Self::SnapshotClone { .. }
            | Self::SourceIdentity
            | Self::Unrecognised => None,
        }
    }

    /// The attribute this request is about, when the path names one.
    ///
    /// Exhaustive for the same reason as [`Resource::entity_id`].
    #[must_use]
    pub const fn attribute(&self) -> Option<&Term> {
        match self {
            Self::EntityAttribute { attribute, .. }
            | Self::TemporalEntityAttribute { attribute, .. }
            | Self::TemporalEntityAttributeInstance { attribute, .. }
            | Self::Attribute { attribute } => Some(attribute),
            Self::Entities
            | Self::Entity { .. }
            | Self::EntityAttributes { .. }
            | Self::EntityBatch { .. }
            | Self::TemporalEntities
            | Self::TemporalEntity { .. }
            | Self::TemporalEntityAttributes { .. }
            | Self::TemporalBatchQuery
            | Self::Subscriptions
            | Self::Subscription { .. }
            | Self::ContextSourceRegistrations
            | Self::ContextSourceRegistration { .. }
            | Self::ContextSourceSubscriptions
            | Self::ContextSourceSubscription { .. }
            | Self::EntityTypes
            | Self::EntityType { .. }
            | Self::Attributes
            | Self::EntityMaps
            | Self::EntityMap { .. }
            | Self::JsonLdContexts
            | Self::JsonLdContext { .. }
            | Self::TemporalEntityMaps
            | Self::Snapshots
            | Self::Snapshot { .. }
            | Self::SnapshotClone { .. }
            | Self::SourceIdentity
            | Self::Unrecognised => None,
        }
    }

    /// Whether this resource is a temporal one.
    ///
    /// Aggregation restrictions apply only here, so the enforcement layer needs to ask.
    #[must_use]
    pub const fn is_temporal(&self) -> bool {
        matches!(
            self,
            Self::TemporalEntities
                | Self::TemporalEntity { .. }
                | Self::TemporalEntityAttributes { .. }
                | Self::TemporalEntityAttribute { .. }
                | Self::TemporalEntityAttributeInstance { .. }
                | Self::TemporalBatchQuery
        )
    }

    /// Whether this resource carries entity data, in the path or in the body.
    ///
    /// Entity-type, scope and attribute restrictions are about entities; subscriptions and
    /// registrations are governed separately.
    #[must_use]
    pub const fn is_entity_shaped(&self) -> bool {
        matches!(
            self,
            Self::Entities | Self::Entity { .. } | Self::EntityAttributes { .. } | Self::EntityAttribute { .. } | Self::EntityBatch { .. }
        ) || self.is_temporal()
    }

    /// Whether this resource is a subscription, addressed as a collection or by identifier.
    ///
    /// A subscription is the one request that makes the broker emit entity data on a channel Libra
    /// never sees: notifications go broker to callback directly. A restriction enforced only on the
    /// query path is therefore bypassed by subscribing, so the enforcement layers must recognise a
    /// subscription and narrow its selectors the way they narrow a query.
    #[must_use]
    pub const fn is_subscription(&self) -> bool {
        matches!(self, Self::Subscriptions | Self::Subscription { .. })
    }

    /// Whether this resource is one of the entity-type or attribute metadata indexes.
    ///
    /// `/types`, `/types/{type}`, `/attributes` and `/attributes/{attr}` (NGSI-LD 5.7.5 to 5.7.10)
    /// answer with an aggregate computed over every entity instance in the system: the type names
    /// present (5.2.24), the attribute names a type's instances carry (5.2.25), a type's attribute
    /// schema and its instance count (5.2.26), the attribute names present (5.2.27) and, per
    /// attribute, the types that have it (5.2.28). The aggregate carries no `scope`, and the
    /// operations take no `q`, `scopeQ` or `type` filter (5.7.5.3, 5.7.8.3), only an optional
    /// `@context`. A caller under a type or attribute restriction would therefore enumerate the names,
    /// schema and counts of data it may not otherwise read. The enforcement layers recognise the
    /// index so they can narrow the aggregate in the response to what the restriction allows, the way
    /// they narrow a query. Scope allows cannot narrow the index (the dimension is absent from both
    /// the request and the response) and are left to a separate recompute.
    #[must_use]
    pub const fn is_metadata_index(&self) -> bool {
        matches!(self, Self::EntityTypes | Self::EntityType { .. } | Self::Attributes | Self::Attribute { .. })
    }

    /// Whether this resource is an entity map, addressed as a collection or by identifier.
    ///
    /// An entity map (NGSI-LD 5.14) maps entity identifiers to context sources during distributed
    /// query execution. Because it contains entity identifiers that disclose entities outside a
    /// caller's type or scope restriction, restricted callers are refused access to entity maps.
    #[must_use]
    pub const fn is_entity_map(&self) -> bool {
        matches!(self, Self::EntityMaps | Self::EntityMap { .. } | Self::TemporalEntityMaps)
    }

    /// Whether this resource is a context source registration, addressed as a collection or by
    /// identifier.
    ///
    /// A registration (NGSI-LD 5.2.9, operations 5.9 and 5.10) names the entity types and attribute
    /// names a context source provides, and the scope it provides them in. Each enforcement layer
    /// judges a registration by the part of it its own restriction is about: what is read is
    /// narrowed or withheld, and what is written is checked.
    #[must_use]
    pub const fn is_context_source_registration(&self) -> bool {
        matches!(self, Self::ContextSourceRegistrations | Self::ContextSourceRegistration { .. })
    }

    /// Whether this resource is a context source subscription, addressed as a collection or by
    /// identifier.
    ///
    /// A context source subscription (NGSI-LD 5.11, 5.12) delivers registrations to an endpoint
    /// Libra never sees, so a restricted caller's notifications could not be narrowed, and
    /// restricted callers are refused access.
    #[must_use]
    pub const fn is_context_source_subscription(&self) -> bool {
        matches!(self, Self::ContextSourceSubscriptions | Self::ContextSourceSubscription { .. })
    }
}
