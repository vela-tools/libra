//! Which operations hand the caller unaggregated entity values.

use libra_ngsi_ld_operation::{operation::Operation, resource::Resource};

/// Whether an operation that is not a temporal read can return unaggregated entity values.
///
/// A restriction that disallows unaggregated reads refuses these. Refusing every non-temporal
/// endpoint would take `/types` and `/attributes` (schema, not values) down with the entity
/// endpoints, and would refuse writes in the name of a rule about reading.
///
/// Listed exhaustively so that a resource added later has to be given an answer here, and so that
/// the wrong default is not the silent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawValues {
    /// The operation can return entity values as they are stored.
    Returned,
    /// The operation returns no entity values.
    NotReturned,
}

impl RawValues {
    /// Whether `operation` can return unaggregated entity values.
    #[must_use]
    pub const fn of(operation: &Operation) -> Self {
        let returned = match &operation.resource {
            // The entity endpoints, when they are being read. A write to one supplies values rather
            // than receiving them, and is governed by the policy's other restrictions.
            Resource::Entities
            | Resource::Entity { .. }
            | Resource::EntityAttributes { .. }
            | Resource::EntityAttribute { .. }
            | Resource::EntityBatch { .. } => operation.is_read(),

            // Creating a subscription opens a standing read whose notifications go from the broker
            // to a callback and never pass through Libra, so they cannot be held to the restriction
            // on the way out. Reading one back returns the subscription document, not entity values.
            Resource::Subscriptions | Resource::Subscription { .. } | Resource::ContextSourceSubscriptions | Resource::ContextSourceSubscription { .. } => {
                !operation.is_read()
            }

            // A path this version cannot name might return anything at all, and a snapshot is a
            // copy of the broker's entities whose later reads nothing here narrows.
            Resource::Unrecognised | Resource::Snapshots | Resource::Snapshot { .. } | Resource::SnapshotClone { .. } => true,

            // Schema and plumbing: type and attribute listings describe the shape of the data,
            // registrations say where it lives, entity maps hold identifiers, cached contexts hold
            // term definitions. The temporal resources are here for a different reason: their reads
            // are answered by the aggregation check itself, and their writes supply instances.
            Resource::EntityTypes
            | Resource::EntityType { .. }
            | Resource::Attributes
            | Resource::Attribute { .. }
            | Resource::ContextSourceRegistrations
            | Resource::ContextSourceRegistration { .. }
            | Resource::EntityMaps
            | Resource::EntityMap { .. }
            | Resource::TemporalEntityMaps
            | Resource::SourceIdentity
            | Resource::JsonLdContexts
            | Resource::JsonLdContext { .. }
            | Resource::TemporalEntities
            | Resource::TemporalEntity { .. }
            | Resource::TemporalEntityAttributes { .. }
            | Resource::TemporalEntityAttribute { .. }
            | Resource::TemporalEntityAttributeInstance { .. }
            | Resource::TemporalBatchQuery => false,
        };

        if returned { Self::Returned } else { Self::NotReturned }
    }
}
