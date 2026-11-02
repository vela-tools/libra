//! The resources a policy allows operations on.
//!
//! `read` and `write` alone made any write allow a write to everything the API exposes: creating a
//! context source registration (which decides where the broker sends other callers' requests and
//! which of their headers it copies), evicting the broker's cached contexts, building entity maps.
//! A policy now names the resources it is about, in families that follow the resource groups of
//! NGSI-LD clause 6, and the families that hold no entity data are reached only by a policy that
//! names them.

use libra_ngsi_ld_operation::resource::Resource;
use serde::{Deserialize, Serialize};
use strum::EnumIter;

/// A family of NGSI-LD resources, as a policy condition names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, EnumIter)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceFamily {
    /// `/entities` and `/entityOperations` (clauses 6.4 to 6.17).
    Entities,
    /// `/temporal/entities` and `/temporal/entityOperations` (clauses 6.18 to 6.24).
    Temporal,
    /// `/types` and `/attributes` (clauses 6.25 to 6.28).
    Discovery,
    /// `/subscriptions` (clauses 6.10 and 6.11).
    Subscriptions,
    /// `/csourceRegistrations` (clauses 6.8 and 6.9).
    ///
    /// `write` here decides where the broker sends requests and which headers it adds to them, so
    /// allowing it is an administrative decision.
    Registrations,
    /// `/csourceSubscriptions` (clauses 6.12 and 6.13).
    RegistrationSubscriptions,
    /// `/entityMaps` and `/temporal/entityMaps` (clauses 6.32, 6.34 and 6.35).
    EntityMaps,
    /// `/jsonldContexts` (clauses 6.29 and 6.30): the broker's context cache, shared by every
    /// tenant.
    Contexts,
    /// `/snapshots` (clauses 6.36 to 6.38).
    Snapshots,
    /// `/info` (clause 6.33).
    Info,
}

impl ResourceFamily {
    /// The family a classified resource belongs to, or `None` for a path no family names.
    #[must_use]
    pub const fn of(resource: &Resource) -> Option<Self> {
        match resource {
            Resource::Entities
            | Resource::Entity { .. }
            | Resource::EntityAttributes { .. }
            | Resource::EntityAttribute { .. }
            | Resource::EntityBatch { .. } => Some(Self::Entities),
            Resource::TemporalEntities
            | Resource::TemporalEntity { .. }
            | Resource::TemporalEntityAttributes { .. }
            | Resource::TemporalEntityAttribute { .. }
            | Resource::TemporalEntityAttributeInstance { .. }
            | Resource::TemporalBatchQuery => Some(Self::Temporal),
            Resource::EntityTypes | Resource::EntityType { .. } | Resource::Attributes | Resource::Attribute { .. } => Some(Self::Discovery),
            Resource::Subscriptions | Resource::Subscription { .. } => Some(Self::Subscriptions),
            Resource::ContextSourceRegistrations | Resource::ContextSourceRegistration { .. } => Some(Self::Registrations),
            Resource::ContextSourceSubscriptions | Resource::ContextSourceSubscription { .. } => Some(Self::RegistrationSubscriptions),
            Resource::EntityMaps | Resource::EntityMap { .. } | Resource::TemporalEntityMaps => Some(Self::EntityMaps),
            Resource::JsonLdContexts | Resource::JsonLdContext { .. } => Some(Self::Contexts),
            Resource::Snapshots | Resource::Snapshot { .. } | Resource::SnapshotClone { .. } => Some(Self::Snapshots),
            Resource::SourceIdentity => Some(Self::Info),
            Resource::Unrecognised => None,
        }
    }

    /// Whether a condition that names no resources covers this family.
    ///
    /// The entity data a policy written before resources existed was about, and nothing else: every
    /// other family is reached only by a policy that names it.
    #[must_use]
    pub const fn is_covered_by_default(self) -> bool {
        match self {
            Self::Entities | Self::Temporal | Self::Discovery => true,
            Self::Subscriptions | Self::Registrations | Self::RegistrationSubscriptions | Self::EntityMaps | Self::Contexts | Self::Snapshots | Self::Info => {
                false
            }
        }
    }

    /// Whether a restriction a policy carries is enforced on requests of this family.
    ///
    /// The scope, entity type, attribute, time and aggregation restrictions narrow entity data,
    /// subscriptions and registrations. On the other families they are either refused by the
    /// enforcement layers (entity maps, context source subscriptions) or meaningless (contexts,
    /// info), and a snapshot copies entity data that nothing narrows afterwards.
    #[must_use]
    pub const fn is_restrictable(self) -> bool {
        match self {
            Self::Entities | Self::Temporal | Self::Discovery | Self::Subscriptions | Self::Registrations => true,
            Self::RegistrationSubscriptions | Self::EntityMaps | Self::Contexts | Self::Snapshots | Self::Info => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_jsonld_term_expansion::name::Term;
    use libra_ngsi_ld_operation::{
        operation::Operation,
        resource::{BatchAction, ResourceId},
    };
    use pretty_assertions::assert_eq;
    use serde::Deserialize;
    use strum::IntoEnumIterator;

    #[derive(Deserialize)]
    struct Named {
        resources: Vec<ResourceFamily>,
    }

    fn family(method: &http::Method, path: &str) -> Option<ResourceFamily> {
        let operation = Operation::classify(method, path).unwrap().unwrap();

        ResourceFamily::of(&operation.resource)
    }

    #[test]
    fn families_are_written_in_kebab_case() {
        let named: Named = toml::from_str(r#"resources = ["entities", "registration-subscriptions", "entity-maps", "info"]"#).unwrap();

        assert_eq!(
            named.resources,
            vec![
                ResourceFamily::Entities,
                ResourceFamily::RegistrationSubscriptions,
                ResourceFamily::EntityMaps,
                ResourceFamily::Info
            ]
        );
    }

    #[test]
    fn an_unknown_family_is_refused() {
        assert!(toml::from_str::<Named>(r#"resources = ["everything"]"#).is_err());
    }

    #[test]
    fn every_route_belongs_to_its_family() {
        let get = http::Method::GET;
        let routes = [
            ("/ngsi-ld/v1/entities", ResourceFamily::Entities),
            ("/ngsi-ld/v1/entities/urn:a/attrs/speed", ResourceFamily::Entities),
            ("/ngsi-ld/v1/temporal/entities/urn:a", ResourceFamily::Temporal),
            ("/ngsi-ld/v1/types", ResourceFamily::Discovery),
            ("/ngsi-ld/v1/attributes/speed", ResourceFamily::Discovery),
            ("/ngsi-ld/v1/subscriptions/urn:s", ResourceFamily::Subscriptions),
            ("/ngsi-ld/v1/csourceRegistrations", ResourceFamily::Registrations),
            ("/ngsi-ld/v1/csourceSubscriptions/urn:c", ResourceFamily::RegistrationSubscriptions),
            ("/ngsi-ld/v1/entityMaps/urn:m", ResourceFamily::EntityMaps),
            ("/ngsi-ld/v1/temporal/entityMaps", ResourceFamily::EntityMaps),
            ("/ngsi-ld/v1/jsonldContexts/urn:x", ResourceFamily::Contexts),
            ("/ngsi-ld/v1/snapshots/urn:s/clone", ResourceFamily::Snapshots),
            ("/ngsi-ld/v1/info/sourceIdentity", ResourceFamily::Info),
        ];

        for (path, expected) in routes {
            assert_eq!(family(&get, path), Some(expected), "{path}");
        }
        assert_eq!(
            ResourceFamily::of(&Resource::EntityBatch { action: BatchAction::Query }),
            Some(ResourceFamily::Entities)
        );
        assert_eq!(
            ResourceFamily::of(&Resource::TemporalEntityAttributeInstance {
                id: ResourceId::new("urn:a"),
                attribute: Term::new("speed"),
                instance: ResourceId::new("urn:i"),
            }),
            Some(ResourceFamily::Temporal)
        );
    }

    #[test]
    fn an_unrecognised_path_has_no_family() {
        assert_eq!(ResourceFamily::of(&Resource::Unrecognised), None);
    }

    #[test]
    fn only_entity_data_is_covered_by_default() {
        let covered: Vec<ResourceFamily> = ResourceFamily::iter().filter(|family| family.is_covered_by_default()).collect();

        assert_eq!(covered, vec![ResourceFamily::Entities, ResourceFamily::Temporal, ResourceFamily::Discovery]);
    }

    #[test]
    fn restrictions_apply_to_entity_data_subscriptions_and_registrations() {
        let restrictable: Vec<ResourceFamily> = ResourceFamily::iter().filter(|family| family.is_restrictable()).collect();

        assert_eq!(
            restrictable,
            vec![
                ResourceFamily::Entities,
                ResourceFamily::Temporal,
                ResourceFamily::Discovery,
                ResourceFamily::Subscriptions,
                ResourceFamily::Registrations
            ]
        );
    }
}
