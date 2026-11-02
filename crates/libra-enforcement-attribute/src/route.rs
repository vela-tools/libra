//! The routes an attribute-restricted caller is refused, whatever the request carries.
//!
//! Everything else in this crate narrows a request to the attributes the policy allows, or refuses
//! one that names a hidden attribute. These routes cannot be narrowed that way:
//!
//! - an entity map (NGSI-LD 5.14) lists the entities a query found, and creating one runs a query
//!   whose `q` and answer no narrowing here reaches;
//! - a context source subscription, and a subscription that already exists, notify an endpoint
//!   Libra never sees, and the broker lists every subscription of the tenant;
//! - deleting or replacing a whole entity takes every attribute with it, the hidden ones included,
//!   so a caller who cannot see an attribute could still destroy it.

use crate::error::FilterError;
use axum::http::Method;
use libra_ngsi_ld_operation::{
    operation::Operation,
    resource::{BatchAction, Resource},
    target::EntityTarget,
};
use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters};
use libra_policy_model::attribute::AttributeAction;

/// The `options` value that makes a batch upsert update rather than replace (NGSI-LD 6.15.3.1).
const UPDATE: &str = "update";
/// The `options` value that makes a batch upsert replace, which is also its default.
const REPLACE: &str = "replace";

/// What a batch upsert does to an entity that already exists (NGSI-LD 5.6.8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpsertMode {
    /// All the existing content is replaced, the default.
    Replace,
    /// The existing content is updated with the attributes the body names.
    Update,
}

impl UpsertMode {
    /// The mode `options` selects.
    ///
    /// `update` only when it is named and `replace` is not: naming both leaves the mode to the
    /// broker, and the default is to replace.
    fn of(parameters: &QueryParameters) -> Self {
        let options = parameters.get(&ParameterName::OPTIONS).unwrap_or_default();
        let named = |wanted: &str| options.split(',').any(|option| option.trim() == wanted);

        if named(UPDATE) && !named(REPLACE) { Self::Update } else { Self::Replace }
    }
}

/// Refuses a route an attribute-restricted caller may not use.
///
/// `method` is the request's, which tells an entity replacement (`PUT`, clause 5.6.18) from a merge
/// (`PATCH`, clause 5.6.17) on the same path.
///
/// # Errors
///
/// Returns [`FilterError::EntityMapDenied`], [`FilterError::ContextSourceSubscriptionDenied`],
/// [`FilterError::SubscriptionsRefused`] or [`FilterError::WholeEntityRefused`] for the routes this
/// module describes.
pub(crate) fn refuse_route(method: &Method, operation: &Operation, parameters: &QueryParameters, action: AttributeAction) -> Result<(), FilterError> {
    if operation.resource.is_entity_map() {
        return Err(FilterError::EntityMapDenied);
    }

    if operation.resource.is_context_source_subscription() {
        return Err(FilterError::ContextSourceSubscriptionDenied);
    }

    match EntityTarget::of(operation) {
        EntityTarget::ExistingSubscriptions => return Err(FilterError::SubscriptionsRefused),
        EntityTarget::BatchDelete => return whole_entity(action),
        EntityTarget::SingleEntity
        | EntityTarget::CollectionQuery
        | EntityTarget::CollectionWrite
        | EntityTarget::TemporalCollectionWrite
        | EntityTarget::BatchQuery
        | EntityTarget::BatchCreate
        | EntityTarget::BatchOverwrite
        | EntityTarget::SubscriptionCreate
        | EntityTarget::Untouched => {}
    }

    let destroys_whole_entities = match &operation.resource {
        Resource::Entity { .. } => method == Method::DELETE || method == Method::PUT,
        Resource::TemporalEntity { .. } | Resource::Entities | Resource::TemporalEntities => method == Method::DELETE,
        Resource::EntityBatch { action } => match action {
            BatchAction::Upsert => UpsertMode::of(parameters) == UpsertMode::Replace,
            BatchAction::Create | BatchAction::Update | BatchAction::Delete | BatchAction::Merge | BatchAction::Query => false,
        },
        Resource::EntityAttributes { .. }
        | Resource::EntityAttribute { .. }
        | Resource::TemporalEntityAttributes { .. }
        | Resource::TemporalEntityAttribute { .. }
        | Resource::TemporalEntityAttributeInstance { .. }
        | Resource::TemporalBatchQuery
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

    if destroys_whole_entities { whole_entity(action) } else { Ok(()) }
}

/// The refusal of a whole-entity delete or replace.
///
/// Under `pick` the caller cannot see every attribute but the listed ones, and under `omit` the
/// listed ones; either way the entity holds attributes the caller could not see and would destroy.
const fn whole_entity(action: AttributeAction) -> Result<(), FilterError> {
    match action {
        AttributeAction::Pick | AttributeAction::Omit => Err(FilterError::WholeEntityRefused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn judged(method: &Method, uri: &str) -> Result<(), FilterError> {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let operation = Operation::classify(method, path).unwrap().unwrap();

        refuse_route(method, &operation, &QueryParameters::parse(query).unwrap(), AttributeAction::Omit)
    }

    #[test]
    fn entity_maps_and_context_source_subscriptions_are_refused() {
        for (method, uri) in [
            (Method::GET, "/ngsi-ld/v1/entityMaps/urn:map:1"),
            (Method::POST, "/ngsi-ld/v1/entityMaps"),
            (Method::GET, "/ngsi-ld/v1/temporal/entityMaps"),
        ] {
            assert_eq!(judged(&method, uri), Err(FilterError::EntityMapDenied), "{method} {uri}");
        }
        for (method, uri) in [
            (Method::GET, "/ngsi-ld/v1/csourceSubscriptions"),
            (Method::POST, "/ngsi-ld/v1/csourceSubscriptions"),
            (Method::DELETE, "/ngsi-ld/v1/csourceSubscriptions/urn:s:1"),
        ] {
            assert_eq!(judged(&method, uri), Err(FilterError::ContextSourceSubscriptionDenied), "{method} {uri}");
        }
    }

    #[test]
    fn existing_subscriptions_are_refused_and_creating_one_is_not() {
        for (method, uri) in [
            (Method::GET, "/ngsi-ld/v1/subscriptions"),
            (Method::GET, "/ngsi-ld/v1/subscriptions/urn:s:1"),
            (Method::PATCH, "/ngsi-ld/v1/subscriptions/urn:s:1"),
            (Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:s:1"),
        ] {
            assert_eq!(judged(&method, uri), Err(FilterError::SubscriptionsRefused), "{method} {uri}");
        }
        assert_eq!(judged(&Method::POST, "/ngsi-ld/v1/subscriptions"), Ok(()));
    }

    #[test]
    fn deleting_or_replacing_whole_entities_is_refused() {
        for (method, uri) in [
            (Method::DELETE, "/ngsi-ld/v1/entities/urn:e:1"),
            (Method::PUT, "/ngsi-ld/v1/entities/urn:e:1"),
            (Method::POST, "/ngsi-ld/v1/entityOperations/delete"),
            (Method::DELETE, "/ngsi-ld/v1/temporal/entities/urn:e:1"),
            (Method::DELETE, "/ngsi-ld/v1/entities?type=Vehicle"),
            (Method::DELETE, "/ngsi-ld/v1/temporal/entities?type=Vehicle"),
        ] {
            assert_eq!(judged(&method, uri), Err(FilterError::WholeEntityRefused), "{method} {uri}");
        }
    }

    #[test]
    fn a_batch_upsert_replaces_unless_it_asks_only_to_update() {
        for uri in [
            "/ngsi-ld/v1/entityOperations/upsert",
            "/ngsi-ld/v1/entityOperations/upsert?options=replace",
            "/ngsi-ld/v1/entityOperations/upsert?options=update,replace",
            "/ngsi-ld/v1/entityOperations/upsert?options=sysAttrs",
        ] {
            assert_eq!(judged(&Method::POST, uri), Err(FilterError::WholeEntityRefused), "{uri}");
        }
        assert_eq!(judged(&Method::POST, "/ngsi-ld/v1/entityOperations/upsert?options=update"), Ok(()));
    }

    #[test]
    fn attribute_level_changes_and_merges_are_left_to_the_attribute_checks() {
        for (method, uri) in [
            (Method::PATCH, "/ngsi-ld/v1/entities/urn:e:1"),
            (Method::PATCH, "/ngsi-ld/v1/entities/urn:e:1/attrs"),
            (Method::DELETE, "/ngsi-ld/v1/entities/urn:e:1/attrs/speed"),
            (Method::PUT, "/ngsi-ld/v1/entities/urn:e:1/attrs/speed"),
            (Method::POST, "/ngsi-ld/v1/entityOperations/update"),
            (Method::POST, "/ngsi-ld/v1/entityOperations/merge"),
            (Method::GET, "/ngsi-ld/v1/entities/urn:e:1"),
        ] {
            assert_eq!(judged(&method, uri), Ok(()), "{method} {uri}");
        }
    }
}
