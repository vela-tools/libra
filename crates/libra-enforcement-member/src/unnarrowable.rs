//! The routes a restriction on one entity member cannot narrow at all.

use libra_ngsi_ld_operation::{operation::Operation, target::EntityTarget};
use thiserror::Error;

/// Why a route is refused whole under a member restriction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Unnarrowable {
    /// A context source subscription notifies registrations to an endpoint Libra never sees, so
    /// they could not be narrowed to the restriction.
    #[error("a context source subscription cannot be narrowed")]
    ContextSourceSubscription,

    /// An entity map lists the entities an earlier query matched, whatever their members, and a
    /// request naming one is answered from that list rather than from its own filter.
    #[error("an entity map cannot be narrowed")]
    EntityMap,

    /// Subscriptions are shared by every caller of a tenant and record nothing of who created
    /// them, so reading, changing or deleting one reaches subscriptions the restriction never
    /// narrowed.
    #[error("an existing subscription cannot be narrowed")]
    ExistingSubscriptions,
}

/// Refuses the routes a member restriction cannot narrow at all.
///
/// # Errors
///
/// Returns the [`Unnarrowable`] of a context source subscription, an entity map, or an existing
/// subscription.
pub const fn refuse_unnarrowable(operation: &Operation) -> Result<(), Unnarrowable> {
    if operation.resource.is_context_source_subscription() {
        return Err(Unnarrowable::ContextSourceSubscription);
    }

    if operation.resource.is_entity_map() {
        return Err(Unnarrowable::EntityMap);
    }

    if matches!(EntityTarget::of(operation), EntityTarget::ExistingSubscriptions) {
        return Err(Unnarrowable::ExistingSubscriptions);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use pretty_assertions::assert_eq;

    fn classify(method: &Method, path: &str) -> Operation {
        Operation::classify(method, path)
            .expect("the request should classify")
            .expect("the path should be under the API root")
    }

    #[test]
    fn a_context_source_subscription_is_refused() {
        assert_eq!(
            refuse_unnarrowable(&classify(&Method::GET, "/ngsi-ld/v1/csourceSubscriptions")),
            Err(Unnarrowable::ContextSourceSubscription)
        );
    }

    #[test]
    fn an_entity_map_is_refused() {
        assert_eq!(
            refuse_unnarrowable(&classify(&Method::GET, "/ngsi-ld/v1/entityMaps/urn:map:1")),
            Err(Unnarrowable::EntityMap)
        );
    }

    #[test]
    fn an_existing_subscription_is_refused_and_a_new_one_is_not() {
        assert_eq!(
            refuse_unnarrowable(&classify(&Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:s:1")),
            Err(Unnarrowable::ExistingSubscriptions)
        );
        assert_eq!(refuse_unnarrowable(&classify(&Method::POST, "/ngsi-ld/v1/subscriptions")), Ok(()));
    }

    #[test]
    fn an_entity_read_is_not_refused() {
        assert_eq!(refuse_unnarrowable(&classify(&Method::GET, "/ngsi-ld/v1/entities")), Ok(()));
    }
}
