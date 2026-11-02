//! What a time restriction makes of a request that names no window.
//!
//! A temporal read names a window, which is narrowed. Everything else is judged by the moment it is
//! made, or, for a current-state read, by the restriction's `current-state` rule.

use crate::{error::TimeError, window::Window};
use jiff::Timestamp;
use libra_ngsi_ld_operation::{
    operation::{Mode, Operation},
    resource::Resource,
};
use libra_policy_model::time::{CurrentState, TimeRestriction};

/// What the membership rule decides about a request that names no window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Membership {
    /// The request is forwarded as written.
    Forward,
    /// A current-state read whose answer is held to this window.
    FilterValues(Window),
}

/// Decides whether a request that names no window may be served at all, and how.
///
/// A current-state read (a read that answers with entities as they are now) is governed by the
/// restriction's `current-state` rule. Everything else keeps the request-time rule of the window's
/// kind, which is also what the two default rules reproduce for a current-state read.
pub(crate) fn check_membership(operation: &Operation, restriction: &TimeRestriction, now: Timestamp) -> Result<Membership, TimeError> {
    let current_state_read = matches!(operation.mode, Mode::Read) && operation.resource.is_entity_shaped();

    if !current_state_read {
        return check_request_time(&operation.resource, restriction, now).map(|()| Membership::Forward);
    }

    match restriction.current_state() {
        CurrentState::Refuse => Err(TimeError::CurrentStateRefused),
        CurrentState::RequestInWindow => request_in_window(restriction, now).map(|()| Membership::Forward),
        CurrentState::Allow => Ok(Membership::Forward),
        CurrentState::ValuesInWindow => Ok(Membership::FilterValues(Window::from(restriction.window(now)))),
    }
}

/// Whether the moment of the request lies inside the window.
fn request_in_window(restriction: &TimeRestriction, now: Timestamp) -> Result<(), TimeError> {
    if Window::from(restriction.window(now)).contains(now) {
        Ok(())
    } else {
        Err(TimeError::OutsideWindow)
    }
}

/// The request-time rule of the window's kind, for a request that is not a current-state read.
fn check_request_time(resource: &Resource, restriction: &TimeRestriction, now: Timestamp) -> Result<(), TimeError> {
    match restriction {
        TimeRestriction::Absolute { .. } => {
            // The only instant a current-state read can be reasoned about from here is the one it
            // is made at, so an absolute window becomes a check on the request time. It is a real
            // check: it fails outside the window. It does not bound the age of what comes back; a
            // policy that needs that says so with `current-state = "values-in-window"`.
            request_in_window(restriction, now)
        }
        TimeRestriction::Relative { .. } => {
            // The same check against a relative window is vacuous by construction: the window is
            // measured from the request, so the request is always inside it, and a policy reading
            // "the past 24 hours only" would place no restriction on `GET /entities`, `createdAt`
            // or `modifiedAt`. There is nothing here to narrow and nothing that can fail, so the
            // resources the restriction was written about, the ones that carry entity data, are
            // refused, and the rest, which carry none, are left alone.
            if resource.is_entity_shaped() { Err(TimeError::Unenforceable) } else { Ok(()) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use libra_policy_model::{duration::IsoDuration, time::Direction};
    use pretty_assertions::assert_eq;

    fn operation(method: &Method, path: &str) -> Operation {
        Operation::classify(method, path).unwrap().unwrap()
    }

    fn past_day(current_state: CurrentState) -> TimeRestriction {
        TimeRestriction::Relative {
            duration: IsoDuration::parse("PT24H").unwrap(),
            direction: Direction::Past,
            current_state,
        }
    }

    #[test]
    fn a_current_state_read_follows_the_current_state_rule() {
        let now: Timestamp = "2026-06-01T12:00:00Z".parse().unwrap();
        let read = operation(&Method::GET, "/ngsi-ld/v1/entities");

        assert_eq!(
            check_membership(&read, &past_day(CurrentState::Refuse), now),
            Err(TimeError::CurrentStateRefused)
        );
        assert_eq!(check_membership(&read, &past_day(CurrentState::Allow), now), Ok(Membership::Forward));
        assert!(matches!(
            check_membership(&read, &past_day(CurrentState::ValuesInWindow), now),
            Ok(Membership::FilterValues(_))
        ));
    }

    #[test]
    fn a_relative_window_refuses_entity_writes_and_leaves_schema_reads() {
        let now: Timestamp = "2026-06-01T12:00:00Z".parse().unwrap();

        assert_eq!(
            check_membership(&operation(&Method::POST, "/ngsi-ld/v1/entities"), &past_day(CurrentState::Allow), now),
            Err(TimeError::Unenforceable)
        );
        assert_eq!(
            check_membership(&operation(&Method::GET, "/ngsi-ld/v1/types"), &past_day(CurrentState::Refuse), now),
            Ok(Membership::Forward)
        );
    }
}
