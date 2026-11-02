//! Properties of the claims path: what a token can and cannot make Libra believe.
//!
//! Everything here starts from JSON, because that is what actually arrives. A token is checked for
//! its signature and then read, and everything after that point is this crate deciding what the
//! caller is called and what they hold, which is the input to every policy decision that follows.

use libra_identity_claims::Claims;
use libra_policy_model::identity::{GroupName, RoleName};
use proptest::{collection::vec, prelude::*};
use serde_json::{Value, json};

/// Names the generators draw from: ordinary, and the shapes that have caused trouble.
fn name() -> impl Strategy<Value = String> {
    prop_oneof!["[a-z][a-z0-9-]{0,12}", Just("admin".to_owned()), Just("ngsi-client:entity-admin".to_owned()),]
}

/// Content an identity provider might put in claims Libra does not read.
fn foreign() -> impl Strategy<Value = Value> {
    (vec(name(), 0..4), vec(name(), 0..4)).prop_map(|(realm, client)| {
        json!({
            "realm_access": { "roles": realm },
            "resource_access": { "ngsi-client": { "roles": client } },
            "preferred_username": "admin",
        })
    })
}

proptest! {
    /// Reading a token is not a place to panic. Whatever arrives is either claims or an error.
    #[test]
    fn arbitrary_json_is_read_or_refused_but_never_fatal(source in "\\PC{0,200}") {
        let _outcome: Result<Claims, _> = serde_json::from_str::<Claims>(&source);
    }

    /// The caller holds exactly what the token lists, in the order it lists it.
    #[test]
    fn nothing_is_invented_and_nothing_is_dropped(
        groups in vec("[a-z][a-z0-9-]{1,8}", 0..4),
        roles in vec(name(), 0..4),
    ) {
        let claims: Claims = serde_json::from_value(json!({ "sub": "alice", "groups": groups, "roles": roles })).unwrap();
        let identity = claims.policy_identity();

        prop_assert_eq!(identity.groups.iter().map(GroupName::as_str).collect::<Vec<_>>(), groups.iter().map(String::as_str).collect::<Vec<_>>());
        prop_assert_eq!(identity.roles.iter().map(RoleName::as_str).collect::<Vec<_>>(), roles.iter().map(String::as_str).collect::<Vec<_>>());
    }

    /// Claims outside the standard set cannot add a role, whatever they hold.
    #[test]
    fn a_role_nested_elsewhere_never_reaches_the_caller(
        roles in vec(name(), 0..4),
        extra in foreign(),
    ) {
        let standard = json!({ "sub": "alice", "roles": roles });
        let mut decorated = standard.clone();
        if let (Some(target), Some(source)) = (decorated.as_object_mut(), extra.as_object()) {
            target.extend(source.clone());
        }

        let plain: Claims = serde_json::from_value(standard).unwrap();
        let with_foreign: Claims = serde_json::from_value(decorated).unwrap();

        prop_assert_eq!(plain.policy_identity(), with_foreign.policy_identity());
    }

    /// Reading the same token twice cannot produce two different callers.
    #[test]
    fn reading_a_token_is_deterministic(roles in vec(name(), 0..4)) {
        let source = json!({ "sub": "alice", "roles": roles }).to_string();
        let first: Claims = serde_json::from_str(&source).unwrap();
        let second: Claims = serde_json::from_str(&source).unwrap();

        prop_assert_eq!(first.policy_identity(), second.policy_identity());
    }
}
