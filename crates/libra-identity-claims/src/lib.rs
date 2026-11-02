//! The identity claims Libra reads out of a validated token.
//!
//! This crate holds the shape of an access token's payload and nothing else: it does not validate
//! a token, and it never decides anything. Signature, expiry, issuer and audience are checked by
//! `libra-identity-jwt` before a value of this type exists, so every [`Claims`] in the process
//! came out of a token that was already accepted.
//!
//! Only standard claims are read: `sub` and `client_id` from RFC 9068 section 2.2, and `groups` and
//! `roles` from RFC 9068 section 2.2.3.1, each at the top level of the payload. There is no
//! configurable claim path and no knowledge of any one identity provider's layout: a role an
//! identity provider nests somewhere else is not a role here. An identity provider that nests them
//! is configured to emit them at the top level instead.
//!
//! The payload is read as [`UncheckedClaims`] and every name is then checked into the newtype from
//! `libra-policy-model` it will be compared as, so no string is ever compared with a role, a group
//! or a user. A token carrying a name those newtypes refuse (a group containing the comma the
//! broker header is split on, a control character, a name past the length limit) is refused with
//! an [`IdentityError`] of its own, which names the kind of name and the reason and never the name.
//! The identity provider chose that text, and the refusal is logged.
//!
//! Refusing fails closed and visibly. The alternative of dropping the offending name hands the
//! policy engine a caller who quietly holds fewer groups or roles than the token says, and the deny
//! that follows looks like a policy bug rather than a token the identity provider must fix.

use libra_policy_model::{
    error::IdentityError,
    identity::{ClientId, GroupName, IdentityName, PolicyIdentity, RoleName, Subject, Username},
};
use serde::{Deserialize, Serialize};

/// The payload of a validated access token, as far as Libra reads it.
///
/// Unknown claims are ignored: a token carries far more than Libra reads, and a deployment whose
/// identity provider adds a claim must not start failing authentication.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "UncheckedClaims")]
pub struct Claims {
    /// Subject: the identity provider's own, stable identifier for the caller (RFC 7519 section
    /// 4.1.2). Required: a token that names nobody authenticates nobody.
    pub sub: Subject,

    /// The client the token was issued to (RFC 9068 section 2.2).
    pub client_id: Option<ClientId>,

    /// Groups the caller belongs to, in the order the token lists them (RFC 9068 section 2.2.3.1).
    pub groups: Vec<GroupName>,

    /// Roles the caller holds, in the order the token lists them (RFC 9068 section 2.2.3.1).
    pub roles: Vec<RoleName>,
}

/// The claims Libra reads, as the token writes them, before any name is checked.
///
/// Read apart from the check so that a name the policy model refuses is told apart from a payload
/// that is not claims at all: the first is an [`IdentityError`] that carries no part of the name,
/// the second a JSON error. [`Claims::try_from`] is the only way out.
#[derive(Debug, Deserialize)]
pub struct UncheckedClaims {
    sub: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
}

impl TryFrom<UncheckedClaims> for Claims {
    type Error = IdentityError;

    /// Checks every name the token carries.
    ///
    /// # Errors
    ///
    /// Returns the [`IdentityError`] of the first name the policy model refuses.
    fn try_from(unchecked: UncheckedClaims) -> Result<Self, Self::Error> {
        Ok(Self {
            sub: Subject::new(unchecked.sub)?,
            client_id: unchecked.client_id.map(ClientId::new).transpose()?,
            groups: unchecked.groups.into_iter().map(GroupName::new).collect::<Result<_, _>>()?,
            roles: unchecked.roles.into_iter().map(RoleName::new).collect::<Result<_, _>>()?,
        })
    }
}

impl Claims {
    /// The names a policy is written in: the account the subject names, and the token's groups and
    /// roles.
    ///
    /// A policy's `users` therefore names subjects. Neither RFC 7519 nor RFC 9068 defines a
    /// human-readable name for the caller, and reading one an identity provider happens to emit
    /// would let that provider's naming rules decide which policy matches.
    #[must_use]
    pub fn policy_identity(&self) -> PolicyIdentity {
        // Owned, because the identity is stored in the request extensions, which outlive the claims.
        PolicyIdentity {
            name: Some(IdentityName::Account(Username::from(self.sub.clone()))),
            groups: self.groups.clone(),
            roles: self.roles.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn claims(json: &str) -> Claims {
        serde_json::from_str(json).expect("the fixture must parse")
    }

    #[test]
    fn every_standard_claim_is_read() {
        let read = claims(r#"{ "sub": "9f1c-uuid", "client_id": "dashboard", "groups": ["ops", "fleet"], "roles": ["reader", "writer"] }"#);

        assert_eq!(
            read,
            Claims {
                sub: Subject::new("9f1c-uuid").unwrap(),
                client_id: Some(ClientId::new("dashboard").unwrap()),
                groups: vec![GroupName::new("ops").unwrap(), GroupName::new("fleet").unwrap()],
                roles: vec![RoleName::new("reader").unwrap(), RoleName::new("writer").unwrap()],
            }
        );
    }

    #[test]
    fn a_token_without_a_subject_is_not_read() {
        // A token that names nobody would otherwise authenticate an anonymous caller who holds
        // whatever roles it lists.
        assert!(serde_json::from_str::<Claims>(r#"{ "roles": ["admin"] }"#).is_err());
        assert!(serde_json::from_str::<Claims>("{}").is_err());
    }

    #[test]
    fn a_token_carrying_no_groups_or_roles_yields_none_rather_than_an_error() {
        let bare = claims(r#"{ "sub": "9f1c-uuid" }"#);

        assert_eq!(bare.groups, [] as [_; 0]);
        assert_eq!(bare.roles, [] as [_; 0]);
        assert_eq!(bare.client_id, None);
    }

    #[test]
    fn roles_and_names_nested_the_way_one_identity_provider_nests_them_are_not_read() {
        // Keycloak's layout. Reading it is claim mapping for one vendor, which this crate does not do:
        // a deployment configures its identity provider to emit standard claims instead.
        let vendor = claims(
            r#"{
                "sub": "9f1c-uuid",
                "azp": "ngsi-client",
                "preferred_username": "alice",
                "email": "alice@example.invalid",
                "realm_access": { "roles": ["fleet-admin"] },
                "resource_access": { "ngsi-client": { "roles": ["admin"] } }
            }"#,
        );

        assert_eq!(vendor.roles, [] as [_; 0]);
        assert_eq!(vendor.client_id, None);
        assert_eq!(
            vendor.policy_identity().name,
            Some(IdentityName::Account(Username::new("9f1c-uuid").unwrap())),
            "the account is the subject, not the username the provider chose to display"
        );
    }

    #[test]
    fn a_token_with_a_name_the_policy_model_refuses_is_not_read() {
        // Skipping the offending entry would hand the policy engine a caller holding fewer roles than
        // the token says and turn a malformed token into what looks like a policy bug.
        for hostile in [
            r#"{ "sub": "s", "groups": ["ops,admins", "fleet"] }"#,
            r#"{ "sub": "s", "groups": ["ops", ""] }"#,
            r#"{ "sub": "s", "roles": ["x,fleet-admin", "viewer"] }"#,
            r#"{ "sub": "s", "client_id": "a,b" }"#,
            r#"{ "sub": "ali\nce" }"#,
            r#"{ "sub": "" }"#,
        ] {
            assert!(serde_json::from_str::<Claims>(hostile).is_err(), "{hostile} must be refused");
        }

        let over_long_role = format!(r#"{{ "sub": "s", "roles": ["{}"] }}"#, "r".repeat(257));
        assert!(serde_json::from_str::<Claims>(&over_long_role).is_err());
    }

    #[test]
    fn a_refused_name_is_reported_by_kind_and_reason_without_the_name() {
        for (payload, kind) in [
            (r#"{ "sub": "s", "groups": ["fleet", "ops,secret-eu"] }"#, "group"),
            (r#"{ "sub": "s", "roles": ["secret-role\nlevel=ERROR forged"] }"#, "role"),
            (r#"{ "sub": "s", "client_id": "secret,client" }"#, "client id"),
            (r#"{ "sub": "secret\u001b[2J" }"#, "subject"),
        ] {
            let unchecked: UncheckedClaims = serde_json::from_str(payload).expect("the payload is claims");
            let refused = Claims::try_from(unchecked).expect_err("the name must be refused");

            assert_eq!(refused.kind, kind, "{payload}");
            assert!(!refused.to_string().contains("secret"), "{refused}");
        }
    }

    #[test]
    fn a_payload_that_is_not_claims_is_not_read_as_unchecked_claims() {
        assert!(serde_json::from_str::<UncheckedClaims>(r#"{ "roles": ["admin"] }"#).is_err());
        assert!(serde_json::from_str::<UncheckedClaims>(r#"{ "sub": "s", "groups": "ops" }"#).is_err());
    }

    #[test]
    fn a_claim_libra_does_not_read_does_not_stop_the_token_being_read() {
        let extra = claims(r#"{ "sub": "9f1c-uuid", "scope": "openid profile", "acr": "1", "custom": { "nested": [1, 2] } }"#);

        assert_eq!(extra.sub, Subject::new("9f1c-uuid").unwrap());
    }

    #[test]
    fn the_policy_identity_is_the_subject_as_an_account_with_the_tokens_groups_and_roles() {
        let identity = claims(r#"{ "sub": "alice", "groups": ["ops", "fleet"], "roles": ["writer", "reader"] }"#).policy_identity();

        assert_eq!(
            identity,
            PolicyIdentity {
                name: Some(IdentityName::Account(Username::new("alice").unwrap())),
                groups: vec![GroupName::new("ops").unwrap(), GroupName::new("fleet").unwrap()],
                roles: vec![RoleName::new("writer").unwrap(), RoleName::new("reader").unwrap()],
            },
            "names keep the order the token gave them"
        );
        assert!(identity.is_authenticated());
    }

    #[test]
    fn claims_serialize_with_the_names_rfc_9068_uses() {
        let source = r#"{"sub":"9f1c-uuid","client_id":"ngsi-client","groups":["ops"],"roles":["admin"]}"#;

        assert_eq!(serde_json::to_string(&claims(source)).unwrap(), source);
    }
}
