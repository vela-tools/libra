//! JWT verification behind the authenticator seam.

use crate::{TokenValidator, ValidationError};
use libra_identity_authenticator::{
    authentication::Authentication,
    authenticator::{AuthenticationFuture, Authenticator, Recognition},
    bearer_token::BearerToken,
    caller::{CallerKind, CallerProfile},
    refusal::Refusal,
};
use libra_identity_claims::Claims;
use tracing::warn;

/// Authenticates callers presenting a JWT access token.
#[derive(Clone)]
pub struct JwtAuthenticator {
    validator: TokenValidator,
}

impl JwtAuthenticator {
    /// Authenticates with `validator`.
    #[must_use]
    pub const fn new(validator: TokenValidator) -> Self {
        Self { validator }
    }
}

impl Authenticator for JwtAuthenticator {
    /// A compact JWS (RFC 7515 section 7.1): three base64url segments separated by dots.
    ///
    /// Recognized by shape alone, so a credential of another kind is never offered to the JWT
    /// library to be refused as malformed, and the dots keep it apart from an API key.
    fn recognizes(&self, token: BearerToken<'_>) -> Recognition {
        shape(token.as_str())
    }

    fn authenticate<'a>(&'a self, token: BearerToken<'a>) -> AuthenticationFuture<'a> {
        Box::pin(async move {
            let claims = self.validator.validate(token).await.map_err(|error| {
                warn!(error = %error, "token validation failed");
                refusal(&error)
            })?;

            Ok(authentication(claims))
        })
    }
}

/// Whether `token` has the shape of a compact JWS.
fn shape(token: &str) -> Recognition {
    let mut segments = token.split('.');
    let three = segments.by_ref().take(3).filter(|segment| is_base64url(segment)).count() == 3;

    if three && segments.next().is_none() {
        Recognition::Recognized
    } else {
        Recognition::Unrecognized
    }
}

/// Whether a segment is non-empty base64url without padding (RFC 7515 section 2).
fn is_base64url(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// The shared reason for a validation failure.
const fn refusal(error: &ValidationError) -> Refusal {
    match error {
        ValidationError::Malformed => Refusal::Malformed,
        ValidationError::UnusableName(_) => Refusal::UnusableName,
        ValidationError::MissingKeyId | ValidationError::UnknownKey { .. } => Refusal::UnknownCredential,
        ValidationError::Expired => Refusal::Expired,
        ValidationError::NotYetValid => Refusal::NotYetValid,
        ValidationError::UntrustedIssuer => Refusal::UntrustedIssuer,
        ValidationError::UntrustedAudience => Refusal::UntrustedAudience,
        ValidationError::MissingRequiredClaim { .. } => Refusal::MissingClaim,
        ValidationError::UnexpectedAlgorithm => Refusal::UnexpectedAlgorithm,
        ValidationError::UnexpectedTokenType => Refusal::UnexpectedTokenType,
        ValidationError::BadSignature => Refusal::Mismatch,
        // Raised when the key set could not be consulted, and for a library refusal with no more
        // specific reason. Neither is a statement about the token being bad.
        ValidationError::Rejected => Refusal::Unavailable,
    }
}

/// The caller a validated token describes.
///
/// An account named by its subject. The token carries no claim Libra reads that would fill a
/// username, an email address or a statement that the caller is a machine, so none is made up.
fn authentication(claims: Claims) -> Authentication {
    let identity = claims.policy_identity();
    let Claims { sub, client_id, .. } = claims;

    Authentication {
        identity,
        caller: CallerProfile {
            subject: Some(sub),
            username: None,
            email: None,
            client: client_id,
            kind: CallerKind::Unstated,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registered_claim::RegisteredClaim;
    use libra_identity_jwks::key_id::KeyId;
    use libra_policy_model::{
        error::IdentityError,
        identity::{ClientId, GroupName, IdentityName, PolicyIdentity, RoleName, Subject, Username},
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn a_compact_jws_is_recognized_and_nothing_else_is() {
        assert_eq!(shape("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"), Recognition::Recognized);
        assert_eq!(shape("aaa.bbb.ccc"), Recognition::Recognized);

        for other in ["libra_01J9ZQ4X7K2V3M5N6P8R9S0T1V_3yZe7d", "a.b", "a.b.c.d", "a..c", "a.b!.c", ".b.c", "a.b."] {
            assert_eq!(shape(other), Recognition::Unrecognized, "{other}");
        }
    }

    #[test]
    fn every_validation_error_maps_to_a_refusal() {
        let table = [
            (ValidationError::Malformed, Refusal::Malformed),
            (
                ValidationError::UnusableName(IdentityError {
                    kind: "group",
                    reason: "it is empty",
                }),
                Refusal::UnusableName,
            ),
            (ValidationError::MissingKeyId, Refusal::UnknownCredential),
            (
                ValidationError::UnknownKey {
                    kid: "k".parse::<KeyId>().unwrap(),
                },
                Refusal::UnknownCredential,
            ),
            (ValidationError::Expired, Refusal::Expired),
            (ValidationError::NotYetValid, Refusal::NotYetValid),
            (ValidationError::UntrustedIssuer, Refusal::UntrustedIssuer),
            (ValidationError::UntrustedAudience, Refusal::UntrustedAudience),
            (ValidationError::MissingRequiredClaim { claim: RegisteredClaim::Exp }, Refusal::MissingClaim),
            (ValidationError::UnexpectedAlgorithm, Refusal::UnexpectedAlgorithm),
            (ValidationError::UnexpectedTokenType, Refusal::UnexpectedTokenType),
            (ValidationError::BadSignature, Refusal::Mismatch),
            (ValidationError::Rejected, Refusal::Unavailable),
        ];

        for (error, expected) in table {
            assert_eq!(refusal(&error), expected, "{error}");
        }
    }

    #[test]
    fn a_token_authenticates_the_account_its_subject_names() {
        let caller = authentication(Claims {
            sub: Subject::new("alice-uuid").unwrap(),
            client_id: Some(ClientId::new("dashboard").unwrap()),
            groups: vec![GroupName::new("ops").unwrap()],
            roles: vec![RoleName::new("reader").unwrap()],
        });

        assert_eq!(
            caller.identity,
            PolicyIdentity {
                name: Some(IdentityName::Account(Username::new("alice-uuid").unwrap())),
                groups: vec![GroupName::new("ops").unwrap()],
                roles: vec![RoleName::new("reader").unwrap()],
            }
        );
        assert_eq!(
            caller.caller,
            CallerProfile {
                subject: Some(Subject::new("alice-uuid").unwrap()),
                username: None,
                email: None,
                client: Some(ClientId::new("dashboard").unwrap()),
                kind: CallerKind::Unstated,
            },
            "nothing the token does not say is said about the caller"
        );
    }

    #[test]
    fn a_token_in_one_identity_providers_layout_holds_nothing_beyond_its_subject() {
        // What a Keycloak token looks like when its mappers are left at their defaults. Only standard
        // claims are read, so its roles, client, username and service-account naming are not.
        let keycloak: Claims = serde_json::from_str(
            r#"{
                "sub": "9f1c-uuid",
                "azp": "ngsi-client",
                "preferred_username": "service-account-ingest",
                "realm_access": { "roles": ["fleet-admin"] },
                "resource_access": { "ngsi-client": { "roles": ["admin"] } }
            }"#,
        )
        .unwrap();

        let caller = authentication(keycloak);

        assert_eq!(caller.identity.roles, [] as [_; 0]);
        assert_eq!(caller.caller.client, None);
        assert_eq!(caller.caller.username, None);
        assert_eq!(caller.caller.kind, CallerKind::Unstated, "a username prefix does not make a machine");
    }
}
