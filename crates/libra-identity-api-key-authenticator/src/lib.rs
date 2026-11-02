//! Authenticating callers who present a Libra API key.
//!
//! The key is parsed, looked up by its id, and its secret checked against the stored verifier
//! before anything else about it is considered, so whether a key is revoked or expired is only
//! ever told to a caller who holds its secret. Every request reads the store: there is no cache, so
//! a revocation applies to the next request.

use jiff::Timestamp;
use libra_identity_api_key::{PREFIX, presented_key::PresentedKey};
use libra_identity_authenticator::{
    authentication::Authentication,
    authenticator::{AuthenticationFuture, Authenticator, Recognition},
    bearer_token::BearerToken,
    caller::{CallerKind, CallerProfile},
    refusal::Refusal,
};
use libra_identity_key_store::{key::StoredKey, store::ApiKeyStore};
use libra_policy_model::identity::Subject;
use tracing::{error, warn};

/// Authenticates callers presenting a Libra API key.
#[derive(Debug, Clone)]
pub struct ApiKeyAuthenticator {
    store: ApiKeyStore,
}

impl ApiKeyAuthenticator {
    /// Authenticates against `store`.
    #[must_use]
    pub const fn new(store: ApiKeyStore) -> Self {
        Self { store }
    }

    async fn judge(&self, token: BearerToken<'_>, now: Timestamp) -> Result<Authentication, Refusal> {
        let presented = PresentedKey::parse(token.as_str()).map_err(|error| {
            warn!(error = %error, "a credential with the API key prefix is not a well-formed key");
            Refusal::Malformed
        })?;
        let id = presented.id();

        let stored = match self.store.lookup(id).await {
            Ok(Some(stored)) => stored,
            Ok(None) => {
                warn!(key = %id, "no key has this id");
                return Err(Refusal::UnknownCredential);
            }
            Err(failure) => {
                error!(key = %id, error = %failure, "the key store could not be read");
                return Err(Refusal::Unavailable);
            }
        };

        let StoredKey {
            verifier,
            expires_at,
            revoked_at,
            principal,
        } = stored;

        if verifier.verify(id, presented.secret()).is_err() {
            warn!(key = %id, "the key's secret does not match its verifier");
            return Err(Refusal::Mismatch);
        }

        if revoked_at.is_some() {
            warn!(key = %id, "the key is revoked");
            return Err(Refusal::Revoked);
        }

        if expires_at <= now {
            warn!(key = %id, "the key has expired");
            return Err(Refusal::Expired);
        }

        // No username: a principal is not an account, and the broker must not be able to mistake
        // one for the other. It is identified by its URN, which also outlives its name.
        Ok(Authentication {
            caller: CallerProfile {
                subject: Some(Subject::from(principal.id)),
                username: None,
                email: None,
                client: None,
                kind: CallerKind::Machine,
            },
            identity: principal.identity(),
        })
    }
}

impl Authenticator for ApiKeyAuthenticator {
    /// Any credential that starts with the Libra prefix and its separator, so a malformed key is
    /// refused as a key rather than offered to an authenticator that would refuse it for a less
    /// useful reason.
    fn recognizes(&self, token: BearerToken<'_>) -> Recognition {
        let recognized = token.as_str().strip_prefix(PREFIX).is_some_and(|rest| rest.starts_with('_'));

        if recognized { Recognition::Recognized } else { Recognition::Unrecognized }
    }

    fn authenticate<'a>(&'a self, token: BearerToken<'a>) -> AuthenticationFuture<'a> {
        Box::pin(self.judge(token, Timestamp::now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;
    use libra_identity_api_key::api_key::ApiKey;
    use libra_identity_key_store::{key::NewKey, principal::NewPrincipal};
    use libra_policy_model::identity::{GroupName, IdentityName, PrincipalName, RoleName};
    use pretty_assertions::assert_eq;
    use secrecy::ExposeSecret;
    use tempfile::TempDir;

    struct Fixture {
        _directory: TempDir,
        store: ApiKeyStore,
        authenticator: ApiKeyAuthenticator,
    }

    async fn fixture() -> Fixture {
        let directory = TempDir::new().unwrap();
        let store = ApiKeyStore::open(&directory.path().join("keys.db")).await.unwrap();
        store
            .create_principal(
                NewPrincipal {
                    name: PrincipalName::new("ingest").unwrap(),
                    groups: vec![GroupName::new("fleet").unwrap()],
                    roles: vec![RoleName::new("writer").unwrap()],
                },
                Timestamp::now(),
            )
            .await
            .unwrap();

        Fixture {
            _directory: directory,
            authenticator: ApiKeyAuthenticator::new(store.clone()),
            store,
        }
    }

    /// Issues a key for `ingest` expiring `lifetime` from now, and returns it as presented.
    async fn issue(fixture: &Fixture, lifetime: SignedDuration) -> (ApiKey, String) {
        let now = Timestamp::now();
        let key = ApiKey::generate(now).unwrap();
        fixture
            .store
            .insert_key(&NewKey {
                id: *key.id(),
                principal: PrincipalName::new("ingest").unwrap(),
                verifier: key.verifier(),
                created_at: now,
                expires_at: now + lifetime,
            })
            .await
            .unwrap();
        let text = key.reveal().expose_secret().to_owned();

        (key, text)
    }

    async fn judge(fixture: &Fixture, text: &str) -> Result<Authentication, Refusal> {
        fixture.authenticator.authenticate(BearerToken::from(text)).await
    }

    const HOUR: SignedDuration = SignedDuration::from_hours(1);

    #[tokio::test]
    async fn a_valid_key_authenticates_as_its_principal() {
        let fixture = fixture().await;
        let (_, text) = issue(&fixture, HOUR).await;

        let authentication = judge(&fixture, &text).await.unwrap();

        assert_eq!(
            authentication.identity.name,
            Some(IdentityName::Principal(PrincipalName::new("ingest").unwrap()))
        );
        assert_eq!(authentication.identity.groups, vec![GroupName::new("fleet").unwrap()]);
        assert_eq!(authentication.identity.roles, vec![RoleName::new("writer").unwrap()]);
        assert!(
            authentication
                .caller
                .subject
                .as_ref()
                .is_some_and(|subject| subject.as_str().starts_with("urn:libra:principal:"))
        );
        assert_eq!(authentication.caller.username, None);
        assert_eq!(authentication.caller.kind, CallerKind::Machine);
        assert_eq!(authentication.caller.email, None);
    }

    #[tokio::test]
    async fn a_key_nobody_issued_is_unknown() {
        let fixture = fixture().await;
        let never_stored = ApiKey::generate(Timestamp::now()).unwrap().reveal().expose_secret().to_owned();

        assert_eq!(judge(&fixture, &never_stored).await, Err(Refusal::UnknownCredential));
    }

    #[tokio::test]
    async fn the_wrong_secret_for_a_known_id_does_not_verify() {
        let fixture = fixture().await;
        let (key, _) = issue(&fixture, HOUR).await;
        let other = ApiKey::generate(Timestamp::now()).unwrap().reveal().expose_secret().to_owned();
        let forged = format!("libra_{}_{}", key.id(), other.rsplit('_').next().unwrap());

        assert_eq!(judge(&fixture, &forged).await, Err(Refusal::Mismatch));
    }

    #[tokio::test]
    async fn a_revoked_key_is_refused_from_the_next_request() {
        let fixture = fixture().await;
        let (key, text) = issue(&fixture, HOUR).await;
        assert!(judge(&fixture, &text).await.is_ok());

        fixture.store.revoke_key(*key.id(), Timestamp::now()).await.unwrap();

        assert_eq!(judge(&fixture, &text).await, Err(Refusal::Revoked));
    }

    #[tokio::test]
    async fn revocation_is_only_reported_to_a_caller_who_holds_the_secret() {
        let fixture = fixture().await;
        let (key, _) = issue(&fixture, HOUR).await;
        fixture.store.revoke_key(*key.id(), Timestamp::now()).await.unwrap();
        let other = ApiKey::generate(Timestamp::now()).unwrap().reveal().expose_secret().to_owned();
        let forged = format!("libra_{}_{}", key.id(), other.rsplit('_').next().unwrap());

        assert_eq!(judge(&fixture, &forged).await, Err(Refusal::Mismatch));
    }

    #[tokio::test]
    async fn an_expired_key_is_refused() {
        let fixture = fixture().await;
        let (_, text) = issue(&fixture, SignedDuration::from_secs(-1)).await;

        assert_eq!(judge(&fixture, &text).await, Err(Refusal::Expired));
    }

    #[tokio::test]
    async fn a_key_whose_principal_was_removed_is_unknown() {
        let fixture = fixture().await;
        let (_, text) = issue(&fixture, HOUR).await;
        fixture.store.remove_principal(&PrincipalName::new("ingest").unwrap()).await.unwrap();

        assert_eq!(judge(&fixture, &text).await, Err(Refusal::UnknownCredential));
    }

    #[tokio::test]
    async fn a_malformed_key_is_recognized_and_refused_as_malformed() {
        let fixture = fixture().await;
        let token = BearerToken::from("libra_not-a-key");

        assert_eq!(fixture.authenticator.recognizes(token), Recognition::Recognized);
        assert_eq!(judge(&fixture, "libra_not-a-key").await, Err(Refusal::Malformed));
    }

    #[tokio::test]
    async fn only_the_libra_prefix_is_recognized() {
        let fixture = fixture().await;

        for other in ["eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", "librarian_x", "libra", "seam_a_b"] {
            assert_eq!(fixture.authenticator.recognizes(BearerToken::from(other)), Recognition::Unrecognized, "{other}");
        }
    }
}
