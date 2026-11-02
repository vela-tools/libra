//! The authenticators a deployment runs, and which of them judges a credential.

use crate::{
    authentication::Authentication,
    authenticator::{Authenticator, Recognition},
    bearer_token::BearerToken,
    refusal::Refusal,
};
use std::sync::Arc;
use thiserror::Error;

/// Why no caller was established from a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthenticationError {
    /// No authenticator recognizes the credential.
    #[error("no authenticator recognizes the credential")]
    Unrecognized,

    /// More than one authenticator recognizes the credential.
    ///
    /// Refused rather than settled by order: which authenticator judges a credential must be a
    /// property of the credential, not of the order a binary registered them in.
    #[error("more than one authenticator recognizes the credential")]
    Ambiguous,

    /// The authenticator that recognized the credential refused it.
    #[error("the credential was refused: {0}")]
    Refused(Refusal),
}

/// The authenticators a deployment runs.
#[derive(Clone, Default)]
pub struct Authenticators {
    authenticators: Vec<Arc<dyn Authenticator>>,
}

impl Authenticators {
    /// The authenticators, in the order they are listed.
    #[must_use]
    pub const fn new(authenticators: Vec<Arc<dyn Authenticator>>) -> Self {
        Self { authenticators }
    }

    /// Whether there is no authenticator at all, so that every credential is unrecognized.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authenticators.is_empty()
    }

    /// Judges a credential by the one authenticator that recognizes it.
    ///
    /// A credential that authenticator refuses is never offered to another: falling through to the
    /// next would let a caller choose who judges them by how they shape the credential.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError`] when no caller is established.
    pub async fn authenticate(&self, token: BearerToken<'_>) -> Result<Authentication, AuthenticationError> {
        let mut recognizing = self
            .authenticators
            .iter()
            .filter(|authenticator| authenticator.recognizes(token) == Recognition::Recognized);

        let Some(authenticator) = recognizing.next() else {
            return Err(AuthenticationError::Unrecognized);
        };

        if recognizing.next().is_some() {
            return Err(AuthenticationError::Ambiguous);
        }

        authenticator.authenticate(token).await.map_err(AuthenticationError::Refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authenticator::AuthenticationFuture, caller::CallerProfile};
    use libra_policy_model::identity::{IdentityName, PolicyIdentity, Username};
    use pretty_assertions::assert_eq;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Recognizes tokens with its prefix, answers with its outcome, and counts how often it was asked.
    struct Stub {
        prefix: &'static str,
        outcome: Result<&'static str, Refusal>,
        asked: AtomicUsize,
    }

    impl Stub {
        fn new(prefix: &'static str, outcome: Result<&'static str, Refusal>) -> Arc<Self> {
            Arc::new(Self {
                prefix,
                outcome,
                asked: AtomicUsize::new(0),
            })
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }
    }

    impl Authenticator for Stub {
        fn recognizes(&self, token: BearerToken<'_>) -> Recognition {
            if token.as_str().starts_with(self.prefix) {
                Recognition::Recognized
            } else {
                Recognition::Unrecognized
            }
        }

        fn authenticate<'a>(&'a self, _token: BearerToken<'a>) -> AuthenticationFuture<'a> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let outcome = self.outcome.map(|name| Authentication {
                identity: PolicyIdentity {
                    name: Some(IdentityName::Account(Username::new(name).unwrap())),
                    ..PolicyIdentity::anonymous()
                },
                caller: CallerProfile::default(),
            });

            Box::pin(async move { outcome })
        }
    }

    fn list(stubs: &[&Arc<Stub>]) -> Authenticators {
        Authenticators::new(stubs.iter().map(|stub| Arc::clone(stub) as Arc<dyn Authenticator>).collect())
    }

    fn user(outcome: &Result<Authentication, AuthenticationError>) -> Option<&str> {
        match outcome.as_ref().ok().and_then(|authentication| authentication.identity.name.as_ref()) {
            Some(IdentityName::Account(user)) => Some(user.as_str()),
            Some(IdentityName::Principal(_)) | None => None,
        }
    }

    #[tokio::test]
    async fn the_one_authenticator_that_recognizes_a_credential_judges_it() {
        let keys = Stub::new("key_", Ok("ingest"));
        let tokens = Stub::new("jwt.", Ok("alice"));

        let outcome = list(&[&tokens, &keys]).authenticate(BearerToken::from("key_1")).await;

        assert_eq!(user(&outcome), Some("ingest"));
        assert_eq!(tokens.asked(), 0);
    }

    #[tokio::test]
    async fn a_credential_nobody_recognizes_is_refused() {
        let tokens = Stub::new("jwt.", Ok("alice"));

        let outcome = list(&[&tokens]).authenticate(BearerToken::from("something-else")).await;

        assert_eq!(outcome, Err(AuthenticationError::Unrecognized));
        assert_eq!(tokens.asked(), 0);
    }

    #[tokio::test]
    async fn a_credential_two_authenticators_recognize_is_refused_without_asking_either() {
        let first = Stub::new("x", Ok("first"));
        let second = Stub::new("x", Ok("second"));

        let outcome = list(&[&first, &second]).authenticate(BearerToken::from("x1")).await;

        assert_eq!(outcome, Err(AuthenticationError::Ambiguous));
        assert_eq!((first.asked(), second.asked()), (0, 0));
    }

    #[tokio::test]
    async fn a_refused_credential_is_never_offered_to_another_authenticator() {
        let keys = Stub::new("key_", Err(Refusal::Revoked));
        let anything = Stub::new("", Ok("anyone"));

        // `anything` recognizes every credential, so this is ambiguous before it is anything else:
        // the refusal of one authenticator cannot be routed round through a broader one.
        let outcome = list(&[&keys, &anything]).authenticate(BearerToken::from("key_1")).await;
        assert_eq!(outcome, Err(AuthenticationError::Ambiguous));

        let outcome = list(&[&keys]).authenticate(BearerToken::from("key_1")).await;
        assert_eq!(outcome, Err(AuthenticationError::Refused(Refusal::Revoked)));
        assert_eq!(anything.asked(), 0);
    }

    #[tokio::test]
    async fn no_authenticators_refuse_everything() {
        let outcome = Authenticators::default().authenticate(BearerToken::from("anything")).await;

        assert_eq!(outcome, Err(AuthenticationError::Unrecognized));
    }

    #[test]
    fn a_set_with_no_authenticator_says_so() {
        assert!(Authenticators::default().is_empty());
        assert!(!Authenticators::new(vec![Stub::new("a.", Ok("alice"))]).is_empty());
    }
}
