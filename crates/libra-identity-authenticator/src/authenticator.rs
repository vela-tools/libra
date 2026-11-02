//! One kind of credential, turned into a caller.

use crate::{authentication::Authentication, bearer_token::BearerToken, refusal::Refusal};
use std::{future::Future, pin::Pin};

/// The future an [`Authenticator`] answers with.
///
/// Boxed because authenticators are held as trait objects, which cannot return `impl Future`.
pub type AuthenticationFuture<'a> = Pin<Box<dyn Future<Output = Result<Authentication, Refusal>> + Send + 'a>>;

/// Whether an authenticator is the one to judge a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recognition {
    /// The credential is of this authenticator's kind.
    Recognized,
    /// The credential is of some other kind.
    Unrecognized,
}

/// Turns one kind of credential into a caller.
///
/// Recognition is decided by the credential's syntax alone, without I/O, and must not overlap
/// another authenticator's: a credential two authenticators recognize is refused, so that which
/// one judges it never depends on the order they were registered in.
pub trait Authenticator: Send + Sync {
    /// Whether `token` is of this authenticator's kind.
    fn recognizes(&self, token: BearerToken<'_>) -> Recognition;

    /// Judges a credential this authenticator recognized.
    ///
    /// Answers [`Refusal`] for every credential it does not accept, including one that cannot be
    /// checked because what it is checked against is unavailable.
    fn authenticate<'a>(&'a self, token: BearerToken<'a>) -> AuthenticationFuture<'a>;
}
