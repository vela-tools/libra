//! The seam between a presented credential and the caller a policy is about.
//!
//! Every credential Libra accepts, whatever its kind, is turned into the same two values: a
//! [`PolicyIdentity`](libra_policy_model::identity::PolicyIdentity), which is all authorization
//! ever sees, and a [`caller::CallerProfile`], which is what the broker, the audit record and the
//! management gate are told about the caller. An [`authenticator::Authenticator`] does that for one
//! kind of credential; [`authenticators::Authenticators`] is the list a deployment runs, and
//! decides which one judges a credential.
//!
//! Nothing here knows HTTP. Reading the `Authorization` header is the one step that is about the
//! wire, and it ends at [`bearer_token::BearerToken`].

pub mod authentication;
pub mod authenticator;
pub mod authenticators;
pub mod bearer_token;
pub mod caller;
pub mod refusal;
