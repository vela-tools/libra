//! What the world outside authorization is told about an authenticated caller.

use libra_policy_model::identity::{ClientId, EmailAddress, Subject, Username};

/// Whether the caller is known to be a machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CallerKind {
    /// The credential does not say. Every caller a standard JWT authenticates.
    #[default]
    Unstated,
    /// The caller is a machine: every holder of a Libra-issued API key, and any caller an
    /// authenticator a build adds knows to be one.
    Machine,
}

/// The caller as propagated to the broker, written into the audit record and named by the
/// management gate.
///
/// Kept apart from the [`PolicyIdentity`](libra_policy_model::identity::PolicyIdentity) on
/// purpose: the policy engine matches names people write into policies, and nothing here is one
/// of them except through that type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerProfile {
    /// The stable identifier of the caller, for the audit record and `X-Auth-Subject`.
    pub subject: Option<Subject>,
    /// The caller's login name, for `X-Auth-Username`, when the credential states one.
    pub username: Option<Username>,
    /// The caller's email address, for `X-Auth-Email`.
    pub email: Option<EmailAddress>,
    /// The OAuth client the credential was issued to, for the management gate's client list.
    pub client: Option<ClientId>,
    /// Whether the caller is a machine, for `X-Auth-Machine`.
    pub kind: CallerKind,
}
