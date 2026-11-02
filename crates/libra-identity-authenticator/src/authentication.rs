//! What a successful authentication produces.

use crate::caller::CallerProfile;
use libra_policy_model::identity::PolicyIdentity;

/// An authenticated caller, as the two halves of the request path read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authentication {
    /// The names a policy matches, and all authorization ever sees.
    pub identity: PolicyIdentity,
    /// What propagation, the audit record and the management gate read.
    pub caller: CallerProfile,
}
