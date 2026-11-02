//! What the layers below the audit layer tell it about the request.
//!
//! The audit layer sits near the top of the stack so that it sees every response, including the ones
//! authentication, tenant resolution, authorization and the hardening layers produce when they
//! refuse. A layer above its inner services cannot read the request extensions those services
//! insert, because the request has been moved down by then. So the audit layer puts one
//! [`AuditSlot`] into the request on the way in, and the layers that know something write it there.
//! The audit layer reads the slot back when the response arrives.
//!
//! This crate still knows nothing about claims, tenants or policies: a contributor passes the
//! already-checked identity, tenant and policy names it wants recorded.

use crate::credential::CredentialFingerprint;
use libra_policy_model::{
    identity::{Subject, TenantId},
    policy::PolicyId,
};
use serde::Serialize;
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex, PoisonError},
};
use strum::Display;

/// Whether the request was let through on the caller's own credentials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Display)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum Access {
    /// The caller presented credentials, or the request was refused before that mattered.
    #[default]
    Credentialed,
    /// There was no caller: the deployment allows public access and the request used it.
    Public,
}

/// The facts contributed so far.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contributions {
    /// The authenticated caller, absent when there was none.
    pub subject: Option<Subject>,
    /// The fingerprint of the credential presented, absent when there was none or the deployment
    /// configured no key to compute it with.
    pub credential: Option<CredentialFingerprint>,
    /// The tenant the request resolved to, absent when it named none.
    pub tenant: Option<TenantId>,
    /// How the caller got in.
    pub access: Access,
    /// The policy that decided the request, absent when none matched.
    pub policy: Option<PolicyId>,
}

/// The place contributors write to, shared by every clone and read once by the audit layer.
#[derive(Debug, Clone, Default)]
pub struct AuditSlot(Arc<Mutex<Contributions>>);

impl AuditSlot {
    /// Locks the slot, recovering from poisoning: nothing inside a critical section can panic, and
    /// a lost audit field is better than a lost request.
    fn lock(&self) -> impl DerefMut<Target = Contributions> + '_ {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records the fingerprint of the credential the caller presented.
    ///
    /// Computed by the caller, which holds both the token and the deployment's key: the slot
    /// never sees credential material, only the keyed digest that names it.
    pub fn record_credential(&self, fingerprint: CredentialFingerprint) {
        self.lock().credential = Some(fingerprint);
    }

    /// Records who the caller is.
    pub fn record_subject(&self, subject: Subject) {
        self.lock().subject = Some(subject);
    }

    /// Records which tenant the request resolved to.
    pub fn record_tenant(&self, tenant: TenantId) {
        self.lock().tenant = Some(tenant);
    }

    /// Records how the caller got in.
    pub fn record_access(&self, access: Access) {
        self.lock().access = access;
    }

    /// Records the policy that decided the request.
    pub fn record_policy(&self, policy: PolicyId) {
        self.lock().policy = Some(policy);
    }

    /// The fingerprint of the credential presented, absent when none was recorded.
    ///
    /// What a layer below authentication names the caller by in its own log lines: it tells one
    /// credential from another without writing down who holds it.
    #[must_use]
    pub fn credential(&self) -> Option<CredentialFingerprint> {
        self.lock().credential.clone() // the guard cannot outlive the lock, and the caller owns what it logs
    }

    /// What has been contributed.
    #[must_use]
    pub fn contributions(&self) -> Contributions {
        self.lock().clone() // the guard cannot outlive the lock, and the record owns its fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::FingerprintKey;
    use pretty_assertions::assert_eq;

    #[test]
    fn an_empty_slot_describes_an_unidentified_credentialed_request() {
        let slot = AuditSlot::default();

        assert_eq!(slot.contributions(), Contributions::default());
        assert_eq!(slot.contributions().access, Access::Credentialed);
    }

    #[test]
    fn every_clone_writes_to_the_same_place() {
        let slot = AuditSlot::default();
        let held_by_a_layer = slot.clone(); // the test exercises the handle's clone semantics

        held_by_a_layer.record_subject(Subject::new("alice").unwrap());
        held_by_a_layer.record_credential(FingerprintKey::new(&[3_u8; 32]).fingerprint("a token"));
        held_by_a_layer.record_tenant(TenantId::new("acme").unwrap());
        held_by_a_layer.record_access(Access::Public);
        held_by_a_layer.record_policy(PolicyId::new("fleet-read").unwrap());

        assert_eq!(
            slot.contributions(),
            Contributions {
                subject: Some(Subject::new("alice").unwrap()),
                credential: Some(FingerprintKey::new(&[3_u8; 32]).fingerprint("a token")),
                tenant: Some(TenantId::new("acme").unwrap()),
                access: Access::Public,
                policy: Some(PolicyId::new("fleet-read").unwrap()),
            }
        );
    }
}
