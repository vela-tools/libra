//! Why a credential was refused, in one vocabulary shared by every kind of credential.

use derive_more::Display;

/// Why an authenticator refused a credential it recognized.
///
/// Every reason answers the caller the same way. They are distinguished for the operator: an
/// expired key and a forged one are the same 401 and completely different events. Each
/// authenticator logs its own detailed error before mapping it here, so nothing above it depends on
/// any one credential's error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Refusal {
    /// The credential is not well formed for its kind.
    #[display("malformed")]
    Malformed,
    /// The credential is well formed and verifies, but names the caller, a client, a group or a
    /// role with a name no policy can hold. The issuer is the one to fix it.
    #[display("unusable name")]
    UnusableName,
    /// The credential names a key or a signer this deployment does not hold.
    #[display("unknown credential")]
    UnknownCredential,
    /// The credential's secret or signature does not verify.
    #[display("does not verify")]
    Mismatch,
    /// The credential's lifetime has ended.
    #[display("expired")]
    Expired,
    /// The credential's lifetime has not begun.
    #[display("not yet valid")]
    NotYetValid,
    /// The credential was revoked.
    #[display("revoked")]
    Revoked,
    /// The credential was issued by an issuer this deployment does not trust.
    #[display("untrusted issuer")]
    UntrustedIssuer,
    /// The credential is not addressed to this deployment.
    #[display("untrusted audience")]
    UntrustedAudience,
    /// The credential is signed with an algorithm this deployment does not accept.
    #[display("unexpected algorithm")]
    UnexpectedAlgorithm,
    /// The credential declares itself to be a kind of token this deployment does not accept as a
    /// credential, or declares nothing where it requires a declaration.
    #[display("unexpected token type")]
    UnexpectedTokenType,
    /// The credential omits something this deployment requires of it.
    #[display("missing claim")]
    MissingClaim,
    /// What the credential is checked against could not be reached.
    ///
    /// Refused, not waved through: a credential that cannot be checked is not one Libra accepts.
    #[display("verification unavailable")]
    Unavailable,
}
