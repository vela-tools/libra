//! The registered JWT claims Libra can require a token to carry.

use strum::{Display, EnumString};

/// A registered claim name (RFC 7519 section 4.1) that validation can require.
///
/// Spelled as RFC 7519 spells it, because the names are compared against the token's own members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum RegisteredClaim {
    /// `exp`, the expiration time (RFC 7519 section 4.1.4).
    Exp,
    /// `nbf`, the not-before time (RFC 7519 section 4.1.5).
    Nbf,
    /// `iss`, the issuer (RFC 7519 section 4.1.1).
    Iss,
    /// `aud`, the audience (RFC 7519 section 4.1.3).
    Aud,
    /// `sub`, the subject (RFC 7519 section 4.1.2).
    Sub,
}

#[cfg(test)]
mod tests {
    use crate::registered_claim::RegisteredClaim;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    #[test]
    fn every_claim_is_spelled_as_rfc_7519_spells_it() {
        let spelled = [
            RegisteredClaim::Exp,
            RegisteredClaim::Nbf,
            RegisteredClaim::Iss,
            RegisteredClaim::Aud,
            RegisteredClaim::Sub,
        ]
        .map(|claim| claim.to_string());

        assert_eq!(spelled, ["exp", "nbf", "iss", "aud", "sub"]);
    }

    #[test]
    fn a_claim_name_reads_back_as_its_claim() {
        assert_eq!(RegisteredClaim::from_str("aud").ok(), Some(RegisteredClaim::Aud));
        assert!(RegisteredClaim::from_str("jti").is_err(), "a claim Libra never requires is not one of these");
    }
}
