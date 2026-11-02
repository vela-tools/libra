//! `[jwt]`: accepting JWT access tokens signed by a key from a JWKS document.
//!
//! The section is optional. A deployment that writes none accepts no JWT, and authenticates with
//! API keys alone.

use crate::{audience::Audience, issuer::Issuer};
use serde::{Deserialize, Serialize};
use url::Url;

/// Signature algorithm accepted for access tokens.
///
/// Declared here rather than reusing the JWT library's enum so this crate stays free of the
/// token-validation stack. The variant names are the JOSE `alg` values (RFC 7518 section 3.1), so
/// the file names an algorithm the way a token header does. `libra-identity-jwt` converts this into
/// the library type.
///
/// Only the RSA algorithms are offered, because the key set is read for RSA keys only: an `ES256`
/// or `EdDSA` deployment would load no key it could verify with, and an `HS256` one would treat
/// the provider's public key set as a shared secret. Naming any of them is refused when the file
/// is read, with the algorithms that are accepted listed.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    #[default]
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    #[serde(rename = "RS384")]
    Rs384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    #[serde(rename = "RS512")]
    Rs512,
    /// RSASSA-PSS with SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
    /// RSASSA-PSS with SHA-384.
    #[serde(rename = "PS384")]
    Ps384,
    /// RSASSA-PSS with SHA-512.
    #[serde(rename = "PS512")]
    Ps512,
}

/// Which `typ` header an access token must carry.
///
/// RFC 9068 section 4 makes a resource server require `at+jwt`, so that an ID token the same issuer
/// signed for the same audience cannot be presented as an access token. Many identity providers do
/// not yet emit that type, so insisting on it by default would refuse their tokens; a deployment
/// whose provider does emit it opts in by name.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AccessTokenType {
    /// A token that verifies is accepted whatever its `typ` says, or whether it says anything.
    #[default]
    Any,
    /// Only a token whose `typ` is `at+jwt`, or `application/at+jwt`, is accepted.
    AtJwt,
}

/// What the key set address may be.
///
/// Whoever can alter the response from the JWKS endpoint chooses which keys Libra trusts, so the
/// default refuses a plain-http address; a deployment that fetches keys over a trusted private
/// network opts in by name.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum JwksTransport {
    /// Only an `https` address is accepted.
    #[default]
    HttpsOnly,
    /// An `http` address is accepted as well, on the operator's word that the network is trusted.
    InsecureHttp,
}

/// How long a fetched key set is used before it is fetched again, when the file does not say.
const DEFAULT_JWKS_CACHE_SECONDS: u64 = 3600;

/// Tolerance applied to `exp` and `nbf` when the file does not say.
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 60;

/// JWT authentication: where the signing keys are, and what a token must say to be accepted.
///
/// Authentication only: Libra validates tokens, it does not obtain them. The issuer and the audience
/// are required because RFC 9068 section 4 makes both checks mandatory for a resource server: with
/// no audience, a token the same issuer minted for any other client is accepted here, and with no
/// issuer, so is a token from anyone whose key reaches the key set.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Jwt {
    /// URL of the JWKS document.
    pub jwks_url: Url,
    /// Whether an `http` key set address is accepted.
    #[serde(default)]
    pub jwks_transport: JwksTransport,
    /// How long to use a fetched key set before fetching it again, in seconds.
    #[serde(default = "default_jwks_cache_seconds")]
    pub jwks_cache_duration: u64,
    /// Algorithm accepted for token signatures.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
    /// The `typ` header an access token must carry.
    #[serde(default)]
    pub token_type: AccessTokenType,
    /// The issuer a token must name in `iss`.
    pub issuer: Issuer,
    /// The audience a token must name in `aud`.
    pub audience: Audience,
    /// Clock skew tolerance in seconds, applied to expiry and not-before.
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
}

/// Serde's default for [`Jwt::jwks_cache_duration`], which takes a function rather than a value.
const fn default_jwks_cache_seconds() -> u64 {
    DEFAULT_JWKS_CACHE_SECONDS
}

/// Serde's default for [`Jwt::clock_skew_seconds`], which takes a function rather than a value.
const fn default_clock_skew_seconds() -> u64 {
    DEFAULT_CLOCK_SKEW_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigError, pending::PendingConfig};
    use pretty_assertions::assert_eq;

    /// The smallest section that loads.
    const MINIMAL: &str = "[jwt]\njwks-url = \"https://idp.test/certs\"\nissuer = \"https://idp.test\"\naudience = \"ngsi-client\"";

    fn section(text: &str) -> Result<Option<Jwt>, ConfigError> {
        PendingConfig::from_toml_with_broker(text).map(|pending| pending.config().jwt.clone())
    }

    /// The message a file is refused with while it is being read into the model.
    fn refusal(text: &str) -> String {
        match PendingConfig::from_toml_with_broker(text) {
            Err(ConfigError::Extract(error)) => error.to_string(),
            other => panic!("expected the file to be refused while it is read, got {other:?}"),
        }
    }

    #[test]
    fn there_is_no_jwt_authentication_unless_the_section_is_written() {
        assert_eq!(section("").unwrap(), None);
        assert!(
            PendingConfig::from_toml_with_broker("").unwrap().finish().is_ok(),
            "an absent optional section is not an unclaimed one"
        );
    }

    #[test]
    fn a_minimal_section_loads_with_every_default_in_place() {
        assert_eq!(
            section(MINIMAL).unwrap(),
            Some(Jwt {
                jwks_url: Url::parse("https://idp.test/certs").unwrap(),
                jwks_transport: JwksTransport::HttpsOnly,
                jwks_cache_duration: 3600,
                algorithm: SignatureAlgorithm::Rs256,
                token_type: AccessTokenType::Any,
                issuer: Issuer::new("https://idp.test".to_owned()).unwrap(),
                audience: Audience::new("ngsi-client".to_owned()).unwrap(),
                clock_skew_seconds: 60,
            })
        );
        assert!(PendingConfig::from_toml_with_broker(MINIMAL).unwrap().finish().is_ok());
    }

    #[test]
    fn the_keys_a_token_is_judged_by_are_required() {
        // Without an issuer or an audience the checks RFC 9068 section 4 requires cannot be made,
        // and without a key set address there is nothing to verify a signature with.
        for (missing, without) in [
            ("jwks-url", "[jwt]\nissuer = \"https://idp.test\"\naudience = \"ngsi-client\""),
            ("issuer", "[jwt]\njwks-url = \"https://idp.test/certs\"\naudience = \"ngsi-client\""),
            ("audience", "[jwt]\njwks-url = \"https://idp.test/certs\"\nissuer = \"https://idp.test\""),
        ] {
            let message = refusal(without);

            assert!(message.contains(missing), "the refusal must name {missing}: {message}");
        }
    }

    #[test]
    fn every_optional_key_can_be_set() {
        let configured = section(&format!(
            "{MINIMAL}\njwks-transport = \"insecure-http\"\njwks-cache-duration = 30\nalgorithm = \"PS384\"\ntoken-type = \"at-jwt\"\nclock-skew-seconds = 5"
        ))
        .unwrap()
        .unwrap();

        assert_eq!(configured.jwks_transport, JwksTransport::InsecureHttp);
        assert_eq!(configured.jwks_cache_duration, 30);
        assert_eq!(configured.algorithm, SignatureAlgorithm::Ps384);
        assert_eq!(configured.token_type, AccessTokenType::AtJwt);
        assert_eq!(configured.clock_skew_seconds, 5);
    }

    #[test]
    fn a_mistyped_key_is_refused() {
        assert!(section(&format!("{MINIMAL}\njwks_url = \"https://idp.test/certs\"")).is_err());
        assert!(section(&format!("{MINIMAL}\nalgorithms = [\"RS256\"]")).is_err());
    }

    #[test]
    fn a_token_type_other_than_the_two_named_is_refused() {
        for written in ["at+jwt", "AT-JWT", "jwt", "required", ""] {
            assert!(
                section(&format!("{MINIMAL}\ntoken-type = \"{written}\"")).is_err(),
                "token-type = {written:?} must be refused"
            );
        }
    }

    #[test]
    fn the_former_keycloak_section_is_not_read() {
        let pending = PendingConfig::from_toml_with_broker("[keycloak]\njwks-url = \"https://idp.test/certs\"").unwrap();

        match pending.finish() {
            Err(ConfigError::UnclaimedSections { names }) => assert_eq!(names, ["keycloak"]),
            other => panic!("expected [keycloak] to be unclaimed, got {other:?}"),
        }
    }

    #[test]
    fn an_algorithm_the_key_set_cannot_verify_is_refused_naming_the_accepted_ones() {
        for written in ["HS256", "HS384", "HS512", "ES256", "ES384", "EdDSA", "none"] {
            let message = refusal(&format!("{MINIMAL}\nalgorithm = \"{written}\""));

            assert!(message.contains(written) && message.contains("RS256"), "{written}: {message}");
        }
    }

    #[test]
    fn every_algorithm_is_named_as_a_token_header_names_it() {
        for (written, algorithm) in [
            ("RS256", SignatureAlgorithm::Rs256),
            ("RS384", SignatureAlgorithm::Rs384),
            ("RS512", SignatureAlgorithm::Rs512),
            ("PS256", SignatureAlgorithm::Ps256),
            ("PS384", SignatureAlgorithm::Ps384),
            ("PS512", SignatureAlgorithm::Ps512),
        ] {
            assert_eq!(serde_json::from_str::<SignatureAlgorithm>(&format!("\"{written}\"")).unwrap(), algorithm);
        }
    }
}
