//! Access token validation: signature, expiry, issuer and audience.
//!
//! A token that comes out of [`TokenValidator::validate`] has had its signature verified against a
//! key the configured identity provider published, under the one algorithm configuration allows,
//! has been checked against the issuer and audience the deployment declared, and names a subject.
//! [`authenticator::JwtAuthenticator`] puts this behind the authenticator seam.
//!
//! The settings are taken once, at construction, and the [`jsonwebtoken::Validation`] they produce
//! is built once and reused, so the rules a request is judged by are fixed before any request
//! arrives rather than assembled at the moment of judging.
//!
//! This crate returns a typed [`ValidationError`] and knows nothing about HTTP. Turning a rejection
//! into a response, and deciding how much of the reason to tell the caller, belongs to the layer.

use crate::{registered_claim::RegisteredClaim, token_type::admits};
use jsonwebtoken::{
    Algorithm,
    Validation,
    decode,
    decode_header,
    errors::{Error as JwtError, ErrorKind as JwtErrorKind},
};
use libra_config::{
    audience::Audience,
    issuer::Issuer,
    jwt::{AccessTokenType, Jwt, SignatureAlgorithm},
};
use libra_identity_authenticator::bearer_token::BearerToken;
use libra_identity_claims::{Claims, UncheckedClaims};
use libra_identity_jwks::{KeyStore, error::KeyStoreError, key_id::KeyId};
use libra_policy_model::error::IdentityError;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, warn};

pub mod authenticator;
pub mod registered_claim;
pub mod token_type;

/// Why a token was not accepted.
///
/// Deliberately typed rather than a ready-made HTTP problem: this crate does not depend on
/// `libra-problem-details`, so the layer above decides what a caller is told. The distinctions
/// here exist for logs and metrics: "expired" and "signature does not verify" are the same 401 to
/// a caller and completely different events to an operator.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// The token is not a well-formed JWT, or its header or payload is not one Libra can read: its
    /// key id is not one any published key can carry, or it names no subject.
    #[error("the token is not a well-formed JWT, or its claims cannot be read")]
    Malformed,

    /// The signed token carries a subject, client, group or role that cannot be a policy name.
    ///
    /// Told apart from [`ValidationError::Malformed`] because the fix is the identity provider's:
    /// it issued a well-formed token whose names Libra cannot carry. The error names the kind of
    /// name and the reason, never the name, which the identity provider chose.
    #[error("the token carries an unusable name: {0}")]
    UnusableName(IdentityError),

    /// The token header names no key, so there is nothing to look up.
    ///
    /// Rejected rather than guessed at. Choosing a key for a token that did not name one is the
    /// first half of accepting a token signed by whichever key happens to work.
    #[error("the token header carries no key id")]
    MissingKeyId,

    /// The key the token names is not one the identity provider publishes.
    #[error("no signing key matches the key id in the token header")]
    UnknownKey {
        /// The `kid` the token header carried. Attacker-chosen text: it comes from a header that
        /// has not been verified at the point this is built, so log it as a structured field
        /// rather than splicing it into a message.
        kid: KeyId,
    },

    /// The token's `exp` has passed, allowing for the configured clock skew.
    #[error("the token has expired")]
    Expired,

    /// The token's `nbf` has not been reached.
    #[error("the token is not valid yet")]
    NotYetValid,

    /// The token's `iss` is not the configured issuer.
    #[error("the token was issued by an issuer this deployment does not trust")]
    UntrustedIssuer,

    /// The token's `aud` does not include the configured audience.
    #[error("the token is not addressed to this audience")]
    UntrustedAudience,

    /// A claim the configuration requires is absent from the token.
    ///
    /// The claim name comes from Libra's own required list, never from the token.
    #[error("the token omits the required '{claim}' claim")]
    MissingRequiredClaim {
        /// Which spec claim was missing.
        claim: RegisteredClaim,
    },

    /// The token header names an algorithm other than the configured one.
    #[error("the token is signed with an algorithm this deployment does not accept")]
    UnexpectedAlgorithm,

    /// The token header's `typ` is not the access token type the configuration requires.
    #[error("the token is not declared to be an access token")]
    UnexpectedTokenType,

    /// The signature does not verify under the named key.
    #[error("the token signature does not verify")]
    BadSignature,

    /// The token was rejected for a reason with no more specific variant.
    #[error("the token was rejected")]
    Rejected,
}

/// Everything the validator needs to judge a token, resolved once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationSettings {
    /// The one algorithm a token signature may use.
    ///
    /// Pinned from configuration and never read from the token header. A validator that trusts the
    /// header's `alg` lets the token choose how it is verified, which is how an RSA public key
    /// gets used as an HMAC secret.
    pub algorithm: Algorithm,

    /// The `typ` header a token must carry.
    pub token_type: AccessTokenType,

    /// The issuer a token must name.
    pub issuer: Issuer,

    /// The audience a token must be addressed to.
    pub audience: Audience,

    /// Tolerance applied to `exp` and `nbf`, in seconds.
    pub clock_skew_seconds: u64,
}

impl From<&Jwt> for ValidationSettings {
    fn from(jwt: &Jwt) -> Self {
        // The configuration is only borrowed, and the validator outlives it.
        Self {
            algorithm: jwt_algorithm(jwt.algorithm),
            token_type: jwt.token_type,
            issuer: jwt.issuer.clone(),
            audience: jwt.audience.clone(),
            clock_skew_seconds: jwt.clock_skew_seconds,
        }
    }
}

/// Maps the configuration's algorithm enum onto the JWT library's.
///
/// `libra-config` declares its own enum so that it stays free of the token-validation stack; this
/// crate owns the concept, so the translation lives here. Every variant is listed: a new algorithm
/// appearing in configuration must be an explicit decision here rather than falling through to a
/// default.
const fn jwt_algorithm(configured: SignatureAlgorithm) -> Algorithm {
    match configured {
        SignatureAlgorithm::Rs256 => Algorithm::RS256,
        SignatureAlgorithm::Rs384 => Algorithm::RS384,
        SignatureAlgorithm::Rs512 => Algorithm::RS512,
        SignatureAlgorithm::Ps256 => Algorithm::PS256,
        SignatureAlgorithm::Ps384 => Algorithm::PS384,
        SignatureAlgorithm::Ps512 => Algorithm::PS512,
    }
}

/// Validates access tokens against a JWKS keystore.
///
/// Cheap to clone: the keystore is shared and the validation rules are a small immutable struct.
#[derive(Clone)]
pub struct TokenValidator {
    keystore: KeyStore,
    validation: Validation,
    token_type: AccessTokenType,
}

impl TokenValidator {
    /// Builds a validator that will judge every token by these settings.
    #[must_use]
    pub fn new(keystore: KeyStore, settings: &ValidationSettings) -> Self {
        let mut validation = Validation::new(settings.algorithm);

        validation.leeway = settings.clock_skew_seconds;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        validation.set_issuer(&[settings.issuer.as_str()]);
        validation.set_audience(&[settings.audience.as_str()]);
        validation.validate_aud = true;

        // `set_issuer` and `set_audience` only compare a claim that is *present*, so on their own
        // they are fail-open: a token carrying no `iss` at all passes an issuer check, and a token
        // carrying no `aud` passes an audience check. Requiring the claims is what closes that.
        // `sub` needs no entry here: the library reads the payload into `Claims` before it checks
        // anything, and `Claims` cannot be read without one.
        validation.set_required_spec_claims(&[RegisteredClaim::Exp, RegisteredClaim::Iss, RegisteredClaim::Aud]);

        Self {
            keystore,
            validation,
            token_type: settings.token_type,
        }
    }

    /// Validates a token and returns its claims.
    ///
    /// The key is chosen by the `kid` in the token header, which is unverified at that point, so
    /// it selects a key rather than allowing anything, and the signature then has to verify under
    /// that one key.
    ///
    /// # Errors
    ///
    /// Returns the [`ValidationError`] describing why the token was not accepted.
    pub async fn validate(&self, token: BearerToken<'_>) -> Result<Claims, ValidationError> {
        let header = decode_header(token.as_str()).map_err(|error| {
            warn!(%error, "the token header could not be read");
            ValidationError::Malformed
        })?;

        // Before the key lookup: a token that declares itself something other than an access token
        // is refused without costing a key fetch. The header is unverified here, which is enough
        // to refuse on and never enough to accept on, because the signature is still checked.
        if !admits(self.token_type, header.typ.as_deref()) {
            return Err(ValidationError::UnexpectedTokenType);
        }

        let Some(kid) = header.kid else {
            return Err(ValidationError::MissingKeyId);
        };

        // Checked before the id reaches a log line or the key store: it is attacker-chosen text,
        // and an id no published key can carry is refused without a key fetch.
        let kid = KeyId::try_from(kid).map_err(|error| {
            warn!(%error, "the token header carries a key id Libra does not accept");
            ValidationError::Malformed
        })?;

        debug!(kid = %kid, "validating a token");

        // The keystore takes the id and hands it back with a refusal, so the one the error
        // carries is the one the header named.
        let key = match self.keystore.get_or_refresh(kid).await {
            Ok(key) => key,
            Err(KeyStoreError::UnknownKeyId { kid }) => {
                warn!(kid = %kid, "the token names a signing key Libra does not hold");
                return Err(ValidationError::UnknownKey { kid });
            }
            Err(
                error @ (KeyStoreError::Client { .. }
                | KeyStoreError::Fetch { .. }
                | KeyStoreError::Status { .. }
                | KeyStoreError::TooLarge { .. }
                | KeyStoreError::Parse { .. }
                | KeyStoreError::NoUsableKey { .. }),
            ) => {
                warn!(%error, "the signing key could not be looked up");
                return Err(ValidationError::Rejected);
            }
        };

        let token_data = decode::<UncheckedClaims>(token.as_str(), &key, &self.validation).map_err(|error| {
            warn!(%error, "token rejected");
            classify(error)
        })?;

        Claims::try_from(token_data.claims).map_err(ValidationError::UnusableName)
    }
}

/// Turns the JWT library's error into the one this crate publishes.
///
/// Written as a chain rather than a `match` because the library's error kind is another crate's
/// enum: a variant added upstream must land on [`ValidationError::Rejected`] rather than stopping
/// the build, and nothing here may depend on the set being closed.
fn classify(error: JwtError) -> ValidationError {
    let kind = error.into_kind();

    if matches!(&kind, JwtErrorKind::ExpiredSignature) {
        ValidationError::Expired
    } else if matches!(&kind, JwtErrorKind::ImmatureSignature) {
        ValidationError::NotYetValid
    } else if matches!(&kind, JwtErrorKind::InvalidIssuer) {
        ValidationError::UntrustedIssuer
    } else if matches!(&kind, JwtErrorKind::InvalidAudience) {
        ValidationError::UntrustedAudience
    } else if matches!(&kind, JwtErrorKind::InvalidAlgorithm) {
        ValidationError::UnexpectedAlgorithm
    } else if matches!(&kind, JwtErrorKind::InvalidSignature) {
        ValidationError::BadSignature
    } else if matches!(&kind, JwtErrorKind::Json(_)) {
        // The payload is read into `Claims` once the signature verifies, so this is a signed token
        // whose claims cannot be read, not a failure to consult anything.
        ValidationError::Malformed
    } else if let JwtErrorKind::MissingRequiredClaim(claim) = &kind
        && let Ok(claim) = RegisteredClaim::from_str(claim)
    {
        ValidationError::MissingRequiredClaim { claim }
    } else {
        ValidationError::Rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::get_current_timestamp;
    use libra_config::jwt::JwksTransport;
    use libra_log_capture::captured;
    use libra_policy_model::identity::{ClientId, GroupName, RoleName, Subject};
    use libra_test_harness::signing_key::SigningKey;
    use pretty_assertions::assert_eq;
    use serde_json::{Value, json};
    use std::sync::OnceLock;
    use url::Url;
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{method, path},
    };

    /// The key id every test token names.
    const KID: &str = "test-signing-key";

    /// The issuer a test deployment declares.
    const ISSUER: &str = "https://idp.example.invalid/realms/fiware";

    /// The audience a test deployment declares.
    const AUDIENCE: &str = "ngsi-broker";

    fn issuer() -> Issuer {
        Issuer::new(ISSUER.to_owned()).expect("the test issuer is an issuer identifier")
    }

    fn audience() -> Audience {
        Audience::new(AUDIENCE.to_owned()).expect("the test audience is an audience")
    }

    /// One key for the whole test binary. Generating a 2048-bit key is expensive enough that doing
    /// it per test would dominate the run.
    fn test_key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();

        KEY.get_or_init(|| SigningKey::generate(KID))
    }

    fn expires_in(seconds: u64) -> u64 {
        get_current_timestamp() + seconds
    }

    /// The claims of a token this deployment accepts, with `changes` applied: a `null` removes a
    /// claim, anything else replaces it.
    fn claims_with(changes: &Value) -> Value {
        let mut claims = json!({ "sub": "alice-uuid", "iss": ISSUER, "aud": AUDIENCE, "exp": expires_in(3600) });

        if let (Some(target), Some(changes)) = (claims.as_object_mut(), changes.as_object()) {
            for (name, value) in changes {
                if value.is_null() {
                    target.remove(name);
                } else {
                    target.insert(name.clone(), value.clone()); // the fixture owns its claims
                }
            }
        }

        claims
    }

    /// A token this deployment accepts, with `changes` applied as in [`claims_with`].
    fn mint(changes: &Value) -> String {
        test_key().sign(&claims_with(changes))
    }

    fn settings() -> ValidationSettings {
        ValidationSettings {
            algorithm: Algorithm::RS256,
            token_type: AccessTokenType::Any,
            issuer: issuer(),
            audience: audience(),
            clock_skew_seconds: 0,
        }
    }

    /// The mock server has to outlive the validator, so it is returned alongside it.
    async fn validator(settings: ValidationSettings) -> (MockServer, TokenValidator) {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SigningKey::jwks(&[test_key()])))
            .mount(&server)
            .await;

        let keystore = KeyStore::new(Url::parse(&format!("{}/certs", server.uri())).expect("the mock server address is a URL"))
            .await
            .expect("building the keystore");

        (server, TokenValidator::new(keystore, &settings))
    }

    async fn validate(token: &str) -> Result<Claims, ValidationError> {
        let (_server, validator) = validator(settings()).await;

        validator.validate(BearerToken::from(token)).await
    }

    #[tokio::test]
    async fn a_token_that_omits_the_issuer_is_rejected() {
        // The most important test in this crate. `Validation::set_issuer` compares `iss` only when
        // the claim is present, so on its own an issuer check is fail-open: a token minted by any
        // identity provider whose signing key ends up in the configured JWKS, or one that simply
        // leaves `iss` out, passes an issuer check that looks configured and enforced.
        assert_eq!(
            validate(&mint(&json!({ "iss": null }))).await,
            Err(ValidationError::MissingRequiredClaim { claim: RegisteredClaim::Iss }),
            "a token with no issuer must not satisfy the configured issuer"
        );
    }

    #[tokio::test]
    async fn a_token_from_another_issuer_is_rejected() {
        assert_eq!(
            validate(&mint(&json!({ "iss": "https://evil.example.invalid/realms/fiware" }))).await,
            Err(ValidationError::UntrustedIssuer)
        );
    }

    #[tokio::test]
    async fn a_token_carrying_the_configured_issuer_and_audience_is_accepted() {
        assert_eq!(
            validate(&mint(&json!({}))).await.map(|claims| claims.sub),
            Ok(Subject::new("alice-uuid").unwrap())
        );
    }

    #[tokio::test]
    async fn a_token_that_omits_the_audience_is_rejected() {
        // The same fail-open shape as the issuer check, for the claim that says which service the
        // token was minted for. Without it, a token issued for any other client of the same issuer
        // is accepted here.
        assert_eq!(
            validate(&mint(&json!({ "aud": null }))).await,
            Err(ValidationError::MissingRequiredClaim { claim: RegisteredClaim::Aud })
        );
    }

    #[tokio::test]
    async fn a_token_addressed_to_another_audience_is_rejected() {
        assert_eq!(
            validate(&mint(&json!({ "aud": "some-other-service" }))).await,
            Err(ValidationError::UntrustedAudience)
        );
    }

    #[tokio::test]
    async fn a_token_that_names_no_subject_is_rejected_as_malformed() {
        // Otherwise the token authenticates nobody in particular, and every role it lists would
        // belong to an anonymous caller.
        assert_eq!(validate(&mint(&json!({ "sub": null }))).await, Err(ValidationError::Malformed));
    }

    #[tokio::test]
    async fn a_signed_token_carrying_a_name_no_policy_can_hold_is_refused_for_that_reason() {
        // A group carrying the comma the broker header splits on is a well-formed, signed token
        // whose names cannot be carried, neither malformed nor a failure to consult the key set.
        let refused = validate(&mint(&json!({ "groups": ["fleet", "ops,admins"] }))).await;

        assert!(
            matches!(refused, Err(ValidationError::UnusableName(error)) if error.kind == "group"),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn an_unusable_name_reaches_neither_the_error_nor_the_log() {
        let (outcome, records) = captured(validate(&mint(&json!({ "roles": ["viewer", "forged\nlevel=ERROR someone-else"] })))).await;

        let Err(refused) = outcome else {
            panic!("a role with a control character must be refused");
        };
        assert!(!refused.to_string().contains("forged"), "{refused}");
        for record in &records {
            assert!(!record.mentions("forged") && !record.mentions("someone-else"), "{record:?}");
        }
    }

    #[tokio::test]
    async fn a_token_that_omits_the_expiry_is_rejected() {
        // `exp` is required whatever else is configured: a token with no expiry is a token that
        // never stops being usable once it leaks.
        assert_eq!(
            validate(&mint(&json!({ "exp": null }))).await,
            Err(ValidationError::MissingRequiredClaim { claim: RegisteredClaim::Exp })
        );
    }

    #[tokio::test]
    async fn a_token_signed_with_an_algorithm_other_than_the_configured_one_is_rejected() {
        // The algorithm is pinned from configuration and never taken from the token header. This
        // token is signed with the same key by the same issuer and is still refused, because the
        // header asked to be verified a different way.
        let mut header = test_key().header();
        header.alg = Algorithm::RS512;

        assert_eq!(
            validate(&test_key().sign_with(&header, &claims_with(&json!({})))).await,
            Err(ValidationError::UnexpectedAlgorithm)
        );
    }

    /// A token whose header declares `typ`, or declares none, with otherwise acceptable claims.
    fn mint_typed(typ: Option<&str>) -> String {
        let mut header = test_key().header();
        header.typ = typ.map(str::to_owned);

        test_key().sign_with(&header, &claims_with(&json!({})))
    }

    async fn validate_requiring_access_token_type(token: &str) -> Result<Claims, ValidationError> {
        let (_server, validator) = validator(ValidationSettings {
            token_type: AccessTokenType::AtJwt,
            ..settings()
        })
        .await;

        validator.validate(BearerToken::from(token)).await
    }

    #[tokio::test]
    async fn an_id_token_is_refused_when_the_access_token_type_is_required() {
        // An ID token from the same issuer, for the same audience, signed by the same key, carries
        // `typ: JWT`. Everything else about it is acceptable, so the type is the only thing standing
        // between it and being used as an access token.
        for typ in [Some("JWT"), Some("id_token"), None] {
            assert_eq!(
                validate_requiring_access_token_type(&mint_typed(typ)).await,
                Err(ValidationError::UnexpectedTokenType),
                "{typ:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_access_token_is_accepted_when_the_access_token_type_is_required() {
        for typ in ["at+jwt", "AT+JWT", "application/at+jwt"] {
            assert_eq!(
                validate_requiring_access_token_type(&mint_typed(Some(typ))).await.map(|claims| claims.sub),
                Ok(Subject::new("alice-uuid").unwrap()),
                "{typ}"
            );
        }
    }

    #[tokio::test]
    async fn an_id_token_is_accepted_when_no_token_type_is_required() {
        for typ in [Some("JWT"), Some("at+jwt"), None] {
            assert_eq!(
                validate(&mint_typed(typ)).await.map(|claims| claims.sub),
                Ok(Subject::new("alice-uuid").unwrap()),
                "{typ:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_token_of_the_wrong_type_is_refused_before_its_key_is_looked_up() {
        // The key id here is one nobody published. Were the key consulted first, the refusal would
        // be an unknown key.
        let mut header = test_key().header();
        header.typ = Some("JWT".to_owned());
        header.kid = Some("a-key-nobody-published".to_owned());

        assert_eq!(
            validate_requiring_access_token_type(&test_key().sign_with(&header, &claims_with(&json!({})))).await,
            Err(ValidationError::UnexpectedTokenType)
        );
    }

    #[tokio::test]
    async fn an_expired_token_is_rejected() {
        assert_eq!(
            validate(&mint(&json!({ "exp": get_current_timestamp() - 3600 }))).await,
            Err(ValidationError::Expired)
        );
    }

    #[tokio::test]
    async fn a_token_that_is_not_valid_yet_is_rejected() {
        // `nbf` is checked as well as `exp`: a token minted ahead of time must not be usable ahead
        // of time.
        assert_eq!(
            validate(&mint(&json!({ "exp": expires_in(7200), "nbf": expires_in(3600) }))).await,
            Err(ValidationError::NotYetValid)
        );
    }

    #[tokio::test]
    async fn the_configured_clock_skew_is_the_only_tolerance_applied_to_expiry() {
        let (_server, validator) = validator(ValidationSettings {
            clock_skew_seconds: 120,
            ..settings()
        })
        .await;

        let just_expired = mint(&json!({ "exp": get_current_timestamp() - 30 }));
        assert!(
            validator.validate(BearerToken::from(just_expired.as_str())).await.is_ok(),
            "30 seconds is inside a 120 second tolerance"
        );

        let long_expired = mint(&json!({ "exp": get_current_timestamp() - 300 }));
        assert_eq!(
            validator.validate(BearerToken::from(long_expired.as_str())).await,
            Err(ValidationError::Expired)
        );
    }

    #[tokio::test]
    async fn a_tampered_signature_is_rejected() {
        let token = mint(&json!({}));
        let (message, signature) = token.rsplit_once('.').expect("a JWT has three parts");

        let mut characters: Vec<char> = signature.chars().collect();
        characters[0] = if characters[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{message}.{}", characters.into_iter().collect::<String>());

        assert_eq!(validate(&tampered).await, Err(ValidationError::BadSignature));
    }

    #[tokio::test]
    async fn a_token_naming_a_key_libra_does_not_hold_is_rejected() {
        let mut header = test_key().header();
        header.kid = Some("a-key-nobody-published".to_owned());

        assert_eq!(
            validate(&test_key().sign_with(&header, &claims_with(&json!({})))).await,
            Err(ValidationError::UnknownKey {
                kid: "a-key-nobody-published".parse::<KeyId>().unwrap()
            })
        );
    }

    #[tokio::test]
    async fn a_key_id_carrying_a_newline_is_refused_before_it_reaches_the_log() {
        let mut header = test_key().header();
        header.kid = Some("forged\nlevel=ERROR message=\"someone else did this\"".to_owned());

        let (outcome, records) = captured(validate(&test_key().sign_with(&header, &claims_with(&json!({}))))).await;

        assert_eq!(outcome, Err(ValidationError::Malformed));
        for record in &records {
            assert!(!record.mentions("forged") && !record.mentions("someone else"), "{record:?}");
        }
    }

    #[tokio::test]
    async fn a_token_naming_no_key_at_all_is_rejected_rather_than_tried_against_every_key() {
        let mut header = test_key().header();
        header.kid = None;

        assert_eq!(
            validate(&test_key().sign_with(&header, &claims_with(&json!({})))).await,
            Err(ValidationError::MissingKeyId)
        );
    }

    #[tokio::test]
    async fn something_that_is_not_a_jwt_is_rejected_without_reaching_the_keystore() {
        assert_eq!(validate("not-a-token").await, Err(ValidationError::Malformed));
        assert_eq!(validate("").await, Err(ValidationError::Malformed));
    }

    #[tokio::test]
    async fn a_valid_token_yields_the_standard_claims_it_carries() {
        let token = mint(&json!({ "client_id": "dashboard", "groups": ["ops"], "roles": ["reader"] }));

        assert_eq!(
            validate(&token).await,
            Ok(Claims {
                sub: Subject::new("alice-uuid").unwrap(),
                client_id: Some(ClientId::new("dashboard").unwrap()),
                groups: vec![GroupName::new("ops").unwrap()],
                roles: vec![RoleName::new("reader").unwrap()],
            })
        );
    }

    #[test]
    fn every_configured_algorithm_maps_to_the_library_algorithm_of_the_same_name() {
        // A new algorithm reaching configuration has to be decided here rather than silently
        // becoming whichever one a default arm named.
        assert_eq!(jwt_algorithm(SignatureAlgorithm::Rs256), Algorithm::RS256);
        assert_eq!(jwt_algorithm(SignatureAlgorithm::Rs384), Algorithm::RS384);
        assert_eq!(jwt_algorithm(SignatureAlgorithm::Rs512), Algorithm::RS512);
        assert_eq!(jwt_algorithm(SignatureAlgorithm::Ps256), Algorithm::PS256);
        assert_eq!(jwt_algorithm(SignatureAlgorithm::Ps384), Algorithm::PS384);
        assert_eq!(jwt_algorithm(SignatureAlgorithm::Ps512), Algorithm::PS512);
    }

    #[test]
    fn the_settings_are_read_from_the_jwt_configuration_section() {
        let jwt = Jwt {
            jwks_url: Url::parse("https://idp.example.invalid/certs").unwrap(),
            jwks_transport: JwksTransport::HttpsOnly,
            jwks_cache_duration: 3600,
            algorithm: SignatureAlgorithm::Ps512,
            token_type: AccessTokenType::AtJwt,
            issuer: issuer(),
            audience: audience(),
            clock_skew_seconds: 30,
        };

        assert_eq!(
            ValidationSettings::from(&jwt),
            ValidationSettings {
                algorithm: Algorithm::PS512,
                token_type: AccessTokenType::AtJwt,
                issuer: issuer(),
                audience: audience(),
                clock_skew_seconds: 30,
            }
        );
    }
}
