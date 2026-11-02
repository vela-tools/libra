//! A token validator whose key set nobody can sign for.
//!
//! The endpoint publishes one RSA public key, `fuzz-key`, whose modulus and exponent decode and
//! nothing more, so no private key exists that a signature could be made with.

use crate::{jwks_endpoint::JwksEndpoint, runtime};
use jsonwebtoken::Algorithm;
use libra_config::{audience::Audience, issuer::Issuer, jwt::AccessTokenType};
use libra_identity_jwks::KeyStore;
use libra_identity_jwt::{TokenValidator, ValidationSettings};
use std::{sync::LazyLock, time::Duration};

/// The published key set.
const KEY_SET: &[u8] = br#"{"keys":[{"kid":"fuzz-key","kty":"RSA","use":"sig","n":"vYM0rC14e5a-vM_1gX-5jQ","e":"AQAB"}]}"#;

/// Long enough that a token naming an unknown key costs no fetch during a run.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(3600);

/// The endpoint lives as long as the process, as the validator reading from it does.
static ENDPOINT: LazyLock<JwksEndpoint> = LazyLock::new(|| JwksEndpoint::start(KEY_SET));

static VALIDATOR: LazyLock<TokenValidator> = LazyLock::new(|| {
    // The store keeps its own copy of the address.
    let keystore = runtime::shared()
        .block_on(KeyStore::with_refresh_cooldown(ENDPOINT.url().clone(), REFRESH_COOLDOWN))
        .expect("the published key set loads");

    let settings = ValidationSettings {
        algorithm: Algorithm::RS256,
        token_type: AccessTokenType::Any,
        issuer: Issuer::new("https://idp.example.test/realms/fuzz".to_owned()).expect("the issuer is an https URL"),
        audience: Audience::new("libra".to_owned()).expect("the audience is one word"),
        clock_skew_seconds: 0,
    };

    TokenValidator::new(keystore, &settings)
});

/// The shared validator.
#[must_use]
pub fn unsignable() -> &'static TokenValidator {
    &VALIDATOR
}
