//! Tokens, signed the way an identity provider signs them, by an issuer the suite runs itself.
//!
//! The issuer is one signing key per test process and an origin serving its JWKS, started the first
//! time a test needs it. Its tokens carry only the claims Libra reads: `sub`, `groups`, `roles` at
//! the top level, as RFC 9068 places them, so what the suite tests is a real signature over the
//! claims a standard identity provider issues.

use crate::{origin::Origin, signing_key::SigningKey};
use jsonwebtoken::get_current_timestamp;
use libra_config::{audience::Audience, issuer::Issuer};
use serde_json::{Value, json};
use std::sync::OnceLock;
use url::Url;

/// The `iss` every suite token carries. Only an identifier: nothing is fetched from it.
pub const ISSUER: &str = "https://issuer.libra.test";

/// The `aud` every suite token carries, and the audience every suite proxy requires.
pub const AUDIENCE: &str = "ngsi-client";

/// How long a suite token is valid for, in seconds.
const LIFETIME_SECONDS: u64 = 3600;

/// The issuer the suite runs: its key, and the origin publishing it.
struct SuiteIssuer {
    key: SigningKey,
    keys: Origin,
}

/// The suite's issuer, started on first use and kept for the life of the test process.
fn suite() -> &'static SuiteIssuer {
    static SUITE: OnceLock<SuiteIssuer> = OnceLock::new();

    SUITE.get_or_init(|| {
        let key = SigningKey::generate("suite-key");
        let keys = Origin::serving("application/json", &SigningKey::jwks(&[&key]));

        SuiteIssuer { key, keys }
    })
}

/// Where the suite's JWKS is served.
#[must_use]
pub fn jwks_url() -> Url {
    suite().keys.endpoint("/certs")
}

/// [`ISSUER`], as the configuration reads it.
///
/// # Panics
///
/// Panics if [`ISSUER`] is not an issuer identifier, which would be a mistake in the harness.
#[must_use]
pub fn issuer() -> Issuer {
    Issuer::new(ISSUER.to_owned()).expect("the suite issuer is an issuer identifier")
}

/// [`AUDIENCE`], as the configuration reads it.
///
/// # Panics
///
/// Panics if [`AUDIENCE`] is not an audience, which would be a mistake in the harness.
#[must_use]
pub fn audience() -> Audience {
    Audience::new(AUDIENCE.to_owned()).expect("the suite audience is an audience")
}

/// The groups and roles a suite user holds.
///
/// Any name is a user; the ones listed here are the users a test about groups or roles relies on.
fn assigned(user: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match user {
        "admin" => (&[], &["libra-admin"]),
        "fleet-reader" => (&[], &["fleet-operator"]),
        "operator" => (&["operations"], &[]),
        _unlisted => (&[], &[]),
    }
}

/// The claims of a token for `user`: the suite's issuer and audience, valid for an hour, with the
/// user's groups and roles.
///
/// A test that is about one claim edits this value and signs it with [`sign`].
#[must_use]
pub fn claims(user: &str) -> Value {
    let (groups, roles) = assigned(user);
    let now = get_current_timestamp();

    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": user,
        "iat": now,
        "exp": now + LIFETIME_SECONDS,
        "groups": groups,
        "roles": roles,
    })
}

/// Signs `claims` with the suite's key.
#[must_use]
pub fn sign(claims: &Value) -> String {
    suite().key.sign(claims)
}

/// An access token for `user`.
#[must_use]
pub fn token(user: &str) -> String {
    sign(&claims(user))
}
