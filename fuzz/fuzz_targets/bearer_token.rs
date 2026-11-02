//! An `Authorization` header, read as a bearer token and validated against a key set.
//!
//! Nobody holds the private half of the key the validator trusts, so no input may be accepted:
//! whatever the header, the payload or the `kid` says, the signature still has to verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::{runtime, token_validator};
use libra_identity_authenticator::bearer_token::BearerToken;

fuzz_target!(|header: &str| {
    let Ok(token) = BearerToken::from_header(header) else {
        return;
    };

    let outcome = runtime::shared().block_on(token_validator::unsignable().validate(token));
    assert!(outcome.is_err(), "a token was accepted without a signature anyone could make");
});
