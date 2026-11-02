//! A JWK key id (RFC 7517 section 4.5) as a token header carries it, before any signature is checked.
//!
//! An accepted id is visible ASCII of at most 128 bytes, and nothing else is accepted: that is
//! what keeps an id from ending or forging a log line.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_identity_jwks::key_id::KeyId;

fuzz_target!(|text: &str| {
    let fits = text.len() <= 128 && text.bytes().all(|byte| byte.is_ascii_graphic());

    match text.parse::<KeyId>() {
        Ok(id) => {
            assert!(fits, "{text:?}");
            assert_eq!(id.to_string(), text);
        }
        Err(_) => assert!(!fits, "{text:?}"),
    }
});
