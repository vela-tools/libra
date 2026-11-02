//! The claims of a token payload, as read once its signature verifies.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_identity_claims::Claims;
use serde_json::from_slice;

fuzz_target!(|payload: &[u8]| {
    if let Ok(claims) = from_slice::<Claims>(payload) {
        let _ = claims.policy_identity();
    }
});
