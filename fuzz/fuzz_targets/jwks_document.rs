//! A JWKS document (RFC 7517 section 5) as an identity provider's endpoint serves it.
//!
//! A document the store accepts leaves it holding at least one key: an empty key set would refuse
//! every caller, so it is refused when it is read rather than cached.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::{jwks_endpoint::JwksEndpoint, runtime};
use libra_identity_jwks::KeyStore;
use std::{sync::LazyLock, time::Duration};

static ENDPOINT: LazyLock<JwksEndpoint> = LazyLock::new(|| JwksEndpoint::start(b"{}"));

fuzz_target!(|document: &[u8]| {
    ENDPOINT.serve(document);

    // The store keeps its own copy of the address.
    let store = runtime::shared().block_on(KeyStore::with_refresh_cooldown(ENDPOINT.url().clone(), Duration::ZERO));

    if let Ok(store) = store {
        assert!(store.has_keys());
    }
});
