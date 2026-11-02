//! The `NGSILD-Tenant` header (ETSI GS CIM 009 v1.9.1 clause 6.3.14).
//!
//! Each line of the input is one copy of the header, and an empty input is a request without it.
//! A request that repeats the header is refused whatever the copies say, and a request that names a
//! tenant is never served without a caller.
#![no_main]

use http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use libra_config::multitenancy::{MissingTenantHeaderPolicy, Multitenancy};
use libra_tenant::{PublicAccess, TENANT_HEADER, Tenant, TenantError, resolve};

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    if !data.is_empty() {
        for line in data.split(|byte| *byte == b'\n') {
            let Ok(value) = HeaderValue::from_bytes(line) else {
                return;
            };
            headers.append(TENANT_HEADER, value);
        }
    }
    let copies = headers.get_all(TENANT_HEADER).iter().count();

    for policy in [
        MissingTenantHeaderPolicy::RequireHeader,
        MissingTenantHeaderPolicy::Authenticate,
        MissingTenantHeaderPolicy::AllowPublic,
    ] {
        let outcome = resolve(&headers, &Multitenancy { policy });

        if copies > 1 {
            assert!(matches!(outcome, Err(TenantError::Repeated)), "{outcome:?}");
        }
        if let Ok(resolution) = &outcome
            && matches!(resolution.tenant, Tenant::Named(_))
        {
            assert_eq!(resolution.public_access, PublicAccess::NotAllowed);
        }
    }
});
