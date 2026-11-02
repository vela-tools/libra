//! A context resolver that fetches nothing.
//!
//! Only the core context and what a request carries inline resolve: a target must not reach the
//! network, and a context it cannot fetch is refused exactly as a deployment with fetching
//! switched off refuses it.

use libra_config::jsonld::JsonLd;
use libra_jsonld_context::resolver::ContextResolver;
use std::sync::{Arc, LazyLock};

static RESOLVER: LazyLock<Arc<ContextResolver>> = LazyLock::new(|| {
    let config = JsonLd {
        allow_remote: false,
        ..JsonLd::default()
    };

    Arc::new(ContextResolver::new(&config).expect("a resolver with fetching switched off builds"))
});

/// The shared resolver.
#[must_use]
pub fn offline() -> Arc<ContextResolver> {
    Arc::clone(&RESOLVER)
}
