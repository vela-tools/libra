//! The NGSI-LD core context, processed once, for targets that expand terms.

use libra_jsonld_context::core_context::process;
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use std::sync::LazyLock;

/// The core context alone: what a request that supplies no context of its own is resolved against
/// (ETSI GS CIM 009 v1.9.1 clause 5.5.7).
static CORE: LazyLock<ResolvedContext> = LazyLock::new(|| process().expect("the embedded core context processes"));

/// The processed core context.
#[must_use]
pub fn resolved() -> &'static ResolvedContext {
    &CORE
}
