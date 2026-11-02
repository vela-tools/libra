//! A self-contained JSON-LD `@context` value, processed and used to expand and compact terms.
//!
//! A name Libra compacts is forwarded, so a name compaction gives has to expand back to its IRI.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_jsonld_term_expansion::resolved::ResolvedContext;

fuzz_target!(|source: &str| {
    let Ok(context) = ResolvedContext::from_json(source) else {
        return;
    };

    for term in context.defined_terms() {
        let _ = context.defines(&term);
        let Some(iri) = context.expand(&term) else {
            continue;
        };
        if let Some(compacted) = context.compact(&iri) {
            assert_eq!(context.expand(&compacted).as_ref(), Some(&iri), "{source:?} compacts {iri:?} to {compacted:?}");
        }
    }
});
