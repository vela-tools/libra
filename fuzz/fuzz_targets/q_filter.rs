//! A `q` expression (ETSI GS CIM 009 v1.9.1 clause 4.9).
//!
//! A narrowed filter is written back out and forwarded, so what Libra writes has to read back as
//! what it meant: rendering the reread filter gives the same text.
//!
//! An accepted expression holds no control character: no production of the grammar admits one.
//!
//! The tree may regroup on the way: `;` and `|` are each associative, so `a|(b|c)` is written
//! `a|b|c` and read back as `(a|b)|c`, which is the same expression. The text may not change.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::core_context;
use libra_ngsi_ld_query::filter::Filter;

fuzz_target!(|source: &str| {
    let Ok(filter) = Filter::parse(source) else {
        return;
    };

    // No grammar admits a control character, so an accepted expression holds none.
    assert!(!source.chars().any(char::is_control), "{source:?}");

    let rendered = filter.to_string();
    let reread = Filter::parse(&rendered).map(|reread| reread.to_string());
    assert_eq!(reread.as_deref(), Ok(rendered.as_str()), "{source:?}");

    let _ = filter.attributes();
    let _ = filter.traverses_linked_entities();
    if let Ok(expanded) = filter.expand(core_context::resolved()) {
        let _ = expanded.root_attributes();
        let _ = expanded.to_string();
    }
});
