//! A `type` selection, with its `;`, `|` and brackets (ETSI GS CIM 009 v1.9.1 clause 4.17).
//!
//! A narrowed selection is written back out and forwarded, so what Libra writes has to read back as
//! what it meant: rendering the reread selection gives the same text.
//!
//! An accepted expression holds no control character: no production of the grammar admits one.
//!
//! The tree may regroup on the way: `;` and `|` are each associative, so `a|(b|c)` is written
//! `a|b|c` and read back as `(a|b)|c`, which is the same expression. The text may not change.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::core_context;
use libra_ngsi_ld_query::type_selection::TypeSelection;

fuzz_target!(|source: &str| {
    let Ok(selection) = TypeSelection::parse(source) else {
        return;
    };

    // No grammar admits a control character, so an accepted expression holds none.
    assert!(!source.chars().any(char::is_control), "{source:?}");

    let rendered = selection.to_string();
    let reread = TypeSelection::parse(&rendered).map(|reread| reread.to_string());
    assert_eq!(reread.as_deref(), Ok(rendered.as_str()), "{source:?}");

    let _ = selection.types();
    let _ = selection.expanded(core_context::resolved());
});
