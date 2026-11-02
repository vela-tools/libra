//! A projection, as `attrs`, `pick` and `omit` carry it (ETSI GS CIM 009 v1.9.1 clause 4.21).
//!
//! A narrowed projection is written back out and forwarded, so what Libra writes has to read back as
//! what it meant: rendering the reread projection gives the same text.
//!
//! An accepted expression holds no control character: no production of the grammar admits one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::core_context;
use libra_ngsi_ld_query::{parameter_name::ParameterName, projection::Projection};

fuzz_target!(|source: &str| {
    let Ok(projection) = Projection::parse(source) else {
        return;
    };

    // No grammar admits a control character, so an accepted expression holds none.
    assert!(!source.chars().any(char::is_control), "{source:?}");

    let rendered = projection.to_string();
    let reread = Projection::parse(&rendered).map(|reread| reread.to_string());
    assert_eq!(reread.as_deref(), Ok(rendered.as_str()), "{source:?}");

    let _ = projection.attributes().count();
    let _ = projection.reaches_linked_entities();
    let _ = projection.expanded(&ParameterName::PICK, core_context::resolved());
});
