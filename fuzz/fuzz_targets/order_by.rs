//! An `orderBy` value, and the attribute paths it ranks by.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::core_context;
use libra_ngsi_ld_query::ordering::Ordering;

fuzz_target!(|source: &str| {
    let Ok(ordering) = Ordering::parse(source) else {
        return;
    };

    for path in ordering.attributes() {
        let _ = path.expand(core_context::resolved());
    }
});
