//! A `Link` header (RFC 8288 section 3), where a request names its JSON-LD context.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_jsonld_context::{
    link_header::{ParamName, parse},
    resolver::CONTEXT_RELATION,
};

fuzz_target!(|header: &str| {
    let Ok(links) = parse(header) else {
        return;
    };

    for link in &links {
        let _ = link.has_relation(&CONTEXT_RELATION);
        let _ = link.param(&ParamName::Type);
    }
});
