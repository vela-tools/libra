//! The headers and parameters that choose a representation: `Accept`, `Content-Type`, `options` and
//! `format`.
//!
//! The input holds one per line, in that order. A missing line is an absent value and an empty
//! line an empty one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_jsonld_context::channel::is_ld_json;
use libra_ngsi_ld_representation::{
    accept::MediaType,
    selection::{RepresentationSelection, ResponseRepresentation},
};

fuzz_target!(|text: &str| {
    let mut lines = text.split('\n');
    let (accept, content_type, options, format) = (lines.next(), lines.next(), lines.next(), lines.next());

    let _ = MediaType::negotiate(accept);
    let _ = MediaType::from_content_type(content_type);
    let _ = is_ld_json(content_type);
    let _ = RepresentationSelection::parse(options, format);
    let _ = ResponseRepresentation::parse(accept, options, format);
});
