//! The query string, decoded into parameters and read by every selector Libra derives from it.
//!
//! Rendering the parameters back out must give a string that decodes to the same parameters: a
//! narrowed query is forwarded in that rendering, so a difference would mean the broker acts on a
//! query other than the one Libra checked.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libra_fuzz::core_context;
use libra_ngsi_ld_query::{canonical::canonicalise, linked_entity::LinkedEntityRequest, parameters::QueryParameters, temporal_selector::TemporalSelector};

fuzz_target!(|query: &str| {
    let Ok(parameters) = QueryParameters::parse(query) else {
        return;
    };

    let rendered = parameters.to_query_string();
    assert_eq!(QueryParameters::parse(&rendered).as_ref(), Ok(&parameters), "{rendered}");

    let context = core_context::resolved();
    let _ = parameters.filter();
    let _ = parameters.entity_type_selection();
    let _ = parameters.expanded_entity_types(context);
    let _ = parameters.selected_attributes();
    let _ = parameters.aggregation_methods();
    let _ = parameters.aggregation_period();
    let _ = parameters.linked_entity_request();
    let _ = LinkedEntityRequest::of_query(&parameters, None);
    let _ = TemporalSelector::of_parameters(&parameters);
    let _ = canonicalise(&parameters, context);
});
