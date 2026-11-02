//! The context and restrictions the request-side unit tests judge against.

use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};
use libra_ngsi_ld_query::parameters::QueryParameters;
use libra_policy_model::attribute::{AttributeAction, CompiledAttributeRestriction};

/// A context defining `speed`, `brand` and `location`, with every other term under `@vocab`.
pub(crate) fn context() -> ResolvedContext {
    ResolvedContext::from_json(
        r#"{
            "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
            "speed": "https://uri.fiware.org/ns/data-models#speed",
            "brand": "https://uri.fiware.org/ns/data-models#brand",
            "location": "https://uri.etsi.org/ngsi-ld/location"
        }"#,
    )
    .expect("the test context should process")
}

/// What `term` means under [`context`].
fn iri(term: &str) -> ExpandedIri {
    context().expand(&Term::new(term)).expect("the term should expand")
}

/// A restriction hiding `terms`.
pub(crate) fn omitting(terms: &[&str]) -> CompiledAttributeRestriction {
    CompiledAttributeRestriction::new(AttributeAction::Omit, terms.iter().map(|term| iri(term)).collect())
}

/// A restriction allowing only `terms`.
pub(crate) fn picking(terms: &[&str]) -> CompiledAttributeRestriction {
    CompiledAttributeRestriction::new(AttributeAction::Pick, terms.iter().map(|term| iri(term)).collect())
}

/// A query string, parsed.
pub(crate) fn query(source: &str) -> QueryParameters {
    QueryParameters::parse(source).expect("the query should parse")
}
