//! Which core terms a caller's context may not give another meaning.
//!
//! Libra composes the core context last and reads a core term with its core definition. A broker
//! that resolved the caller's definition instead, with a positional rule, would store what Libra
//! judged as `location` under the caller's IRI, so a caller context that defines a core term with
//! another IRI is refused.
//!
//! The refusal guards terms Libra judges by their IRI. The members of a `geoQ` (NGSI-LD clause
//! 5.2.13) are core terms too, but every reader of a geo-query in Libra takes them by their JSON
//! key and never expands them, so a caller's definition of one changes nothing Libra decides. The
//! Smart Data Models context defines `coordinates` as `geojson:coordinates` without defining the
//! `geojson` prefix; refusing that would refuse every request sending the most widely used
//! data-model context, for a term no decision reads.

use crate::error::ContextError;
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};

/// The `geoQ` members of NGSI-LD clause 5.2.13, which Libra reads by key and never by IRI.
const GEO_QUERY_MEMBERS: [&str; 4] = ["geometry", "coordinates", "georel", "geoproperty"];

/// Refuses a caller context that defines a core term Libra judges by IRI with another IRI.
///
/// Restating a core term with its own IRI, as a context that imports the core one does, is
/// accepted, and so is restating it in the core namespace over `http`, which expansion records as
/// the core IRI.
///
/// # Errors
///
/// Returns [`ContextError::RedefinesCoreTerm`] naming the first such term.
pub fn refuse_core_redefinition(core: &ResolvedContext, caller: &ResolvedContext) -> Result<(), ContextError> {
    caller
        .defined_terms()
        .find(|term| is_judged_by_iri(term) && core.defines(term) && caller.expand(term) != core.expand(term))
        .map_or(Ok(()), |term| Err(ContextError::RedefinesCoreTerm { term }))
}

/// Whether some decision in Libra reads `term` through its expansion.
fn is_judged_by_iri(term: &Term) -> bool {
    !GEO_QUERY_MEMBERS.contains(&term.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{Parse, Value};

    fn context(definitions: &str) -> ResolvedContext {
        let (value, _) = Value::parse_str(definitions).expect("the test context parses");
        ResolvedContext::from_value(&value).expect("the test context processes")
    }

    fn core() -> ResolvedContext {
        context(
            r#"{
            "location": "https://uri.etsi.org/ngsi-ld/location",
            "coordinates": "https://uri.etsi.org/ngsi-ld/coordinates",
            "geometry": "https://uri.etsi.org/ngsi-ld/geometry",
            "georel": "https://uri.etsi.org/ngsi-ld/georel",
            "geoproperty": "https://uri.etsi.org/ngsi-ld/geoproperty"
        }"#,
        )
    }

    #[test]
    fn a_core_term_given_another_iri_is_refused() {
        let caller = context(r#"{ "location": "https://example.test/probe#location" }"#);

        let refused = refuse_core_redefinition(&core(), &caller);

        assert!(matches!(refused, Err(ContextError::RedefinesCoreTerm { term }) if term == Term::new("location")));
    }

    #[test]
    fn the_smart_data_models_definition_of_coordinates_is_accepted() {
        // The prefix is never defined, so JSON-LD reads `geojson:coordinates` as an absolute IRI.
        let caller = context(r#"{ "coordinates": { "@container": "@list", "@id": "geojson:coordinates" } }"#);

        assert!(refuse_core_redefinition(&core(), &caller).is_ok());
    }

    #[test]
    fn every_geo_query_member_may_be_given_another_iri() {
        let caller = context(
            r#"{
            "coordinates": "https://example.test/probe#coordinates",
            "geometry": "https://example.test/probe#geometry",
            "georel": "https://example.test/probe#georel",
            "geoproperty": "https://example.test/probe#geoproperty"
        }"#,
        );

        assert!(refuse_core_redefinition(&core(), &caller).is_ok());
    }

    #[test]
    fn a_geo_query_member_beside_a_redefined_core_term_does_not_hide_the_refusal() {
        let caller = context(
            r#"{
            "coordinates": "geojson:coordinates",
            "location": "https://example.test/probe#location"
        }"#,
        );

        let refused = refuse_core_redefinition(&core(), &caller);

        assert!(matches!(refused, Err(ContextError::RedefinesCoreTerm { term }) if term == Term::new("location")));
    }

    #[test]
    fn a_term_the_core_context_does_not_define_is_the_callers() {
        let caller = context(r#"{ "Sensor": "https://example.test/probe#Sensor" }"#);

        assert!(refuse_core_redefinition(&core(), &caller).is_ok());
    }
}
