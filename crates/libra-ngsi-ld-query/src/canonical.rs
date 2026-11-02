//! One spelling of a query, so two queries that mean the same thing look the same.
//!
//! Two places need this and they need the *same* answer from it. A policy condition that matches
//! on a query has to compare the policy's query with the request's, and a cache key has to be the
//! same key for two requests that asked for the same thing. Both break in the same way if the
//! comparison is textual: parameters in a different order, or a type written as a term on one side
//! and as its IRI on the other, are the same query and would not look like it.

use crate::{
    error::QueryError,
    filter::Filter,
    parameter_name::ParameterName,
    parameters::QueryParameters,
    projection::{PROJECTION_PARAMETERS, Projection},
    selector::{expand_list, is_term_valued},
    type_selection::TypeSelection,
};
use derive_more::Display;
use libra_jsonld_term_expansion::resolved::ResolvedContext;

/// A query rendered by [`canonicalise`].
///
/// A distinct type so a canonical query cannot be confused with, or compared against, a query as
/// written: two of these are equal exactly when the queries ask for the same thing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("{_0}")]
pub struct CanonicalQuery(String);

impl CanonicalQuery {
    /// The canonical query string, without a leading `?`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Renders a query in a form that depends only on what it asks for.
///
/// Parameters are ordered, names are expanded to IRIs, and lists of names are sorted and
/// deduplicated. Everything else is left exactly as the caller wrote it, because a value that is
/// not a name means what the broker says it means and Libra must not normalise it.
///
/// # Errors
///
/// Returns [`QueryError`] if a name cannot be expanded, or if a `q` expression is malformed.
/// Either is a query Libra cannot compare, and comparing it anyway would be comparing the wrong
/// thing.
pub fn canonicalise(parameters: &QueryParameters, context: &ResolvedContext) -> Result<CanonicalQuery, QueryError> {
    let mut canonical = QueryParameters::default();

    for (name, value) in parameters.iter() {
        // `iter` yields the parameters already ordered, and `set` preserves that order, so the
        // rendering below depends on the query's content and not on how it arrived.
        if *name == ParameterName::TYPE {
            // A type selection is an expression, not a list: `A;B` and `A|B` are different queries
            // and joining their expanded names with commas would make them one.
            // Each name is cloned into the canonical copy, which owns its own parameters.
            canonical.set(name.clone(), TypeSelection::parse(value)?.expanded(context)?.to_string());
        } else if PROJECTION_PARAMETERS.contains(name) {
            // A projection is parsed rather than split: `a|b` is `a,b`, and the commas inside
            // `a{b,c}` belong to the linked entity's projection, not to this one.
            canonical.set(name.clone(), Projection::parse(value)?.expanded(name, context)?.to_string());
        } else if is_term_valued(name) {
            let expanded = expand_list(name, value, context)?;
            let joined = expanded.iter().map(|iri| iri.as_str().to_owned()).collect::<Vec<_>>().join(",");
            canonical.set(name.clone(), joined); // the canonical form owns its keys, the request keeps its own
        } else if *name == ParameterName::Q {
            let filter = Filter::parse(value)?;
            canonical.set(name.clone(), filter.expand(context)?.to_string()); // as above
        } else {
            canonical.set(name.clone(), value); // as above
        }
    }

    Ok(CanonicalQuery(canonical.to_query_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
                "speed": "https://uri.fiware.org/ns/data-models#speed"
            }"#,
        )
        .unwrap()
    }

    fn canonical(source: &str) -> String {
        canonicalise(&QueryParameters::parse(source).unwrap(), &context()).unwrap().to_string()
    }

    #[test]
    fn parameter_order_does_not_change_the_query() {
        assert_eq!(canonical("type=Vehicle&limit=10"), canonical("limit=10&type=Vehicle"));
    }

    #[test]
    fn two_spellings_of_one_type_canonicalise_together() {
        // The bypass, in cache-key form: `?type=Car` and `?type=Vehicle` are one query under this
        // context, and a key that told them apart would serve one caller's answer to neither.
        assert_eq!(canonical("type=Car"), canonical("type=Vehicle"));
        assert_eq!(canonical("type=https://uri.fiware.org/ns/data-models%23Vehicle"), canonical("type=Vehicle"));
    }

    #[test]
    fn a_conjunction_and_a_disjunction_of_the_same_types_stay_different_queries() {
        assert_ne!(canonical("type=Vehicle;Car"), canonical("type=Vehicle|Car"));
        assert_eq!(canonical("type=Car|Vehicle"), canonical("type=Vehicle,Vehicle"));
    }

    #[test]
    fn a_list_of_names_is_ordered_and_deduplicated() {
        assert_eq!(canonical("attrs=speed,speed"), canonical("attrs=speed"));
        assert_eq!(canonical("type=Vehicle,Car"), canonical("type=Car,Vehicle"));
    }

    #[test]
    fn a_filter_is_canonicalised_through_its_names() {
        assert_eq!(canonical("q=speed>40"), canonical("q=https://uri.fiware.org/ns/data-models%23speed>40"));
    }

    #[test]
    fn either_projection_separator_is_the_same_query() {
        // Clause 4.21 makes `|` and `,` one operator.
        assert_eq!(canonical("pick=speed|brand"), canonical("pick=brand,speed"));
    }

    #[test]
    fn a_linked_entity_projection_is_canonicalised_through_its_inner_names() {
        assert_eq!(
            canonical("pick=observation{humidity|speed}"),
            canonical("pick=observation{https://uri.fiware.org/ns/data-models%23speed,humidity}")
        );
        assert_ne!(canonical("pick=observation{speed}"), canonical("pick=observation,speed"));
    }

    #[test]
    fn a_linked_entity_filter_canonicalises_rather_than_refusing() {
        // Clause 4.9 `LinkedEntityRelation`. Read as one name it could not be expanded, and every
        // caller would be refused.
        assert_eq!(
            canonical("q=sensor{speed}>40"),
            canonical("q=sensor{https://uri.fiware.org/ns/data-models%23speed}>40")
        );
    }

    #[test]
    fn a_value_that_is_not_a_name_is_left_alone() {
        // A scope is a path, a limit is a number, and a timestamp is a timestamp. Normalising any
        // of them would make Libra's idea of the query differ from the broker's.
        let rendered = canonical("scopeQ=/Madrid/Gardens&limit=10&timeAt=2026-01-01T00:00:00Z");

        assert!(rendered.contains("%2FMadrid%2FGardens"), "{rendered}");
        assert!(rendered.contains("limit=10"), "{rendered}");
        assert!(rendered.contains("2026-01-01T00%3A00%3A00Z"), "{rendered}");
    }

    #[test]
    fn a_name_that_cannot_be_expanded_refuses_rather_than_canonicalising_to_itself() {
        let bare = ResolvedContext::from_json(r#"{"Vehicle": "https://example.test/Vehicle"}"#).unwrap();
        let refused = canonicalise(&QueryParameters::parse("type=Mystery").unwrap(), &bare);

        assert!(refused.is_err(), "an unresolvable name must not become a cache key or a policy match");
    }

    #[test]
    fn the_canonical_form_is_stable_across_repeated_rendering() {
        let once = canonical("type=Vehicle&attrs=speed&q=speed>40");

        for _ in 0..16 {
            assert_eq!(canonical("q=speed>40&attrs=speed&type=Car"), once);
        }
    }
}
