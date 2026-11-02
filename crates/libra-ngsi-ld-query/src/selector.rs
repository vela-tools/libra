//! The query parameters whose values are names, and the ones whose values are not.
//!
//! Splitting these apart is the whole point. `?type=Vehicle` and `?limit=10` are both `key=value`
//! pairs, but only one of them means something that a caller's `@context` can redefine. Anything
//! that compares a query against a policy has to expand the first kind and leave the second alone,
//! and it has to make the same choice on both sides of the comparison, so the list lives here,
//! once, rather than in each layer that happens to care.

use crate::{
    control_character::refuse_control_characters,
    error::QueryError,
    expansion::expand_term,
    filter::Filter,
    parameter_name::ParameterName,
    parameters::QueryParameters,
    projection::{PROJECTION_PARAMETERS, Projection},
    type_selection::TypeSelection,
};
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};

/// Parameters whose value is made of terms: a type selection, a projection (clause 4.21), or a
/// comma-separated list of names.
///
/// `q` is not here: its names are inside an expression and are reached through [`Filter`].
/// `scopeQ` is not here either: a scope is a path, not a name, and no context redefines it.
pub const TERM_VALUED: [ParameterName; 6] = [
    ParameterName::TYPE,
    ParameterName::ATTRS,
    ParameterName::PICK,
    ParameterName::OMIT,
    ParameterName::GEOPROPERTY,
    ParameterName::TIMEPROPERTY,
];

/// Whether the parameter called `name` is term-valued.
///
/// Whether a parameter has to be expanded before it can be compared is decided here and nowhere
/// else, so the two sides of a comparison make the same choice.
#[must_use]
pub fn is_term_valued(name: &ParameterName) -> bool {
    TERM_VALUED.contains(name)
}

/// Splits a comma-separated parameter value into terms.
///
/// Empty pieces are dropped: `?geoproperty=location,` names one attribute, and an empty name is not
/// a name. A projection is not split here: its grammar is [`Projection`]'s.
fn terms_of(value: &str) -> Vec<Term> {
    value.split(',').map(str::trim).filter(|piece| !piece.is_empty()).map(Term::new).collect()
}

/// Expands a comma-separated parameter value that is not a projection.
///
/// # Errors
///
/// Returns [`QueryError::ControlCharacter`] if the value holds a control character, and
/// [`QueryError::UnexpandableTerm`] if any piece has no meaning in this context. A name whose
/// meaning is unknown cannot be compared with a policy's name, so the caller must refuse.
pub fn expand_list(parameter: &ParameterName, value: &str, context: &ResolvedContext) -> Result<Vec<ExpandedIri>, QueryError> {
    refuse_control_characters(value)?;
    let mut expanded = Vec::new();

    for term in terms_of(value) {
        expanded.push(expand_term(parameter, &term, context)?);
    }

    expanded.sort();
    expanded.dedup();

    Ok(expanded)
}

impl QueryParameters {
    /// The parsed `type` selection, if the query has one.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::MalformedTypeSelection`] if the expression does not fit the grammar.
    pub fn entity_type_selection(&self) -> Result<Option<TypeSelection>, QueryError> {
        self.get(&ParameterName::TYPE).map(TypeSelection::parse).transpose()
    }

    /// Every entity type the query names, expanded, whichever connective joined them.
    ///
    /// A selection `A|B` and a selection `A;B` both name `A` and `B`: for deciding whether a policy
    /// about those types applies, what matters is which types the broker may answer with.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::MalformedTypeSelection`] if the expression does not parse, and
    /// [`QueryError::UnexpandableTerm`] if any type has no meaning in this context.
    pub fn expanded_entity_types(&self, context: &ResolvedContext) -> Result<Vec<ExpandedIri>, QueryError> {
        let Some(selection) = self.entity_type_selection()? else {
            return Ok(Vec::new());
        };

        let mut expanded = Vec::new();
        for term in selection.types() {
            expanded.push(expand_term(&ParameterName::TYPE, term, context)?);
        }

        expanded.sort();
        expanded.dedup();

        Ok(expanded)
    }

    /// The attributes the query asks for, as authored, from whichever selector it used.
    ///
    /// `attrs` and `pick` both narrow the response to the names they list; `omit` removes them.
    /// All three are returned, because an attribute restriction has to see every name the caller
    /// mentioned regardless of which parameter carried it. Only the attributes of the queried
    /// entities are returned, not those a linked-entity term reaches inside another entity.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::MalformedProjection`] if a selector does not fit the projection
    /// grammar.
    pub fn selected_attributes(&self) -> Result<Vec<Term>, QueryError> {
        let mut selected = Vec::new();

        for value in PROJECTION_PARAMETERS.iter().filter_map(|parameter| self.get(parameter)) {
            // Each name is cloned out of a projection that is dropped at the end of the iteration.
            selected.extend(Projection::parse(value)?.attributes().cloned());
        }

        Ok(selected)
    }

    /// The parsed `q` filter, if the query has one.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::MalformedFilter`] if the expression does not fit the grammar.
    pub fn filter(&self) -> Result<Option<Filter>, QueryError> {
        self.get(&ParameterName::Q).map(Filter::parse).transpose()
    }
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
                "Car": "https://uri.fiware.org/ns/data-models#Vehicle"
            }"#,
        )
        .unwrap()
    }

    fn query(source: &str) -> QueryParameters {
        QueryParameters::parse(source).unwrap()
    }

    #[test]
    fn the_parameters_that_carry_names_are_named() {
        assert!(is_term_valued(&ParameterName::TYPE));
        assert!(is_term_valued(&ParameterName::ATTRS));
        // A scope is a path and a limit is a number. Expanding either would be wrong.
        assert!(!is_term_valued(&ParameterName::SCOPE_Q));
        assert!(!is_term_valued(&ParameterName::from_static("limit")));
        assert!(!is_term_valued(&ParameterName::Q), "the names in q are inside the expression");
    }

    #[test]
    fn a_comma_separated_value_is_a_list_of_names() {
        assert_eq!(terms_of("location,observationSpace"), [Term::new("location"), Term::new("observationSpace")]);
        assert_eq!(terms_of("location, observationSpace"), [Term::new("location"), Term::new("observationSpace")]);
        assert_eq!(terms_of("location,"), [Term::new("location")]);
        assert_eq!(terms_of(""), Vec::<Term>::new());
    }

    #[test]
    fn two_spellings_of_one_type_expand_to_one_iri() {
        assert_eq!(
            query("type=Vehicle,Car").expanded_entity_types(&context()).unwrap().len(),
            1,
            "Car and Vehicle are one type under this context"
        );
    }

    #[test]
    fn a_type_the_context_cannot_expand_is_an_error_rather_than_an_empty_list() {
        let bare = ResolvedContext::from_json(r#"{"Vehicle": "https://example.test/Vehicle"}"#).unwrap();
        let refused = query("type=Mystery").expanded_entity_types(&bare);

        assert!(
            matches!(&refused, Err(QueryError::UnexpandableTerm { parameter, .. }) if *parameter == ParameterName::TYPE),
            "{refused:?}"
        );
    }

    #[test]
    fn a_type_expression_names_every_type_in_it() {
        // `Secret|Vehicle`, `(Secret)` and `Secret;Vehicle` are expressions, not one unknown name each.
        let context = ResolvedContext::from_json(r#"{"@vocab": "https://example.test/", "Secret": "https://example.test/Secret"}"#).unwrap();

        for source in ["type=Secret|Vehicle", "type=(Secret);Vehicle", "type=Vehicle,Secret"] {
            let expanded = query(source).expanded_entity_types(&context).unwrap();
            assert_eq!(expanded.len(), 2, "{source}");
        }
        assert_eq!(query("type=(Secret)").expanded_entity_types(&context).unwrap().len(), 1);
    }

    #[test]
    fn a_malformed_type_expression_is_an_error() {
        assert!(matches!(
            query("type=Secret|").expanded_entity_types(&context()),
            Err(QueryError::MalformedTypeSelection { .. })
        ));
    }

    #[test]
    fn every_attribute_selector_is_collected() {
        // A policy restricting attributes has to see the names whichever parameter carried them.
        assert_eq!(
            query("attrs=speed&omit=location").selected_attributes().unwrap(),
            [Term::new("speed"), Term::new("location")]
        );
    }

    #[test]
    fn a_selector_is_read_in_the_projection_language() {
        // `|` separates names as `,` does, and a linked-entity term is one attribute of the queried
        // entity however many names its braces hold.
        assert_eq!(
            query("pick=speed|observation{temperature,humidity}").selected_attributes().unwrap(),
            [Term::new("speed"), Term::new("observation")]
        );
        assert!(matches!(
            query("pick=observation{").selected_attributes(),
            Err(QueryError::MalformedProjection { .. })
        ));
    }

    #[test]
    fn a_query_without_a_filter_has_no_filter() {
        assert_eq!(query("type=Vehicle").filter().unwrap(), None);
        assert!(query("q=speed>40").filter().unwrap().is_some());
        assert!(query("q=speed>").filter().is_err());
    }
}
