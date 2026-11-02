//! Expansion of one term a query names, under the request's context.
//!
//! A name whose meaning is unknown cannot be compared with a policy's name, so a term that does not
//! expand refuses the whole query rather than matching nothing. Every selector that carries terms
//! expands them through this one function, so they all refuse the same way.

use crate::{error::QueryError, parameter_name::ParameterName};
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};

/// The IRI `term` expands to under `context`.
///
/// # Errors
///
/// Returns [`QueryError::UnexpandableTerm`] naming `parameter` and `term` if the term has no meaning
/// in this context.
pub(crate) fn expand_term(parameter: &ParameterName, term: &Term, context: &ResolvedContext) -> Result<ExpandedIri, QueryError> {
    context.expand(term).ok_or_else(|| QueryError::UnexpandableTerm {
        // Cloned because the error owns the name and the term; the query keeps its own.
        parameter: parameter.clone(),
        term: term.clone(),
    })
}

#[cfg(test)]
mod tests {
    use crate::{error::QueryError, expansion::expand_term, parameter_name::ParameterName};
    use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(r#"{"speed": "https://example.test/speed"}"#).unwrap()
    }

    #[test]
    fn a_defined_term_expands_to_its_iri() {
        let iri = expand_term(&ParameterName::ATTRS, &Term::new("speed"), &context()).unwrap();

        assert_eq!(iri.as_str(), "https://example.test/speed");
    }

    #[test]
    fn an_undefined_term_names_the_parameter_and_term_it_came_from() {
        assert_eq!(
            expand_term(&ParameterName::PICK, &Term::new("mystery"), &context()),
            Err(QueryError::UnexpandableTerm {
                parameter: ParameterName::PICK,
                term: Term::new("mystery"),
            })
        );
    }
}
