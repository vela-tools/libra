//! Taking the one query parameter a member restriction narrows out of the query.

use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters};
use thiserror::Error;

/// The query carries more than one spelling of the parameter a restriction narrows.
///
/// Refused for the reason a repeated parameter is: the proxy would enforce one of them and the
/// broker might read the other.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the query carries more than one spelling of the {parameter} parameter")]
pub struct AmbiguousParameter {
    /// The parameter, in the spelling the specification gives it.
    pub parameter: ParameterName,
}

/// Takes the parameter `canonical` names out of the query, whatever the caller spelled it, and
/// returns its value.
///
/// The specification says parameter names are case-sensitive, but brokers differ. Removing
/// whichever spelling arrived, so the caller re-emits the canonical one, means there is never a
/// second, unchecked value left behind for a lenient broker to read instead of the narrowed one.
///
/// An empty value is not a filter: a broker reads it as no filter at all, so it is returned as
/// `None`, a value the caller never wrote, and replaced by the restriction rather than refused.
///
/// # Errors
///
/// Returns [`AmbiguousParameter`] if more than one spelling arrived.
pub fn take_parameter(parameters: &mut QueryParameters, canonical: &ParameterName) -> Result<Option<String>, AmbiguousParameter> {
    // Cloned because the names are removed from the parameters they are borrowed from.
    let spellings: Vec<ParameterName> = parameters
        .iter()
        .map(|(name, _)| name)
        .filter(|name| name.eq_ignore_ascii_case(canonical))
        .cloned()
        .collect();

    match spellings.as_slice() {
        [] => Ok(None),
        [only] => Ok(parameters.remove(only).filter(|value| !value.trim().is_empty())),
        _ => Err(AmbiguousParameter {
            // Cloned because the error owns the name and the caller keeps its own.
            parameter: canonical.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Parameters in the spellings given, set one by one: a parsed query refuses a case variant of
    /// a parameter it knows before any layer sees it.
    fn parameters(pairs: &[(&'static str, &str)]) -> QueryParameters {
        let mut parameters = QueryParameters::parse("").expect("the empty query should parse");
        for (name, value) in pairs {
            parameters.set(ParameterName::from_static(name), *value);
        }
        parameters
    }

    #[test]
    fn an_absent_parameter_is_none() {
        let mut parameters = parameters(&[("q", "speed>40")]);

        assert_eq!(take_parameter(&mut parameters, &ParameterName::SCOPE_Q), Ok(None));
        assert!(parameters.contains(&ParameterName::Q));
    }

    #[test]
    fn a_parameter_in_another_case_is_taken_out() {
        let mut parameters = parameters(&[("ScopeQ", "/Madrid"), ("q", "speed>40")]);

        assert_eq!(take_parameter(&mut parameters, &ParameterName::SCOPE_Q), Ok(Some("/Madrid".to_owned())));
        assert_eq!(parameters.iter().count(), 1);
    }

    #[test]
    fn an_empty_value_is_taken_out_and_read_as_none() {
        let mut parameters = parameters(&[("type", " ")]);

        assert_eq!(take_parameter(&mut parameters, &ParameterName::TYPE), Ok(None));
        assert!(parameters.is_empty());
    }

    #[test]
    fn two_spellings_are_refused() {
        let mut parameters = parameters(&[("type", "Vehicle"), ("TYPE", "Building")]);

        assert_eq!(
            take_parameter(&mut parameters, &ParameterName::TYPE),
            Err(AmbiguousParameter {
                parameter: ParameterName::TYPE
            })
        );
        assert_eq!(
            AmbiguousParameter {
                parameter: ParameterName::SCOPE_Q
            }
            .to_string(),
            "the query carries more than one spelling of the scopeQ parameter"
        );
    }
}
