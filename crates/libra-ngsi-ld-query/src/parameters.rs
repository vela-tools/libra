//! The raw query string, decoded once and held in a form that cannot be read two ways.
//!
//! Everything above this module works from [`QueryParameters`] rather than from the query string,
//! so there is one decoding per request and one answer to "what did the caller ask for".

use crate::{error::QueryError, parameter_name::ParameterName};
use http::{Uri, uri::InvalidUri};
use percent_encoding::percent_decode_str;
use std::{borrow::Cow, collections::BTreeMap, fmt::Write as _};

/// The parameters of one request, decoded and deduplicated.
///
/// Ordered, because a canonical rendering is what a cache key is built from and two requests that
/// differ only in parameter order are one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryParameters {
    parameters: BTreeMap<ParameterName, String>,
}

impl QueryParameters {
    /// Parses a query string, without the leading `?`.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::DuplicateParameter`] when a parameter repeats, and
    /// [`QueryError::UndecodableParameter`] when percent decoding does not produce UTF-8.
    pub fn parse(query: &str) -> Result<Self, QueryError> {
        let mut parameters = BTreeMap::new();

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }

            let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));

            let name = ParameterName::decoded(decode(raw_name, raw_name)?);
            let value = decode(raw_value, raw_name)?;

            // A repeated parameter is not a merge and not a last-one-wins: it is ambiguous, and
            // implementations resolve the ambiguity differently. See the error's documentation.
            if parameters.contains_key(&name) {
                return Err(QueryError::DuplicateParameter { name });
            }
            if let Some(other) = parameters
                .keys()
                .chain(ParameterName::READ.iter())
                .find(|other| **other != name && other.eq_ignore_ascii_case(&name))
            {
                // Cloned because the error owns the name it reports and the map keeps its key.
                let other = other.clone();
                return Err(QueryError::CaseVariantParameter { name, other });
            }
            parameters.insert(name, value);
        }

        Ok(Self { parameters })
    }

    /// The value of one parameter.
    #[must_use]
    pub fn get(&self, name: &ParameterName) -> Option<&str> {
        self.parameters.get(name).map(String::as_str)
    }

    /// Whether the parameter was supplied at all, even empty.
    #[must_use]
    pub fn contains(&self, name: &ParameterName) -> bool {
        self.parameters.contains_key(name)
    }

    /// Every parameter, in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&ParameterName, &str)> {
        self.parameters.iter().map(|(name, value)| (name, value.as_str()))
    }

    /// Whether any parameter was supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parameters.is_empty()
    }

    /// Replaces one parameter, or adds it.
    ///
    /// Used by the enforcement layers that narrow a request rather than refusing it, such as an
    /// aggregation period raised to the policy minimum, a type filter reduced to what the policy
    /// allows.
    pub fn set(&mut self, name: ParameterName, value: impl Into<String>) {
        self.parameters.insert(name, value.into());
    }

    /// Removes one parameter.
    pub fn remove(&mut self, name: &ParameterName) -> Option<String> {
        self.parameters.remove(name)
    }

    /// Renders the parameters back to a query string, in canonical order.
    ///
    /// Deterministic: two requests that differ only in the order they wrote their parameters
    /// render identically, which is what makes this safe to use in a cache key.
    #[must_use]
    pub fn to_query_string(&self) -> String {
        let mut rendered = String::new();

        for (name, value) in &self.parameters {
            if !rendered.is_empty() {
                rendered.push('&');
            }
            rendered.push_str(&encode(name.as_str()));
            rendered.push('=');
            rendered.push_str(&encode(value));
        }

        rendered
    }

    /// The target of a request at `path` that carries these parameters as its query.
    ///
    /// # Errors
    ///
    /// Returns the [`InvalidUri`] the path and the rendered query make together, which a path read
    /// from a valid URI and a query this type rendered never do.
    pub fn uri_at(&self, path: &str) -> Result<Uri, InvalidUri> {
        let query = self.to_query_string();

        if query.is_empty() { path.parse() } else { format!("{path}?{query}").parse() }
    }
}

/// Percent-decodes one piece of a query string.
///
/// `+` is left alone rather than decoded to a space. The form-encoding rule that turns it into one
/// belongs to HTML forms; an NGSI-LD query is a URI, and its values routinely contain a literal
/// `+` in a timezone offset. Decoding it would change `2026-01-01T00:00:00+01:00` into a time an
/// hour and a timezone away from the one asked for.
fn decode(raw: &str, name_for_error: &str) -> Result<String, QueryError> {
    percent_decode_str(raw)
        .decode_utf8()
        .map(Cow::into_owned)
        .map_err(|_| QueryError::UndecodableParameter {
            name: name_for_error.to_owned(),
        })
}

/// Percent-encodes one piece of a query string.
///
/// Conservative on purpose: everything outside the unreserved set is encoded, so a rendered query
/// cannot be re-split differently from the one that was parsed.
fn encode(value: &str) -> String {
    const UNRESERVED_EXTRA: [char; 4] = ['-', '.', '_', '~'];

    let mut encoded = String::with_capacity(value.len());

    for byte in value.bytes() {
        let character = char::from(byte);
        if character.is_ascii_alphanumeric() || UNRESERVED_EXTRA.contains(&character) {
            encoded.push(character);
        } else {
            // Infallible: writing to a String cannot fail, and the lint that bans `expect` is
            // right that a request path is no place to find out otherwise.
            let _ = write!(encoded, "%{byte:02X}");
        }
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parameters_are_decoded() {
        let parameters = QueryParameters::parse("type=Vehicle&attrs=speed%2Cbrand").unwrap();

        assert_eq!(parameters.get(&ParameterName::TYPE), Some("Vehicle"));
        assert_eq!(parameters.get(&ParameterName::ATTRS), Some("speed,brand"));
    }

    #[test]
    fn an_expanded_iri_survives_decoding() {
        let parameters = QueryParameters::parse("type=https%3A%2F%2Fexample.test%23Vehicle").unwrap();

        assert_eq!(parameters.get(&ParameterName::TYPE), Some("https://example.test#Vehicle"));
    }

    #[test]
    fn a_repeated_parameter_is_refused() {
        // Parameter smuggling: whichever copy the proxy reads, the broker may read the other.
        assert_eq!(
            QueryParameters::parse("type=Vehicle&type=Building"),
            Err(QueryError::DuplicateParameter { name: ParameterName::TYPE })
        );
    }

    #[test]
    fn a_plus_stays_a_plus() {
        // A timezone offset is the common case. Decoding `+` to a space here would silently move
        // the requested instant.
        let parameters = QueryParameters::parse("timeAt=2026-01-01T00:00:00+01:00").unwrap();

        assert_eq!(parameters.get(&ParameterName::TIME_AT), Some("2026-01-01T00:00:00+01:00"));
    }

    #[test]
    fn a_valueless_parameter_is_present_and_empty() {
        let parameters = QueryParameters::parse("count").unwrap();

        assert!(parameters.contains(&ParameterName::from_static("count")));
        assert_eq!(parameters.get(&ParameterName::from_static("count")), Some(""));
    }

    #[test]
    fn the_canonical_form_does_not_depend_on_the_order_they_arrived_in() {
        let one = QueryParameters::parse("type=Vehicle&limit=10&attrs=speed").unwrap();
        let other = QueryParameters::parse("attrs=speed&type=Vehicle&limit=10").unwrap();

        assert_eq!(one.to_query_string(), other.to_query_string());
        assert_eq!(one, other);
    }

    #[test]
    fn rendering_round_trips_through_parsing() {
        let original = QueryParameters::parse("q=speed%3E40&type=https%3A%2F%2Fexample.test%23Vehicle").unwrap();
        let reparsed = QueryParameters::parse(&original.to_query_string()).unwrap();

        assert_eq!(original, reparsed);
    }

    #[test]
    fn an_empty_query_string_is_an_empty_query() {
        assert!(QueryParameters::parse("").unwrap().is_empty());
    }

    #[test]
    fn the_rendered_query_is_set_on_the_path() {
        let parameters = QueryParameters::parse("type=Vehicle&q=speed%3E1").unwrap();

        assert_eq!(
            parameters.uri_at("/ngsi-ld/v1/entities").unwrap(),
            "/ngsi-ld/v1/entities?q=speed%3E1&type=Vehicle"
        );
    }

    #[test]
    fn no_parameters_leave_the_path_without_a_query() {
        let parameters = QueryParameters::parse("").unwrap();

        assert_eq!(parameters.uri_at("/ngsi-ld/v1/entities").unwrap(), "/ngsi-ld/v1/entities");
    }

    fn case_variant(query: &str) -> bool {
        matches!(QueryParameters::parse(query), Err(QueryError::CaseVariantParameter { .. }))
    }

    #[test]
    fn a_case_variant_of_q_is_refused() {
        assert!(case_variant("Q=secret==1"));
    }

    #[test]
    fn a_case_variant_of_time_at_is_refused() {
        assert!(case_variant("timerel=before&TIMEAT=2026-01-01T00:00:00Z"));
    }

    #[test]
    fn a_case_variant_of_type_is_refused() {
        assert!(case_variant("Type=Secret"));
    }

    #[test]
    fn two_unknown_parameters_differing_only_in_case_are_refused() {
        assert!(case_variant("vendorFlag=1&VENDORFLAG=2"));
    }

    #[test]
    fn an_unknown_parameter_is_kept_as_written() {
        let parameters = QueryParameters::parse("vendorFlag=1").unwrap();

        assert_eq!(parameters.get(&ParameterName::decoded("vendorFlag".to_owned())), Some("1"));
    }
}
