//! Matching a policy against the exact query a caller sent.
//!
//! A query selector is written the way a caller would write the query, and compared against what
//! the caller actually sent, but through the canonical form, so the comparison is about what the
//! query asks for rather than how it was spelled. Without that, a policy written about
//! `?type=Vehicle` would not match `?type=Car` under a context where the two are one type, nor
//! `?limit=10&type=Vehicle` under any context at all.

use crate::{error::CompileError, policy::PolicyId};
use derive_more::Display;
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_ngsi_ld_query::{
    canonical::{CanonicalQuery, canonicalise},
    error::QueryError,
    parameters::QueryParameters,
};
use serde::{Deserialize, Serialize};

/// A query a policy matches on, as authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display)]
#[display("{written}")]
#[serde(try_from = "String", into = "String")]
pub struct QuerySelector {
    written: String,
    parameters: QueryParameters,
}

impl QuerySelector {
    /// Parses a query selector.
    ///
    /// # Errors
    ///
    /// Returns the query model's own error if the selector is not a well-formed query string.
    pub fn parse(value: impl Into<String>) -> Result<Self, QueryError> {
        let written = value.into();
        let parameters = QueryParameters::parse(written.trim_start_matches('?'))?;

        Ok(Self { written, parameters })
    }

    /// Canonicalises the selector against the policy's declared context.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError::Query`] if a name in the selector has no meaning in that context.
    pub fn compile(&self, policy: &PolicyId, context: &ResolvedContext) -> Result<CompiledQuerySelector, CompileError> {
        let canonical = canonicalise(&self.parameters, context).map_err(|source| CompileError::Query {
            policy: policy.clone(), // the error owns the id, the caller keeps its own
            source,
        })?;

        Ok(CompiledQuerySelector { canonical })
    }

    /// The selector as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.written
    }
}

impl TryFrom<String> for QuerySelector {
    type Error = QueryError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<QuerySelector> for String {
    fn from(selector: QuerySelector) -> Self {
        selector.written
    }
}

/// A query selector reduced to what it asks for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompiledQuerySelector {
    canonical: CanonicalQuery,
}

impl CompiledQuerySelector {
    /// Builds a selector from a request's own query, for comparison.
    #[must_use]
    pub const fn from_canonical(canonical: CanonicalQuery) -> Self {
        Self { canonical }
    }

    /// The canonical form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.canonical.as_str()
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

    fn compiled(selector: &str) -> CompiledQuerySelector {
        QuerySelector::parse(selector)
            .unwrap()
            .compile(&PolicyId::new("p").unwrap(), &context())
            .unwrap()
    }

    fn request(query: &str) -> CompiledQuerySelector {
        CompiledQuerySelector::from_canonical(canonicalise(&QueryParameters::parse(query).unwrap(), &context()).unwrap())
    }

    #[test]
    fn a_selector_matches_the_request_that_asks_the_same_thing() {
        assert_eq!(compiled("type=Vehicle&limit=10"), request("limit=10&type=Vehicle"));
    }

    #[test]
    fn a_selector_matches_through_the_context_rather_than_the_spelling() {
        // A policy written about vehicles applies to a caller who writes `Car`, because under this
        // context that is the same request.
        assert_eq!(compiled("type=Vehicle"), request("type=Car"));
    }

    #[test]
    fn a_different_query_does_not_match() {
        assert_ne!(compiled("type=Vehicle"), request("type=Vehicle&limit=10"));
        assert_ne!(compiled("type=Vehicle"), request("type=Building"));
    }

    #[test]
    fn a_leading_question_mark_is_accepted_because_that_is_how_people_write_them() {
        assert_eq!(compiled("?type=Vehicle"), compiled("type=Vehicle"));
    }

    #[test]
    fn a_malformed_selector_is_a_load_error() {
        assert!(QuerySelector::parse("type=Vehicle&type=Building").is_err(), "a repeated parameter is ambiguous");
    }

    #[test]
    fn a_selector_naming_something_the_context_does_not_define_is_a_load_error() {
        let bare = ResolvedContext::from_json(r#"{"Vehicle": "https://example.test/Vehicle"}"#).unwrap();

        assert!(
            QuerySelector::parse("type=Mystery")
                .unwrap()
                .compile(&PolicyId::new("p").unwrap(), &bare)
                .is_err()
        );
    }

    #[test]
    fn a_selector_is_written_back_exactly_as_it_was_read() {
        let selector = QuerySelector::parse("?type=Vehicle").unwrap();

        assert_eq!(selector.as_str(), "?type=Vehicle");
        assert_eq!(String::from(selector), "?type=Vehicle");
    }

    #[test]
    fn the_canonical_form_names_what_the_selector_asks_for() {
        let selector = compiled("type=Vehicle");

        assert_eq!(selector.as_str(), request("type=Car").as_str());
        assert_ne!(selector.as_str(), request("type=Building").as_str());
        assert_eq!(selector.as_str(), "type=https%3A%2F%2Furi.fiware.org%2Fns%2Fdata-models%23Vehicle");
    }
}
