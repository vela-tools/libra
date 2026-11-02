//! The two kinds of name, kept apart by the type system.
//!
//! A [`Term`] is what someone wrote: in a policy file, in a query parameter, in a request body. It
//! has no meaning on its own. An [`ExpandedIri`] is what that term resolves to under a particular
//! context, and it is the only thing that may be compared.
//!
//! These are separate types on purpose. Comparing a policy's term against a request's term as
//! strings silently succeeds, and silently enforces the wrong thing, whenever the caller controls
//! the context. Making the two unassignable to each other turns that class of mistake into a
//! compile error.

use derive_more::Display;
use iri_rs::{Iri, iri};
use serde::{Deserialize, Serialize};

/// A name as authored: an entity type, an attribute name, a scope. Meaningless without a context.
///
/// Serialisable, because policies are authored in terms and this is what a policy file holds
/// before it is compiled.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display, Serialize, Deserialize)]
#[display("{_0}")]
#[serde(transparent)]
pub struct Term(String);

impl Term {
    /// Wraps an authored name.
    #[must_use]
    pub fn new(term: impl Into<String>) -> Self {
        Self(term.into())
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this term is already an absolute IRI.
    ///
    /// Sending the expanded IRI in place of the term is legal on the wire, so a request can
    /// contain either form and both have to reach the same comparison.
    #[must_use]
    pub fn looks_absolute(&self) -> bool {
        // An absolute IRI has a scheme, and the scheme is followed by a colon. Checking for the
        // colon alone would misread a compact IRI such as `ex:Vehicle`, which is a term that still
        // needs the context to expand its prefix.
        self.0.starts_with("http://") || self.0.starts_with("https://") || self.0.starts_with("urn:")
    }
}

/// The namespace ETSI GS CIM 009 defines its core terms in.
pub static CORE_NAMESPACE: Iri<&str> = iri!("https://uri.etsi.org/ngsi-ld/");

/// The core namespace over plain `http`.
///
/// Published contexts use it for core terms: the Smart Data Models context maps `location` to
/// `http://uri.etsi.org/ngsi-ld/location`. RFC 3987 makes that a different IRI from the core one,
/// so read literally such a context redefines a core term, and every request sending it would be
/// refused. It names the same term, so it is read as [`CORE_NAMESPACE`].
pub static CORE_NAMESPACE_OVER_HTTP: Iri<&str> = iri!("http://uri.etsi.org/ngsi-ld/");

/// A name after expansion: an absolute IRI, and the only form that may be compared.
///
/// There is no `From<String>` and no `Deserialize`. An expanded IRI is a result, produced by
/// expanding a term against a resolved context, never something read straight out of a file. A
/// policy may still name an absolute IRI: it is read as a [`Term`] and expands to itself, so it
/// reaches this type through the same expansion as any other name, and the same refusals and the
/// same core-namespace normalisation apply to it. A value that bypassed expansion would get
/// neither.
///
/// An IRI in [`CORE_NAMESPACE_OVER_HTTP`] is recorded in [`CORE_NAMESPACE`]. Doing it here, where
/// every comparable IRI is made, is what keeps the two spellings from ever comparing unequal: a
/// policy, a request and a response member naming `location` either way reach the same IRI, so an
/// attribute restriction on `location` cannot be stepped around by spelling it over `http`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display, Serialize)]
#[display("{_0}")]
#[serde(transparent)]
pub struct ExpandedIri(String);

impl ExpandedIri {
    /// Records the result of an expansion.
    ///
    /// Only expansion should call this. It is public because the crate that performs expansion is
    /// this one's caller, not because an IRI may be conjured from any string.
    #[must_use]
    pub fn new(iri: impl Into<String>) -> Self {
        let iri = iri.into();

        match iri.strip_prefix(CORE_NAMESPACE_OVER_HTTP.as_str()) {
            Some(core_term) => Self(format!("{}{core_term}", CORE_NAMESPACE.as_str())),
            None => Self(iri),
        }
    }

    /// The IRI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_term_round_trips_through_serde_as_a_bare_string() {
        let term: Term = serde_json::from_str("\"Vehicle\"").unwrap();

        assert_eq!(term.as_str(), "Vehicle");
        assert_eq!(serde_json::to_string(&term).unwrap(), "\"Vehicle\"");
    }

    #[test]
    fn an_absolute_iri_sent_as_a_term_is_recognised() {
        assert!(Term::new("https://uri.etsi.org/ngsi-ld/default-context/Vehicle").looks_absolute());
        assert!(Term::new("http://example.test/Vehicle").looks_absolute());
        assert!(Term::new("urn:ngsi-ld:Vehicle").looks_absolute());
    }

    #[test]
    fn a_compact_iri_is_not_absolute() {
        // `ex:Vehicle` still needs the context to say what `ex` is, so treating it as absolute
        // would compare an unexpanded prefix against a real IRI.
        assert!(!Term::new("ex:Vehicle").looks_absolute());
        assert!(!Term::new("Vehicle").looks_absolute());
    }

    #[test]
    fn expanded_iris_compare_by_value() {
        let left = ExpandedIri::new("https://example.test/Vehicle");
        let right = ExpandedIri::new("https://example.test/Vehicle");
        let other = ExpandedIri::new("https://example.test/Building");

        assert_eq!(left, right);
        assert_ne!(left, other);
    }

    #[test]
    fn a_core_term_over_http_is_recorded_in_the_core_namespace() {
        let over_http = ExpandedIri::new("http://uri.etsi.org/ngsi-ld/location");

        assert_eq!(over_http.as_str(), "https://uri.etsi.org/ngsi-ld/location");
        assert_eq!(over_http, ExpandedIri::new("https://uri.etsi.org/ngsi-ld/location"));
    }

    #[test]
    fn an_iri_outside_the_core_namespace_keeps_its_scheme() {
        assert_eq!(ExpandedIri::new("http://example.test/location").as_str(), "http://example.test/location");
        assert_eq!(
            ExpandedIri::new("http://uri.etsi.org/ngsi-ld-extension/location").as_str(),
            "http://uri.etsi.org/ngsi-ld-extension/location"
        );
        assert_eq!(
            ExpandedIri::new("http://uri.etsi.org/other/location").as_str(),
            "http://uri.etsi.org/other/location"
        );
    }
}
