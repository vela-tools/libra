//! The NGSI-LD core context, compiled into the binary.
//!
//! The core context underlies every NGSI-LD request. Fetching it at runtime would make the proxy's
//! ability to make any authorization decision depend on a third-party host being reachable and
//! willing, and it is not reliably willing: `uri.etsi.org` answers `403` to some user agents.
//! Since Libra fails closed, an unavailable core context would mean refusing every request.
//!
//! So it ships in the binary. The copy here is the document served at [`url()`], and the parity
//! harness checks it has not drifted from the published document.
//!
//! It is processed once, at startup, by whoever builds the resolver. Processing it lazily on the
//! request path would mean a failure there had nowhere to go but a panic, and a proxy that panics
//! mid-request is a proxy that fails open for everything already in flight.

use iri_rs::{Iri, iri};
use jstrict::{Parse, Value};
use libra_jsonld_term_expansion::resolved::{ProcessingError, ResolvedContext};
use url::Url;
use url_macro::url as static_url;

/// Where the embedded copy came from.
///
/// A function rather than a constant because a [`Url`] cannot be built in a constant context. The
/// address is checked when this crate is compiled.
#[must_use]
pub fn url() -> Url {
    static_url!("https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld")
}

/// The vocabulary the core context sets, and therefore what an otherwise undefined term expands
/// against. Scorpio stores an undefined term under this vocabulary as well.
pub static DEFAULT_CONTEXT_VOCABULARY: Iri<&str> = iri!("https://uri.etsi.org/ngsi-ld/default-context/");

/// The embedded document, verbatim.
pub const DOCUMENT: &str = include_str!("../contexts/ngsi-ld-core-context.jsonld");

/// Processes the embedded core context.
///
/// # Errors
///
/// Returns [`ProcessingError`] if the embedded document is not a valid context.
pub fn process() -> Result<ResolvedContext, ProcessingError> {
    let (json, _) = Parse::parse_str(DOCUMENT).map_err(|error| ProcessingError::Json { reason: error.to_string() })?;

    let Value::Object(object) = &json else {
        return Err(ProcessingError::Syntax {
            reason: "the core context document is not a JSON object".to_owned(),
        });
    };

    let value = object.get_unique("@context").ok().flatten().ok_or_else(|| ProcessingError::Syntax {
        reason: "the core context document has no unique @context entry".to_owned(),
    })?;

    ResolvedContext::from_value(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_jsonld_term_expansion::name::{ExpandedIri, Term};
    use pretty_assertions::assert_eq;

    #[test]
    fn the_embedded_core_context_processes() {
        assert!(process().is_ok(), "the compiled-in core context must be processable, or the proxy cannot start");
    }

    fn core() -> ResolvedContext {
        process().expect("the embedded core context must process")
    }

    #[test]
    fn it_defines_the_ngsi_ld_structural_terms() {
        let core = core();

        assert_eq!(
            core.expand(&Term::new("Property")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/Property")
        );
        assert_eq!(
            core.expand(&Term::new("Relationship")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/Relationship")
        );
        assert_eq!(
            core.expand(&Term::new("observedAt")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/observedAt")
        );
        assert_eq!(
            core.expand(&Term::new("location")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/location")
        );
    }

    #[test]
    fn an_undefined_term_expands_against_the_default_context() {
        // The broker agrees: an entity created as type `Widget` with no context is retrievable at
        // https://uri.etsi.org/ngsi-ld/default-context/Widget.
        assert_eq!(
            core().expand(&Term::new("Widget")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/default-context/Widget")
        );
    }

    #[test]
    fn id_and_type_stay_keywords() {
        // The core context aliases `id` to `@id` and `type` to `@type`. Neither is a name a policy
        // may be written about, so neither may expand to a comparable IRI.
        assert!(core().expand(&Term::new("id")).is_none());
        assert!(core().expand(&Term::new("type")).is_none());
    }

    #[test]
    fn the_vocabulary_constant_matches_the_document() {
        assert!(
            DOCUMENT.contains(DEFAULT_CONTEXT_VOCABULARY.as_str()),
            "the declared default-context vocabulary must be the one the document sets"
        );
    }
}
