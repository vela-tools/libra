//! Attribute restrictions: which attributes of an entity a caller may see or write.
//!
//! Attribute names are terms, exactly as entity types are, and are compared as IRIs for the same
//! reason. There is no implicit allow list here: exempting a handful of names, `location` among
//! them, from every restriction would let a policy written to hide a device's position be accepted,
//! reported as loaded, and do nothing. Structural members of the document
//! (`id`, `type`, `@context`) are not attributes and are handled by the filter as document shape,
//! not by silently allowing them here.

use crate::{
    error::{CompileError, ValueError},
    policy::PolicyId,
};
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

/// Whether the listed attributes are the only ones allowed, or the only ones forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttributeAction {
    /// Only the listed attributes are allowed.
    Pick,
    /// Every attribute except the listed ones is allowed.
    Omit,
}

/// Which attributes a policy allows access to, as authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AttributeRestriction {
    /// Whether the list allows or forbids.
    pub action: AttributeAction,

    /// The attributes the action applies to. Must name at least one.
    #[serde(deserialize_with = "non_empty_terms")]
    pub attributes: Vec<Term>,
}

impl AttributeRestriction {
    /// Expands every attribute name against the policy's declared context.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError::UnexpandableTerm`] if an attribute has no meaning in that context.
    pub fn compile(&self, policy: &PolicyId, context: &ResolvedContext) -> Result<CompiledAttributeRestriction, CompileError> {
        // As in [`crate::entity_type::TypeRestriction::compile`]: the deserializer is not the only
        // way one of these is built, and an empty list means something different from what it
        // looks like.
        if self.attributes.is_empty() {
            return Err(CompileError::EmptyRestriction {
                policy: policy.clone(), // the error owns the id, the caller keeps its own
                field: "the attribute restriction",
            });
        }

        let mut attributes = Vec::with_capacity(self.attributes.len());

        for term in &self.attributes {
            attributes.push(context.expand(term).ok_or_else(|| CompileError::UnexpandableTerm {
                policy: policy.clone(), // the error owns the id, the caller keeps its own
                field: "the attribute restriction",
                term: term.clone(), // the error owns the offending term, the policy keeps its own
            })?);
        }

        attributes.sort();
        attributes.dedup();

        Ok(CompiledAttributeRestriction {
            action: self.action,
            attributes,
        })
    }
}

/// An attribute restriction whose names are IRIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledAttributeRestriction {
    action: AttributeAction,
    attributes: Vec<ExpandedIri>,
}

impl CompiledAttributeRestriction {
    /// Builds a restriction directly.
    ///
    /// The engine needs this: the effective restriction for a request is derived from every
    /// matching policy rather than taken from one of them.
    #[must_use]
    pub fn new(action: AttributeAction, mut attributes: Vec<ExpandedIri>) -> Self {
        attributes.sort();
        attributes.dedup();

        Self { action, attributes }
    }

    /// Whether the list allows or forbids.
    #[must_use]
    pub const fn action(&self) -> AttributeAction {
        self.action
    }

    /// The attributes the action applies to.
    #[must_use]
    pub fn attributes(&self) -> &[ExpandedIri] {
        &self.attributes
    }

    /// Whether this restriction allows `attribute`.
    #[must_use]
    pub fn allows(&self, attribute: &ExpandedIri) -> bool {
        let listed = self.attributes.contains(attribute);

        match self.action {
            AttributeAction::Pick => listed,
            AttributeAction::Omit => !listed,
        }
    }
}

/// Rejects an empty attribute list.
fn non_empty_terms<'de, D>(deserializer: D) -> Result<Vec<Term>, D::Error>
where
    D: Deserializer<'de>,
{
    let terms = Vec::<Term>::deserialize(deserializer)?;

    if terms.is_empty() {
        // An empty pick list allows nothing but enforces as an empty `attrs` parameter, which a
        // broker reads as "every attribute". An empty omit list forbids nothing and is a no-op.
        return Err(DeError::custom(ValueError::EmptyAllowList {
            restriction: "an attribute restriction",
        }));
    }

    Ok(terms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "location": "https://uri.etsi.org/ngsi-ld/location",
                "speed": "https://uri.fiware.org/ns/data-models#speed"
            }"#,
        )
        .unwrap()
    }

    fn iri(term: &str) -> ExpandedIri {
        context().expand(&Term::new(term)).unwrap()
    }

    fn restriction(source: &str) -> CompiledAttributeRestriction {
        toml::from_str::<AttributeRestriction>(source)
            .unwrap()
            .compile(&PolicyId::new("p").unwrap(), &context())
            .unwrap()
    }

    #[test]
    fn a_pick_allows_only_what_it_lists() {
        let compiled = restriction("action = \"pick\"\nattributes = [\"speed\"]");

        assert!(compiled.allows(&iri("speed")));
        assert!(!compiled.allows(&iri("location")));
    }

    #[test]
    fn an_omit_forbids_only_what_it_lists() {
        let compiled = restriction("action = \"omit\"\nattributes = [\"location\"]");

        assert!(compiled.allows(&iri("speed")));
        assert!(!compiled.allows(&iri("location")));
    }

    #[test]
    fn location_is_an_ordinary_attribute_and_can_be_omitted() {
        // There is no implicit allow list of "core" names (location, createdAt, observationSpace and
        // others) consulted before the policy, so a geo-privacy policy omitting `location` takes effect.
        let compiled = restriction("action = \"omit\"\nattributes = [\"location\"]");

        assert!(!compiled.allows(&iri("location")), "a policy that omits location must omit location");
    }

    #[test]
    fn an_attribute_sent_as_its_iri_reaches_the_same_comparison() {
        let compiled = restriction("action = \"omit\"\nattributes = [\"location\"]");

        assert!(!compiled.allows(&iri("https://uri.etsi.org/ngsi-ld/location")));
    }

    #[test]
    fn an_empty_attribute_list_is_refused_when_it_is_read_and_again_when_it_is_compiled() {
        for empty in ["action = \"pick\"\nattributes = []", "action = \"omit\"\nattributes = []"] {
            assert!(toml::from_str::<AttributeRestriction>(empty).is_err(), "{empty}");
        }

        let built = AttributeRestriction {
            action: AttributeAction::Pick,
            attributes: Vec::new(),
        };

        assert!(built.compile(&PolicyId::new("built-in-code").unwrap(), &context()).is_err());
    }

    #[test]
    fn an_attribute_the_context_does_not_define_is_a_load_error() {
        let bare = ResolvedContext::from_json(r#"{"speed": "https://example.test/speed"}"#).unwrap();
        let authored: AttributeRestriction = toml::from_str("action = \"pick\"\nattributes = [\"mystery\"]").unwrap();

        assert!(authored.compile(&PolicyId::new("p").unwrap(), &bare).is_err());
    }

    #[test]
    fn the_engine_can_build_an_effective_restriction_directly() {
        let combined = CompiledAttributeRestriction::new(AttributeAction::Pick, vec![iri("speed"), iri("location"), iri("speed")]);

        assert_eq!(combined.attributes().len(), 2, "duplicates collapse");
        assert!(combined.allows(&iri("speed")));
    }
}
