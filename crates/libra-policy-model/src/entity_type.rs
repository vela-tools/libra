//! Entity type restrictions, in both the form they are written and the form they are compared in.
//!
//! This is the restriction the JSON-LD layer exists for. A policy naming `Vehicle` and a request
//! naming `Vehicle` agree only if both terms mean the same IRI, and the caller chooses the context
//! that decides. Comparing the words is bypassed by sending the expanded IRI or by aliasing the
//! term; comparing the IRIs is not.

use crate::{
    error::{CompileError, ValueError},
    member_on_write::MemberOnWrite,
    policy::PolicyId,
};
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

/// Which entity types a policy allows access to, as authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TypeRestriction {
    /// The types this policy allows. Must name at least one.
    #[serde(deserialize_with = "non_empty_terms")]
    pub allowed: Vec<Term>,

    /// What a write payload that carries no type meets under this restriction.
    #[serde(default)]
    pub type_on_write: MemberOnWrite,
}

impl TypeRestriction {
    /// Expands every type against the policy's declared context.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError::UnexpandableTerm`] if a type has no meaning in that context. That
    /// is a load failure, not an empty allow list: a policy naming a type the context does not
    /// define was written in the belief that it applied.
    pub fn compile(&self, policy: &PolicyId, context: &ResolvedContext) -> Result<CompiledTypeRestriction, CompileError> {
        // Checked here as well as in the deserializer. The fields are public, so a restriction can
        // be built in code without passing through serde, and an empty allow list that reached
        // enforcement would be a restriction that allows nothing while looking like one that
        // allows something.
        if self.allowed.is_empty() {
            return Err(CompileError::EmptyRestriction {
                policy: policy.clone(), // the error owns the id, the caller keeps its own
                field: "the entity type restriction",
            });
        }

        let mut allowed = Vec::with_capacity(self.allowed.len());

        for term in &self.allowed {
            allowed.push(context.expand(term).ok_or_else(|| CompileError::UnexpandableTerm {
                policy: policy.clone(), // the error owns the id, the caller keeps its own
                field: "the entity type restriction",
                term: term.clone(), // the error owns the offending term, the policy keeps its own
            })?);
        }

        allowed.sort();
        allowed.dedup();

        Ok(CompiledTypeRestriction {
            allowed,
            on_write: self.type_on_write,
        })
    }
}

/// An entity type restriction whose types are IRIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledTypeRestriction {
    allowed: Vec<ExpandedIri>,
    on_write: MemberOnWrite,
}

impl CompiledTypeRestriction {
    /// The allowed types.
    #[must_use]
    pub fn allowed(&self) -> &[ExpandedIri] {
        &self.allowed
    }

    /// What a write payload that carries no type meets under this restriction.
    #[must_use]
    pub const fn on_write(&self) -> MemberOnWrite {
        self.on_write
    }

    /// Whether this restriction allows `entity_type`.
    #[must_use]
    pub fn allows(&self, entity_type: &ExpandedIri) -> bool {
        self.allowed.contains(entity_type)
    }
}

/// Rejects an empty type allow list.
fn non_empty_terms<'de, D>(deserializer: D) -> Result<Vec<Term>, D::Error>
where
    D: Deserializer<'de>,
{
    let terms = Vec::<Term>::deserialize(deserializer)?;

    if terms.is_empty() {
        return Err(DeError::custom(ValueError::EmptyAllowList {
            restriction: "an entity type restriction",
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
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Car": "https://uri.fiware.org/ns/data-models#Vehicle"
            }"#,
        )
        .unwrap()
    }

    fn restriction(allowed: &str) -> TypeRestriction {
        toml::from_str(&format!("allowed = {allowed}")).unwrap()
    }

    #[test]
    fn types_are_compared_as_iris_not_as_words() {
        // `Car` and `Vehicle` are one type under this context. A policy naming either must catch a
        // request naming the other, which string comparison could never do.
        let compiled = restriction(r#"["Vehicle"]"#).compile(&PolicyId::new("p").unwrap(), &context()).unwrap();

        assert!(compiled.allows(&context().expand(&Term::new("Car")).unwrap()));
    }

    #[test]
    fn a_request_sending_the_expanded_iri_reaches_the_same_comparison() {
        // The form the bypass used: the caller sends the IRI rather than the term, and a proxy
        // matching words sees something its policy never mentioned.
        let compiled = restriction(r#"["Vehicle"]"#).compile(&PolicyId::new("p").unwrap(), &context()).unwrap();
        let sent_expanded = context().expand(&Term::new("https://uri.fiware.org/ns/data-models#Vehicle")).unwrap();

        assert!(compiled.allows(&sent_expanded));
    }

    #[test]
    fn a_type_the_context_does_not_define_is_a_load_error() {
        let bare = ResolvedContext::from_json(r#"{"Vehicle": "https://example.test/Vehicle"}"#).unwrap();
        let refused = restriction(r#"["Unknown"]"#).compile(&PolicyId::new("fleet-read").unwrap(), &bare);

        assert_eq!(
            refused,
            Err(CompileError::UnexpandableTerm {
                policy: PolicyId::new("fleet-read").unwrap(),
                field: "the entity type restriction",
                term: Term::new("Unknown"),
            })
        );
    }

    #[test]
    fn a_policy_term_under_an_ambiguous_prefix_fails_to_compile() {
        // `ex` names a plain IRI, so `ex:Secret` has one meaning for 1.1 and another for 1.0.
        // A policy whose meaning depends on which reader it meets refuses to load.
        let ambiguous = ResolvedContext::from_json(r#"{"ex": "https://host/Sec"}"#).unwrap();
        let refused = restriction(r#"["ex:Secret"]"#).compile(&PolicyId::new("fleet-read").unwrap(), &ambiguous);

        assert_eq!(
            refused,
            Err(CompileError::UnexpandableTerm {
                policy: PolicyId::new("fleet-read").unwrap(),
                field: "the entity type restriction",
                term: Term::new("ex:Secret"),
            })
        );
    }

    #[test]
    fn duplicate_spellings_of_one_type_collapse() {
        let compiled = restriction(r#"["Vehicle", "Car", "Vehicle"]"#)
            .compile(&PolicyId::new("p").unwrap(), &context())
            .unwrap();

        assert_eq!(compiled.allowed().len(), 1, "three spellings, one type");
    }

    #[test]
    fn an_empty_allow_list_is_refused_when_it_is_read_and_again_when_it_is_compiled() {
        // Twice on purpose. The fields are public, so a restriction can be built without passing
        // through serde, and one that reached enforcement empty would allow nothing while reading
        // as though it allowed something.
        assert!(toml::from_str::<TypeRestriction>("allowed = []").is_err());

        let built = TypeRestriction {
            allowed: Vec::new(),
            type_on_write: MemberOnWrite::Required,
        };

        assert_eq!(
            built.compile(&PolicyId::new("built-in-code").unwrap(), &context()),
            Err(CompileError::EmptyRestriction {
                policy: PolicyId::new("built-in-code").unwrap(),
                field: "the entity type restriction",
            })
        );
    }

    #[test]
    fn a_write_without_a_type_is_refused_unless_the_policy_says_otherwise() {
        assert_eq!(restriction(r#"["Vehicle"]"#).type_on_write, MemberOnWrite::Required);

        let relaxed: TypeRestriction = toml::from_str(
            r#"
            allowed = ["Vehicle"]
            type-on-write = "optional"
            "#,
        )
        .unwrap();

        assert_eq!(relaxed.type_on_write, MemberOnWrite::Optional);
    }

    #[test]
    fn a_type_the_restriction_does_not_list_is_not_allowed() {
        let compiled = restriction(r#"["Vehicle"]"#).compile(&PolicyId::new("p").unwrap(), &context()).unwrap();

        assert!(!compiled.allows(&context().expand(&Term::new("Building")).unwrap()));
    }
}
