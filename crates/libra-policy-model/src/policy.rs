//! A policy, and the file it is written in.
//!
//! A policy file declares the context its terms are written against. That declaration is not
//! optional decoration: `Vehicle` in a policy means whatever the policy's context says it means,
//! and without one there would be no answer to what the policy is about, only a word that happens
//! to look like the word a request used.

use crate::{
    access::{Access, CompiledAccess},
    condition::{CompiledCondition, Condition},
    error::{CompileError, ValueError},
    resource_family::ResourceFamily,
};
use derive_more::Display;
use iri_rs::IriBuf;
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use serde::{Deserialize, Serialize};

/// Longest policy identifier Libra will accept.
const MAX_POLICY_ID_LENGTH: usize = 128;

/// A policy's identifier.
///
/// Restricted to characters that need no escaping in a URL path segment, because the management
/// API addresses a policy by putting this in one. An identifier that had to be escaped could be
/// addressed two ways, and a policy that can be addressed two ways can be deleted by a request
/// that an audit log records as touching something else.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[display("{_0}")]
#[serde(try_from = "String", into = "String")]
pub struct PolicyId(String);

impl PolicyId {
    /// Checks and wraps an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::PolicyId`] if the identifier is empty, longer than 128 characters, or
    /// contains anything outside `A-Z`, `a-z`, `0-9`, `-`, `.`, `_` and `~`.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        let reason = if value.is_empty() {
            Some("it is empty")
        } else if value.len() > MAX_POLICY_ID_LENGTH {
            Some("it is longer than 128 characters")
        } else if !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~'))
        {
            Some("it contains a character that would have to be escaped in a URL path")
        } else {
            None
        };

        match reason {
            Some(reason) => Err(ValueError::PolicyId { value, reason }),
            None => Ok(Self(value)),
        }
    }

    /// The identifier as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PolicyId {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PolicyId> for String {
    fn from(id: PolicyId) -> Self {
        id.0
    }
}

/// One authorization policy, as authored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Policy {
    /// What this policy is called.
    pub id: PolicyId,

    /// What it is for, in the author's words.
    #[serde(default)]
    pub description: String,

    /// Which policy wins when more than one matches. Higher is stronger.
    pub priority: u32,

    /// What has to be true of a request for this policy to apply.
    #[serde(default)]
    pub condition: Condition,

    /// What it allows, and the restrictions it attaches.
    pub access: Access,
}

impl Policy {
    /// Whether the policy can ever apply and allow something.
    #[must_use]
    pub fn is_satisfiable(&self) -> bool {
        self.condition.is_satisfiable() && self.access.is_satisfiable()
    }

    /// Expands every name in the policy against `context`.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] if any name has no meaning in that context.
    pub fn compile(&self, context: &ResolvedContext) -> Result<CompiledPolicy, CompileError> {
        let id = &self.id;
        self.check_shape()?;

        Ok(CompiledPolicy {
            id: self.id.clone(),                   // compiling borrows the parsed policy
            description: self.description.clone(), // compiling borrows the parsed policy
            priority: self.priority,
            condition: self.condition.compile(id, context)?,
            access: self.access.compile(id, context)?,
        })
    }
}

impl Policy {
    /// Refuses the combinations of effect, resources and restrictions that would not mean what they
    /// say.
    fn check_shape(&self) -> Result<(), CompileError> {
        // The error owns the id, the caller keeps its policy.
        let policy = || self.id.clone();
        let restricted = self.access.is_restricted();

        if self.access.effect.is_deny() {
            if self.condition.queries.is_some() {
                return Err(CompileError::DenyByQuery { policy: policy() });
            }
            if restricted {
                return Err(CompileError::RestrictedDeny { policy: policy() });
            }
        }

        if let (true, Some(resources)) = (restricted, &self.condition.resources) {
            if resources.contains(&ResourceFamily::Snapshots) {
                return Err(CompileError::RestrictedSnapshots { policy: policy() });
            }
            if !resources.iter().any(|family| family.is_restrictable()) {
                return Err(CompileError::RestrictionNeverApplies { policy: policy() });
            }
        }

        Ok(())
    }
}

/// A policy whose names are IRIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// What this policy is called.
    pub id: PolicyId,
    /// What it is for.
    pub description: String,
    /// Which policy wins when more than one matches.
    pub priority: u32,
    /// What has to be true of a request for this policy to apply.
    pub condition: CompiledCondition,
    /// What it allows.
    pub access: CompiledAccess,
}

/// One policy file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicyFile {
    /// The contexts the terms in this file are written against, innermost first.
    ///
    /// Empty means the NGSI-LD core context alone, which is what the specification prescribes for
    /// a request that supplies nothing. Whatever is listed here is composed the same way a
    /// request's context is, so a policy and a request resolve a term through the same rules.
    #[serde(default)]
    pub context: Vec<IriBuf>,

    /// The policies in this file.
    #[serde(default)]
    pub policy: Vec<Policy>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle"
            }"#,
        )
        .unwrap()
    }

    const FILE: &str = r#"
        context = ["https://example.test/fleet.jsonld"]

        [[policy]]
        id = "fleet-read"
        description = "Fleet operators may read vehicles"
        priority = 100

        [policy.condition]
        roles = ["fleet-operator"]
        operations = ["read"]
        entity-types = ["Vehicle"]

        [policy.access]
        effect = "allow"

        [policy.access.attribute]
        action = "omit"
        attributes = ["location"]
    "#;

    #[test]
    fn a_policy_file_reads_the_way_it_is_written() {
        let file: PolicyFile = toml::from_str(FILE).unwrap();

        assert_eq!(file.context, [IriBuf::new("https://example.test/fleet.jsonld".to_owned()).unwrap()]);
        assert_eq!(file.policy.len(), 1);
        assert_eq!(file.policy[0].id.as_str(), "fleet-read");
        assert_eq!(file.policy[0].priority, 100);
    }

    #[test]
    fn a_policy_compiles_its_names_to_iris() {
        let file: PolicyFile = toml::from_str(FILE).unwrap();
        let compiled = file.policy[0].compile(&context()).unwrap();

        assert_eq!(
            compiled.condition.entity_types.as_ref().map(Vec::len),
            Some(1),
            "the condition's type is an IRI by the time it is stored"
        );
        assert!(compiled.access.attribute.is_some());
    }

    #[test]
    fn an_identifier_that_would_need_escaping_in_a_url_is_refused() {
        // The management API puts this in a path segment. Two spellings of one policy is one
        // policy that can be deleted by a request the audit log records differently.
        for hostile in ["", "a/b", "a b", "a%2Fb", "a?b", "a#b", "../etc"] {
            assert!(PolicyId::new(hostile).is_err(), "{hostile:?} must not be a policy id");
        }
        assert!(PolicyId::new("fleet-read.v2_1~a").is_ok());
    }

    #[test]
    fn a_policy_with_no_condition_applies_to_everything() {
        let catch_all: Policy = toml::from_str(
            r#"
            id = "default-deny"
            priority = 0

            [access]
            effect = "deny"
            "#,
        )
        .unwrap();

        assert_eq!(catch_all.condition, Condition::default());
        assert!(catch_all.is_satisfiable());
    }

    #[test]
    fn a_policy_that_could_never_apply_is_recognised() {
        let never: Policy = toml::from_str(
            r#"
            id = "never"
            priority = 1

            [condition]
            roles = []

            [access]
            effect = "allow"
            "#,
        )
        .unwrap();

        assert!(!never.is_satisfiable());
    }

    #[test]
    fn a_misspelled_top_level_key_is_refused() {
        // `[[policies]]` would parse into a file with no policies at all: every policy in the
        // file silently not loaded, and the default effect applying to everything.
        assert!(toml::from_str::<PolicyFile>("[[policies]]\nid = \"x\"\npriority = 1").is_err());
    }

    #[test]
    fn a_file_that_declares_no_context_is_legal() {
        let file: PolicyFile = toml::from_str("[[policy]]\nid = \"x\"\npriority = 1\n\n[policy.access]\neffect = \"deny\"").unwrap();

        assert!(file.context.is_empty(), "the core context alone is the specification's own default");
    }

    fn shaped(condition: &str, access: &str) -> Result<CompiledPolicy, CompileError> {
        let source = format!("id = \"p\"\npriority = 1\n[condition]\n{condition}\n[access]\n{access}");
        let policy: Policy = toml::from_str(&source).unwrap();

        policy.compile(&context())
    }

    const OMIT: &str = "effect = \"allow\"\n[access.attribute]\naction = \"omit\"\nattributes = [\"location\"]";

    #[test]
    fn a_restriction_on_resources_that_hold_no_entity_data_fails_to_load() {
        assert!(matches!(
            shaped("resources = [\"contexts\"]", OMIT),
            Err(CompileError::RestrictionNeverApplies { .. })
        ));
    }

    #[test]
    fn a_restriction_beside_an_entity_resource_loads() {
        assert!(shaped("resources = [\"contexts\", \"entities\"]", OMIT).is_ok());
    }

    #[test]
    fn a_restriction_without_resources_applies_to_entity_data_and_loads() {
        assert!(shaped("", OMIT).is_ok());
    }

    #[test]
    fn a_restriction_naming_snapshots_fails_to_load() {
        assert!(matches!(
            shaped("resources = [\"entities\", \"snapshots\"]", OMIT),
            Err(CompileError::RestrictedSnapshots { .. })
        ));
    }

    #[test]
    fn an_unrestricted_policy_may_name_snapshots() {
        assert!(shaped("resources = [\"snapshots\"]", "effect = \"allow\"").is_ok());
    }

    #[test]
    fn a_deny_with_queries_fails_to_load() {
        assert!(matches!(
            shaped("queries = [\"?type=Vehicle\"]", "effect = \"deny\""),
            Err(CompileError::DenyByQuery { .. })
        ));
    }

    #[test]
    fn a_deny_carrying_a_restriction_fails_to_load() {
        let restricted_deny = "effect = \"deny\"\n[access.scope]\nallowed = [\"/Madrid/#\"]";

        assert!(matches!(shaped("", restricted_deny), Err(CompileError::RestrictedDeny { .. })));
    }

    #[test]
    fn an_allow_with_queries_loads() {
        assert!(shaped("queries = [\"?type=Vehicle\"]", "effect = \"allow\"").is_ok());
    }

    #[test]
    fn a_policy_id_is_written_back_exactly_as_it_was_read() {
        // The management API and the audit log both carry the id in its written form.
        assert_eq!(String::from(PolicyId::new("fleet-read").unwrap()), "fleet-read");
    }
}
