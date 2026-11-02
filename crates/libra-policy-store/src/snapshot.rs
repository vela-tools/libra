//! The compiled policy set, in the order the engine evaluates it.
//!
//! Ordering is part of the security model rather than a detail of storage. Two policies that both
//! match must resolve the same way on every process and every restart, or an authorization
//! decision depends on which order a directory listing came back in.

use libra_policy_model::{
    effect::Effect,
    policy::{CompiledPolicy, PolicyId},
};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// An immutable, ordered policy set.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    policies: Vec<CompiledPolicy>,
    sources: BTreeMap<PolicyId, Source>,
    default_effect: Effect,
}

/// Where a policy came from.
///
/// Recorded because the management API edits files, and it can only edit a policy whose file it
/// can identify. Rewriting a hand-authored file that holds several policies would flatten a
/// multi-file layout into one generated file while leaving the originals on disk, so that the next
/// reload found every policy twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The file the policy was read from.
    pub path: PathBuf,
    /// How many policies that file holds.
    pub siblings: usize,
}

impl PolicySnapshot {
    /// Orders a policy set and freezes it.
    #[must_use]
    pub fn new(policies: Vec<CompiledPolicy>, default_effect: Effect) -> Self {
        Self::with_sources(policies, BTreeMap::new(), default_effect)
    }

    /// Orders a policy set, freezes it, and records where each policy came from.
    #[must_use]
    pub fn with_sources(mut policies: Vec<CompiledPolicy>, sources: BTreeMap<PolicyId, Source>, default_effect: Effect) -> Self {
        policies.sort_by(Self::precedence);

        Self {
            policies,
            sources,
            default_effect,
        }
    }

    /// The file a policy was read from, and how many policies share it.
    #[must_use]
    pub fn source_of(&self, id: &PolicyId) -> Option<&Source> {
        self.sources.get(id)
    }

    /// Whether a policy is the only one in its file, and therefore editable as a file.
    #[must_use]
    pub fn is_solely_defined_by_its_file(&self, id: &PolicyId) -> bool {
        self.source_of(id).is_some_and(|source| source.siblings == 1)
    }

    /// Every file the policy set was read from.
    #[must_use]
    pub fn files(&self) -> Vec<&Path> {
        let mut files: Vec<&Path> = self.sources.values().map(|source| source.path.as_path()).collect();
        files.sort_unstable();
        files.dedup();

        files
    }

    /// The policies, strongest first.
    #[must_use]
    pub fn policies(&self) -> &[CompiledPolicy] {
        &self.policies
    }

    /// What applies when no policy matches.
    #[must_use]
    pub const fn default_effect(&self) -> Effect {
        self.default_effect
    }

    /// How many policies are loaded.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.policies.len()
    }

    /// Whether the set is empty.
    ///
    /// An empty set is legal: it means the default effect decides every request, which with the
    /// default configuration is a refusal.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Finds a policy by identifier.
    #[must_use]
    pub fn get(&self, id: &PolicyId) -> Option<&CompiledPolicy> {
        self.policies.iter().find(|policy| &policy.id == id)
    }

    /// The order policies are evaluated in.
    ///
    /// Descending priority first, because that is what priority means. Then deny before allow at
    /// equal priority, so a tie is broken towards refusing. Then ascending identifier, so the
    /// result does not depend on the order the files were read in; without that last step, two
    /// equally-ranked policies would resolve differently on different machines.
    fn precedence(left: &CompiledPolicy, right: &CompiledPolicy) -> Ordering {
        // Deny sorts before allow, so a tie is broken towards refusing.
        let rank = |effect: Effect| u8::from(!effect.is_deny());

        right
            .priority
            .cmp(&left.priority)
            .then_with(|| rank(left.access.effect).cmp(&rank(right.access.effect)))
            .then_with(|| left.id.cmp(&right.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_jsonld_term_expansion::resolved::ResolvedContext;
    use libra_policy_model::{
        access::Access,
        condition::Condition,
        policy::{Policy, PolicyId},
    };
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(r#"{"@vocab": "https://uri.etsi.org/ngsi-ld/default-context/"}"#).unwrap()
    }

    fn policy(id: &str, priority: u32, effect: Effect) -> CompiledPolicy {
        Policy {
            id: PolicyId::new(id).unwrap(),
            description: String::new(),
            priority,
            condition: Condition::default(),
            access: Access {
                effect,
                scope: None,
                entity_type: None,
                time: None,
                attribute: None,
                aggregation: None,
            },
        }
        .compile(&context())
        .unwrap()
    }

    fn order(policies: Vec<CompiledPolicy>) -> Vec<String> {
        PolicySnapshot::new(policies, Effect::Deny)
            .policies()
            .iter()
            .map(|policy| policy.id.as_str().to_owned())
            .collect()
    }

    #[test]
    fn a_higher_priority_policy_comes_first() {
        assert_eq!(
            order(vec![policy("low", 1, Effect::Allow), policy("high", 100, Effect::Allow)]),
            ["high", "low"]
        );
    }

    #[test]
    fn a_tie_is_broken_towards_refusing() {
        assert_eq!(
            order(vec![policy("z-allow", 50, Effect::Allow), policy("a-deny", 50, Effect::Deny)]),
            ["a-deny", "z-allow"]
        );
    }

    #[test]
    fn a_remaining_tie_is_broken_by_identifier_so_it_does_not_depend_on_the_filesystem() {
        // Without this, two equally-ranked policies resolve in whatever order the directory
        // listing produced, which differs between machines and between runs.
        assert_eq!(
            order(vec![policy("beta", 50, Effect::Allow), policy("alpha", 50, Effect::Allow)]),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn the_order_is_the_same_however_the_policies_arrived() {
        let scrambled = vec![
            policy("c-allow", 10, Effect::Allow),
            policy("a-deny", 10, Effect::Deny),
            policy("b-deny", 10, Effect::Deny),
            policy("d-allow", 10, Effect::Allow),
        ];
        let reversed: Vec<CompiledPolicy> = scrambled.iter().rev().cloned().collect();

        assert_eq!(order(scrambled), ["a-deny", "b-deny", "c-allow", "d-allow"]);
        assert_eq!(order(reversed), ["a-deny", "b-deny", "c-allow", "d-allow"]);
    }

    #[test]
    fn an_empty_set_leaves_the_default_effect_to_decide() {
        let snapshot = PolicySnapshot::new(Vec::new(), Effect::Deny);

        assert!(snapshot.is_empty());
        assert_eq!(snapshot.default_effect(), Effect::Deny);
    }
}
