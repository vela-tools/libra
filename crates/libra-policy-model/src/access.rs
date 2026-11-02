//! What a matched policy allows, and the restrictions it attaches.
//!
//! Every restriction is a field here. A key that is none of them is refused when the policy file is
//! read, which is what keeps a misspelled restriction from being read as an unrestricted allow.

use crate::{
    aggregation::AggregationRestriction,
    attribute::{AttributeRestriction, CompiledAttributeRestriction},
    effect::Effect,
    entity_type::{CompiledTypeRestriction, TypeRestriction},
    error::CompileError,
    policy::PolicyId,
    scope::ScopeRestriction,
    time::TimeRestriction,
};
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The outcome block of a policy, as authored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Access {
    /// Whether the request is allowed.
    pub effect: Effect,

    /// Scopes the restriction is limited to.
    #[serde(default)]
    pub scope: Option<ScopeRestriction>,

    /// Entity types the restriction is limited to.
    #[serde(default)]
    pub entity_type: Option<TypeRestriction>,

    /// The window of instants the restriction covers.
    #[serde(default)]
    pub time: Option<TimeRestriction>,

    /// Attributes the restriction covers.
    #[serde(default)]
    pub attribute: Option<AttributeRestriction>,

    /// How temporal reads under the restriction have to aggregate.
    #[serde(default)]
    pub aggregation: Option<AggregationRestriction>,
}

impl Access {
    /// Whether the access block can ever allow anything.
    #[must_use]
    pub fn is_satisfiable(&self) -> bool {
        self.time.as_ref().is_none_or(TimeRestriction::is_satisfiable)
    }

    /// Whether the access block carries any restriction.
    #[must_use]
    pub const fn is_restricted(&self) -> bool {
        self.scope.is_some() || self.entity_type.is_some() || self.time.is_some() || self.attribute.is_some() || self.aggregation.is_some()
    }

    /// Expands every name in the access block against the policy's declared context.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError::UnexpandableTerm`] if a type or attribute name has no meaning in
    /// that context.
    pub fn compile(&self, policy: &PolicyId, context: &ResolvedContext) -> Result<CompiledAccess, CompileError> {
        // The restrictions that need no expansion are cloned once, here: compiling borrows the
        // parsed policy, and every decision after this shares the compiled copy.
        Ok(CompiledAccess {
            effect: self.effect,
            scope: self.scope.clone().map(Arc::new),
            entity_type: self
                .entity_type
                .as_ref()
                .map(|restriction| restriction.compile(policy, context).map(Arc::new))
                .transpose()?,
            time: self.time.clone().map(Arc::new),
            attribute: self
                .attribute
                .as_ref()
                .map(|restriction| restriction.compile(policy, context).map(Arc::new))
                .transpose()?,
            aggregation: self.aggregation.clone().map(Arc::new),
        })
    }
}

/// An access block whose names are IRIs.
///
/// Each restriction is shared: every decision this policy makes holds the same one, so handing a
/// restriction to a request costs a reference count rather than a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledAccess {
    /// Whether the request is allowed.
    pub effect: Effect,
    /// Scopes the restriction is limited to.
    pub scope: Option<Arc<ScopeRestriction>>,
    /// Entity types the restriction is limited to.
    pub entity_type: Option<Arc<CompiledTypeRestriction>>,
    /// The window of instants the restriction covers.
    pub time: Option<Arc<TimeRestriction>>,
    /// Attributes the restriction covers.
    pub attribute: Option<Arc<CompiledAttributeRestriction>>,
    /// How temporal reads under the restriction have to aggregate.
    pub aggregation: Option<Arc<AggregationRestriction>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::UnaggregatedReads;
    use pretty_assertions::assert_eq;

    fn access(source: &str) -> Access {
        toml::from_str(source).unwrap()
    }

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(r#"{"@vocab": "https://uri.etsi.org/ngsi-ld/default-context/"}"#).unwrap()
    }

    #[test]
    fn an_unrestricted_allow_carries_no_restriction() {
        let allow = access("effect = \"allow\"");

        assert!(allow.scope.is_none() && allow.entity_type.is_none() && allow.time.is_none() && allow.attribute.is_none() && allow.aggregation.is_none());
    }

    #[test]
    fn every_restriction_is_read_into_its_own_field() {
        let full = access(
            r#"
            effect = "allow"

            [scope]
            allowed = ["/Madrid/#"]

            [entity-type]
            allowed = ["Vehicle"]

            [time]
            type = "relative"
            duration = "PT24H"

            [attribute]
            action = "omit"
            attributes = ["location"]

            [aggregation]
            unaggregated = "disallowed"
            allowed-methods = ["avg"]
            min-period-duration = "PT1H"
            "#,
        );

        assert!(full.scope.is_some());
        assert!(full.entity_type.is_some());
        assert!(full.time.is_some());
        assert!(full.attribute.is_some());
        assert_eq!(
            full.aggregation.as_ref().map(AggregationRestriction::unaggregated),
            Some(UnaggregatedReads::Disallowed)
        );
    }

    #[test]
    fn a_key_that_is_no_restriction_is_refused_when_read_and_named() {
        // `[scopes]` is a misspelling and `[embargo]` a restriction nothing enforces. Either one,
        // loaded and ignored, would turn the policy into an unrestricted allow.
        for (source, key) in [
            ("effect = \"allow\"\n\n[scopes]\nallowed = [\"/Madrid/#\"]", "scopes"),
            ("effect = \"allow\"\n\n[embargo]\nuntil = 2030-01-01T00:00:00Z", "embargo"),
        ] {
            let refused = toml::from_str::<Access>(source).unwrap_err();

            assert!(refused.to_string().contains(key), "{refused}");
        }
    }

    #[test]
    fn a_deny_carrying_a_restriction_compiles() {
        // A deny refuses outright, so a restriction on it is never enforced and needs nothing.
        let deny = access(
            r#"
            effect = "deny"

            [aggregation]
            allowed-methods = ["avg"]
            "#,
        );

        assert!(deny.compile(&PolicyId::new("p").unwrap(), &context()).is_ok());
    }

    #[test]
    fn compiling_keeps_the_aggregation_restriction() {
        let allow = access(
            r#"
            effect = "allow"

            [aggregation]
            allowed-methods = ["avg"]
            "#,
        );

        let compiled = allow.compile(&PolicyId::new("p").unwrap(), &context()).unwrap();

        assert_eq!(compiled.aggregation.as_deref(), allow.aggregation.as_ref());
    }

    #[test]
    fn an_access_block_with_a_backwards_window_is_unsatisfiable() {
        let backwards = access(
            r#"
            effect = "allow"

            [time]
            type = "absolute"
            start = 2026-02-01T00:00:00Z
            end = 2026-01-01T00:00:00Z
            "#,
        );

        assert!(!backwards.is_satisfiable());
    }

    #[test]
    fn a_misspelled_key_inside_a_restriction_is_refused() {
        // The restriction's own table denies unknown fields too, so a typo one level down cannot
        // leave the list at its default.
        assert!(
            toml::from_str::<Access>(
                r#"
                effect = "allow"

                [scope]
                alowed = ["/Madrid/#"]
                "#
            )
            .is_err()
        );
    }

    #[test]
    fn any_one_restriction_makes_an_access_block_restricted() {
        // Each restriction on its own has to count: an allow whose only restriction went unnoticed
        // would be enforced as an unrestricted allow.
        assert!(!access("effect = \"allow\"").is_restricted());

        for section in [
            "[scope]\nallowed = [\"/Madrid/#\"]",
            "[entity-type]\nallowed = [\"Vehicle\"]",
            "[time]\ntype = \"relative\"\nduration = \"PT24H\"",
            "[attribute]\naction = \"omit\"\nattributes = [\"location\"]",
            "[aggregation]\nallowed-methods = [\"avg\"]",
        ] {
            assert!(access(&format!("effect = \"allow\"\n\n{section}")).is_restricted(), "{section}");
        }
    }
}
