//! What evaluation produces, and what the enforcement layers read.

use libra_policy_model::{
    aggregation::AggregationRestriction,
    attribute::CompiledAttributeRestriction,
    effect::Effect,
    entity_type::CompiledTypeRestriction,
    policy::PolicyId,
    scope::ScopeRestriction,
    time::TimeRestriction,
};
use std::sync::Arc;

/// The outcome of evaluating one request.
///
/// The restrictions are the matched policy's own, shared rather than copied, so an enforcement
/// layer takes one with a reference count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the request is allowed at all.
    pub effect: Effect,

    /// The policy that decided it, or `None` when the default effect applied.
    pub matched: Option<PolicyId>,

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

impl Decision {
    /// A refusal, with nothing attached.
    #[must_use]
    pub const fn deny(matched: Option<PolicyId>) -> Self {
        Self {
            effect: Effect::Deny,
            matched,
            scope: None,
            entity_type: None,
            time: None,
            attribute: None,
            aggregation: None,
        }
    }

    /// Whether the request was refused.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        self.effect.is_deny()
    }
}
