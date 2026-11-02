//! Evaluating a request against the policy set.
//!
//! One scan, in precedence order. The strongest matching policy decides everything: whether the
//! request is allowed, and every restriction the allow carries. Nothing is combined across
//! policies, because a restriction is only meaningful beside the others its own policy states: an
//! attribute restriction written for one scope, joined to another policy's scope, allows something
//! neither policy says.

use crate::{decision::Decision, matching::matches, request::EvaluationRequest};
use libra_policy_model::effect::Effect;
use libra_policy_store::snapshot::PolicySnapshot;
use tracing::debug;

/// Decides whether a request is allowed, and under what restrictions.
///
/// The first matching policy in precedence order is the decision. A deny carries nothing, because
/// there is nothing to restrict in a request that is refused.
#[must_use]
pub fn evaluate(snapshot: &PolicySnapshot, request: &EvaluationRequest<'_>) -> Decision {
    let Some(policy) = snapshot
        .policies()
        .iter()
        .find(|policy| matches(&policy.condition, policy.access.effect, request))
    else {
        debug!(effect = ?snapshot.default_effect(), "no policy matched");

        return Decision {
            effect: snapshot.default_effect(),
            matched: None,
            scope: None,
            entity_type: None,
            time: None,
            attribute: None,
            aggregation: None,
        };
    };

    if policy.access.effect.is_deny() {
        debug!(policy = %policy.id, "denied by policy");

        return Decision::deny(Some(policy.id.clone())); // the decision outlives the policy snapshot it was read from
    }

    debug!(policy = %policy.id, "allowed by policy");

    // The decision outlives the policy snapshot it was read from. The id is copied; each
    // restriction is shared, so its clone is a reference count.
    Decision {
        effect: Effect::Allow,
        matched: Some(policy.id.clone()),
        scope: policy.access.scope.clone(),
        entity_type: policy.access.entity_type.clone(),
        time: policy.access.time.clone(),
        attribute: policy.access.attribute.clone(),
        aggregation: policy.access.aggregation.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::RequestedTypes;
    use jiff::Timestamp;
    use libra_jsonld_term_expansion::{
        name::{ExpandedIri, Term},
        resolved::ResolvedContext,
    };
    use libra_ngsi_ld_query::aggregation::AggregationMethod;
    use libra_policy_model::{
        attribute::AttributeAction,
        identity::{GroupName, IdentityName, PrincipalName, RoleName, TenantId, TenantSelector, Username},
        operation::Operation,
        policy::{PolicyFile, PolicyId},
        query::{CompiledQuerySelector, QuerySelector},
        resource_family::ResourceFamily,
    };
    use pretty_assertions::assert_eq;
    use strum::IntoEnumIterator;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Building": "https://uri.fiware.org/ns/data-models#Building",
                "speed": "https://uri.fiware.org/ns/data-models#speed",
                "brand": "https://uri.fiware.org/ns/data-models#brand",
                "location": "https://uri.etsi.org/ngsi-ld/location"
            }"#,
        )
        .expect("the test context should process")
    }

    fn iri(term: &str) -> ExpandedIri {
        context().expand(&Term::new(term)).expect("the term should expand")
    }

    fn snapshot(source: &str, default_effect: Effect) -> PolicySnapshot {
        let file: PolicyFile = toml::from_str(source).expect("the policy file should parse");
        let context = context();
        let compiled = file
            .policy
            .iter()
            .map(|policy| policy.compile(&context).expect("the policy should compile"))
            .collect();

        PolicySnapshot::new(compiled, default_effect)
    }

    fn at(text: &str) -> Timestamp {
        text.parse().expect("the instant should parse")
    }

    /// A request with nothing narrowed, for tests that vary one thing.
    struct Request {
        name: Option<IdentityName>,
        groups: Vec<GroupName>,
        roles: Vec<RoleName>,
        tenant: TenantSelector,
        operation: Operation,
        resource: ResourceFamily,
        entity_types: Option<Vec<ExpandedIri>>,
        query: Option<CompiledQuerySelector>,
        now: Timestamp,
    }

    impl Default for Request {
        fn default() -> Self {
            Self {
                name: Some(IdentityName::Account(Username::new("alice").unwrap())),
                groups: Vec::new(),
                roles: Vec::new(),
                tenant: TenantSelector::Untenanted,
                operation: Operation::Read,
                resource: ResourceFamily::Entities,
                entity_types: None,
                query: None,
                now: at("2026-01-15T12:00:00Z"),
            }
        }
    }

    impl Request {
        fn decide(&self, snapshot: &PolicySnapshot) -> Decision {
            evaluate(
                snapshot,
                &EvaluationRequest {
                    name: self.name.as_ref(),
                    groups: &self.groups,
                    roles: &self.roles,
                    tenant: &self.tenant,
                    operation: self.operation,
                    resource: self.resource,
                    entity_types: self.entity_types.as_deref().map_or(RequestedTypes::Unbounded, RequestedTypes::Named),
                    query: self.query.as_ref(),
                    now: self.now,
                },
            )
        }
    }

    const ALLOW_ALL: &str = r#"
        [[policy]]
        id = "allow-all"
        priority = 1
        [policy.access]
        effect = "allow"
    "#;

    #[test]
    fn nothing_matching_leaves_the_default_effect_to_decide() {
        let empty = snapshot("", Effect::Deny);
        let decision = Request::default().decide(&empty);

        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.matched, None);
    }

    #[test]
    fn a_policy_with_no_condition_matches_everything() {
        let decision = Request::default().decide(&snapshot(ALLOW_ALL, Effect::Deny));

        assert_eq!(decision.effect, Effect::Allow);
        assert!(!decision.is_deny());
        assert_eq!(decision.matched.map(|id| id.as_str().to_owned()), Some("allow-all".to_owned()));
    }

    #[test]
    fn the_highest_priority_policy_decides() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "low-deny"
            priority = 1
            [policy.access]
            effect = "deny"

            [[policy]]
            id = "high-allow"
            priority = 100
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        assert_eq!(Request::default().decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn a_tie_is_broken_towards_refusing() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "z-allow"
            priority = 50
            [policy.access]
            effect = "allow"

            [[policy]]
            id = "a-deny"
            priority = 50
            [policy.access]
            effect = "deny"
            "#,
            Effect::Allow,
        );

        let decision = Request::default().decide(&policies);

        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.matched.map(|id| id.as_str().to_owned()), Some("a-deny".to_owned()));
    }

    #[test]
    fn a_role_matches_only_by_its_exact_name() {
        // A role called `admin` must not satisfy a policy that asked for `ngsi-client:admin`. They
        // are different roles that happen to share a word.
        let policies = snapshot(
            r#"
            [[policy]]
            id = "client-admin"
            priority = 10
            [policy.condition]
            roles = ["ngsi-client:admin"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        let bare = Request {
            roles: vec![RoleName::new("admin").unwrap()],
            ..Request::default()
        };
        let prefixed = Request {
            roles: vec![RoleName::new("ngsi-client:admin").unwrap()],
            ..Request::default()
        };

        assert_eq!(bare.decide(&policies).effect, Effect::Deny);
        assert_eq!(prefixed.decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn an_untenanted_request_is_not_the_same_as_any_named_tenant() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "acme-only"
            priority = 10
            [policy.condition]
            tenants = ["acme"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        let untenanted = Request::default();
        let acme = Request {
            tenant: TenantSelector::Named(TenantId::new("acme").unwrap()),
            ..Request::default()
        };

        assert_eq!(untenanted.decide(&policies).effect, Effect::Deny);
        assert_eq!(acme.decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn a_policy_can_name_the_untenanted_case_explicitly() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "public"
            priority = 10
            [policy.condition]
            tenants = ["*untenanted"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        assert_eq!(Request::default().decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn a_type_condition_matches_through_the_context_rather_than_the_spelling() {
        // The policy says `Vehicle`, the request says `Car`, and under this context they are one type.
        let policies = snapshot(
            r#"
            [[policy]]
            id = "vehicles"
            priority = 10
            [policy.condition]
            entity-types = ["Vehicle"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        let as_car = Request {
            entity_types: Some(vec![iri("Car")]),
            ..Request::default()
        };
        let as_building = Request {
            entity_types: Some(vec![iri("Building")]),
            ..Request::default()
        };

        assert_eq!(as_car.decide(&policies).effect, Effect::Allow);
        assert_eq!(as_building.decide(&policies).effect, Effect::Deny);
    }

    #[test]
    fn a_request_that_names_no_type_does_not_satisfy_a_type_condition() {
        // An unknown type is not treated as matching. Leaving the check to a layer further down would
        // rely on a layer that may be absent and that must not treat its own pre-flight failures as
        // permission.
        let policies = snapshot(
            r#"
            [[policy]]
            id = "vehicles"
            priority = 10
            [policy.condition]
            entity-types = ["Vehicle"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        assert_eq!(
            Request::default().decide(&policies).effect,
            Effect::Deny,
            "a caller who does not say what they are touching is governed by whichever policy does not ask"
        );
    }

    const SECRET_DENY_OVER_BROAD_ALLOW: &str = r#"
        [[policy]]
        id = "no-secrets"
        priority = 100
        [policy.condition]
        entity-types = ["Building"]
        [policy.access]
        effect = "deny"

        [[policy]]
        id = "allow-all"
        priority = 1
        [policy.access]
        effect = "allow"
    "#;

    #[test]
    fn a_deny_on_a_type_applies_to_a_request_that_names_no_type() {
        // A read by id, a batch body and a subscription name their type outside the query string.
        // A deny that stood aside for them would be bypassed by asking differently.
        let policies = snapshot(SECRET_DENY_OVER_BROAD_ALLOW, Effect::Deny);
        let decision = Request::default().decide(&policies);

        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.matched.map(|id| id.as_str().to_owned()), Some("no-secrets".to_owned()));
    }

    #[test]
    fn a_deny_on_a_type_applies_when_the_request_names_it_among_others() {
        // `?type=Vehicle|Building` and `?type=Vehicle,Building` both reach the broker as "either".
        let policies = snapshot(SECRET_DENY_OVER_BROAD_ALLOW, Effect::Deny);
        let request = Request {
            entity_types: Some(vec![iri("Vehicle"), iri("Building")]),
            ..Request::default()
        };

        assert_eq!(request.decide(&policies).effect, Effect::Deny);
    }

    #[test]
    fn a_deny_on_a_type_leaves_a_request_for_other_types_alone() {
        let policies = snapshot(SECRET_DENY_OVER_BROAD_ALLOW, Effect::Deny);
        let request = Request {
            entity_types: Some(vec![iri("Vehicle")]),
            ..Request::default()
        };

        assert_eq!(request.decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn an_allow_for_one_type_does_not_cover_a_request_that_also_names_another() {
        // `?type=Vehicle,Building` is answered with buildings too, which this allow never allowed.
        let policies = snapshot(
            r#"
            [[policy]]
            id = "vehicles"
            priority = 10
            [policy.condition]
            entity-types = ["Vehicle"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );
        let both = Request {
            entity_types: Some(vec![iri("Vehicle"), iri("Building")]),
            ..Request::default()
        };
        let aliases_of_one = Request {
            entity_types: Some(vec![iri("Car"), iri("Vehicle")]),
            ..Request::default()
        };

        assert_eq!(both.decide(&policies).effect, Effect::Deny);
        assert_eq!(aliases_of_one.decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn an_anonymous_request_cannot_satisfy_a_policy_that_names_users() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "alice-only"
            priority = 10
            [policy.condition]
            users = ["alice"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        let anonymous = Request {
            name: None,
            ..Request::default()
        };

        assert_eq!(anonymous.decide(&policies).effect, Effect::Deny);
        assert_eq!(Request::default().decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn users_and_principals_are_separate_namespaces() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "alice-account"
            priority = 10
            [policy.condition]
            users = ["alice"]
            [policy.access]
            effect = "allow"

            [[policy]]
            id = "ingest-principal"
            priority = 10
            [policy.condition]
            principals = ["ingest"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );
        let caller = |name: IdentityName| Request {
            name: Some(name),
            ..Request::default()
        };
        let account = |name: &str| caller(IdentityName::Account(Username::new(name).unwrap()));
        let principal = |name: &str| caller(IdentityName::Principal(PrincipalName::new(name).unwrap()));

        assert_eq!(account("alice").decide(&policies).effect, Effect::Allow);
        assert_eq!(principal("ingest").decide(&policies).effect, Effect::Allow);
        // The same names in the other namespace match nothing.
        assert_eq!(principal("alice").decide(&policies).effect, Effect::Deny);
        assert_eq!(account("ingest").decide(&policies).effect, Effect::Deny);
    }

    #[test]
    fn a_recurring_interval_gates_when_the_request_may_be_made() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "office-hours"
            priority = 10
            [policy.condition.time-interval]
            days = ["mon", "tue", "wed", "thu"]
            start = 09:00:00
            end = 17:00:00
            timezone = "UTC"
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        // 2026-01-15 is a Thursday.
        let inside = Request {
            now: at("2026-01-15T12:00:00Z"),
            ..Request::default()
        };
        let after_hours = Request {
            now: at("2026-01-15T21:00:00Z"),
            ..Request::default()
        };
        let weekend = Request {
            now: at("2026-01-17T12:00:00Z"),
            ..Request::default()
        };

        assert_eq!(inside.decide(&policies).effect, Effect::Allow);
        assert_eq!(after_hours.decide(&policies).effect, Effect::Deny);
        assert_eq!(weekend.decide(&policies).effect, Effect::Deny);
    }

    #[test]
    fn a_weaker_allows_pick_does_not_widen_the_winners() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "speed"
            priority = 20
            [policy.access]
            effect = "allow"
            [policy.access.attribute]
            action = "pick"
            attributes = ["speed"]

            [[policy]]
            id = "brand"
            priority = 10
            [policy.access]
            effect = "allow"
            [policy.access.attribute]
            action = "pick"
            attributes = ["brand"]
            "#,
            Effect::Deny,
        );

        let attribute = Request::default().decide(&policies).attribute.expect("an attribute restriction");

        assert_eq!(attribute.action(), AttributeAction::Pick);
        assert!(attribute.allows(&iri("speed")));
        assert!(!attribute.allows(&iri("brand")), "the weaker restriction is not the decision");
    }

    #[test]
    fn a_weaker_allows_pick_does_not_narrow_an_unrestricted_winner() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "everything"
            priority = 20
            [policy.access]
            effect = "allow"

            [[policy]]
            id = "speed"
            priority = 10
            [policy.access]
            effect = "allow"
            [policy.access.attribute]
            action = "pick"
            attributes = ["speed"]
            "#,
            Effect::Deny,
        );

        assert_eq!(Request::default().decide(&policies).attribute, None);
    }

    #[test]
    fn a_weaker_allows_omit_does_not_narrow_the_winner() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "plain-allow"
            priority = 20
            [policy.access]
            effect = "allow"
            [policy.access.attribute]
            action = "pick"
            attributes = ["speed", "location"]

            [[policy]]
            id = "hide-location"
            priority = 10
            [policy.access]
            effect = "allow"
            [policy.access.attribute]
            action = "omit"
            attributes = ["location"]
            "#,
            Effect::Deny,
        );

        let attribute = Request::default().decide(&policies).attribute.expect("an attribute restriction");

        assert!(attribute.allows(&iri("speed")));
        assert!(attribute.allows(&iri("location")), "a weaker policy has no say in what the winner exposes");
    }

    #[test]
    fn an_attribute_restriction_never_travels_to_another_policys_scope() {
        // Combining the two would expose `brand` inside `/A`, which neither policy allows.
        let policies = snapshot(
            r#"
            [[policy]]
            id = "speed-in-a"
            priority = 20
            [policy.access]
            effect = "allow"
            [policy.access.scope]
            allowed = ["/A"]
            [policy.access.attribute]
            action = "pick"
            attributes = ["speed"]

            [[policy]]
            id = "brand-in-b"
            priority = 10
            [policy.access]
            effect = "allow"
            [policy.access.scope]
            allowed = ["/B"]
            [policy.access.attribute]
            action = "pick"
            attributes = ["brand"]
            "#,
            Effect::Deny,
        );

        let decision = Request::default().decide(&policies);
        let attribute = decision.attribute.expect("an attribute restriction");

        assert_eq!(decision.matched, Some(PolicyId::new("speed-in-a").unwrap()));
        assert_eq!(attribute.attributes(), [iri("speed")]);
    }

    #[test]
    fn a_deny_that_lost_the_decision_does_not_change_what_the_winner_exposes() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "plain-allow"
            priority = 100
            [policy.access]
            effect = "allow"
            [policy.access.attribute]
            action = "pick"
            attributes = ["speed"]

            [[policy]]
            id = "weak-deny"
            priority = 1
            [policy.access]
            effect = "deny"
            "#,
            Effect::Deny,
        );

        let attribute = Request::default().decide(&policies).attribute.expect("an attribute restriction");

        assert_eq!(attribute.attributes(), [iri("speed")]);
    }

    #[test]
    fn the_strongest_matching_allow_supplies_the_other_restrictions() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "strong"
            priority = 100
            [policy.access]
            effect = "allow"
            [policy.access.entity-type]
            allowed = ["Vehicle"]

            [[policy]]
            id = "weak"
            priority = 1
            [policy.access]
            effect = "allow"
            [policy.access.entity-type]
            allowed = ["Building"]
            "#,
            Effect::Deny,
        );

        let entity_type = Request::default().decide(&policies).entity_type.expect("a type restriction");

        assert!(entity_type.allows(&iri("Vehicle")));
        assert!(!entity_type.allows(&iri("Building")), "the weaker policy's list must not leak in");
    }

    #[test]
    fn a_deny_short_circuits_and_carries_nothing() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "refuse"
            priority = 100
            [policy.access]
            effect = "deny"

            [[policy]]
            id = "plain-allow"
            priority = 1
            [policy.access]
            effect = "allow"
            [policy.access.attribute]
            action = "pick"
            attributes = ["speed"]
            "#,
            Effect::Deny,
        );

        let decision = Request::default().decide(&policies);

        assert!(decision.is_deny());
        assert_eq!(decision.attribute, None, "a refused request has nothing to filter");
        assert_eq!(decision.scope, None);
    }

    #[test]
    fn the_decision_does_not_depend_on_the_order_the_policies_were_written_in() {
        let one = snapshot(
            r#"
            [[policy]]
            id = "a-deny"
            priority = 10
            [policy.access]
            effect = "deny"

            [[policy]]
            id = "b-allow"
            priority = 10
            [policy.access]
            effect = "allow"
            "#,
            Effect::Allow,
        );
        let other = snapshot(
            r#"
            [[policy]]
            id = "b-allow"
            priority = 10
            [policy.access]
            effect = "allow"

            [[policy]]
            id = "a-deny"
            priority = 10
            [policy.access]
            effect = "deny"
            "#,
            Effect::Allow,
        );

        assert_eq!(Request::default().decide(&one), Request::default().decide(&other));
    }

    #[test]
    fn the_winning_policys_aggregation_restriction_reaches_the_decision() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "strong"
            priority = 100
            [policy.access]
            effect = "allow"
            [policy.access.aggregation]
            allowed-methods = ["avg"]

            [[policy]]
            id = "weak"
            priority = 50
            [policy.access]
            effect = "allow"
            [policy.access.aggregation]
            allowed-methods = ["max"]
            "#,
            Effect::Deny,
        );

        let aggregation = Request::default().decide(&policies).aggregation.expect("an aggregation restriction");

        assert!(aggregation.allows(AggregationMethod::Avg));
        assert!(!aggregation.allows(AggregationMethod::Max), "the weaker policy's list must not leak in");
    }

    #[test]
    fn a_refusal_carries_no_aggregation_restriction() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "deny"
            priority = 100
            [policy.access]
            effect = "deny"

            [[policy]]
            id = "allow"
            priority = 50
            [policy.access]
            effect = "allow"
            [policy.access.aggregation]
            allowed-methods = ["avg"]
            "#,
            Effect::Deny,
        );

        let decision = Request::default().decide(&policies);

        assert!(decision.is_deny());
        assert_eq!(decision.aggregation, None);
    }

    #[test]
    fn the_default_effect_carries_no_aggregation_restriction() {
        let policies = snapshot("", Effect::Allow);

        assert_eq!(Request::default().decide(&policies).aggregation, None);
    }

    #[test]
    fn an_allow_that_carries_no_aggregation_restriction_has_none() {
        let policies = snapshot(ALLOW_ALL, Effect::Deny);

        assert_eq!(Request::default().decide(&policies).aggregation, None);
    }

    const WRITE_ALLOW: &str = r#"
        [[policy]]
        id = "writers"
        priority = 1
        [policy.condition]
        operations = ["write"]
        [policy.access]
        effect = "allow"
    "#;

    fn writing(resource: ResourceFamily) -> Request {
        Request {
            operation: Operation::Write,
            resource,
            ..Request::default()
        }
    }

    #[test]
    fn a_policy_naming_no_resources_does_not_allow_a_registration_write() {
        assert_eq!(
            writing(ResourceFamily::Registrations).decide(&snapshot(WRITE_ALLOW, Effect::Deny)).effect,
            Effect::Deny
        );
    }

    #[test]
    fn a_policy_naming_no_resources_covers_only_entity_data() {
        let policies = snapshot(WRITE_ALLOW, Effect::Deny);

        for family in ResourceFamily::iter() {
            let expected = if family.is_covered_by_default() { Effect::Allow } else { Effect::Deny };

            assert_eq!(writing(family).decide(&policies).effect, expected, "{family:?}");
        }
    }

    #[test]
    fn a_deny_naming_no_resources_refuses_every_family_another_policy_allows() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "everything"
            priority = 1
            [policy.condition]
            resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts", "snapshots", "info"]
            [policy.access]
            effect = "allow"

            [[policy]]
            id = "not-this-caller"
            priority = 2
            [policy.condition]
            operations = ["write"]
            [policy.access]
            effect = "deny"
            "#,
            Effect::Deny,
        );

        for family in ResourceFamily::iter() {
            assert_eq!(writing(family).decide(&policies).effect, Effect::Deny, "{family:?}");
        }
    }

    #[test]
    fn a_policy_naming_registrations_allows_a_registration_write_and_nothing_else() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "registrars"
            priority = 1
            [policy.condition]
            resources = ["registrations"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        assert_eq!(writing(ResourceFamily::Registrations).decide(&policies).effect, Effect::Allow);
        assert_eq!(writing(ResourceFamily::Entities).decide(&policies).effect, Effect::Deny);
    }

    #[test]
    fn a_deny_naming_contexts_denies_only_contexts() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "everything"
            priority = 1
            [policy.condition]
            resources = ["entities", "contexts"]
            [policy.access]
            effect = "allow"

            [[policy]]
            id = "no-contexts"
            priority = 10
            [policy.condition]
            resources = ["contexts"]
            [policy.access]
            effect = "deny"
            "#,
            Effect::Deny,
        );

        assert_eq!(writing(ResourceFamily::Contexts).decide(&policies).effect, Effect::Deny);
        assert_eq!(writing(ResourceFamily::Entities).decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn a_group_condition_is_met_only_by_a_caller_holding_one_of_its_groups() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "fleet"
            priority = 10
            [policy.condition]
            groups = ["fleet"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );

        let in_no_group = Request::default();
        let in_another = Request {
            groups: vec![GroupName::new("billing").unwrap()],
            ..Request::default()
        };
        let in_fleet = Request {
            groups: vec![GroupName::new("billing").unwrap(), GroupName::new("fleet").unwrap()],
            ..Request::default()
        };

        assert_eq!(in_no_group.decide(&policies).effect, Effect::Deny);
        assert_eq!(in_another.decide(&policies).effect, Effect::Deny);
        assert_eq!(in_fleet.decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn an_operation_condition_is_met_only_by_the_operations_it_names() {
        let policies = snapshot(WRITE_ALLOW, Effect::Deny);

        assert_eq!(Request::default().decide(&policies).effect, Effect::Deny);
        assert_eq!(writing(ResourceFamily::Entities).decide(&policies).effect, Effect::Allow);
    }

    #[test]
    fn a_query_condition_is_met_only_by_the_query_it_names() {
        let policies = snapshot(
            r#"
            [[policy]]
            id = "vehicles-query"
            priority = 10
            [policy.condition]
            queries = ["?type=Vehicle"]
            [policy.access]
            effect = "allow"
            "#,
            Effect::Deny,
        );
        let compiled = |query: &str| {
            QuerySelector::parse(query)
                .unwrap()
                .compile(&PolicyId::new("request").unwrap(), &context())
                .unwrap()
        };

        let without_a_query = Request::default();
        let another_query = Request {
            query: Some(compiled("?type=Building")),
            ..Request::default()
        };
        let the_named_query = Request {
            query: Some(compiled("?type=Vehicle")),
            ..Request::default()
        };

        assert_eq!(without_a_query.decide(&policies).effect, Effect::Deny);
        assert_eq!(another_query.decide(&policies).effect, Effect::Deny);
        assert_eq!(the_named_query.decide(&policies).effect, Effect::Allow);
    }
}
