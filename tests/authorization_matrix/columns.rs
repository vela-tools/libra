//! The policy each column of the matrix runs under.

use libra_policy_model::{access::Access, resource_family::ResourceFamily};
use strum::{EnumIter, IntoEnumIterator};

/// The user every matrix request is sent as.
pub const USER: &str = "matrix";

/// One restriction a policy can attach to an allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub enum RestrictionKind {
    Scope,
    EntityType,
    Time,
    Attribute,
    Aggregation,
}

impl RestrictionKind {
    /// The restriction's table, as a policy file writes it under `[policy.access]`.
    const fn table(self) -> &'static str {
        match self {
            Self::Scope => "[policy.access.scope]\nallowed = [\"/Allowed/#\"]",
            Self::EntityType => "[policy.access.entity-type]\nallowed = [\"Vehicle\"]",
            Self::Time => "[policy.access.time]\ntype = \"relative\"\nduration = \"PT24H\"",
            Self::Attribute => "[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]",
            Self::Aggregation => "[policy.access.aggregation]\nunaggregated = \"disallowed\"\nallowed-methods = [\"avg\"]",
        }
    }

    /// The restriction kinds an access block carries.
    ///
    /// Destructured without a rest pattern, so a restriction added to [`Access`] does not compile
    /// here until it is given a kind, and a kind is not covered until every route says what it
    /// expects under it.
    fn carried_by(access: &Access) -> Vec<Self> {
        let Access {
            effect: _,
            scope,
            entity_type,
            time,
            attribute,
            aggregation,
        } = access;

        [
            (scope.is_some(), Self::Scope),
            (entity_type.is_some(), Self::EntityType),
            (time.is_some(), Self::Time),
            (attribute.is_some(), Self::Attribute),
            (aggregation.is_some(), Self::Aggregation),
        ]
        .into_iter()
        .filter_map(|(carried, kind)| carried.then_some(kind))
        .collect()
    }
}

/// What a column's policy set says about the matrix user.
#[derive(Debug, Clone, Copy)]
pub enum Column {
    /// A deny over every resource family, above an allow over every family.
    Deny,
    /// An allow over every family, with no restriction.
    Allow,
    /// An allow carrying one restriction, over every family a restricted policy may name.
    Restricted(RestrictionKind),
}

impl Column {
    /// The policy file this column runs under.
    pub fn policies(self) -> String {
        match self {
            Self::Deny => format!(
                "{}\n{}",
                policy("matrix-deny", 200, "deny", &families(ResourceFamily::iter()), ""),
                allow_everything()
            ),
            Self::Allow => allow_everything(),
            // A restriction on snapshots fails to load (a snapshot copies entity data nothing
            // narrows afterwards), so a restricted allow names every other family.
            Self::Restricted(kind) => policy(
                "matrix-restricted",
                100,
                "allow",
                &families(ResourceFamily::iter().filter(|family| *family != ResourceFamily::Snapshots)),
                kind.table(),
            ),
        }
    }
}

fn allow_everything() -> String {
    policy("matrix-allow", 100, "allow", &families(ResourceFamily::iter()), "")
}

fn families(families: impl Iterator<Item = ResourceFamily>) -> String {
    families
        .map(|family| toml::Value::try_from(family).map(|value| value.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("a resource family serialises: {error}"))
        .join(", ")
}

fn policy(id: &str, priority: u32, effect: &str, families: &str, restriction: &str) -> String {
    format!(
        "[[policy]]\nid = \"{id}\"\npriority = {priority}\n\n[policy.condition]\nusers = [\"{USER}\"]\nresources = [{families}]\n\n[policy.access]\neffect = \"{effect}\"\n\n{restriction}\n"
    )
}

#[test]
fn each_restricted_column_carries_exactly_its_own_restriction() {
    for kind in RestrictionKind::iter() {
        let access: Access =
            toml::from_str(&format!("effect = \"allow\"\n{}", kind.table().replace("policy.access.", ""))).unwrap_or_else(|error| panic!("{kind:?}: {error}"));

        assert_eq!(RestrictionKind::carried_by(&access), vec![kind]);
    }
}
