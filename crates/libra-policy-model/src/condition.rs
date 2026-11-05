//! What has to be true of a request for a policy to apply to it.
//!
//! Every field is an allow list, and an absent field matches everything. That is the one rule that
//! makes a policy file readable: a condition names only what it narrows.

use crate::{
    datetime::{deserialize_time_of_day, serialize_time_of_day},
    error::CompileError,
    identity::{CallerKind, GroupName, PrincipalName, RoleName, TenantSelector, Username},
    operation::Operation,
    policy::PolicyId,
    query::{CompiledQuerySelector, QuerySelector},
    resource_family::ResourceFamily,
    time_zone::PolicyTimeZone,
};
use jiff::{
    Timestamp,
    civil::{Time, Weekday},
};
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};
use serde::{Deserialize, Serialize};

/// A day of the week, as a recurring interval names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Day {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}

// Written out because no derive maps the variants of one enum onto another's.
impl From<Weekday> for Day {
    fn from(weekday: Weekday) -> Self {
        match weekday {
            Weekday::Monday => Self::Mon,
            Weekday::Tuesday => Self::Tue,
            Weekday::Wednesday => Self::Wed,
            Weekday::Thursday => Self::Thu,
            Weekday::Friday => Self::Fri,
            Weekday::Saturday => Self::Sat,
            Weekday::Sunday => Self::Sun,
        }
    }
}

/// A recurring window during which a policy applies.
///
/// This is *when the request may be made*, which is a different question from the temporal window
/// a request may read, which is [`crate::time::TimeRestriction`], and it lives in the access block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TimeIntervalCondition {
    /// The days the interval covers. Must name at least one.
    pub days: Vec<Day>,

    /// When the window opens, in `timezone`.
    #[serde(deserialize_with = "deserialize_time_of_day", serialize_with = "serialize_time_of_day")]
    pub start: Time,

    /// The first instant past the window, which the window does not include. Earlier than `start`
    /// means the window crosses midnight, so `00:00:00` closes it at midnight; equal to `start`
    /// means it runs a whole day from `start`.
    ///
    /// Exclusive because an inclusive end has no spelling for the end of a day: `23:59:59` leaves
    /// the last second out, and a deny written that way stands aside for it every day.
    #[serde(deserialize_with = "deserialize_time_of_day", serialize_with = "serialize_time_of_day")]
    pub end: Time,

    /// The zone `start` and `end` are read in.
    ///
    /// Parsed here rather than on the request path. Left as text, an unrecognised zone would fail once
    /// per request and be handled by refusing: correct, but a policy that never applies and never says
    /// why.
    pub timezone: PolicyTimeZone,
}

impl TimeIntervalCondition {
    /// Whether `at` falls inside the interval.
    #[must_use]
    pub fn contains(&self, at: Timestamp) -> bool {
        let local = self.timezone.to_datetime(at);

        let time = local.time();
        let today = self.days.contains(&Day::from(local.weekday()));

        if self.start < self.end {
            return today && time >= self.start && time < self.end;
        }

        // A window written as 22:00 to 06:00 crosses midnight. The days name when it opens, so
        // "Monday 22:00 to 06:00" runs into Tuesday morning: the evening part belongs to today, and
        // the morning part belongs to a window that opened yesterday. A window whose end equals its
        // start is the same shape with a day between them.
        let yesterday = self.days.contains(&Day::from(local.weekday().previous()));

        (today && time >= self.start) || (yesterday && time < self.end)
    }

    /// Whether the interval can ever be satisfied.
    #[must_use]
    pub const fn is_satisfiable(&self) -> bool {
        !self.days.is_empty()
    }
}

/// The conditions a request must satisfy, as authored.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct Condition {
    /// Whether this policy applies to anonymous callers or to authenticated ones. Absent, it applies
    /// to both.
    pub callers: Option<CallerKind>,

    /// Accounts this policy applies to: callers an identity provider authenticated, by username.
    pub users: Option<Vec<Username>>,

    /// Principals this policy applies to: callers holding a Libra API key, by principal name.
    pub principals: Option<Vec<PrincipalName>>,

    /// Groups whose members this policy applies to. Any one of them is enough.
    pub groups: Option<Vec<GroupName>>,

    /// Roles this policy applies to. Any one of them is enough.
    pub roles: Option<Vec<RoleName>>,

    /// Tenants this policy applies to. `"*untenanted"` matches a request that carried none.
    pub tenants: Option<Vec<TenantSelector>>,

    /// Whether this policy applies to reads, writes, or both.
    pub operations: Option<Vec<Operation>>,

    /// The resources this policy applies to. Absent, it applies to entity data only: entities,
    /// temporal entities and the type and attribute listings.
    pub resources: Option<Vec<ResourceFamily>>,

    /// Entity types this policy applies to.
    pub entity_types: Option<Vec<Term>>,

    /// Exact queries this policy applies to.
    pub queries: Option<Vec<QuerySelector>>,

    /// The recurring window during which this policy applies.
    pub time_interval: Option<TimeIntervalCondition>,
}

impl Condition {
    /// Expands every name in the condition against the policy's declared context.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] if an entity type or a query names something the context does not
    /// define.
    pub fn compile(&self, policy: &PolicyId, context: &ResolvedContext) -> Result<CompiledCondition, CompileError> {
        let entity_types = match &self.entity_types {
            None => None,
            Some(terms) => {
                let mut expanded = Vec::with_capacity(terms.len());
                for term in terms {
                    expanded.push(context.expand(term).ok_or_else(|| CompileError::UnexpandableTerm {
                        policy: policy.clone(), // the error owns the id, the caller keeps its own
                        field: "the entity type condition",
                        term: term.clone(), // the error owns the offending term, the policy keeps its own
                    })?);
                }
                expanded.sort();
                expanded.dedup();
                Some(expanded)
            }
        };

        let queries = match &self.queries {
            None => None,
            Some(selectors) => {
                let mut compiled = Vec::with_capacity(selectors.len());
                for selector in selectors {
                    compiled.push(selector.compile(policy, context)?);
                }
                Some(compiled)
            }
        };

        Ok(CompiledCondition {
            callers: self.callers,
            users: self.users.clone(),           // compiling borrows the parsed policy
            principals: self.principals.clone(), // compiling borrows the parsed policy
            groups: self.groups.clone(),         // compiling borrows the parsed policy
            roles: self.roles.clone(),           // compiling borrows the parsed policy
            tenants: self.tenants.clone(),       // compiling borrows the parsed policy
            operations: self.operations.clone(), // compiling borrows the parsed policy
            resources: self.resources.clone(),   // compiling borrows the parsed policy
            entity_types,
            queries,
            time_interval: self.time_interval.clone(), // compiling borrows the parsed policy
        })
    }

    /// Whether the condition can ever be satisfied.
    ///
    /// An empty list is not a wildcard (that is what omitting the field means), so a list with
    /// nothing in it is a policy that can never apply, written as though it applies to something.
    /// So is an identity condition beside `callers = "anonymous"`: an anonymous caller has no name,
    /// no groups and no roles for it to match.
    #[must_use]
    pub fn is_satisfiable(&self) -> bool {
        let non_empty = |list: Option<usize>| list != Some(0);

        let names_identity = self.users.is_some() || self.principals.is_some() || self.groups.is_some() || self.roles.is_some();

        !(names_identity && self.callers.is_some_and(|callers| !callers.can_carry_identity()))
            && non_empty(self.users.as_ref().map(Vec::len))
            && non_empty(self.principals.as_ref().map(Vec::len))
            && non_empty(self.groups.as_ref().map(Vec::len))
            && non_empty(self.roles.as_ref().map(Vec::len))
            && non_empty(self.tenants.as_ref().map(Vec::len))
            && non_empty(self.operations.as_ref().map(Vec::len))
            && non_empty(self.resources.as_ref().map(Vec::len))
            && non_empty(self.entity_types.as_ref().map(Vec::len))
            && non_empty(self.queries.as_ref().map(Vec::len))
            && self.time_interval.as_ref().is_none_or(TimeIntervalCondition::is_satisfiable)
    }
}

/// A condition whose names are IRIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCondition {
    /// Whether this policy applies to anonymous callers, authenticated ones, or both.
    pub callers: Option<CallerKind>,
    /// Accounts this policy applies to.
    pub users: Option<Vec<Username>>,
    /// Principals this policy applies to.
    pub principals: Option<Vec<PrincipalName>>,
    /// Groups whose members this policy applies to.
    pub groups: Option<Vec<GroupName>>,
    /// Roles this policy applies to.
    pub roles: Option<Vec<RoleName>>,
    /// Tenants this policy applies to.
    pub tenants: Option<Vec<TenantSelector>>,
    /// Whether this policy applies to reads, writes, or both.
    pub operations: Option<Vec<Operation>>,
    /// The resources this policy applies to; absent means entity data only.
    pub resources: Option<Vec<ResourceFamily>>,
    /// Entity types this policy applies to, as IRIs.
    pub entity_types: Option<Vec<ExpandedIri>>,
    /// Exact queries this policy applies to, canonicalised.
    pub queries: Option<Vec<CompiledQuerySelector>>,
    /// The recurring window during which this policy applies.
    pub time_interval: Option<TimeIntervalCondition>,
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

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    #[test]
    fn an_omitted_field_matches_everything() {
        let condition = Condition::default();

        assert!(condition.users.is_none());
        assert!(condition.is_satisfiable());
    }

    #[test]
    fn an_empty_list_is_not_a_wildcard_and_is_refused_as_unsatisfiable() {
        // Written as though it narrows to something, it narrows to nothing. The store rejects it
        // rather than loading a policy that can never apply.
        let condition: Condition = toml::from_str("users = []").unwrap();

        assert!(!condition.is_satisfiable());
        assert!(!toml::from_str::<Condition>("principals = []").unwrap().is_satisfiable());
    }

    #[test]
    fn principals_are_named_apart_from_users() {
        let condition: Condition = toml::from_str("users = [\"alice\"]\nprincipals = [\"ingest\"]").unwrap();

        assert_eq!(condition.users, Some(vec![Username::new("alice").unwrap()]));
        assert_eq!(condition.principals, Some(vec![PrincipalName::new("ingest").unwrap()]));
    }

    #[test]
    fn callers_name_the_kind_of_caller_in_kebab_case() {
        assert_eq!(
            toml::from_str::<Condition>(r#"callers = "anonymous""#).unwrap().callers,
            Some(CallerKind::Anonymous)
        );
        assert_eq!(
            toml::from_str::<Condition>(r#"callers = "authenticated""#).unwrap().callers,
            Some(CallerKind::Authenticated)
        );
        assert!(toml::from_str::<Condition>(r#"callers = "everyone""#).is_err());
        assert!(toml::from_str::<Condition>(r#"callers = "Anonymous""#).is_err());
    }

    #[test]
    fn an_anonymous_caller_beside_an_identity_condition_can_never_be_satisfied() {
        for identity in [
            r#"users = ["alice"]"#,
            r#"principals = ["ingest"]"#,
            r#"groups = ["fleet"]"#,
            r#"roles = ["reader"]"#,
        ] {
            let anonymous: Condition = toml::from_str(&format!("callers = \"anonymous\"\n{identity}")).unwrap();
            let authenticated: Condition = toml::from_str(&format!("callers = \"authenticated\"\n{identity}")).unwrap();

            assert!(!anonymous.is_satisfiable(), "{identity}");
            assert!(authenticated.is_satisfiable(), "{identity}");
        }

        assert!(toml::from_str::<Condition>(r#"callers = "anonymous""#).unwrap().is_satisfiable());
    }

    #[test]
    fn entity_types_in_a_condition_become_iris() {
        let condition: Condition = toml::from_str(r#"entity-types = ["Vehicle", "Car"]"#).unwrap();
        let compiled = condition.compile(&PolicyId::new("p").unwrap(), &context()).unwrap();

        assert_eq!(
            compiled.entity_types.as_ref().map(Vec::len),
            Some(1),
            "Car and Vehicle are one type under this context"
        );
    }

    #[test]
    fn a_type_the_context_does_not_define_is_a_load_error() {
        let bare = ResolvedContext::from_json(r#"{"Vehicle": "https://example.test/Vehicle"}"#).unwrap();
        let condition: Condition = toml::from_str(r#"entity-types = ["Mystery"]"#).unwrap();

        assert!(condition.compile(&PolicyId::new("p").unwrap(), &bare).is_err());
    }

    #[test]
    fn a_recurring_window_is_read_in_its_own_zone() {
        let condition: TimeIntervalCondition = toml::from_str(
            r#"
            days = ["mon", "tue", "wed", "thu", "fri"]
            start = 09:00:00
            end = 17:00:00
            timezone = "Europe/Ljubljana"
            "#,
        )
        .unwrap();

        // 2026-01-15 is a Thursday. 09:00 UTC is 10:00 local in January, inside the window;
        // 17:30 UTC is 18:30 local, outside it.
        assert!(condition.contains(at("2026-01-15T09:00:00Z")));
        assert!(!condition.contains(at("2026-01-15T17:30:00Z")));
        // A Saturday is outside it whatever the hour.
        assert!(!condition.contains(at("2026-01-17T10:00:00Z")));
    }

    #[test]
    fn a_window_may_cross_midnight() {
        let condition: TimeIntervalCondition = toml::from_str(
            r#"
            days = ["mon"]
            start = 22:00:00
            end = 06:00:00
            timezone = "UTC"
            "#,
        )
        .unwrap();

        assert!(condition.contains(at("2026-01-12T23:00:00Z")), "Monday 23:00 is inside");
        assert!(condition.contains(at("2026-01-13T05:00:00Z")), "Tuesday 05:00 is the tail of Monday's window");
        assert!(condition.contains(at("2026-01-13T05:59:59.999Z")));
        assert!(!condition.contains(at("2026-01-13T06:00:00Z")), "the end is exclusive");
        assert!(
            !condition.contains(at("2026-01-12T05:00:00Z")),
            "Monday 05:00 is the tail of Sunday's window, and Sunday is not listed"
        );
        assert!(
            !condition.contains(at("2026-01-13T23:00:00Z")),
            "Tuesday 23:00 opens a window Tuesday does not have"
        );
        assert!(!condition.contains(at("2026-01-12T12:00:00Z")));
    }

    fn window(days: &str, start: &str, end: &str) -> TimeIntervalCondition {
        toml::from_str(&format!("days = {days}\nstart = {start}\nend = {end}\ntimezone = \"UTC\"")).unwrap()
    }

    #[test]
    fn a_window_includes_its_start_and_excludes_its_end() {
        let condition = window(r#"["thu"]"#, "09:00:00", "17:00:00");

        // 2026-01-15 is a Thursday.
        assert!(!condition.contains(at("2026-01-15T08:59:59.999999999Z")));
        assert!(condition.contains(at("2026-01-15T09:00:00Z")));
        assert!(condition.contains(at("2026-01-15T16:59:59.999999999Z")));
        assert!(!condition.contains(at("2026-01-15T17:00:00Z")));
    }

    #[test]
    fn a_window_closing_at_midnight_covers_the_last_second_of_the_day() {
        // The shape a deny for the rest of the evening takes. An inclusive `23:59:59` would leave
        // the last second out, and the deny would stand aside for it every day.
        let condition = window(r#"["thu"]"#, "18:00:00", "00:00:00");

        assert!(condition.contains(at("2026-01-15T23:59:59Z")));
        assert!(condition.contains(at("2026-01-15T23:59:59.999999999Z")));
        assert!(!condition.contains(at("2026-01-16T00:00:00Z")), "Friday midnight is past the window");
        assert!(!condition.contains(at("2026-01-15T17:59:59Z")));
    }

    #[test]
    fn a_window_whose_end_equals_its_start_runs_a_whole_day() {
        let midnight = window(r#"["sat", "sun"]"#, "00:00:00", "00:00:00");

        // 2026-01-17 and 2026-01-18 are a Saturday and a Sunday.
        assert!(!midnight.contains(at("2026-01-16T23:59:59.999999999Z")));
        assert!(midnight.contains(at("2026-01-17T00:00:00Z")));
        assert!(midnight.contains(at("2026-01-18T23:59:59.999999999Z")));
        assert!(!midnight.contains(at("2026-01-19T00:00:00Z")));

        let morning = window(r#"["mon"]"#, "09:00:00", "09:00:00");

        // 2026-01-12 is a Monday.
        assert!(!morning.contains(at("2026-01-12T08:59:59Z")));
        assert!(morning.contains(at("2026-01-12T09:00:00Z")));
        assert!(morning.contains(at("2026-01-13T08:59:59Z")), "the day runs into Tuesday morning");
        assert!(!morning.contains(at("2026-01-13T09:00:00Z")));
    }

    #[test]
    fn a_recurring_window_follows_daylight_saving_time() {
        let condition: TimeIntervalCondition = toml::from_str(
            r#"
            days = ["wed"]
            start = 09:00:00
            end = 17:00:00
            timezone = "Europe/Ljubljana"
            "#,
        )
        .unwrap();

        // 2026-07-15 is a Wednesday. Summer time is UTC+2, so 07:30 UTC is 09:30 local and 15:30
        // UTC is 17:30 local; in winter both would be an hour earlier.
        assert!(condition.contains(at("2026-07-15T07:30:00Z")));
        assert!(!condition.contains(at("2026-07-15T15:30:00Z")));
    }

    #[test]
    fn an_unrecognised_timezone_is_a_load_error_rather_than_a_policy_that_never_applies() {
        assert!(
            toml::from_str::<TimeIntervalCondition>(
                r#"
                days = ["mon"]
                start = 09:00:00
                end = 17:00:00
                timezone = "Mars/Olympus"
                "#
            )
            .is_err()
        );
    }

    #[test]
    fn a_misspelled_condition_key_is_refused() {
        // `entity_types` instead of `entity-types` would otherwise be ignored, and the policy would
        // apply to every type rather than the listed ones.
        assert!(toml::from_str::<Condition>(r#"entity_types = ["Vehicle"]"#).is_err());
    }

    #[test]
    fn a_window_on_no_day_can_never_be_satisfied() {
        assert!(!window("[]", "09:00:00", "17:00:00").is_satisfiable());
        assert!(window(r#"["mon"]"#, "09:00:00", "17:00:00").is_satisfiable());
    }
}
