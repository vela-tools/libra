//! What a request asks for in NGSI-LD Linked Entity Retrieval (clause 4.5.23).
//!
//! Linked Entity Retrieval follows an entity's Relationships and returns the entities they point
//! at. With `join=inline` (clause 4.5.23.2) the linked entity is nested under the Relationship as an
//! `entity` sub-attribute, or under a `ListRelationship` as `entityList`; with `join=flat` (clause
//! 4.5.23.3) it is appended to the response array alongside the linking entities. Either way the
//! linked entities are of whatever type and scope the Relationship happens to point at, and none of
//! the request-side narrowing Libra applies to the queried entities reaches them. What the broker
//! answers says what each linked entity is, so a restricted caller's answer is judged entity by
//! entity on the way back; this module says whether the request asks for such an answer, and in
//! which shape.
//!
//! A request reaches linked entities in two independent ways, and [`LinkedEntityRequest`] records
//! both. Its [`LinkedAnswer`] says whether the answer holds linked entities; its [`LinkedFilter`]
//! says whether a `q` filter (clause 4.9) follows a Relationship, selecting the queried entities by
//! the attributes of the entities they link to. A filter path never shows up in the answer, so
//! whether it can be served depends on the restriction: one that judges attribute names can check
//! every name in the path, while one that judges an entity's type or scope has nothing to judge
//! the linked entity by.
//!
//! The answer is one of three. A request whose answer holds nothing linked is
//! [`LinkedAnswer::NotRequested`]. One that asks for a join this proxy can judge is a [`Join`],
//! carrying the shape and the members a projection removes from the entities of the answer. One
//! that reaches linked entities in a way no answer can be judged against is
//! [`LinkedAnswer::Unservable`], with the reason:
//!
//! * `join` set to something other than `flat`, `inline` or `@none`. A broker that read it as a join
//!   would answer in a shape nobody named.
//! * `joinLevel` without a `join`. The specification says it is only meaningful alongside `join`,
//!   but a broker that honoured it alone would disclose linked entities in a shape nobody named.
//! * A `{...}` linked-entity term in a projection (clause 4.21) without a `join`, for the same
//!   reason.
//! * Any of the above in a subscription's `notification` (clause 5.2.14), whose linked entities go
//!   straight from the broker to the notification endpoint and never pass back through Libra.
//!
//! Three places carry the selectors. A query string carries them as parameters; a `Query` body
//! (clause 5.2.23) as members of the same names; and a subscription in its `q` member and in the
//! `join`, `joinLevel`, `pick`, `omit` and deprecated `attributes` members of its `notification`.

use crate::{
    entity_member::EntityMember,
    error::QueryError,
    filter::Filter,
    parameter_name::ParameterName,
    parameters::QueryParameters,
    projection::{PROJECTION_PARAMETERS, Projection, ProjectionKind},
};
use jstrict::{Value, object::Object};
use std::borrow::Cow;
use strum::{Display, EnumString, IntoEnumIterator};

/// The value of `join` that turns retrieval off. It is the default when `join` is absent.
const JOIN_NONE: &str = "@none";
/// The members of a `NotificationParams` object written in the projection language (clause
/// 5.2.14). `attributes` is a deprecated synonym for `pick`.
const NOTIFICATION_PROJECTION_MEMBERS: [&str; 3] = ["attributes", "pick", "omit"];
/// The member of a subscription that holds its `NotificationParams` (clause 5.2.12).
const NOTIFICATION_MEMBER: &str = "notification";

/// The shape a join answer takes (clause 4.5.23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum JoinMode {
    /// `join=inline` (clause 4.5.23.2): each linked entity is nested under the Relationship that
    /// points at it.
    Inline,
    /// `join=flat` (clause 4.5.23.3): the linked entities are appended to the answer's array.
    Flat,
}

/// A join this proxy can judge the answer to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    mode: JoinMode,
}

impl Join {
    /// The shape of the answer.
    #[must_use]
    pub const fn mode(&self) -> JoinMode {
        self.mode
    }
}

/// What one request asks for in Linked Entity Retrieval: in its answer, and in its filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedEntityRequest {
    /// Whether the answer holds linked entities.
    pub answer: LinkedAnswer,
    /// Whether a `q` filter follows a Relationship.
    pub filter: LinkedFilter,
    /// The entity members a `pick` or `omit` of the request removes from some entity of the answer,
    /// linked entities included.
    pub removed: Vec<EntityMember>,
}

impl LinkedEntityRequest {
    /// A request that reaches no linked entity at all.
    pub const NOTHING: Self = Self {
        answer: LinkedAnswer::NotRequested,
        filter: LinkedFilter::None,
        removed: Vec::new(),
    };

    /// Whether the request reaches no linked entity, in its answer or in its filter.
    #[must_use]
    pub const fn is_nothing(&self) -> bool {
        matches!(self.answer, LinkedAnswer::NotRequested) && matches!(self.filter, LinkedFilter::None)
    }

    /// Whether a `pick` or `omit` of the request removes `member` from some entity of the answer.
    ///
    /// An answer's entities are judged by their own `type` and `scope`, so a projection that removes
    /// one of them leaves every entity it was removed from impossible to judge.
    #[must_use]
    pub fn removes(&self, member: EntityMember) -> bool {
        self.removed.contains(&member)
    }
}

/// What the answer to one request holds of Linked Entity Retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkedAnswer {
    /// Nothing linked: the answer holds the queried entities and nothing else.
    NotRequested,
    /// A join whose answer can be judged entity by entity.
    Join(Join),
    /// A request that reaches linked entities in a way no answer can be judged against.
    Unservable(LinkedEntityRetrieval),
}

/// Whether a request's `q` filter follows a Relationship to the entity it points at (clause 4.9).
///
/// A linked path in the query string, a `Query` body or a subscription's `q` trigger counts alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkedFilter {
    /// No `q` filter, or one whose every path stays on the queried entity.
    None,
    /// A `q` filter with at least one `{...}` linked-entity path.
    Paths,
}

/// Why a request that reaches linked entities cannot be served to a restricted caller.
///
/// The value is carried into the refusal so the caller is told which part of their request was the
/// one that could not be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum LinkedEntityRetrieval {
    /// `join` carried a value other than `flat`, `inline` or `@none`.
    #[strum(to_string = "a join value other than flat, inline or @none")]
    UnknownJoin,
    /// The query string and the `Query` body asked for different joins.
    #[strum(to_string = "a join in the query string and a different one in the Query body")]
    ConflictingJoin,
    /// `joinLevel` was supplied without a `join`.
    #[strum(to_string = "the joinLevel parameter without a join")]
    JoinLevelWithoutJoin,
    /// A projection carried a `{...}` linked-entity term without a `join` (clause 4.21).
    #[strum(to_string = "a linked-entity projection term without a join")]
    ProjectionTermWithoutJoin,
    /// A subscription's notification members asked for linked entities (clause 5.2.14).
    #[strum(to_string = "linked entity retrieval in a subscription's notification")]
    Subscription,
}

impl QueryParameters {
    /// What the query string asks for in Linked Entity Retrieval.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError`] if a projection or the `q` filter does not parse: what it asks for
    /// cannot be told, and the request has to be refused rather than forwarded unread.
    pub fn linked_entity_request(&self) -> Result<LinkedEntityRequest, QueryError> {
        LinkedEntityRequest::of_query(self, None)
    }
}

impl LinkedEntityRequest {
    /// What a query asks for, from its query string and, for a batch query, its `Query` body
    /// (clause 5.2.23).
    ///
    /// Both are read and the answer covers both: a broker may honour either, so a projection in one
    /// counts as much as a projection in the other, and two different joins are refused rather than
    /// one of them guessed at. A body that is not an object asks for nothing here; its shape is the
    /// broker's to refuse.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError`] if a projection or a `q` filter does not parse.
    pub fn of_query(parameters: &QueryParameters, body: Option<&Value>) -> Result<Self, QueryError> {
        let mut sources = vec![Selectors::of_parameters(parameters)?];
        if let Some(query) = body.and_then(Value::as_object) {
            sources.push(Selectors::of_members(query, &PROJECTION_PARAMETERS.each_ref().map(ParameterName::as_str))?);
        }

        Ok(decide(&sources))
    }

    /// What a subscription body (clause 5.2.12), whole or as an update fragment, asks for.
    ///
    /// Anything its notification asks for is unservable, because the notification never passes
    /// back through Libra to be judged; a linked path in its `q` trigger is a linked filter as it is
    /// in a query.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError`] if a projection member or the `q` member does not parse.
    pub fn of_subscription(document: &Value) -> Result<Self, QueryError> {
        let Some(subscription) = document.as_object() else {
            return Ok(Self::NOTHING);
        };

        let answer = match member(subscription, NOTIFICATION_MEMBER)?.and_then(Value::as_object) {
            Some(notification) if !decide(&[Selectors::of_members(notification, &NOTIFICATION_PROJECTION_MEMBERS)?]).is_nothing() => {
                LinkedAnswer::Unservable(LinkedEntityRetrieval::Subscription)
            }
            Some(_) | None => LinkedAnswer::NotRequested,
        };

        Ok(Self {
            answer,
            filter: linked_filter(filter_member(subscription)?.iter()),
            // A notification's entities never pass back through Libra, so nothing judges them.
            removed: Vec::new(),
        })
    }
}

/// What one `join` value asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JoinValue {
    /// Absent, empty, `null` or `@none`.
    Off,
    /// `flat` or `inline`.
    Mode(JoinMode),
    /// Anything else, which a broker might read as a join of some shape.
    Unknown,
}

impl JoinValue {
    /// Reads a `join` string.
    ///
    /// A broker reads an empty `join` as no join at all, the same as the `@none` default.
    fn of_str(value: &str) -> Self {
        let value = value.trim();

        if value.is_empty() || value == JOIN_NONE {
            return Self::Off;
        }

        value.parse().map_or(Self::Unknown, Self::Mode)
    }

    /// Reads a `join` member of a body.
    ///
    /// A `null` member is an absent one: a merge-patch update of a subscription removes a member by
    /// setting it to `null`. A `join` that is neither `null` nor a string is malformed.
    fn of_member(member: Option<&Value>) -> Self {
        match member {
            None | Some(Value::Null) => Self::Off,
            Some(Value::String(value)) => Self::of_str(value),
            Some(Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => Self::Unknown,
        }
    }
}

/// Whether `joinLevel` was supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JoinLevel {
    Absent,
    Present,
}

/// The selectors one source carries: a query string, a `Query` body, or a notification.
struct Selectors {
    join: JoinValue,
    join_level: JoinLevel,
    /// Every projection, `attrs` and its deprecated synonyms included, each parsed once and marked
    /// with its kind when it is a `pick` or an `omit`.
    projections: Vec<(Option<ProjectionKind>, Projection)>,
    filter: Option<Filter>,
}

impl Selectors {
    /// The selectors of a query string.
    fn of_parameters(parameters: &QueryParameters) -> Result<Self, QueryError> {
        Ok(Self {
            join: parameters.get(&ParameterName::JOIN).map_or(JoinValue::Off, JoinValue::of_str),
            join_level: if parameters.contains(&ParameterName::JOIN_LEVEL) {
                JoinLevel::Present
            } else {
                JoinLevel::Absent
            },
            projections: PROJECTION_PARAMETERS
                .iter()
                .filter_map(|name| {
                    let parsed = parameters.get(name).map(Projection::parse)?;
                    Some(parsed.map(|projection| (projection_kind(name.as_str()), projection)))
                })
                .collect::<Result<_, _>>()?,
            filter: parameters.filter()?,
        })
    }

    /// The selectors of a body object, whose projection members are named `projections`.
    fn of_members(object: &Object, projections: &[&str]) -> Result<Self, QueryError> {
        let parse = |name: &str| member(object, name).and_then(projection_member);

        Ok(Self {
            join: JoinValue::of_member(member(object, ParameterName::JOIN.as_str())?),
            join_level: if member(object, ParameterName::JOIN_LEVEL.as_str())?.is_some_and(|level| !level.is_null()) {
                JoinLevel::Present
            } else {
                JoinLevel::Absent
            },
            projections: projections
                .iter()
                .filter_map(|name| {
                    let parsed = parse(name).transpose()?;
                    Some(parsed.map(|projection| (projection_kind(name), projection)))
                })
                .collect::<Result<_, _>>()?,
            filter: filter_member(object)?,
        })
    }

    /// Whether this source removes `member` from some entity of the answer.
    fn removes(&self, member: EntityMember) -> bool {
        self.projections
            .iter()
            .any(|(kind, projection)| kind.is_some_and(|kind| projection.removes(member, kind)))
    }
}

/// The kind of projection a selector named `name` carries: `pick` and `omit` remove members from
/// an entity, and every other projection only lists attributes.
fn projection_kind(name: &str) -> Option<ProjectionKind> {
    if name == ParameterName::PICK.as_str() {
        Some(ProjectionKind::Pick)
    } else if name == ParameterName::OMIT.as_str() {
        Some(ProjectionKind::Omit)
    } else {
        None
    }
}

/// Decides what the sources of one request ask for, together.
fn decide(sources: &[Selectors]) -> LinkedEntityRequest {
    LinkedEntityRequest {
        answer: decide_answer(sources),
        filter: linked_filter(sources.iter().filter_map(|source| source.filter.as_ref())),
        removed: EntityMember::iter()
            .filter(|member| sources.iter().any(|source| source.removes(*member)))
            .collect(),
    }
}

/// Whether any of `filters` follows a Relationship.
fn linked_filter<'filter>(mut filters: impl Iterator<Item = &'filter Filter>) -> LinkedFilter {
    if filters.any(Filter::traverses_linked_entities) {
        LinkedFilter::Paths
    } else {
        LinkedFilter::None
    }
}

/// Decides what the answer to the sources of one request holds, together.
fn decide_answer(sources: &[Selectors]) -> LinkedAnswer {
    let mut mode = None;
    for source in sources {
        match (source.join, mode) {
            (JoinValue::Off, _) => {}
            (JoinValue::Unknown, _) => return LinkedAnswer::Unservable(LinkedEntityRetrieval::UnknownJoin),
            (JoinValue::Mode(asked), None) => mode = Some(asked),
            (JoinValue::Mode(asked), Some(already)) if asked == already => {}
            (JoinValue::Mode(_), Some(_)) => return LinkedAnswer::Unservable(LinkedEntityRetrieval::ConflictingJoin),
        }
    }

    let Some(mode) = mode else {
        if sources.iter().any(|source| source.join_level == JoinLevel::Present) {
            return LinkedAnswer::Unservable(LinkedEntityRetrieval::JoinLevelWithoutJoin);
        }

        if sources
            .iter()
            .flat_map(|source| &source.projections)
            .any(|(_, projection)| projection.reaches_linked_entities())
        {
            return LinkedAnswer::Unservable(LinkedEntityRetrieval::ProjectionTermWithoutJoin);
        }

        return LinkedAnswer::NotRequested;
    };

    LinkedAnswer::Join(Join { mode })
}

/// The projection a body member holds, if it holds one.
///
/// The specification types these members as `String[]`, each element a projection; a single string
/// is read as one too, because a broker that accepts it would act on it. The elements are one list:
/// a broker reads `["speed", "brand"]` as it reads `speed,brand`. Elements that are not strings carry
/// no projection.
fn projection_member(member: Option<&Value>) -> Result<Option<Projection>, QueryError> {
    let joined = match member {
        Some(Value::Array(elements)) => Cow::Owned(elements.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",")),
        Some(Value::String(value)) => Cow::Borrowed(value.as_str()),
        None | Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Object(_)) => return Ok(None),
    };

    Projection::parse(&joined).map(Some)
}

/// The `q` member of a body object, parsed.
fn filter_member(object: &Object) -> Result<Option<Filter>, QueryError> {
    member(object, ParameterName::Q.as_str())?
        .and_then(Value::as_str)
        .map(Filter::parse)
        .transpose()
}

/// The member `name` of a body object.
///
/// A member that occurs twice is refused rather than read: RFC 8259 section 4 leaves its meaning
/// unpredictable, and the occurrence read here need not be the one the broker acts on.
fn member<'object>(object: &'object Object, name: &str) -> Result<Option<&'object Value>, QueryError> {
    object.get_unique(name).map_err(|_| QueryError::RepeatedMember { member: name.to_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{json, object::Key};
    use pretty_assertions::assert_eq;

    fn query(source: &str) -> LinkedEntityRequest {
        QueryParameters::parse(source)
            .expect("the test query should parse")
            .linked_entity_request()
            .expect("the test query should be readable")
    }

    fn body(document: &Value) -> LinkedEntityRequest {
        LinkedEntityRequest::of_query(&QueryParameters::default(), Some(document)).expect("the test body should be readable")
    }

    fn unfiltered(answer: LinkedAnswer) -> LinkedEntityRequest {
        LinkedEntityRequest {
            answer,
            filter: LinkedFilter::None,
            removed: Vec::new(),
        }
    }

    fn filtered(answer: LinkedAnswer) -> LinkedEntityRequest {
        LinkedEntityRequest {
            answer,
            filter: LinkedFilter::Paths,
            removed: Vec::new(),
        }
    }

    const fn joined(mode: JoinMode) -> LinkedAnswer {
        LinkedAnswer::Join(Join { mode })
    }

    fn join(mode: JoinMode, removed: &[EntityMember]) -> LinkedEntityRequest {
        LinkedEntityRequest {
            removed: removed.to_vec(),
            ..unfiltered(joined(mode))
        }
    }

    fn unservable(reason: LinkedEntityRetrieval) -> LinkedEntityRequest {
        unfiltered(LinkedAnswer::Unservable(reason))
    }

    #[test]
    fn an_inline_or_flat_join_is_a_join_in_that_shape() {
        assert_eq!(query("type=Vehicle&join=inline"), join(JoinMode::Inline, &[]));
        assert_eq!(query("type=Vehicle&join=flat&joinLevel=2"), join(JoinMode::Flat, &[]));
    }

    #[test]
    fn the_none_default_and_an_empty_join_ask_for_nothing() {
        // A broker reads `join=` as no join at all, the same as the `@none` default.
        assert_eq!(query("type=Vehicle&join=@none"), LinkedEntityRequest::NOTHING);
        assert_eq!(query("join="), LinkedEntityRequest::NOTHING);
        assert!(query("type=Vehicle&attrs=speed&pick=colour|speed").is_nothing());
    }

    #[test]
    fn an_unknown_join_value_is_unservable() {
        // A broker that read `deep` as some join would answer in a shape nobody named.
        assert_eq!(query("join=deep"), unservable(LinkedEntityRetrieval::UnknownJoin));
        assert_eq!(query("join=Inline"), unservable(LinkedEntityRetrieval::UnknownJoin));
    }

    #[test]
    fn a_join_level_without_a_join_is_unservable() {
        assert_eq!(query("joinLevel=2"), unservable(LinkedEntityRetrieval::JoinLevelWithoutJoin));
    }

    #[test]
    fn a_linked_projection_term_without_a_join_is_unservable() {
        for source in ["attrs=parkedIn{name}", "pick=a{b}", "omit=parkedIn{name}", "pick=speed|parkedIn{name}"] {
            assert_eq!(
                query(source).answer,
                unservable(LinkedEntityRetrieval::ProjectionTermWithoutJoin).answer,
                "{source}"
            );
        }
    }

    #[test]
    fn a_linked_projection_term_with_a_join_is_part_of_the_join() {
        assert_eq!(
            query("join=inline&pick=type,scope,a{type,scope,b}"),
            join(JoinMode::Inline, &[EntityMember::Id])
        );
    }

    #[test]
    fn a_linked_filter_path_is_recorded_apart_from_the_answer() {
        // Clause 4.9: the queried vehicles are selected by an attribute of the entity `parkedIn`
        // points at, which nothing in the answer shows. Whether that is servable is the
        // restriction's call; what the answer holds is told on its own.
        assert_eq!(query("type=Vehicle&q=parkedIn{name}==\"Downtown\""), filtered(LinkedAnswer::NotRequested));
        assert_eq!(query("q=a{b}==1"), filtered(LinkedAnswer::NotRequested));
        assert_eq!(query("join=inline&q=a{b}==1"), filtered(joined(JoinMode::Inline)));
        assert_eq!(query("q=speed>40"), LinkedEntityRequest::NOTHING, "a filter on the entity itself links nothing");
    }

    #[test]
    fn a_join_records_the_members_its_projection_removes() {
        assert_eq!(
            query("join=inline&pick=name"),
            join(JoinMode::Inline, &[EntityMember::Id, EntityMember::Type, EntityMember::Scope])
        );
        assert_eq!(query("join=inline&pick=id,type,scope,name"), join(JoinMode::Inline, &[]));
        assert_eq!(query("join=flat&omit=type"), join(JoinMode::Flat, &[EntityMember::Type]));
        assert_eq!(
            query("join=inline&pick=id,type,scope,isParked{name}"),
            join(JoinMode::Inline, &[EntityMember::Id, EntityMember::Type, EntityMember::Scope])
        );
        assert_eq!(
            query("join=inline&pick=id,type,scope,isParked{id,type,scope,name}"),
            join(JoinMode::Inline, &[])
        );
    }

    #[test]
    fn attrs_does_not_remove_a_member() {
        // `attrs` selects attributes; `id`, `type` and `scope` are not attributes and stay.
        assert_eq!(query("join=inline&attrs=speed"), join(JoinMode::Inline, &[]));
    }

    #[test]
    fn an_unreadable_selector_is_an_error_rather_than_no_retrieval() {
        for source in ["pick=parkedIn{name", "q=parkedIn{name", "join=inline&omit=a{"] {
            assert!(
                QueryParameters::parse(source).unwrap().linked_entity_request().is_err(),
                "{source} cannot be read, so what it asks for cannot be told"
            );
        }
    }

    #[test]
    fn a_query_body_is_read_as_the_query_string_is() {
        // Clause 5.2.23 gives the Query body `join`, `joinLevel`, projections and `q` of its own.
        assert_eq!(body(&json!({ "type": "Query", "join": "inline" })), join(JoinMode::Inline, &[]));
        assert_eq!(
            body(&json!({ "type": "Query", "join": "flat", "pick": ["id", "type"] })),
            join(JoinMode::Flat, &[EntityMember::Scope])
        );
        assert_eq!(
            body(&json!({ "type": "Query", "joinLevel": 2 })),
            unservable(LinkedEntityRetrieval::JoinLevelWithoutJoin)
        );
        assert_eq!(
            body(&json!({ "type": "Query", "join": "deep" })),
            unservable(LinkedEntityRetrieval::UnknownJoin)
        );
        assert_eq!(
            body(&json!({ "type": "Query", "q": "parkedIn{name}==\"Downtown\"" })),
            filtered(LinkedAnswer::NotRequested)
        );
    }

    #[test]
    fn a_join_member_that_is_not_a_string_is_unservable() {
        assert_eq!(body(&json!({ "type": "Query", "join": true })), unservable(LinkedEntityRetrieval::UnknownJoin));
    }

    #[test]
    fn a_none_or_null_join_in_a_body_asks_for_nothing() {
        for document in [
            json!({ "type": "Query", "join": "@none" }),
            json!({ "type": "Query", "join": null, "joinLevel": null }),
            json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "pick": ["speed|brand"], "q": "speed>40" }),
            json!(["not", "a", "query"]),
        ] {
            assert!(body(&document).is_nothing(), "{document}");
        }
    }

    #[test]
    fn a_linked_term_in_a_query_body_projection_without_a_join_is_unservable() {
        for document in [
            json!({ "type": "Query", "pick": ["speed", "parkedIn{name}"] }),
            json!({ "type": "Query", "omit": ["parkedIn{name}"] }),
            json!({ "type": "Query", "attrs": "speed,parkedIn{name}" }),
        ] {
            assert_eq!(
                body(&document).answer,
                unservable(LinkedEntityRetrieval::ProjectionTermWithoutJoin).answer,
                "{document}"
            );
        }
    }

    #[test]
    fn the_elements_of_a_body_projection_are_one_list() {
        // `["type", "name"]` keeps `type`; read element by element, `name` alone would remove it.
        assert_eq!(
            body(&json!({ "type": "Query", "join": "inline", "pick": ["id", "type", "scope", "name"] })),
            join(JoinMode::Inline, &[])
        );
    }

    #[test]
    fn the_query_string_and_the_body_are_read_together() {
        let parameters = QueryParameters::parse("join=inline").unwrap();

        let projected = LinkedEntityRequest::of_query(&parameters, Some(&json!({ "type": "Query", "omit": ["scope"] })));
        assert_eq!(projected, Ok(join(JoinMode::Inline, &[EntityMember::Scope])));

        let conflicting = LinkedEntityRequest::of_query(&parameters, Some(&json!({ "type": "Query", "join": "flat" })));
        assert_eq!(conflicting, Ok(unservable(LinkedEntityRetrieval::ConflictingJoin)));

        let agreeing = LinkedEntityRequest::of_query(&parameters, Some(&json!({ "type": "Query", "join": "inline" })));
        assert_eq!(agreeing, Ok(join(JoinMode::Inline, &[])));
    }

    #[test]
    fn an_unreadable_query_body_member_is_an_error() {
        for document in [json!({ "type": "Query", "pick": ["parkedIn{"] }), json!({ "type": "Query", "q": "a{" })] {
            assert!(
                LinkedEntityRequest::of_query(&QueryParameters::default(), Some(&document)).is_err(),
                "{document}"
            );
        }
    }

    fn repeating(name: &str, first: Value, second: Value) -> Value {
        let mut object = Object::new();
        object.push(Key::from(name), first);
        object.push(Key::from(name), second);
        Value::Object(object)
    }

    #[test]
    fn a_repeated_selector_member_is_an_error_rather_than_one_occurrence_read() {
        // One occurrence for Libra, the other for the broker, is how a join would be hidden.
        for (name, first, second) in [
            ("join", json!("@none"), json!("inline")),
            ("joinLevel", json!(null), json!(2)),
            ("pick", json!(["id", "type", "scope"]), json!(["name"])),
            ("q", json!("speed>40"), json!("a{b}==1")),
        ] {
            assert_eq!(
                LinkedEntityRequest::of_query(&QueryParameters::default(), Some(&repeating(name, first, second))),
                Err(QueryError::RepeatedMember { member: name.to_owned() }),
                "{name}"
            );
        }

        let notification = json!({ "notification": repeating("join", json!("@none"), json!("flat")) });
        assert_eq!(
            LinkedEntityRequest::of_subscription(&notification),
            Err(QueryError::RepeatedMember { member: "join".to_owned() })
        );
        assert_eq!(
            LinkedEntityRequest::of_subscription(&repeating("notification", json!({}), json!({ "join": "flat" }))),
            Err(QueryError::RepeatedMember {
                member: "notification".to_owned()
            })
        );
    }

    #[test]
    fn anything_linked_in_a_subscription_notification_is_unservable() {
        // Clause 5.2.14: the notification carries `join` and `joinLevel`, and the linked entities go
        // straight to the endpoint.
        for document in [
            json!({ "type": "Subscription", "notification": { "join": "flat", "endpoint": { "uri": "http://sink.test" } } }),
            json!({ "notification": { "joinLevel": 3 } }),
            json!({ "notification": { "join": "deep" } }),
            json!({ "type": "Subscription", "notification": { "pick": ["parkedIn{name}"] } }),
            json!({ "type": "Subscription", "notification": { "omit": ["parkedIn{name}"] } }),
            json!({ "type": "Subscription", "notification": { "attributes": ["parkedIn{name}"] } }),
        ] {
            assert_eq!(
                LinkedEntityRequest::of_subscription(&document),
                Ok(unservable(LinkedEntityRetrieval::Subscription)),
                "{document}"
            );
        }
    }

    #[test]
    fn a_linked_path_in_a_subscription_trigger_is_a_linked_filter() {
        let document = json!({ "type": "Subscription", "q": "parkedIn{name}==\"Downtown\"" });

        assert_eq!(LinkedEntityRequest::of_subscription(&document), Ok(filtered(LinkedAnswer::NotRequested)));

        let notifying = json!({ "type": "Subscription", "q": "a{b}==1", "notification": { "join": "inline" } });
        assert_eq!(
            LinkedEntityRequest::of_subscription(&notifying),
            Ok(filtered(LinkedAnswer::Unservable(LinkedEntityRetrieval::Subscription))),
            "the notification and the trigger are told apart"
        );
    }

    #[test]
    fn a_subscription_that_reaches_nothing_linked_asks_for_nothing() {
        for document in [
            // A subscription's own members do not include `join`; only its notification's do.
            json!({ "type": "Subscription", "join": "inline", "notification": { "pick": ["speed"] } }),
            json!({ "type": "Subscription", "notification": { "join": "@none", "joinLevel": null } }),
            json!("not a subscription"),
        ] {
            assert_eq!(LinkedEntityRequest::of_subscription(&document), Ok(LinkedEntityRequest::NOTHING), "{document}");
        }
    }

    #[test]
    fn the_reason_names_itself_for_the_refusal() {
        assert_eq!(LinkedEntityRetrieval::UnknownJoin.to_string(), "a join value other than flat, inline or @none");
        assert_eq!(
            LinkedEntityRetrieval::JoinLevelWithoutJoin.to_string(),
            "the joinLevel parameter without a join"
        );
        assert_eq!(
            LinkedEntityRetrieval::Subscription.to_string(),
            "linked entity retrieval in a subscription's notification"
        );
    }

    #[test]
    fn a_projection_without_a_join_still_records_what_it_removes() {
        let request = query("type=Vehicle&pick=name");

        assert_eq!(request.answer, LinkedAnswer::NotRequested);
        assert!(request.removes(EntityMember::Type));
        assert!(request.removes(EntityMember::Scope));
        assert!(!query("type=Vehicle&omit=speed").removes(EntityMember::Type));
    }
}
