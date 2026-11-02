//! Reading and checking the scopes a JSON document carries.
//!
//! Two documents matter here and they are not the same shape. An entity (in a create, an update,
//! or a pre-flight response) carries a `scope` member. A `Query`, the body of
//! `POST /entityOperations/query`, carries a `scopeQ` expression, which is read from the payload
//! as well as from the URL.

use crate::{error::ScopeError, expression::ScopeExpression, matching::scope_matches};
use jstrict::{Value, object::Key};
use libra_enforcement_member::location::Location;
use libra_entity_preflight::{batch_write::StoredEntity, error::PreflightError};
use libra_json_body::narrowing::Narrowing;
use libra_ngsi_ld_operation::{operation::Mode, resource::ResourceId};
use libra_policy_model::{
    member_on_write::MemberOnWrite,
    scope::{ScopePattern, ScopeRestriction},
};

/// The member an entity declares its scopes in.
const SCOPE_MEMBER: &str = "scope";

/// The member a `Query` body carries its scope filter in.
const SCOPE_FILTER_MEMBER: &str = "scopeQ";

/// The member a normalised NGSI-LD property carries its value in.
const VALUE_MEMBER: &str = "value";

/// Whether the allowed patterns cover a scope.
#[must_use]
pub fn allows(allowed: &[ScopePattern], scope: &ScopePattern) -> bool {
    allowed.iter().any(|pattern| scope_matches(pattern, scope))
}

/// The scopes an entity document declares, if it declares any.
///
/// Three spellings are legal NGSI-LD and all three are read: a bare string, an array of strings,
/// and the normalised `{"type": "Property", "value": ...}` form. Reading the last as no scope at all would
/// let an entity be given any scope it liked under a policy that does not require a scope on write.
///
/// # Errors
///
/// Returns [`ScopeError::UnreadableScope`] for a shape Libra cannot read: refused rather than
/// ignored, because a scope that cannot be read cannot be compared, and
/// [`ScopeError::MalformedScope`] for a scope that is not a usable path. A `scope` member named
/// twice is unreadable too: the broker may read either occurrence.
pub fn scopes_of(entity: &Value, at: &Location) -> Result<Option<Vec<ScopePattern>>, ScopeError> {
    let Some(members) = entity.as_object() else {
        return Ok(None);
    };

    let Some(member) = members
        .get_unique(SCOPE_MEMBER)
        // Cloned because the error owns the place and the caller keeps its own.
        .map_err(|_| ScopeError::UnreadableScope { at: at.clone() })?
    else {
        return Ok(None);
    };

    read_scopes(member, at)
}

/// Reads a `scope` member in any of the forms NGSI-LD allows.
///
/// Every refusal clones `at`, because the error owns the place and the caller keeps its own.
fn read_scopes(member: &Value, at: &Location) -> Result<Option<Vec<ScopePattern>>, ScopeError> {
    match member {
        Value::Null => Ok(None),
        Value::String(scope) => Ok(Some(vec![to_pattern(scope)?])),
        Value::Array(items) => {
            let mut scopes = Vec::with_capacity(items.len());

            for item in items {
                let Value::String(scope) = item else {
                    return Err(ScopeError::UnreadableScope { at: at.clone() });
                };
                scopes.push(to_pattern(scope)?);
            }

            // An empty array declares no scope. Saying so here means one answer to "has this
            // entity a scope" rather than an empty list that later reads as "all of them".
            Ok(if scopes.is_empty() { None } else { Some(scopes) })
        }
        Value::Object(members) => {
            let Ok(Some(inner)) = members.get_unique(VALUE_MEMBER) else {
                return Err(ScopeError::UnreadableScope { at: at.clone() });
            };

            // One level only. A nested property object is not a scope, and recursing without a
            // floor would let a deeply nested document decide how long this runs for.
            if matches!(inner, Value::Object(_)) {
                return Err(ScopeError::UnreadableScope { at: at.clone() });
            }

            read_scopes(inner, at)
        }
        Value::Boolean(_) | Value::Number(_) => Err(ScopeError::UnreadableScope { at: at.clone() }),
    }
}

/// Turns a scope as written into a checked pattern.
fn to_pattern(scope: &str) -> Result<ScopePattern, ScopeError> {
    ScopePattern::new(scope).map_err(|error| ScopeError::MalformedScope {
        value: scope.to_owned(),
        reason: error.to_string(),
    })
}

/// Checks one entity's scopes against what the policy allows.
///
/// `on_write` says whether an entity carrying no scope is refused. It is the policy's
/// `scope-on-write` for a payload that creates or replaces an entity, and optional where the scope's
/// presence has already been checked by a pre-flight against the entity that exists.
///
/// # Errors
///
/// Returns [`ScopeError::MissingScope`] when a scope is required and absent,
/// [`ScopeError::ScopeDenied`] when one lies outside the restriction, and the errors [`scopes_of`]
/// returns.
pub fn check_entity(entity: &Value, restriction: &ScopeRestriction, on_write: MemberOnWrite, at: &Location) -> Result<(), ScopeError> {
    if entity.as_object().is_none() {
        return Err(ScopeError::MalformedBody { expected: "an entity" });
    }

    let Some(scopes) = scopes_of(entity, at)? else {
        if on_write == MemberOnWrite::Required {
            // Cloned because the error owns the place and the caller keeps its own.
            return Err(ScopeError::MissingScope { at: at.clone() });
        }

        return Ok(());
    };

    for scope in &scopes {
        if !allows(&restriction.allowed, scope) {
            // Cloned because the error owns the refused scope and the request keeps its own.
            return Err(ScopeError::ScopeDenied { scope: scope.clone() });
        }
    }

    Ok(())
}

/// Checks the scope of an entity that already exists.
///
/// A read is allowed when any one of the entity's scopes is allowed, which is how a `scopeQ`
/// collection query treats it; the response is then filtered to the allowed scopes. A write
/// requires every scope to be allowed. An entity with no scope is refused for a read, precisely as
/// a `scopeQ`-filtered query would not return it, and for a write follows
/// `scope-on-write`.
///
/// A write to an entity the caller may read, through one of its scopes, but not change is refused
/// as forbidden rather than withheld: the caller can already fetch it, so answering as though it
/// were absent would be untrue without hiding anything.
///
/// The answer is the broker's, so a refusal names only the identifier the caller addressed: its
/// stored scopes are what the restriction keeps from this caller. An identifier the broker does not
/// hold is refused exactly as one outside the allowed scopes, so the refusal does not say which
/// identifiers exist.
///
/// # Errors
///
/// Returns [`ScopeError::Withheld`] for an identifier the broker does not hold, an unscoped entity
/// that may not be touched, or one none of whose scopes the restriction covers,
/// [`ScopeError::OutsideScopesOnWrite`] for a write to an entity only some of whose scopes it covers,
/// [`ScopeError::Unenforceable`] for any other failed pre-flight, and the errors [`scopes_of`]
/// returns.
pub fn check_existing(answer: Result<Value, PreflightError>, restriction: &ScopeRestriction, mode: Mode, id: &ResourceId) -> Result<(), ScopeError> {
    // Cloned because the error owns the identifier and the request keeps its own.
    let withheld = || ScopeError::Withheld { id: id.clone() };
    let entity = match StoredEntity::of(answer)? {
        StoredEntity::Held(entity) => entity,
        StoredEntity::Absent => return Err(withheld()),
    };
    // Cloned because the place owns the identifier and the request keeps its own.
    let at = Location::Stored { id: id.clone() };

    let Some(scopes) = scopes_of(&entity, &at)? else {
        if matches!(mode, Mode::Write) && restriction.scope_on_write == MemberOnWrite::Optional {
            return Ok(());
        }

        return Err(withheld());
    };

    let covered = |scope: &ScopePattern| allows(&restriction.allowed, scope);

    match mode {
        Mode::Read if scopes.iter().any(covered) => Ok(()),
        Mode::Write if scopes.iter().all(covered) => Ok(()),
        // Cloned because the error owns the identifier and the request keeps its own.
        Mode::Write if scopes.iter().any(covered) => Err(ScopeError::OutsideScopesOnWrite { id: id.clone() }),
        Mode::Read | Mode::Write => Err(withheld()),
    }
}

/// Checks the body of a write against what the policy allows.
///
/// # Errors
///
/// As [`check_entity`], plus [`ScopeError::MalformedBody`] when the body is neither an entity nor
/// a batch of them.
pub fn check_write_body(document: &Value, restriction: &ScopeRestriction, on_write: MemberOnWrite) -> Result<(), ScopeError> {
    match document {
        Value::Object(_) => check_entity(document, restriction, on_write, &Location::Payload),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                check_entity(item, restriction, on_write, &Location::BatchEntity { index })?;
            }

            Ok(())
        }
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Err(ScopeError::MalformedBody {
            expected: "an entity or a batch of entities",
        }),
    }
}

/// Brings a `Query` body's scope filter inside what the policy allows.
///
/// The body is where `POST /entityOperations/query` carries its filter, so this is where the
/// restriction has to be applied. A caller that named no `scopeQ` gets the policy's own restriction
/// written in, exactly as a URL query would. The filter keeps its place among the body's members,
/// and one that narrows to exactly what the caller wrote is reported [`Narrowing::Unchanged`].
///
/// # Errors
///
/// Returns [`ScopeError::MalformedBody`] if the body is not a `Query` object,
/// [`ScopeError::UnreadableScope`] if its `scopeQ` is not a string or is named twice, and whatever
/// [`ScopeExpression::narrow`] returns for a filter outside the restriction.
pub fn narrow_query_document(document: &mut Value, allowed: &[ScopePattern]) -> Result<Narrowing, ScopeError> {
    let Value::Object(members) = document else {
        return Err(ScopeError::MalformedBody { expected: "a Query object" });
    };

    let unreadable = || ScopeError::UnreadableScope { at: Location::QueryBody };
    let restriction = || ScopeExpression::any_of(allowed).ok_or(ScopeError::EmptyAllowList);

    match members.get_unique_mut(SCOPE_FILTER_MEMBER).map_err(|_| unreadable())? {
        None => {
            members.push(Key::from(SCOPE_FILTER_MEMBER), Value::from(restriction()?.to_string()));
            Ok(Narrowing::Narrowed)
        }
        Some(filter @ Value::Null) => {
            *filter = Value::from(restriction()?.to_string());
            Ok(Narrowing::Narrowed)
        }
        Some(Value::String(filter)) => {
            let narrowed = ScopeExpression::parse(filter)?.narrow(allowed)?.to_string();

            if narrowed == filter.as_str() {
                return Ok(Narrowing::Unchanged);
            }

            *filter = narrowed.into();
            Ok(Narrowing::Narrowed)
        }
        Some(Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => Err(unreadable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use jstrict::{Print, json, object::Object};
    use pretty_assertions::assert_eq;

    fn restriction(allowed: &[&str], scope_on_write: MemberOnWrite) -> ScopeRestriction {
        ScopeRestriction {
            allowed: allowed
                .iter()
                .map(|value| ScopePattern::new(*value).expect("the test pattern should be well formed"))
                .collect(),
            scope_on_write,
        }
    }

    /// The `scopeQ` member of a narrowed `Query` body.
    fn scope_filter(document: &Value) -> Option<&str> {
        document.as_object()?.get_unique(SCOPE_FILTER_MEMBER).ok()??.as_str()
    }

    fn scopes(entity: &Value) -> Option<Vec<String>> {
        scopes_of(entity, &Location::Payload)
            .expect("the scope should be readable")
            .map(|scopes| scopes.iter().map(ToString::to_string).collect())
    }

    #[test]
    fn a_bare_string_scope_is_read() {
        assert_eq!(scopes(&json!({ "scope": "/Madrid" })), Some(vec!["/Madrid".to_owned()]));
    }

    #[test]
    fn an_array_of_scopes_is_read() {
        assert_eq!(
            scopes(&json!({ "scope": ["/Madrid", "/Barcelona"] })),
            Some(vec!["/Madrid".to_owned(), "/Barcelona".to_owned()])
        );
    }

    #[test]
    fn a_normalised_scope_is_read_rather_than_ignored() {
        // `{"type": "Property", "value": "/Madrid"}` is ordinary NGSI-LD, and reading it as no scope would let
        // an entity be written into any scope as long as it spelled the member the normalised way.
        assert_eq!(
            scopes(&json!({ "scope": { "type": "Property", "value": "/Madrid" } })),
            Some(vec!["/Madrid".to_owned()])
        );
        assert_eq!(
            scopes(&json!({ "scope": { "type": "Property", "value": ["/Madrid", "/Barcelona"] } })),
            Some(vec!["/Madrid".to_owned(), "/Barcelona".to_owned()])
        );
    }

    #[test]
    fn a_normalised_scope_outside_the_restriction_is_refused() {
        let refused = check_entity(
            &json!({ "id": "urn:e:1", "type": "Sensor", "scope": { "type": "Property", "value": "/Barcelona" } }),
            &restriction(&["/Madrid/#"], MemberOnWrite::Required),
            MemberOnWrite::Required,
            &Location::Payload,
        );

        assert_eq!(
            refused,
            Err(ScopeError::ScopeDenied {
                scope: ScopePattern::new("/Barcelona").unwrap()
            })
        );
    }

    #[test]
    fn an_absent_or_empty_scope_is_no_scope() {
        assert_eq!(scopes(&json!({ "id": "urn:e:1" })), None);
        assert_eq!(scopes(&json!({ "scope": [] })), None);
        assert_eq!(scopes(&json!({ "scope": null })), None);
    }

    #[test]
    fn a_scope_in_a_shape_libra_cannot_read_is_refused_rather_than_allowed() {
        for member in [
            json!(42),
            json!(true),
            json!({ "type": "Property" }),
            json!([1, 2]),
            json!({ "value": { "nested": 1 } }),
        ] {
            let entity = json!({ "scope": member });
            let refused = scopes_of(&entity, &Location::Payload);

            assert!(
                matches!(refused, Err(ScopeError::UnreadableScope { .. })),
                "{entity} must be refused, got {refused:?}"
            );
        }
    }

    #[test]
    fn a_scope_that_is_not_a_usable_path_is_refused() {
        let entity = json!({ "scope": "Madrid/Gardens" });

        assert!(matches!(scopes_of(&entity, &Location::Payload), Err(ScopeError::MalformedScope { .. })));
    }

    #[test]
    fn a_write_inside_the_restriction_is_accepted() {
        let entity = json!({ "id": "urn:e:1", "type": "Sensor", "scope": "/Madrid/Gardens/ParqueNorte" });

        assert_eq!(
            check_entity(
                &entity,
                &restriction(&["/Madrid/Gardens/#"], MemberOnWrite::Required),
                MemberOnWrite::Required,
                &Location::Payload
            ),
            Ok(())
        );
    }

    #[test]
    fn a_write_without_a_scope_follows_the_policy_flag() {
        let entity = json!({ "id": "urn:e:1", "type": "Sensor" });

        assert_eq!(
            check_entity(
                &entity,
                &restriction(&["/Madrid/#"], MemberOnWrite::Required),
                MemberOnWrite::Required,
                &Location::Payload
            ),
            Err(ScopeError::MissingScope { at: Location::Payload })
        );
        assert_eq!(
            check_entity(
                &entity,
                &restriction(&["/Madrid/#"], MemberOnWrite::Optional),
                MemberOnWrite::Optional,
                &Location::Payload
            ),
            Ok(())
        );
    }

    #[test]
    fn a_stored_entity_outside_the_allowed_scopes_is_refused_without_naming_its_scope() {
        let stored = json!({ "id": "urn:e:1", "type": "Sensor", "scope": "/Barcelona/B" });
        let restriction = restriction(&["/Madrid/#"], MemberOnWrite::Required);

        for mode in [Mode::Read, Mode::Write] {
            // Cloned because each mode judges its own answer.
            let refused = check_existing(Ok(stored.clone()), &restriction, mode, &ResourceId::new("urn:e:1"));

            assert_eq!(
                refused,
                Err(ScopeError::Withheld {
                    id: ResourceId::new("urn:e:1")
                })
            );
            let message = refused.unwrap_err().to_string();
            assert!(!message.contains("Barcelona"), "the refusal names the stored scope: {message}");
        }
    }

    #[test]
    fn a_stored_entity_without_a_scope_is_refused_without_saying_so() {
        let stored = json!({ "id": "urn:e:1", "type": "Sensor" });

        assert_eq!(
            check_existing(
                Ok(stored),
                &restriction(&["/Madrid/#"], MemberOnWrite::Required),
                Mode::Read,
                &ResourceId::new("urn:e:1")
            ),
            Err(ScopeError::Withheld {
                id: ResourceId::new("urn:e:1")
            })
        );
    }

    #[test]
    fn a_stored_entity_with_an_empty_scope_array_is_refused_as_unscoped_for_reads_and_writes() {
        let stored = json!({ "id": "urn:e:1", "type": "Sensor", "scope": [] });
        let restriction = restriction(&["/Madrid/#"], MemberOnWrite::Required);
        let id = ResourceId::new("urn:e:1");

        for mode in [Mode::Read, Mode::Write] {
            assert_eq!(
                check_existing(Ok(stored.clone()), &restriction, mode, &id),
                Err(ScopeError::Withheld { id: id.clone() }),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn a_stored_entity_is_read_when_one_scope_is_allowed_and_written_only_when_every_scope_is() {
        let stored = json!({ "id": "urn:e:1", "type": "Sensor", "scope": ["/Madrid/A", "/Barcelona/B"] });
        let restriction = restriction(&["/Madrid/#"], MemberOnWrite::Required);
        let id = ResourceId::new("urn:e:1");

        // Cloned because each mode judges its own answer.
        assert_eq!(check_existing(Ok(stored.clone()), &restriction, Mode::Read, &id), Ok(()));
        let refused = check_existing(Ok(stored), &restriction, Mode::Write, &id);
        assert_eq!(
            refused,
            Err(ScopeError::OutsideScopesOnWrite {
                id: ResourceId::new("urn:e:1")
            })
        );
        // The caller can read the entity, so the refusal is a 403, and it still names no stored scope.
        let refused = refused.unwrap_err();
        assert_eq!(refused.to_problem().status(), StatusCode::FORBIDDEN);
        assert!(!refused.to_string().contains("Barcelona"), "the refusal names the stored scope: {refused}");
    }

    #[test]
    fn an_absent_entity_is_refused_exactly_as_one_outside_the_allowed_scopes() {
        let id = ResourceId::new("urn:e:1");
        let outside = json!({ "id": "urn:e:1", "type": "Sensor", "scope": "/Barcelona/B" });
        let restriction = restriction(&["/Madrid/#"], MemberOnWrite::Required);

        let absent = check_existing(Err(PreflightError::Status { status: StatusCode::NOT_FOUND }), &restriction, Mode::Read, &id).unwrap_err();
        let withheld = check_existing(Ok(outside), &restriction, Mode::Read, &id).unwrap_err();

        assert_eq!(absent, withheld);
        assert_eq!(absent.to_problem().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_batch_is_checked_entity_by_entity_and_says_which_one_failed() {
        let batch = json!([
            { "id": "urn:e:1", "type": "Sensor", "scope": "/Madrid/A" },
            { "id": "urn:e:2", "type": "Sensor", "scope": "/Barcelona/B" }
        ]);

        assert_eq!(
            check_write_body(&batch, &restriction(&["/Madrid/#"], MemberOnWrite::Required), MemberOnWrite::Required),
            Err(ScopeError::ScopeDenied {
                scope: ScopePattern::new("/Barcelona/B").unwrap()
            })
        );
    }

    #[test]
    fn a_query_body_without_a_filter_is_given_the_policys_own() {
        // A scope filter in the payload is where this endpoint's filter lives, so the layer inspects
        // the payload and not only the URL.
        let mut document = json!({ "type": "Query", "entities": [{ "type": "Vehicle" }] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["/Madrid/#", "/Barcelona/#"], MemberOnWrite::Required).allowed),
            Ok(Narrowing::Narrowed)
        );

        assert_eq!(scope_filter(&document), Some("/Madrid/#|/Barcelona/#"));
    }

    #[test]
    fn a_query_body_filter_is_narrowed_in_place() {
        let mut document = json!({ "type": "Query", "scopeQ": "/Madrid/#" });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["/Madrid/Gardens/#"], MemberOnWrite::Required).allowed),
            Ok(Narrowing::Narrowed)
        );

        assert_eq!(scope_filter(&document), Some("/Madrid/Gardens/#"));
    }

    #[test]
    fn a_query_body_filter_outside_the_restriction_is_refused() {
        let mut document = json!({ "type": "Query", "scopeQ": "/Barcelona/#" });

        assert!(narrow_query_document(&mut document, &restriction(&["/Madrid/#"], MemberOnWrite::Required).allowed).is_err());
    }

    #[test]
    fn a_query_body_filter_inside_the_restriction_is_reported_unchanged() {
        let mut document = json!({ "type": "Query", "scopeQ": "/Madrid/Gardens/#", "q": "speed>40" });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["/Madrid/#"], MemberOnWrite::Required).allowed),
            Ok(Narrowing::Unchanged)
        );
        assert_eq!(scope_filter(&document), Some("/Madrid/Gardens/#"));
    }

    #[test]
    fn a_narrowed_filter_keeps_its_place_among_the_members() {
        let mut document = json!({ "type": "Query", "scopeQ": "/Madrid/#", "q": "speed>40" });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["/Madrid/Gardens/#"], MemberOnWrite::Required).allowed),
            Ok(Narrowing::Narrowed)
        );
        assert_eq!(
            document.compact_print().to_string(),
            r#"{"type":"Query","scopeQ":"/Madrid/Gardens/#","q":"speed>40"}"#
        );
    }

    #[test]
    fn a_scope_or_a_filter_named_twice_is_unreadable_rather_than_resolved() {
        let mut entity = Object::new();
        entity.push(Key::from("scope"), json!("/Madrid/A"));
        entity.push(Key::from("scope"), json!("/Secret/X"));

        assert!(matches!(
            scopes_of(&Value::Object(entity), &Location::Payload),
            Err(ScopeError::UnreadableScope { .. })
        ));

        let mut query = Object::new();
        query.push(Key::from("scopeQ"), json!("/Madrid/#"));
        query.push(Key::from("scopeQ"), json!("/Secret/#"));
        let mut document = Value::Object(query);

        assert!(matches!(
            narrow_query_document(&mut document, &restriction(&["/Madrid/#"], MemberOnWrite::Required).allowed),
            Err(ScopeError::UnreadableScope { .. })
        ));
    }
}
