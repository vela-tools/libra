//! Reading and checking the entity types a JSON document carries.
//!
//! Two shapes again, and they are not the same. An entity (in a create, an update, or a
//! pre-flight response) carries a `type` member, which NGSI-LD allows to be one name or several.
//! A `Query`, the body of `POST /entityOperations/query`, carries an `entities` array of
//! selectors, each with a `type` of its own; the type filter that decides what that endpoint
//! returns is read from the body as well as from the URL.

use crate::{error::TypeError, names};
use jstrict::{
    Array,
    Value,
    object::{Key, Object},
};
use libra_enforcement_member::location::Location;
use libra_entity_preflight::{batch_write::StoredEntity, error::PreflightError};
use libra_json_body::narrowing::Narrowing;
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_ngsi_ld_operation::resource::ResourceId;
use libra_ngsi_ld_query::type_selection::TypeSelection;
use libra_policy_model::{entity_type::CompiledTypeRestriction, member_on_write::MemberOnWrite};
use std::mem;

/// The member an entity declares its types in.
const TYPE_MEMBER: &str = "type";

/// The member a `Query` body carries its entity selectors in.
const ENTITIES_MEMBER: &str = "entities";

/// What the body of a batch query or a subscription is expected to be, phrased for the caller.
const QUERY_OBJECT: &str = "a Query object";

/// The types an entity document declares.
///
/// NGSI-LD entities may carry one type or several, so both a bare string and an array of strings
/// are read. Anything else is refused rather than skipped: a type Libra cannot read is one it
/// cannot compare. So is a `type` member named twice, of which the broker may read either.
///
/// # Errors
///
/// Returns [`TypeError::UnreadableType`] for a shape that is neither, or for a repeated `type`.
pub fn types_of(entity: &Object, at: &Location) -> Result<Vec<Term>, TypeError> {
    // Cloned because the error owns the place and the caller keeps its own.
    let unreadable = || TypeError::UnreadableType { at: at.clone() };

    let Some(member) = entity.get_unique(TYPE_MEMBER).map_err(|_| unreadable())? else {
        return Ok(Vec::new());
    };

    match member {
        Value::Null => Ok(Vec::new()),
        Value::String(name) => Ok(vec![Term::new(name.as_str())]),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(name) => Ok(Term::new(name.as_str())),
                Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => Err(unreadable()),
            })
            .collect(),
        Value::Boolean(_) | Value::Number(_) | Value::Object(_) => Err(unreadable()),
    }
}

/// Checks one entity's types against what the policy allows.
///
/// `on_write` says whether an entity carrying no type is refused. It is the policy's
/// `type-on-write` for a payload that creates or replaces an entity, and optional where the type's
/// presence has already been checked by a pre-flight against the entity that exists, which is what
/// makes a merge patch enforceable at all, since its body carries no type by design.
///
/// # Errors
///
/// Returns [`TypeError::MissingType`] when a type is required and absent,
/// [`TypeError::TypeDenied`] when one is outside the restriction, and [`TypeError::Unresolvable`] when
/// the request's context cannot expand a name.
pub fn check_entity(
    entity: &Value,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    on_write: MemberOnWrite,
    at: &Location,
) -> Result<(), TypeError> {
    let Value::Object(members) = entity else {
        return Err(TypeError::MalformedBody { expected: "an entity" });
    };

    let names = types_of(members, at)?;

    if names.is_empty() {
        if on_write == MemberOnWrite::Required {
            // Cloned because the error owns the place and the caller keeps its own.
            return Err(TypeError::MissingType { at: at.clone() });
        }

        return Ok(());
    }

    match first_denied(&names, restriction, context)? {
        // Cloned because the error owns the term and the document keeps its own.
        Some(name) => Err(TypeError::TypeDenied { entity_type: name.clone() }),
        None => Ok(()),
    }
}

/// Checks the types of the entity a pre-flight answered for.
///
/// An entity the broker does not hold, and one of a type outside the restriction, are refused
/// alike, naming only the identifier the caller sent: the stored type is what the restriction
/// keeps from this caller, and a refusal that told the two apart would say which identifiers exist
/// under it. A stored type the request's context cannot expand is refused the same way, since its
/// name is stored data too.
///
/// # Errors
///
/// Returns [`TypeError::Withheld`] for an entity the broker does not hold or one with a type
/// outside the restriction or that cannot be expanded, [`TypeError::MissingType`] for one with no
/// type, [`TypeError::UnreadableType`] or [`TypeError::MalformedBody`] for one Libra cannot read,
/// and [`TypeError::Unenforceable`] for any other failed pre-flight.
pub fn check_stored(
    answer: Result<Value, PreflightError>,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    id: &ResourceId,
) -> Result<(), TypeError> {
    // Cloned because the error owns the identifier and the request keeps its own.
    let withheld = || TypeError::Withheld { id: id.clone() };
    let entity = match StoredEntity::of(answer)? {
        StoredEntity::Held(entity) => entity,
        StoredEntity::Absent => return Err(withheld()),
    };

    // Cloned because the place owns the identifier and the request keeps its own.
    let at = Location::Stored { id: id.clone() };
    let Value::Object(members) = &entity else {
        return Err(TypeError::MalformedBody { expected: "an entity" });
    };

    let names = types_of(members, &at)?;

    if names.is_empty() {
        return Err(TypeError::MissingType { at });
    }

    match first_denied(&names, restriction, context) {
        Ok(None) => Ok(()),
        Ok(Some(_)) | Err(TypeError::Unresolvable { .. }) => Err(withheld()),
        Err(other) => Err(other),
    }
}

/// The first of `names` the restriction does not allow.
fn first_denied<'names>(names: &'names [Term], restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<Option<&'names Term>, TypeError> {
    for name in names {
        if !names::allows(restriction, name, context)? {
            return Ok(Some(name));
        }
    }

    Ok(None)
}

/// Checks the body of a write against what the policy allows.
///
/// # Errors
///
/// As [`check_entity`], plus [`TypeError::MalformedBody`] when the body is neither an entity nor a
/// batch of them.
pub fn check_write_body(document: &Value, restriction: &CompiledTypeRestriction, context: &ResolvedContext, on_write: MemberOnWrite) -> Result<(), TypeError> {
    match document {
        Value::Object(_) => check_entity(document, restriction, context, on_write, &Location::Payload),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                check_entity(item, restriction, context, on_write, &Location::BatchEntity { index })?;
            }

            Ok(())
        }
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Err(TypeError::MalformedBody {
            expected: "an entity or a batch of entities",
        }),
    }
}

/// Brings a `Query` body's entity selectors inside what the policy allows.
///
/// A selector naming a type has it narrowed to the allowed types, and a selector narrowed to
/// nothing is dropped: the selectors are a disjunction (clause 5.2.33), so the others still select
/// what they selected. A selector naming none (or a body with no `entities` at all) selects every
/// type there is, and is written out as one selector per allowed type. That is the disjunction the
/// specification's own selector list expresses, and it needs nothing newer than NGSI-LD 1.6 to be
/// understood, unlike writing `A|B` into a single selector.
///
/// The selectors keep their place among the body's members, and a body whose selectors were all
/// inside the restriction as written is reported [`Narrowing::Unchanged`].
///
/// # Errors
///
/// Returns [`TypeError::MalformedBody`] if the body is not a `Query` object or names `entities`
/// twice, [`TypeError::UnreadableType`] if a selector's `type` is not a string or is named twice, and
/// the [`TypeError::TypeDenied`] of the first dropped selector when every selector is dropped.
pub fn narrow_query_document(document: &mut Value, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<Narrowing, TypeError> {
    let Value::Object(members) = document else {
        return Err(TypeError::MalformedBody { expected: QUERY_OBJECT });
    };

    let malformed = || TypeError::MalformedBody { expected: QUERY_OBJECT };

    match members.get_unique_mut(ENTITIES_MEMBER).map_err(|_| malformed())? {
        None => {
            members.push(Key::from(ENTITIES_MEMBER), Value::Array(every_allowed_type(restriction)?));
            Ok(Narrowing::Narrowed)
        }
        Some(entities @ Value::Null) => {
            *entities = Value::Array(every_allowed_type(restriction)?);
            Ok(Narrowing::Narrowed)
        }
        Some(Value::Array(items)) if items.is_empty() => {
            *items = every_allowed_type(restriction)?;
            Ok(Narrowing::Narrowed)
        }
        Some(Value::Array(items)) => narrow_selectors(items, restriction, context),
        Some(Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Object(_)) => Err(malformed()),
    }
}

/// One selector per allowed type, standing in for selectors that named every type.
fn every_allowed_type(restriction: &CompiledTypeRestriction) -> Result<Array, TypeError> {
    let allowed = names::allowed(restriction)?;

    allowed.iter().map(|iri| selector_for(&Object::new(), iri.as_str())).collect()
}

/// Narrows a non-empty list of selectors in place.
fn narrow_selectors(items: &mut Array, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<Narrowing, TypeError> {
    let allowed = names::allowed(restriction)?;
    let unreadable = || TypeError::UnreadableType { at: Location::QueryBody };

    let mut narrowed = Vec::with_capacity(items.len());
    let mut narrowing = Narrowing::Unchanged;
    let mut first_denial = None;

    for item in mem::take(items) {
        let Value::Object(mut selector) = item else {
            return Err(TypeError::MalformedBody { expected: QUERY_OBJECT });
        };

        match selector.get_unique_mut(TYPE_MEMBER).map_err(|_| unreadable())? {
            Some(Value::String(selected)) => {
                let parsed = TypeSelection::parse(selected)?;
                match names::narrow_selection(&parsed, restriction, context) {
                    Ok(kept) => {
                        if kept != parsed {
                            *selected = kept.to_string().into();
                            narrowing = Narrowing::Narrowed;
                        }
                        narrowed.push(Value::Object(selector));
                    }
                    Err(denial @ TypeError::TypeDenied { .. }) => {
                        first_denial.get_or_insert(denial);
                        narrowing = Narrowing::Narrowed;
                    }
                    Err(error) => return Err(error),
                }
            }
            None | Some(Value::Null) => {
                for iri in allowed {
                    narrowed.push(selector_for(&selector, iri.as_str())?);
                }
                narrowing = Narrowing::Narrowed;
            }
            Some(Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => return Err(unreadable()),
        }
    }

    if let (true, Some(denial)) = (narrowed.is_empty(), first_denial) {
        return Err(denial);
    }

    *items = Array::from(narrowed);

    Ok(narrowing)
}

/// Copies a selector and gives it one type, in the place its own `type` held if it had one.
fn selector_for(selector: &Object, entity_type: &str) -> Result<Value, TypeError> {
    // One copy per allowed type: every selector keeps the other members and differs only in `type`.
    let mut copy = selector.clone();

    match copy.get_unique_mut(TYPE_MEMBER) {
        Ok(Some(slot)) => *slot = Value::from(entity_type),
        Ok(None) => {
            copy.push(Key::from(TYPE_MEMBER), Value::from(entity_type));
        }
        Err(_) => {
            return Err(TypeError::UnreadableType { at: Location::QueryBody });
        }
    }

    Ok(Value::Object(copy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use jstrict::{Print, json};
    use libra_policy_model::{entity_type::TypeRestriction, member_on_write::MemberOnWrite, policy::PolicyId};
    use pretty_assertions::assert_eq;

    const VEHICLE: &str = "https://uri.fiware.org/ns/data-models#Vehicle";

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Building": "https://uri.fiware.org/ns/data-models#Building"
            }"#,
        )
        .expect("the test context should process")
    }

    fn restriction(allowed: &[&str]) -> CompiledTypeRestriction {
        TypeRestriction {
            allowed: allowed.iter().map(|name| Term::new(*name)).collect(),
            type_on_write: MemberOnWrite::Required,
        }
        .compile(&PolicyId::new("test").unwrap(), &context())
        .expect("the test restriction should compile")
    }

    fn types_of(entity: &Value, at: &Location) -> Result<Vec<Term>, TypeError> {
        super::types_of(entity.as_object().expect("the test entity is an object"), at)
    }

    /// The `entities` member of a narrowed `Query` body.
    fn entities(document: &Value) -> Option<&Value> {
        document.as_object()?.get_unique(ENTITIES_MEMBER).ok()?
    }

    #[test]
    fn a_single_type_and_a_list_of_types_are_both_read() {
        assert_eq!(types_of(&json!({ "type": "Vehicle" }), &Location::Payload), Ok(vec![Term::new("Vehicle")]));
        assert_eq!(
            types_of(&json!({ "type": ["Vehicle", "Building"] }), &Location::Payload),
            Ok(vec![Term::new("Vehicle"), Term::new("Building")])
        );
        assert_eq!(types_of(&json!({ "id": "urn:e:1" }), &Location::Payload), Ok(Vec::new()));
    }

    #[test]
    fn a_type_in_a_shape_libra_cannot_read_is_refused() {
        for member in [json!(1), json!(true), json!({ "value": "Vehicle" }), json!([1])] {
            let entity = json!({ "type": member });

            assert!(
                matches!(types_of(&entity, &Location::Payload), Err(TypeError::UnreadableType { .. })),
                "{entity} must be refused"
            );
        }
    }

    #[test]
    fn a_write_of_an_aliased_type_is_accepted() {
        let entity = json!({ "id": "urn:e:1", "type": "Car" });

        assert_eq!(
            check_entity(&entity, &restriction(&["Vehicle"]), &context(), MemberOnWrite::Required, &Location::Payload),
            Ok(())
        );
    }

    #[test]
    fn a_write_of_a_type_outside_the_restriction_is_refused() {
        let entity = json!({ "id": "urn:e:1", "type": "Building" });

        assert_eq!(
            check_entity(&entity, &restriction(&["Vehicle"]), &context(), MemberOnWrite::Required, &Location::Payload),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
    }

    fn not_found() -> Result<Value, PreflightError> {
        Err(PreflightError::Status { status: StatusCode::NOT_FOUND })
    }

    #[test]
    fn a_stored_entity_of_a_forbidden_type_is_refused_without_naming_its_type() {
        let stored = json!({ "id": "urn:e:1", "type": "Building" });

        let refused = check_stored(Ok(stored), &restriction(&["Vehicle"]), &context(), &ResourceId::new("urn:e:1"));

        assert_eq!(
            refused,
            Err(TypeError::Withheld {
                id: ResourceId::new("urn:e:1")
            })
        );
        let message = refused.unwrap_err().to_string();
        assert!(!message.contains("Building"), "the refusal names the stored type: {message}");
    }

    #[test]
    fn a_stored_type_the_context_cannot_expand_is_refused_without_naming_it() {
        // An empty context expands no bare term, so the stored name is unresolvable.
        let bare = ResolvedContext::from_json("{}").expect("the test context should process");
        let stored = json!({ "id": "urn:e:1", "type": "Building" });

        assert_eq!(
            check_stored(Ok(stored), &restriction(&["Vehicle"]), &bare, &ResourceId::new("urn:e:1")),
            Err(TypeError::Withheld {
                id: ResourceId::new("urn:e:1")
            })
        );
    }

    #[test]
    fn a_stored_entity_of_an_allowed_type_passes() {
        let stored = json!({ "id": "urn:e:1", "type": ["Car", "Vehicle"] });

        assert_eq!(
            check_stored(Ok(stored), &restriction(&["Vehicle"]), &context(), &ResourceId::new("urn:e:1")),
            Ok(())
        );
    }

    #[test]
    fn an_absent_entity_is_refused_exactly_as_one_of_a_forbidden_type() {
        let id = ResourceId::new("urn:e:1");
        let forbidden = json!({ "id": "urn:e:1", "type": "Building" });

        let absent = check_stored(not_found(), &restriction(&["Vehicle"]), &context(), &id).unwrap_err();
        let withheld = check_stored(Ok(forbidden), &restriction(&["Vehicle"]), &context(), &id).unwrap_err();

        assert_eq!(absent, withheld);
        assert_eq!(absent.to_problem().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_pre_flight_that_fails_otherwise_is_not_mistaken_for_an_absent_entity() {
        let failed = Err(PreflightError::Status {
            status: StatusCode::SERVICE_UNAVAILABLE,
        });

        assert!(matches!(
            check_stored(failed, &restriction(&["Vehicle"]), &context(), &ResourceId::new("urn:e:1")),
            Err(TypeError::Unenforceable(_))
        ));
    }

    #[test]
    fn a_write_without_a_type_follows_the_policy_flag() {
        let entity = json!({ "id": "urn:e:1" });

        assert_eq!(
            check_entity(&entity, &restriction(&["Vehicle"]), &context(), MemberOnWrite::Required, &Location::Payload),
            Err(TypeError::MissingType { at: Location::Payload })
        );
        assert_eq!(
            check_entity(&entity, &restriction(&["Vehicle"]), &context(), MemberOnWrite::Optional, &Location::Payload),
            Ok(())
        );
    }

    #[test]
    fn a_batch_is_checked_entity_by_entity_and_says_which_one_failed() {
        let batch = json!([{ "id": "urn:e:1", "type": "Vehicle" }, { "id": "urn:e:2", "type": "Building" }]);

        assert_eq!(
            check_write_body(&batch, &restriction(&["Vehicle"]), &context(), MemberOnWrite::Required),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
    }

    #[test]
    fn a_query_body_selector_is_inspected() {
        // `entities: [{"type": ...}]` in the payload is what decides what this endpoint returns, so the
        // payload is checked as well as the URL.
        let mut document = json!({ "type": "Query", "entities": [{ "type": "Building" }] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
    }

    #[test]
    fn a_query_body_selector_of_a_forbidden_type_is_dropped_and_the_rest_kept() {
        let mut document = json!({ "type": "Query", "entities": [{ "type": "Building" }, { "type": "Vehicle" }] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Ok(Narrowing::Narrowed)
        );

        assert_eq!(entities(&document), Some(&json!([{ "type": "Vehicle" }])));
    }

    #[test]
    fn a_query_body_selector_allowed_in_part_is_narrowed_to_that_part() {
        let mut document = json!({ "type": "Query", "entities": [{ "type": "Vehicle,Building", "idPattern": "urn:.*" }] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Ok(Narrowing::Narrowed)
        );

        assert_eq!(entities(&document), Some(&json!([{ "type": "Vehicle", "idPattern": "urn:.*" }])));
    }

    #[test]
    fn a_query_body_whose_every_selector_is_dropped_is_refused() {
        let mut document = json!({ "type": "Query", "entities": [{ "type": "Building" }, { "type": "Vehicle;Building" }] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
    }

    #[test]
    fn a_query_body_without_selectors_is_given_the_restriction() {
        let mut document = json!({ "type": "Query", "q": "speed>40" });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Ok(Narrowing::Narrowed)
        );

        assert_eq!(entities(&document), Some(&json!([{ "type": VEHICLE }])));
    }

    #[test]
    fn a_query_body_with_an_empty_selector_list_is_given_the_restriction() {
        // An empty `entities` selects no type at all, so it is as unbounded as an absent one.
        let mut document = json!({ "type": "Query", "entities": [], "q": "speed>40" });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Ok(Narrowing::Narrowed)
        );

        assert_eq!(entities(&document), Some(&json!([{ "type": VEHICLE }])));
    }

    #[test]
    fn a_selector_that_names_no_type_is_given_one_copy_per_allowed_type() {
        let mut document = json!({ "type": "Query", "entities": [{ "idPattern": "urn:.*" }] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle", "Building"]), &context()),
            Ok(Narrowing::Narrowed)
        );

        let selectors = entities(&document).and_then(Value::as_array).unwrap_or_default();

        assert_eq!(selectors.len(), 2, "one selector per allowed type: {selectors:?}");
        assert!(
            selectors
                .iter()
                .all(|selector| selector.as_object().and_then(|members| members.get_unique("idPattern").ok().flatten()) == Some(&json!("urn:.*"))),
            "{selectors:?}"
        );
    }

    #[test]
    fn a_selector_naming_an_aliased_allowed_type_is_left_as_written() {
        let mut document = json!({ "type": "Query", "entities": [{ "type": "Car" }] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Ok(Narrowing::Unchanged)
        );

        assert_eq!(entities(&document), Some(&json!([{ "type": "Car" }])));
    }

    #[test]
    fn a_type_named_twice_is_unreadable_rather_than_resolved() {
        let mut entity = Object::new();
        entity.push(Key::from("type"), json!("Vehicle"));
        entity.push(Key::from("type"), json!("Building"));

        assert_eq!(
            super::types_of(&entity, &Location::Payload),
            Err(TypeError::UnreadableType { at: Location::Payload })
        );
    }

    #[test]
    fn a_selector_naming_its_type_twice_is_refused() {
        let mut selector = Object::new();
        selector.push(Key::from("type"), json!("Vehicle"));
        selector.push(Key::from("type"), json!("Building"));
        let mut document = json!({ "type": "Query", "entities": [Value::Object(selector)] });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Err(TypeError::UnreadableType { at: Location::QueryBody })
        );
    }

    #[test]
    fn a_query_body_naming_its_selectors_twice_is_refused() {
        let mut members = Object::new();
        members.push(Key::from("entities"), json!([{ "type": "Vehicle" }]));
        members.push(Key::from("entities"), json!([{ "type": "Building" }]));
        let mut document = Value::Object(members);

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Err(TypeError::MalformedBody { expected: "a Query object" })
        );
    }

    #[test]
    fn narrowed_selectors_keep_their_place_among_the_members() {
        let mut document = json!({ "type": "Query", "entities": [{ "type": "Building" }, { "type": "Vehicle" }], "q": "speed>40" });

        assert_eq!(
            narrow_query_document(&mut document, &restriction(&["Vehicle"]), &context()),
            Ok(Narrowing::Narrowed)
        );
        assert_eq!(
            document.compact_print().to_string(),
            r#"{"type":"Query","entities":[{"type":"Vehicle"}],"q":"speed>40"}"#
        );
    }
}
