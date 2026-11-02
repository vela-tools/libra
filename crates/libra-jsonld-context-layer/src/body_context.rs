//! Finding the `@context` a request body carries, and refusing every body whose context the
//! broker could read differently from Libra.
//!
//! The broker expands names under whatever context it finds in the body. Libra authorizes under
//! the context it finds. Any body where those two readings can differ is a way to show Libra one
//! meaning and the broker another, so each such shape is refused here instead of being quietly read
//! as "no context". A body the broker reads under a context Libra did not see is a body whose
//! types and attribute names Libra authorized under a different meaning.

use jstrict::Value;
use libra_json_body::request_body::RequestBody;
use libra_jsonld_context::channel::is_ld_json;
use libra_problem_details::problem::Problem;

/// The body's `@context`, if it has exactly one reading of it.
///
/// - A body that is not JSON has no context, unless it claims to be `application/ld+json`: then it
///   is refused, because a parser more lenient than this one may still find a context in it.
/// - An object with more than one `@context` member is refused. Parsers disagree about which
///   duplicate wins, and treating the member as absent would resolve the request against the
///   default context while the broker used the caller's.
/// - An `@context` anywhere below the top level of the body, or below the elements of a batch, is
///   refused. JSON-LD lets a node object carry a context that applies inside it, which a broker
///   honours and Libra, resolving one context per request, would not.
/// - An array is a batch, whose entities may each carry their own `@context`. Libra resolves one
///   context per request, so a batch is accepted only when every element that has a context has
///   the same one and none lacks it; any other mix is refused.
///
/// # Errors
///
/// Returns [`Problem::BadRequest`] for each refused shape above.
pub fn find(body: &RequestBody, content_type: Option<&str>) -> Result<Option<Value>, Problem> {
    if let RequestBody::Json(document) = body {
        refuse_nested_context(document)?;
    }

    match body {
        RequestBody::NotJson => refuse_if_ld_json(content_type, "the body is not valid JSON"),
        RequestBody::Json(Value::Object(object)) => context_of(object),
        RequestBody::Json(Value::Array(elements)) => batch_context(elements.iter()),
        RequestBody::Empty | RequestBody::Json(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_)) => Ok(None),
    }
}

/// Refuses an `@context` member anywhere Libra does not read one: below the top-level object, or
/// below the elements of a top-level array.
fn refuse_nested_context(document: &Value) -> Result<(), Problem> {
    let mut pending: Vec<&Value> = match document {
        Value::Object(object) => members_beside_context(object).collect(),
        Value::Array(elements) => elements
            .iter()
            .flat_map(|element| match element {
                Value::Object(object) => members_beside_context(object).collect::<Vec<_>>(),
                Value::Array(items) => items.iter().collect(),
                Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Vec::new(),
            })
            .collect(),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Vec::new(),
    };

    while let Some(value) = pending.pop() {
        match value {
            Value::Object(object) => {
                if object.contains_key("@context") {
                    return Err(Problem::BadRequest(
                        "an @context below the top level of the body applies to part of it, and a request has one context".to_owned(),
                    ));
                }
                pending.extend(object.iter().map(|entry| &entry.value));
            }
            Value::Array(items) => pending.extend(items.iter()),
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    Ok(())
}

/// The values of an object's members other than its own `@context`.
fn members_beside_context(object: &jstrict::Object) -> impl Iterator<Item = &Value> {
    object.iter().filter(|entry| entry.key.as_str() != "@context").map(|entry| &entry.value)
}

/// A body that cannot be read is no context, except for a body that promised to carry one.
fn refuse_if_ld_json(content_type: Option<&str>, reason: &str) -> Result<Option<Value>, Problem> {
    if is_ld_json(content_type) {
        return Err(Problem::BadRequest(format!("{reason}, so its @context cannot be read")));
    }

    Ok(None)
}

/// The one `@context` of an object, refusing a repeated member.
fn context_of(object: &jstrict::Object) -> Result<Option<Value>, Problem> {
    object
        .get_unique("@context")
        .map(Option::<&Value>::cloned)
        .map_err(|_| Problem::BadRequest("the body has more than one @context member".to_owned()))
}

/// The shared `@context` of a batch, or a refusal if its elements do not agree on one.
fn batch_context<'elements>(elements: impl Iterator<Item = &'elements Value>) -> Result<Option<Value>, Problem> {
    let mut shared: Option<Value> = None;
    let mut without = false;

    for element in elements {
        let context = match element {
            Value::Object(object) => context_of(object)?,
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => None,
        };

        match (context, &shared) {
            (None, _) => without = true,
            (Some(context), None) => shared = Some(context),
            (Some(context), Some(first)) if context == *first => {}
            (Some(_), Some(_)) => {
                return Err(Problem::BadRequest(
                    "the entities of a batch carry different @context values, and one request has one context".to_owned(),
                ));
            }
        }
    }

    if shared.is_some() && without {
        return Err(Problem::BadRequest(
            "some entities of a batch carry an @context and some do not, so the request has no single context".to_owned(),
        ));
    }

    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn found(body: &str, content_type: Option<&str>) -> Result<Option<String>, Problem> {
        let body = RequestBody::read(body.as_bytes()).map_err(|error| Problem::BadRequest(error.to_string()))?;

        find(&body, content_type).map(|context| context.map(|value| value.to_string()))
    }

    #[test]
    fn a_single_context_is_found() {
        assert_eq!(
            found(r#"{"@context": "https://a.test/c", "id": "x"}"#, None).unwrap(),
            Some("\"https://a.test/c\"".to_owned())
        );
        assert_eq!(found(r#"{"id": "x"}"#, None).unwrap(), None);
    }

    #[test]
    fn a_repeated_context_member_is_refused_rather_than_read_as_none() {
        // `get_unique` errors on a duplicate, and reading that error as "no context" would resolve the
        // request under the default context while a last-wins broker used the second member.
        let body = r#"{"@context": "https://a.test/c", "@context": {"Vehicle": "https://evil.test/Public"}}"#;

        assert!(matches!(found(body, Some("application/ld+json")), Err(Problem::BadRequest(_))));
    }

    #[test]
    fn an_unreadable_body_is_refused_only_when_it_promised_a_context() {
        assert!(matches!(found("{not json", Some("application/ld+json")), Err(Problem::BadRequest(_))));
        assert!(matches!(
            found("{not json", Some("Application/LD+JSON; charset=utf-8")),
            Err(Problem::BadRequest(_))
        ));
        assert_eq!(
            found("{not json", Some("application/json")).unwrap(),
            None,
            "the broker answers a plain bad body itself"
        );
        assert_eq!(found("", None).unwrap(), None);
    }

    #[test]
    fn a_batch_whose_entities_share_one_context_has_that_context() {
        let body = r#"[{"id": "a", "@context": "https://a.test/c"}, {"id": "b", "@context": "https://a.test/c"}]"#;

        assert_eq!(found(body, Some("application/ld+json")).unwrap(), Some("\"https://a.test/c\"".to_owned()));
    }

    #[test]
    fn a_batch_whose_entities_disagree_about_the_context_is_refused() {
        // Each entity is expanded by the broker under its own context; Libra has one.
        let body = r#"[{"id": "a", "@context": "https://a.test/c"}, {"id": "b", "@context": {"Vehicle": "https://evil.test/Public"}}]"#;

        assert!(matches!(found(body, Some("application/ld+json")), Err(Problem::BadRequest(_))));
    }

    #[test]
    fn a_batch_where_only_some_entities_carry_a_context_is_refused() {
        let body = r#"[{"id": "a", "@context": {"Vehicle": "https://evil.test/Public"}}, {"id": "b"}]"#;

        assert!(matches!(found(body, Some("application/ld+json")), Err(Problem::BadRequest(_))));
    }

    #[test]
    fn a_duplicate_context_inside_a_batch_entity_is_refused() {
        let body = r#"[{"@context": "https://a.test/c", "@context": "https://b.test/c"}]"#;

        assert!(matches!(found(body, Some("application/ld+json")), Err(Problem::BadRequest(_))));
    }

    #[test]
    fn a_batch_of_ids_has_no_context() {
        // `entityOperations/delete` takes a list of identifiers.
        assert_eq!(found(r#"["urn:ngsi-ld:A:1", "urn:ngsi-ld:A:2"]"#, None).unwrap(), None);
    }

    #[test]
    fn a_nested_context_member_is_refused() {
        let body = r#"{"id": "urn:a", "type": "Vehicle", "speed": {"type": "Property", "value": {"@context": {"x": "https://evil.test/x"}, "x": 1}}}"#;

        assert!(matches!(found(body, Some("application/ld+json")), Err(Problem::BadRequest(_))));
    }

    #[test]
    fn a_context_member_on_each_batch_entity_is_still_read() {
        let body = r#"[{"id": "a", "@context": "https://a.test/c"}, {"id": "b", "@context": "https://a.test/c"}]"#;

        assert!(found(body, Some("application/ld+json")).is_ok());
    }

    #[test]
    fn a_context_member_below_a_batch_entity_is_refused() {
        let body = r#"[{"id": "a", "@context": "https://a.test/c", "rel": {"type": "Relationship", "object": "urn:b", "entity": {"@context": "https://evil.test/c"}}}]"#;

        assert!(matches!(found(body, Some("application/ld+json")), Err(Problem::BadRequest(_))));
    }
}
