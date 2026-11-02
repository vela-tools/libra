//! Finding the registrations of a document and deciding which of them are shown.

use crate::error::Unreadable;
use jstrict::{Array, Object, Value};

/// The member a registration lists what it registers in (NGSI-LD 5.2.9).
pub(crate) const INFORMATION_MEMBER: &str = "information";

/// The member of a `RegistrationInfo` that lists its entity selectors (NGSI-LD 5.2.10).
pub(crate) const ENTITIES_MEMBER: &str = "entities";

/// What a judge decides about one registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// The caller may see the registration, as the judge left it.
    Show,
    /// The caller may not see the registration, and it is removed.
    Withhold,
}

/// Calls `visit` on every registration of a document, and removes the ones it withholds.
///
/// A query (NGSI-LD 5.10.2) answers with an array of registrations and a retrieval (5.10.1) with
/// one. An array element that is not an object is not a registration anyone could judge, and is
/// removed. The returned visibility is the single registration's, so a retrieval whose registration is
/// withheld can be refused; an array is always shown, holding whatever was kept. A document that is
/// neither is withheld.
///
/// # Errors
///
/// Returns whatever `visit` fails with, as soon as it fails.
pub fn for_each_registration<E>(document: &mut Value, mut visit: impl FnMut(&mut Object) -> Result<Visibility, E>) -> Result<Visibility, E> {
    match document {
        Value::Array(items) => {
            let mut kept = Vec::with_capacity(items.len());

            for item in items.drain(..) {
                let Value::Object(mut registration) = item else {
                    continue;
                };

                if visit(&mut registration)? == Visibility::Show {
                    kept.push(Value::Object(registration));
                }
            }

            *items = Array::from(kept);

            Ok(Visibility::Show)
        }
        Value::Object(registration) => visit(registration),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Ok(Visibility::Withhold),
    }
}

/// Whether a registration, or an update fragment of one, carries an `information` member.
///
/// A fragment without one leaves what the registration registers as it was; `null` asks for the
/// member's removal, which changes it. A fragment naming it twice carries it too, and is refused by
/// whatever then reads it.
#[must_use]
pub fn carries_information(registration: &Object) -> bool {
    registration.contains_key(INFORMATION_MEMBER)
}

/// The `RegistrationInfo` objects of a registration, as a mutable list.
///
/// JSON-LD compaction writes a one-element array as its element, so a single object is read as a
/// list of one. `None` when the registration has no `information`.
///
/// # Errors
///
/// Returns [`Unreadable`] when the registration names `information` twice.
pub(crate) fn information_mut(registration: &mut Object) -> Result<Option<InformationMut<'_>>, Unreadable> {
    Ok(unique_mut(registration, INFORMATION_MEMBER)?.map(|information| match information {
        Value::Array(items) => InformationMut::List(items),
        Value::Object(info) => InformationMut::Single(info),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => InformationMut::Unreadable,
    }))
}

/// The `information` member of a registration, in whichever shape it arrived.
pub(crate) enum InformationMut<'registration> {
    /// An array, whose elements should each be a `RegistrationInfo`.
    List(&'registration mut Array),
    /// One `RegistrationInfo`, compacted out of its array.
    Single(&'registration mut Object),
    /// Something that is not a `RegistrationInfo` at all.
    Unreadable,
}

/// Reads a member that holds a list of objects, or one object compacted out of its list.
///
/// `None` when the member is absent or `null`. An empty list is unreadable: the specification
/// forbids empty arrays in a registration, and a list that names nothing cannot be shown to name
/// only what a restriction allows.
///
/// # Errors
///
/// Returns [`Unreadable`], with `reason`, when the member holds anything else, an empty array, or
/// an array element that is not an object.
pub(crate) fn objects<'document>(member: Option<&'document Value>, reason: &'static str) -> Result<Option<Vec<&'document Object>>, Unreadable> {
    let unreadable = Unreadable { reason };

    match member {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(vec![object])),
        Some(Value::Array(items)) if items.is_empty() => Err(unreadable),
        Some(Value::Array(items)) => items.iter().map(|item| item.as_object().ok_or(unreadable)).collect::<Result<_, _>>().map(Some),
        Some(Value::Boolean(_) | Value::Number(_) | Value::String(_)) => Err(unreadable),
    }
}

/// A member of a registration object, or `None` when it is absent.
///
/// # Errors
///
/// Returns [`Unreadable`] when the object names the member twice: RFC 8259 section 4 leaves the
/// meaning of a repeated name to each parser, so the occurrence read here may not be the one the
/// broker acts on.
pub(crate) fn unique<'object>(object: &'object Object, member: &str) -> Result<Option<&'object Value>, Unreadable> {
    object.get_unique(member).map_err(|_| REPEATED_MEMBER)
}

/// A member of a registration object, for editing in place, or `None` when it is absent.
///
/// # Errors
///
/// Returns [`Unreadable`] when the object names the member twice.
pub(crate) fn unique_mut<'object>(object: &'object mut Object, member: &str) -> Result<Option<&'object mut Value>, Unreadable> {
    object.get_unique_mut(member).map_err(|_| REPEATED_MEMBER)
}

/// The refusal for an object that names a member it is read by twice.
pub(crate) const REPEATED_MEMBER: Unreadable = Unreadable {
    reason: "it names one of its members twice",
};

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;
    use std::convert::Infallible;

    fn keep_named(document: &mut Value, name: &str) -> (Visibility, Vec<String>) {
        let mut visited = Vec::new();
        let visibility = for_each_registration(document, |registration| {
            let id = registration.get_unique("id").ok().flatten().and_then(Value::as_str).unwrap_or("-").to_owned();
            let visibility = if id == name { Visibility::Show } else { Visibility::Withhold };
            visited.push(id);
            Ok::<_, Infallible>(visibility)
        })
        .unwrap_or_else(|error| match error {});

        (visibility, visited)
    }

    #[test]
    fn one_registration_and_an_array_of_them_are_both_visited() {
        let mut single = json!({ "id": "a" });
        assert_eq!(keep_named(&mut single, "a"), (Visibility::Show, vec!["a".to_owned()]));
        assert_eq!(keep_named(&mut single, "b"), (Visibility::Withhold, vec!["a".to_owned()]));

        let mut listing = json!([{ "id": "a" }, { "id": "b" }, "not a registration"]);
        assert_eq!(keep_named(&mut listing, "b"), (Visibility::Show, vec!["a".to_owned(), "b".to_owned()]));
        assert_eq!(listing, json!([{ "id": "b" }]), "the withheld one and the non-object are gone");
    }

    #[test]
    fn a_document_that_is_no_registration_is_withheld() {
        assert_eq!(keep_named(&mut json!("x"), "x"), (Visibility::Withhold, Vec::new()));
    }

    #[test]
    fn a_failing_judge_stops_the_walk() {
        let result = for_each_registration(&mut json!([{ "id": "a" }]), |_| Err::<Visibility, _>("unjudgeable"));

        assert_eq!(result, Err("unjudgeable"));
    }

    #[test]
    fn information_is_told_apart_from_its_absence() {
        assert!(carries_information(json!({ "information": [] }).as_object().unwrap()));
        assert!(carries_information(json!({ "information": null }).as_object().unwrap()));
        assert!(!carries_information(json!({ "endpoint": "http://x.test" }).as_object().unwrap()));
    }

    #[test]
    fn a_repeated_information_member_is_unreadable() {
        let mut registration = json!({ "information": [], "information": [] });
        let object = registration.as_object_mut().unwrap();

        assert!(carries_information(object));
        assert_eq!(information_mut(object).err(), Some(REPEATED_MEMBER));
    }

    #[test]
    fn a_member_is_read_only_when_it_is_named_once() {
        let registration = json!({ "endpoint": "http://x.test", "id": "a", "id": "b" });
        let object = registration.as_object().unwrap();

        assert_eq!(unique(object, "endpoint"), Ok(Some(&json!("http://x.test"))));
        assert_eq!(unique(object, "information"), Ok(None));
        assert_eq!(unique(object, "id"), Err(REPEATED_MEMBER));
    }
}
