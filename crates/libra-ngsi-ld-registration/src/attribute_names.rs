//! The attribute names a registration registers, and narrowing them.

use crate::{
    error::Unreadable,
    registration::{ENTITIES_MEMBER, INFORMATION_MEMBER, InformationMut, REPEATED_MEMBER, Visibility, information_mut, objects, unique, unique_mut},
};
use jstrict::{Array, Object, Value};
use libra_jsonld_term_expansion::name::Term;
use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};

/// The members of a `RegistrationInfo` that list attribute names (NGSI-LD 5.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "camelCase")]
pub enum Names {
    /// `propertyNames`: the Properties the context source provides.
    PropertyNames,
    /// `relationshipNames`: the Relationships the context source provides.
    RelationshipNames,
}

impl Names {
    /// The member name, as NGSI-LD spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// What narrowing a registration's names left of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retained {
    /// How many names were removed.
    pub removed: usize,
    /// Whether anything the registration registers is left to show.
    pub visibility: Visibility,
}

/// Every attribute name a registration, or an update fragment of one, registers.
///
/// A registration without `information` registers no name; whether it may be written without one is
/// the broker's to decide.
///
/// # Errors
///
/// Returns [`Unreadable`] when `information` is not a list of objects, a name list holds anything
/// but names, or a member it reads is named twice.
pub fn attribute_names(registration: &Object) -> Result<Vec<Term>, Unreadable> {
    let Some(information) = objects(
        unique(registration, INFORMATION_MEMBER)?,
        "its information is not a list of RegistrationInfo objects",
    )?
    else {
        return Ok(Vec::new());
    };

    let mut names = Vec::new();

    for info in information {
        for list in Names::iter() {
            match unique(info, list.as_str())? {
                None | Some(Value::Null) => {}
                Some(Value::String(name)) => names.push(Term::new(name.as_str())),
                Some(Value::Array(items)) => {
                    for item in items {
                        names.push(item.as_str().map(Term::new).ok_or(UNREADABLE_NAMES)?);
                    }
                }
                Some(Value::Boolean(_) | Value::Number(_) | Value::Object(_)) => return Err(UNREADABLE_NAMES),
            }
        }
    }

    Ok(names)
}

/// Removes the attribute names `allows` refuses from every `RegistrationInfo` of a registration.
///
/// A name list left empty is removed, since NGSI-LD forbids empty arrays. A `RegistrationInfo`
/// that named attributes and is left naming none is removed whole: what is left of it would
/// register every attribute of its entities (NGSI-LD 5.2.10), which is more than it registered. One
/// that never named any attribute registers whole entities and is kept. A registration left with no
/// `RegistrationInfo` is withheld. A name that is not a string is not one `allows` can judge, and
/// is removed.
///
/// # Errors
///
/// Returns [`Unreadable`] when `information` is absent or not a list of objects, a name list is
/// neither a name nor a list, or a member it reads is named twice.
pub fn retain_names(registration: &mut Object, mut allows: impl FnMut(&Term) -> bool) -> Result<Retained, Unreadable> {
    let mut removed = 0;

    let visibility = match information_mut(registration)? {
        None | Some(InformationMut::Unreadable) => return Err(UNREADABLE_INFORMATION),
        Some(InformationMut::Single(info)) => {
            if retain_info_names(info, &mut allows, &mut removed)? == Visibility::Show {
                Visibility::Show
            } else {
                Visibility::Withhold
            }
        }
        Some(InformationMut::List(items)) => {
            let mut kept = Vec::with_capacity(items.len());

            for item in items.drain(..) {
                let Value::Object(mut info) = item else {
                    return Err(UNREADABLE_INFORMATION);
                };

                if retain_info_names(&mut info, &mut allows, &mut removed)? == Visibility::Show {
                    kept.push(Value::Object(info));
                }
            }

            let visibility = if kept.is_empty() { Visibility::Withhold } else { Visibility::Show };
            *items = Array::from(kept);

            visibility
        }
    };

    Ok(Retained { removed, visibility })
}

/// Narrows the name lists of one `RegistrationInfo`, and says whether it is left registering
/// anything.
fn retain_info_names(info: &mut Object, allows: &mut impl FnMut(&Term) -> bool, removed: &mut usize) -> Result<Visibility, Unreadable> {
    let mut named = false;
    let mut left = false;

    for list in Names::iter() {
        let keep = match unique_mut(info, list.as_str())? {
            None | Some(Value::Null) => continue,
            Some(Value::String(name)) => {
                let keep = allows(&Term::new(name.as_str()));
                *removed += usize::from(!keep);
                keep
            }
            Some(Value::Array(items)) => {
                let before = items.len();
                items.retain(|item| item.as_str().is_some_and(|name| allows(&Term::new(name))));
                *removed += before - items.len();
                !items.is_empty()
            }
            Some(Value::Boolean(_) | Value::Number(_) | Value::Object(_)) => return Err(UNREADABLE_NAMES),
        };

        named = true;
        if keep {
            left = true;
        } else {
            info.remove_unique(list.as_str()).map_err(|_| REPEATED_MEMBER)?;
        }
    }

    let registers_entities = unique(info, ENTITIES_MEMBER)?.is_some_and(|entities| !entities.is_null());

    Ok(match (named, left, registers_entities) {
        (true, true, _) | (false, _, true) => Visibility::Show,
        (true, false, _) | (false, _, false) => Visibility::Withhold,
    })
}

/// The refusal for an `information` member that is not a list of objects.
const UNREADABLE_INFORMATION: Unreadable = Unreadable {
    reason: "its information is not a list of RegistrationInfo objects",
};

/// The refusal for a name list that holds anything but names.
const UNREADABLE_NAMES: Unreadable = Unreadable {
    reason: "a propertyNames or relationshipNames member is not a list of names",
};

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    fn without_location(term: &Term) -> bool {
        term.as_str() != "location"
    }

    fn retain(mut registration: Value, allows: impl FnMut(&Term) -> bool) -> (Value, Result<Retained, Unreadable>) {
        let retained = retain_names(registration.as_object_mut().expect("the test registration is an object"), allows);

        (registration, retained)
    }

    #[test]
    fn a_forbidden_name_leaves_its_list() {
        let (registration, retained) = retain(
            json!({ "information": [{ "entities": [{ "type": "Vehicle" }], "propertyNames": ["speed", "location"] }] }),
            without_location,
        );

        assert_eq!(
            retained,
            Ok(Retained {
                removed: 1,
                visibility: Visibility::Show
            })
        );
        assert_eq!(
            registration,
            json!({ "information": [{ "entities": [{ "type": "Vehicle" }], "propertyNames": ["speed"] }] })
        );
    }

    #[test]
    fn a_list_left_empty_is_removed_while_another_list_keeps_the_info() {
        let (registration, retained) = retain(
            json!({ "information": [{ "propertyNames": ["location"], "relationshipNames": ["owner"] }] }),
            without_location,
        );

        assert_eq!(
            retained,
            Ok(Retained {
                removed: 1,
                visibility: Visibility::Show
            })
        );
        assert_eq!(registration, json!({ "information": [{ "relationshipNames": ["owner"] }] }));
    }

    #[test]
    fn an_info_left_naming_nothing_is_removed() {
        // `{entities: [Vehicle]}` alone would register every attribute of a vehicle, which is
        // more than the info registered.
        let (registration, retained) = retain(
            json!({ "information": [
                { "entities": [{ "type": "Vehicle" }], "propertyNames": ["location"] },
                { "entities": [{ "type": "Building" }] }
            ] }),
            without_location,
        );

        assert_eq!(
            retained,
            Ok(Retained {
                removed: 1,
                visibility: Visibility::Show
            })
        );
        assert_eq!(registration, json!({ "information": [{ "entities": [{ "type": "Building" }] }] }));
    }

    #[test]
    fn a_registration_left_with_no_info_is_withheld() {
        let (_, listed) = retain(json!({ "information": [{ "propertyNames": ["location"] }] }), without_location);
        let (_, single) = retain(json!({ "information": { "propertyNames": "location" } }), without_location);

        assert_eq!(
            listed,
            Ok(Retained {
                removed: 1,
                visibility: Visibility::Withhold
            })
        );
        assert_eq!(
            single,
            Ok(Retained {
                removed: 1,
                visibility: Visibility::Withhold
            })
        );
    }

    #[test]
    fn every_name_forbidden_removes_the_member() {
        let (registration, retained) = retain(
            json!({ "information": [{ "entities": [{ "type": "Vehicle" }], "propertyNames": ["location"], "relationshipNames": ["owner", 3] }] }),
            |term: &Term| term.as_str() == "owner",
        );

        assert_eq!(
            retained,
            Ok(Retained {
                removed: 2,
                visibility: Visibility::Show
            })
        );
        assert_eq!(
            registration,
            json!({ "information": [{ "entities": [{ "type": "Vehicle" }], "relationshipNames": ["owner"] }] })
        );
    }

    #[test]
    fn a_registration_whose_names_cannot_be_read_is_unreadable() {
        for registration in [
            json!({ "information": [{ "propertyNames": { "speed": 1 } }] }),
            json!({ "information": ["speed"] }),
            json!({ "information": 7 }),
            json!({ "endpoint": "http://source.test" }),
            json!({ "information": [{ "propertyNames": ["speed"], "propertyNames": ["location"] }] }),
            json!({ "information": [{ "entities": [], "entities": [], "propertyNames": ["speed"] }] }),
            json!({ "information": [], "information": [{ "propertyNames": ["speed"] }] }),
        ] {
            assert!(retain(registration.clone(), without_location).1.is_err(), "{registration}");
        }
    }

    #[test]
    fn every_registered_name_is_listed() {
        let registration = json!({ "information": [
            { "entities": [{ "type": "Vehicle" }], "propertyNames": ["speed", "location"] },
            { "relationshipNames": "owner" }
        ] });

        assert_eq!(
            attribute_names(registration.as_object().unwrap()),
            Ok(vec![Term::new("speed"), Term::new("location"), Term::new("owner")])
        );
        assert_eq!(attribute_names(json!({ "endpoint": "http://x.test" }).as_object().unwrap()), Ok(Vec::new()));
        assert!(attribute_names(json!({ "information": [{ "propertyNames": [1] }] }).as_object().unwrap()).is_err());
        assert_eq!(
            attribute_names(
                json!({ "information": [{ "relationshipNames": "a", "relationshipNames": "b" }] })
                    .as_object()
                    .unwrap()
            ),
            Err(REPEATED_MEMBER)
        );
    }
}
