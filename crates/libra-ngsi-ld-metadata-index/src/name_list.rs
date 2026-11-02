//! Narrowing a list of names in a metadata-index document.

use crate::index_member::IndexMember;
use jstrict::{Array, Value};

/// Removes the names `allows` refuses from a name-list member, such as `typeList` or
/// `attributeNames`.
///
/// Returns how many names were removed, or `None` when the member holds something that is not a
/// list of names, or is named twice: a value this function cannot read is one it cannot show holds
/// only allowed names. An absent member holds no names and removes none. A name that is not a
/// string is not one `allows` can judge, and is removed.
#[must_use]
pub fn retain_names(document: &mut Value, member: IndexMember, allows: impl Fn(&str) -> bool) -> Option<usize> {
    match member.of_mut(document).ok()? {
        None => Some(0),
        Some(Value::Array(names)) => {
            let before = names.len();
            names.retain(|name| name.as_str().is_some_and(&allows));

            Some(before - names.len())
        }
        // JSON-LD compaction writes a one-element set as a bare value, so a list of one name can
        // arrive as a string.
        Some(single @ Value::String(_)) => {
            if single.as_str().is_some_and(&allows) {
                Some(0)
            } else {
                *single = Value::Array(Array::new());
                Some(1)
            }
        }
        Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Object(_)) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    fn only_vehicle(name: &str) -> bool {
        name == "Vehicle"
    }

    #[test]
    fn a_refused_name_and_anything_that_is_not_a_name_leave_the_list() {
        let mut document = json!({ "typeList": ["Vehicle", "Building", 7] });

        assert_eq!(retain_names(&mut document, IndexMember::TypeList, only_vehicle), Some(2));
        assert_eq!(document, json!({ "typeList": ["Vehicle"] }));
    }

    #[test]
    fn a_list_compacted_to_one_name_is_narrowed_too() {
        let mut allowed = json!({ "typeNames": "Vehicle" });
        let mut refused = json!({ "typeNames": "Building" });

        assert_eq!(retain_names(&mut allowed, IndexMember::TypeNames, only_vehicle), Some(0));
        assert_eq!(allowed, json!({ "typeNames": "Vehicle" }));
        assert_eq!(retain_names(&mut refused, IndexMember::TypeNames, only_vehicle), Some(1));
        assert_eq!(refused, json!({ "typeNames": [] }));
    }

    #[test]
    fn an_absent_member_removes_nothing() {
        let mut document = json!({ "type": "Attribute" });

        assert_eq!(retain_names(&mut document, IndexMember::TypeNames, only_vehicle), Some(0));
    }

    #[test]
    fn a_member_that_is_not_a_list_of_names_is_not_recognised() {
        for value in [json!(null), json!(true), json!(3), json!({ "Building": 1 })] {
            let mut document = json!({ "typeNames": value });

            assert_eq!(retain_names(&mut document, IndexMember::TypeNames, only_vehicle), None);
        }
    }

    #[test]
    fn a_name_list_named_twice_is_not_recognised_and_is_left_as_it_was() {
        let mut document = json!({ "typeNames": ["Vehicle"], "typeNames": ["Building"] });

        assert_eq!(retain_names(&mut document, IndexMember::TypeNames, only_vehicle), None);
        assert_eq!(document, json!({ "typeNames": ["Vehicle"], "typeNames": ["Building"] }));
    }
}
