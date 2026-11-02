//! Reading one member of a request body.
//!
//! RFC 8259 section 4 leaves the meaning of a repeated member name unpredictable. A member this
//! layer checks is the member the broker acts on only if there is exactly one of it, so a body that
//! repeats a member read here is refused as malformed rather than judged by one occurrence.

use crate::error::FilterError;
use jstrict::{Value, object::Object};

/// The one member of `object` called `name`, if it has one.
///
/// # Errors
///
/// Returns [`FilterError::MalformedBody`] when `object` names the member more than once.
pub(crate) fn member<'o>(object: &'o Object, name: &str) -> Result<Option<&'o Value>, FilterError> {
    object.get_unique(name).map_err(|_| FilterError::MalformedBody)
}

/// The one member of `object` called `name`, for editing in place, if it has one.
///
/// # Errors
///
/// Returns [`FilterError::MalformedBody`] when `object` names the member more than once.
pub(crate) fn member_mut<'o>(object: &'o mut Object, name: &str) -> Result<Option<&'o mut Value>, FilterError> {
    object.get_unique_mut(name).map_err(|_| FilterError::MalformedBody)
}

/// Removes the one member of `object` called `name`, if it has one.
///
/// # Errors
///
/// Returns [`FilterError::MalformedBody`] when `object` names the member more than once.
pub(crate) fn remove_member(object: &mut Object, name: &str) -> Result<(), FilterError> {
    object.remove_unique(name).map(drop).map_err(|_| FilterError::MalformedBody)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    fn object(value: Value) -> Object {
        value.into_object().expect("the test value is an object")
    }

    #[test]
    fn a_member_named_once_is_read_and_one_named_twice_is_refused() {
        let once = object(json!({ "q": "speed>40" }));
        let twice = object(json!({ "q": "speed>40", "q": "location!=null" }));

        assert_eq!(member(&once, "q"), Ok(Some(&json!("speed>40"))));
        assert_eq!(member(&once, "attrs"), Ok(None));
        assert_eq!(member(&twice, "q"), Err(FilterError::MalformedBody));
    }

    #[test]
    fn a_member_named_twice_is_neither_edited_nor_removed() {
        let mut twice = object(json!({ "pick": ["speed"], "pick": ["location"] }));

        assert_eq!(member_mut(&mut twice, "pick").err(), Some(FilterError::MalformedBody));
        assert_eq!(remove_member(&mut twice, "pick"), Err(FilterError::MalformedBody));
    }

    #[test]
    fn a_member_named_once_is_removed() {
        let mut once = object(json!({ "omit": ["speed"], "pick": ["location"] }));

        assert_eq!(remove_member(&mut once, "omit"), Ok(()));
        assert_eq!(remove_member(&mut once, "omit"), Ok(()), "an absent member is nothing to remove");
        assert_eq!(Value::Object(once), json!({ "pick": ["location"] }));
    }
}
