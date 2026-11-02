//! The strict parse every JSON body Libra reads goes through, and the printing of what it narrowed.

use crate::{
    error::BodyError,
    nesting::{MAX_DEPTH, within},
};
use jstrict::{Print, Value, parse::parse_str_value};

/// Parses a JSON body, refusing one nested past [`MAX_DEPTH`] or repeating a member anywhere.
///
/// A repeated member is refused wherever it is, not only where Libra happens to read: a member
/// nothing checks today is one a later check would read differently from the broker.
///
/// # Errors
///
/// Returns the [`BodyError`] naming what is wrong with the body.
pub fn parse(bytes: &[u8]) -> Result<Value, BodyError> {
    let text = str::from_utf8(bytes).map_err(|_| BodyError::NotUtf8)?;

    if !within(text.as_bytes(), MAX_DEPTH) {
        return Err(BodyError::TooDeep { limit: MAX_DEPTH });
    }

    let value = parse_str_value(text).map_err(|_| BodyError::NotJson)?;
    refuse_repeated_members(&value)?;

    Ok(value)
}

/// The compact text of a value, as it is forwarded.
///
/// Members keep their order and numbers their lexical form, so what was not narrowed reaches the
/// broker as the caller wrote it.
#[must_use]
pub fn print(value: &Value) -> Vec<u8> {
    value.compact_print().to_string().into_bytes()
}

/// Walks every object of `value` and refuses the first that names a member twice.
fn refuse_repeated_members(value: &Value) -> Result<(), BodyError> {
    let mut pending = vec![value];

    while let Some(value) = pending.pop() {
        match value {
            Value::Object(object) => {
                if let Some(member) = first_repeated(object) {
                    return Err(BodyError::RepeatedMember { member });
                }

                pending.extend(object.iter().map(|entry| &entry.value));
            }
            Value::Array(items) => pending.extend(items.iter()),
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    Ok(())
}

/// The name of the first member `object` repeats, if it repeats one.
fn first_repeated(object: &jstrict::Object) -> Option<String> {
    if !object.contains_duplicate_keys() {
        return None;
    }

    object
        .entries()
        .iter()
        .find(|entry| object.get_unique(entry.key.as_str()).is_err())
        .map(|entry| entry.key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_body_within_the_limits_is_parsed() {
        let value = parse(br#"{"id":"urn:a","type":"Vehicle"}"#).unwrap();

        assert_eq!(value.as_object().map(jstrict::Object::len), Some(2));
    }

    #[test]
    fn a_repeated_member_at_the_top_is_refused() {
        assert_eq!(
            parse(br#"{"id":"urn:a","type":"Secret","type":"Vehicle"}"#),
            Err(BodyError::RepeatedMember { member: "type".to_owned() })
        );
    }

    #[test]
    fn a_repeated_member_deep_inside_is_refused() {
        assert_eq!(
            parse(br#"[{"speed":{"type":"Property","value":1,"value":2}}]"#),
            Err(BodyError::RepeatedMember { member: "value".to_owned() })
        );
    }

    #[test]
    fn the_same_member_in_two_objects_is_not_a_repetition() {
        assert!(parse(br#"[{"type":"A"},{"type":"B"}]"#).is_ok());
    }

    #[test]
    fn a_body_nested_past_the_limit_is_refused_before_it_is_parsed() {
        let text = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));

        assert_eq!(parse(text.as_bytes()), Err(BodyError::TooDeep { limit: MAX_DEPTH }));
    }

    #[test]
    fn a_body_nested_exactly_to_the_limit_is_parsed() {
        let text = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));

        assert!(parse(text.as_bytes()).is_ok());
    }

    #[test]
    fn a_body_that_is_not_utf8_is_refused_as_such() {
        assert_eq!(parse(&[b'"', 0xff, b'"']), Err(BodyError::NotUtf8));
    }

    #[test]
    fn a_body_that_is_not_json_is_refused_as_such() {
        assert_eq!(parse(b"{not json"), Err(BodyError::NotJson));
    }

    #[test]
    fn printing_keeps_member_order_and_the_lexical_form_of_numbers() {
        let text = r#"{"z":1.0,"a":1e400,"m":12345678901234567890123}"#;

        assert_eq!(String::from_utf8(print(&parse(text.as_bytes()).unwrap())).unwrap(), text);
    }
}
