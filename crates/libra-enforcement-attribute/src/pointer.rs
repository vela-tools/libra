//! Reading a member of a test document by JSON pointer (RFC 6901).

use jstrict::Value;

/// The value `pointer` addresses in `document`, or `None` when nothing, or more than one member,
/// is there.
///
/// Segments are not unescaped: no test document names a member with `~` or `/` in it.
pub(crate) fn at<'d>(document: &'d Value, pointer: &str) -> Option<&'d Value> {
    pointer.split('/').skip(1).try_fold(document, |value, segment| match value {
        Value::Object(object) => object.get_unique(segment).ok().flatten(),
        Value::Array(items) => segment.parse::<usize>().ok().and_then(|index| items.get(index)),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_pointer_walks_objects_and_arrays() {
        let document = json!({ "features": [{ "id": "a" }] });

        assert_eq!(at(&document, "/features/0/id"), Some(&json!("a")));
        assert_eq!(at(&document, "/features/1/id"), None);
        assert_eq!(at(&document, ""), Some(&document));
    }
}
