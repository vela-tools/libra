//! How deep a JSON text nests, measured on the bytes before anything is built from them.
//!
//! Parsing and dropping a `jstrict::Value` do not recurse, but cloning and comparing one do, and so
//! does every walk Libra makes over a body. Measuring the text first refuses a body nested a million
//! levels deep without allocating a million containers to find out.

/// The deepest nesting of arrays and objects Libra reads.
///
/// An NGSI-LD document stays far below it: a normalized entity whose attribute holds a `GeoJSON`
/// `MultiPolygon` is about eight levels deep, and sub-attributes add two levels each.
pub const MAX_DEPTH: usize = 64;

/// Whether the arrays and objects of `text` nest no deeper than `limit`.
///
/// Brackets inside strings are not structure, so strings and their escapes are skipped. The text is
/// not otherwise validated: a malformed text is the parser's to refuse.
#[must_use]
pub fn within(text: &[u8], limit: usize) -> bool {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for &byte in text {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                (false, _) => {}
            }

            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > limit {
                    return false;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(levels: usize) -> String {
        format!("{}{}", "[".repeat(levels), "]".repeat(levels))
    }

    #[test]
    fn a_text_nested_exactly_to_the_limit_is_within_it() {
        assert!(within(nested(MAX_DEPTH).as_bytes(), MAX_DEPTH));
    }

    #[test]
    fn a_text_nested_one_level_past_the_limit_is_not() {
        assert!(!within(nested(MAX_DEPTH + 1).as_bytes(), MAX_DEPTH));
    }

    #[test]
    fn objects_and_arrays_count_alike() {
        let text = format!("{}{}", r#"{"a":"#.repeat(3), "}".repeat(3));

        assert!(within(text.as_bytes(), 3));
        assert!(!within(text.as_bytes(), 2));
    }

    #[test]
    fn brackets_inside_strings_are_not_structure() {
        let text = format!(r#"["{}"]"#, "[{".repeat(1000));

        assert!(within(text.as_bytes(), 1));
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        let text = r#"["a\"[[[[", 1]"#;

        assert!(within(text.as_bytes(), 1));
    }

    #[test]
    fn an_escaped_backslash_before_a_quote_ends_the_string() {
        let text = r#"["a\\", [[1]]]"#;

        assert!(within(text.as_bytes(), 3));
        assert!(!within(text.as_bytes(), 2));
    }

    #[test]
    fn a_million_levels_are_measured_without_building_them() {
        assert!(!within(nested(1_000_000).as_bytes(), MAX_DEPTH));
    }
}
