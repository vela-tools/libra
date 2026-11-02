//! The query string the broker is made to read.
//!
//! Libra parses the query once, percent-decoded, and everything downstream of that parse is judged
//! on the decoded values. One byte in a query is ambiguous about what the next reader will see,
//! and it is repaired here rather than trusted.

use std::borrow::Cow;

/// The query string to forward, with every byte that outlives one reading encoded.
///
/// A literal `;` is a parameter separator for servlet containers and Netty-family decoders, which
/// split on it before percent-decoding, so it can hide a second `type` from a duplicate check. A
/// literal `+` is a space for form decoding, where percent-decoding reads it as itself. Both are
/// percent-encoded here; every other byte passes through untouched, and a sequence that is already
/// an escape is never re-encoded, so the bytes the broker decodes are exactly the values Libra
/// parsed.
pub(crate) fn forwardable(query: &str) -> Cow<'_, str> {
    let Some(offset) = query.bytes().position(|byte| matches!(byte, b'+' | b';')) else {
        return Cow::Borrowed(query);
    };

    let mut encoded = String::with_capacity(query.len());
    encoded.push_str(&query[..offset]);

    for character in query[offset..].chars() {
        match character {
            '+' => encoded.push_str("%2B"),
            ';' => encoded.push_str("%3B"),
            other => encoded.push(other),
        }
    }

    Cow::Owned(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn only_the_ambiguous_bytes_are_encoded() {
        assert_eq!(
            forwardable("type=Vehicle&q=a;b&timeAt=2026-01-01T00:00:00+01:00"),
            "type=Vehicle&q=a%3Bb&timeAt=2026-01-01T00:00:00%2B01:00"
        );
    }

    #[test]
    fn a_query_with_nothing_ambiguous_is_returned_borrowed() {
        let query = "type=Veh%20icle&q=speed>50";

        assert!(matches!(forwardable(query), Cow::Borrowed(_)), "a clean query must not be copied");
        assert_eq!(forwardable(query), query);
    }

    #[test]
    fn existing_escapes_are_never_re_encoded() {
        // `%2B` and a newly encoded `+` decode identically, which is the point: the broker decodes
        // one value either way. Re-encoding the `%` would produce a literal percent sign instead.
        assert_eq!(forwardable("q=%2B%3B%20"), "q=%2B%3B%20");
    }

    #[test]
    fn multibyte_characters_around_the_ambiguous_bytes_survive() {
        // The scan runs on bytes and the rewrite on characters; a value that mixes both must come
        // out byte-identical apart from the encoded semicolon.
        assert_eq!(forwardable("q=plüs;more"), "q=plüs%3Bmore");
    }
}
