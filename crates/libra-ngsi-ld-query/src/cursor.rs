//! The cursor the hand-written selector parsers advance over their source.
//!
//! The `q` grammar (NGSI-LD clause 4.9), the entity type selection language (clause 4.17) and the
//! attribute projection language (clause 4.21) are each read by a small recursive-descent parser.
//! They step over characters the same way, bound their recursion by the same depth, and report a
//! failure at the offset they stopped at, so that much is held once, here.

use crate::{error::QueryError, parameter_name::ParameterName};

/// How deeply a selector may nest: parentheses, or the braces of a linked-entity path or term.
///
/// The parsers, the renderers and the compiler-generated drop glue all recurse over the tree, and a
/// selector arrives before anything has been authorised: an unbounded depth is a stack overflow that
/// aborts the whole process rather than failing one request.
pub(crate) const MAX_DEPTH: usize = 32;

/// Which grammar a cursor reads, which decides the error a parse failure is reported as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Grammar {
    /// The query language of a `q` or `scopeQ` expression, read from the named parameter.
    Filter(ParameterName),
    /// The entity type selection language.
    TypeSelection,
    /// The attribute projection language.
    Projection,
}

/// A position in the source of one selector.
#[derive(Debug)]
pub(crate) struct Cursor<'source> {
    source: &'source str,
    offset: usize,
    grammar: Grammar,
}

impl<'source> Cursor<'source> {
    /// Starts at the beginning of `source`, read as `grammar`.
    pub(crate) const fn new(source: &'source str, grammar: Grammar) -> Cursor<'source> {
        Cursor { source, offset: 0, grammar }
    }

    /// The byte offset reached so far.
    pub(crate) const fn offset(&self) -> usize {
        self.offset
    }

    /// The source not yet consumed.
    pub(crate) fn rest(&self) -> &'source str {
        &self.source[self.offset..]
    }

    /// The source consumed since `start`, a byte offset this cursor reported earlier.
    pub(crate) fn since(&self, start: usize) -> &'source str {
        &self.source[start..self.offset]
    }

    /// The next character, without consuming it.
    pub(crate) fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// Consumes `bytes` bytes of the rest, which must end on a character boundary.
    pub(crate) const fn advance(&mut self, bytes: usize) {
        self.offset += bytes;
    }

    /// Consumes `expected` if it is next, and answers whether it was.
    pub(crate) fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.advance(expected.len_utf8());
            return true;
        }

        false
    }

    /// Consumes characters up to the first one in `terminators`, or the end, and returns them.
    pub(crate) fn take_until(&mut self, terminators: &[char]) -> &'source str {
        let start = self.offset;

        while let Some(character) = self.peek().filter(|character| !terminators.contains(character)) {
            self.advance(character.len_utf8());
        }

        self.since(start)
    }

    /// Fails unless the whole source has been consumed.
    pub(crate) fn expect_end(&self) -> Result<(), QueryError> {
        if self.offset == self.source.len() {
            return Ok(());
        }

        Err(self.error("unexpected trailing input"))
    }

    /// A parse failure of this cursor's grammar, pointing at the current offset.
    pub(crate) fn error(&self, reason: &str) -> QueryError {
        let offset = self.offset;
        let reason = reason.to_owned();

        match &self.grammar {
            Grammar::Filter(parameter) => QueryError::MalformedFilter {
                // Cloned because the error owns the name; a static name is borrowed, not copied.
                parameter: parameter.clone(),
                offset,
                reason,
            },
            Grammar::TypeSelection => QueryError::MalformedTypeSelection { offset, reason },
            Grammar::Projection => QueryError::MalformedProjection { offset, reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cursor::{Cursor, Grammar},
        error::QueryError,
        parameter_name::ParameterName,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn eating_consumes_only_the_expected_character() {
        let mut cursor = Cursor::new("ab", Grammar::Projection);

        assert!(!cursor.eat('b'));
        assert!(cursor.eat('a'));
        assert_eq!(cursor.offset(), 1);
        assert_eq!(cursor.peek(), Some('b'));
    }

    #[test]
    fn taking_stops_at_a_terminator_and_steps_over_multibyte_characters() {
        let mut cursor = Cursor::new("äb|c", Grammar::TypeSelection);

        assert_eq!(cursor.take_until(&['|']), "äb");
        assert_eq!(cursor.rest(), "|c");
    }

    #[test]
    fn the_end_is_expected_only_once_everything_is_consumed() {
        let mut cursor = Cursor::new("a", Grammar::Projection);

        assert_eq!(
            cursor.expect_end(),
            Err(QueryError::MalformedProjection {
                offset: 0,
                reason: "unexpected trailing input".to_owned(),
            })
        );
        assert!(cursor.eat('a'));
        assert_eq!(cursor.expect_end(), Ok(()));
    }

    #[test]
    fn a_failure_is_reported_as_the_grammar_being_read() {
        let mut cursor = Cursor::new("ab", Grammar::Filter(ParameterName::SCOPE_Q));
        cursor.advance(1);

        assert_eq!(
            cursor.error("expected"),
            QueryError::MalformedFilter {
                parameter: ParameterName::SCOPE_Q,
                offset: 1,
                reason: "expected".to_owned(),
            }
        );
        assert_eq!(
            Cursor::new("", Grammar::TypeSelection).error("expected"),
            QueryError::MalformedTypeSelection {
                offset: 0,
                reason: "expected".to_owned(),
            }
        );
    }
}
