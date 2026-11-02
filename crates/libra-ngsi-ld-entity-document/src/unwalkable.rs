//! Why a response document could not be walked.

use jstrict::object::Duplicate;
use strum::{Display, IntoStaticStr};
use thiserror::Error;

/// Why a response document could not be walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error, Display, IntoStaticStr)]
pub enum Unwalkable {
    /// A linked member held something other than entity objects.
    #[strum(to_string = "a linked entity in the response is not an entity object")]
    NotAnEntity,
    /// The answer nests deeper than [`MAX_DEPTH`](crate::linked::MAX_DEPTH).
    #[strum(to_string = "the linked entities in the response nest too deeply")]
    TooDeep,
    /// A member the walk reads occurs more than once in one object.
    ///
    /// RFC 8259 section 4 leaves the meaning of a repeated member name unpredictable, so whichever
    /// occurrence the walk read, the caller might be shown the other.
    #[strum(to_string = "a member of the response appears more than once in one object")]
    RepeatedMember,
    /// An answer that should be a list of entities is a single entity, and the caller may not see
    /// it.
    ///
    /// The entity cannot be removed from a document it is the whole of, so the answer is withheld.
    #[strum(to_string = "the response is a single entity the caller may not see")]
    SoleEntityWithheld,
}

impl Unwalkable {
    /// The reason, for an error variant that carries it.
    #[must_use]
    pub fn reason(self) -> &'static str {
        self.into()
    }
}

/// The refusal of a member that occurs more than once, whichever two occurrences were found.
pub(crate) fn repeated<T>(_: Duplicate<T>) -> Unwalkable {
    Unwalkable::RepeatedMember
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_reason_is_the_message() {
        for unwalkable in [
            Unwalkable::NotAnEntity,
            Unwalkable::TooDeep,
            Unwalkable::RepeatedMember,
            Unwalkable::SoleEntityWithheld,
        ] {
            assert_eq!(unwalkable.reason(), unwalkable.to_string());
        }
    }
}
