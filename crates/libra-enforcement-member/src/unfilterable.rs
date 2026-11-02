//! Why an answer whose entities are judged on the way back could not be filtered.

use libra_ngsi_ld_entity_document::unwalkable::Unwalkable;
use libra_response_json::error::RewriteError;

/// The reason an answer could not be filtered, for the refusal that withholds it.
///
/// An answer is filtered entity by entity, so it is refused either because its body could not be
/// read or because its entities could not be walked.
#[must_use]
pub fn unfilterable_reason(error: &RewriteError<Unwalkable>) -> &'static str {
    match error {
        RewriteError::Unreadable(unreadable) => unreadable.reason(),
        RewriteError::Edit(unwalkable) => unwalkable.reason(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn an_unwalkable_answer_is_refused_with_the_reason_of_the_walk() {
        assert_eq!(
            unfilterable_reason(&RewriteError::Edit(Unwalkable::RepeatedMember)),
            Unwalkable::RepeatedMember.reason()
        );
        assert_eq!(
            unfilterable_reason(&RewriteError::Edit(Unwalkable::SoleEntityWithheld)),
            Unwalkable::SoleEntityWithheld.reason()
        );
    }
}
