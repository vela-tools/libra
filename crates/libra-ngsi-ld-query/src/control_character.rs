//! The one character class no query grammar admits.
//!
//! No production of the query language (ETSI GS CIM 009 v1.9.1 clause 4.9), the entity type
//! selection language (clause 4.17), the attribute projection language (clause 4.21) or the entity
//! ordering language (clause 4.23.3) admits a control character. A short name is letters, digits
//! and `_` (clause 4.6.2), an IRI excludes them (RFC 3987 section 2.2), and a quoted value is a
//! JSON string, which escapes them (RFC 8259 section 7). One that arrives anyway is refused before
//! the expression is read: a broker may strip it, stop at it or refuse it, so the name Libra judged
//! need not be the name the broker acts on, and it would reach the log as written.

use crate::error::QueryError;

/// Refuses `source` if it holds a control character anywhere.
///
/// # Errors
///
/// Returns [`QueryError::ControlCharacter`] with the byte offset of the first one.
pub(crate) fn refuse_control_characters(source: &str) -> Result<(), QueryError> {
    match source.char_indices().find(|(_, character)| character.is_control()) {
        Some((offset, _)) => Err(QueryError::ControlCharacter { offset }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        control_character::refuse_control_characters,
        error::QueryError,
        filter::Filter,
        parameter_name::ParameterName,
        projection::Projection,
        selector::expand_list,
        type_selection::TypeSelection,
    };
    use libra_jsonld_term_expansion::resolved::ResolvedContext;
    use pretty_assertions::assert_eq;

    #[test]
    fn an_expression_of_names_iris_and_quoted_values_passes() {
        assert_eq!(
            refuse_control_characters(r#"speed>50;brandName=="Mercedes";https://example.test/ns#höhe<3"#),
            Ok(())
        );
    }

    #[test]
    fn every_control_character_is_refused_at_its_offset() {
        for (source, offset) in [
            ("a\u{0}b", 1),
            ("speed\u{1e}x==1", 5),
            ("ab\tc", 2),
            ("ab\nc", 2),
            ("ab\u{7f}", 2),
            ("é\u{85}", 2),
        ] {
            assert_eq!(refuse_control_characters(source), Err(QueryError::ControlCharacter { offset }), "{source:?}");
        }
    }

    #[test]
    fn the_refusal_repeats_no_part_of_the_expression() {
        let refused = refuse_control_characters("secretName\u{0}").unwrap_err().to_string();

        assert!(!refused.contains("secretName"), "{refused}");
    }

    #[test]
    fn every_selector_grammar_refuses_a_control_character_before_reading_it() {
        let refused = Err(QueryError::ControlCharacter { offset: 5 });
        let context = ResolvedContext::from_json(r#"{"@vocab": "https://example.test/"}"#).unwrap();

        assert_eq!(Filter::parse("speed\u{1e}x==1").map(drop), refused);
        assert_eq!(Projection::parse("speed\u{0},brand").map(drop), refused);
        assert_eq!(TypeSelection::parse("Truck\u{0}|Car").map(drop), refused);
        assert_eq!(expand_list(&ParameterName::ATTRS, "speed\u{1b}", &context).map(drop), refused);
    }

    #[test]
    fn a_control_character_inside_a_quoted_value_is_refused_too() {
        // A quoted value is a JSON string, and RFC 8259 section 7 escapes every control character.
        assert_eq!(Filter::parse("name==\"a\u{7}b\"").map(drop), Err(QueryError::ControlCharacter { offset: 8 }));
    }
}
