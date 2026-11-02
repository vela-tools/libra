//! Withholding what a registration carries for its source.
//!
//! `contextSourceInfo` (NGSI-LD clause 5.2.9) is a list of key-value pairs the broker sends to the
//! registered source with every request it forwards there (clause 4.3.6.5). It is where a source's
//! credentials go, so a reader who may not write registrations is shown them without it.

use crate::registration::{Visibility, for_each_registration};
use jstrict::Value;
use std::convert::Infallible;

/// The member that carries a source's key-value pairs.
const SOURCE_INFO_MEMBER: &str = "contextSourceInfo";

/// Removes `contextSourceInfo` from every registration of a query or retrieval answer.
///
/// Every occurrence is removed, so a registration naming the member twice keeps neither.
pub fn withhold_source_info(document: &mut Value) {
    let shown: Result<Visibility, Infallible> = for_each_registration(document, |registration| {
        drop(registration.remove(SOURCE_INFO_MEMBER));
        Ok(Visibility::Show)
    });

    match shown {
        Ok(Visibility::Show | Visibility::Withhold) => {}
        Err(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{json, parse::parse_str_value};
    use pretty_assertions::assert_eq;

    #[test]
    fn source_info_is_removed_from_a_retrieved_registration() {
        let mut document = json!({
            "id": "urn:r:1",
            "type": "ContextSourceRegistration",
            "endpoint": "http://source.test",
            "contextSourceInfo": [{"key": "Authorization", "value": "Bearer secret"}]
        });

        withhold_source_info(&mut document);

        assert_eq!(
            document,
            json!({"id": "urn:r:1", "type": "ContextSourceRegistration", "endpoint": "http://source.test"})
        );
    }

    #[test]
    fn every_registration_of_a_listing_loses_it() {
        let mut document = json!([
            {"id": "urn:r:1", "contextSourceInfo": [{"key": "k", "value": "v"}]},
            {"id": "urn:r:2", "contextSourceInfo": [{"key": "k", "value": "v"}]}
        ]);

        withhold_source_info(&mut document);

        assert_eq!(document, json!([{"id": "urn:r:1"}, {"id": "urn:r:2"}]));
    }

    #[test]
    fn a_registration_without_source_info_is_unchanged() {
        let mut document = json!({"id": "urn:r:1", "endpoint": "http://source.test"});

        withhold_source_info(&mut document);

        assert_eq!(document, json!({"id": "urn:r:1", "endpoint": "http://source.test"}));
    }

    #[test]
    fn source_info_named_twice_is_removed_in_both_places() {
        // Built from text: the literal macro cannot write a member twice.
        let mut document = parse_str_value(r#"{"id":"urn:r:1","contextSourceInfo":[],"contextSourceInfo":[{"key":"k","value":"v"}]}"#).unwrap();

        withhold_source_info(&mut document);

        assert_eq!(document, json!({"id": "urn:r:1"}));
    }
}
