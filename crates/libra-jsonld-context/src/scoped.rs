//! Refusing a context whose meaning depends on where a term is used.
//!
//! JSON-LD 1.1 lets a term definition carry a context of its own (section 4.1.8): a type-scoped
//! context applies inside every node of that type, a property-scoped one inside the value of that
//! property, and `@propagate` decides how far either reaches. Libra resolves one context per request
//! and expands every name against it, while a JSON-LD 1.1 broker applies the scoped one where it
//! applies: `"Vehicle": {"@id": "...", "@context": {"speed": "<a hidden attribute>"}}` has Libra
//! judging `speed` as the attribute it publicly names and the broker storing the hidden one. The
//! same mechanism could redefine `location` or `observedAt` inside one entity type. `@import` pulls in
//! a context nothing here reads before it is merged. Each of these is refused rather than modelled.

use jstrict::Value;

/// Keywords that make a term mean something different in different places.
const SCOPING_KEYWORDS: [&str; 2] = ["@context", "@propagate"];

/// Checks a context value, as it appears under `@context`: a reference, an inline definition, or an
/// array of either.
///
/// # Errors
///
/// Returns the reason a context is refused: a term definition carrying `@context` or
/// `@propagate`, or a context carrying `@propagate` or `@import`.
pub fn refuse_scoped(context: &Value) -> Result<(), &'static str> {
    match context {
        Value::Array(items) => items.iter().try_for_each(refuse_scoped),
        Value::Object(definitions) => definitions.iter().try_for_each(|entry| match (entry.key.as_str(), &entry.value) {
            ("@propagate", _) => Err("a context carrying @propagate applies differently in different places"),
            ("@import", _) => Err("a context carrying @import pulls in definitions that are not read before they apply"),
            (_, Value::Object(definition)) if SCOPING_KEYWORDS.iter().any(|keyword| definition.contains_key(*keyword)) => {
                Err("a term definition carrying its own @context or @propagate means different things in different places")
            }
            (_, Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_) | Value::Object(_)) => Ok(()),
        }),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

/// Checks a context document, as it is fetched or preloaded: an object whose `@context` member is
/// the context.
///
/// # Errors
///
/// As [`refuse_scoped`], and for a document that names `@context` twice.
pub fn refuse_scoped_document(document: &Value) -> Result<(), &'static str> {
    let Value::Object(document) = document else {
        // Not a context document at all; the processor refuses it with its own reason.
        return Ok(());
    };

    match document.get_unique("@context") {
        Ok(Some(context)) => refuse_scoped(context),
        Ok(None) => Ok(()),
        Err(_) => Err("the document names @context twice"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{json, parse::parse_str_value};
    use pretty_assertions::assert_eq;

    #[test]
    fn a_plain_context_is_accepted() {
        let context = json!(["https://example.test/ctx.jsonld", {"Vehicle": "https://example.test/Vehicle", "speed": {"@id": "https://example.test/speed", "@type": "@id"}}]);

        assert_eq!(refuse_scoped(&context), Ok(()));
    }

    #[test]
    fn a_type_scoped_context_is_refused() {
        let context = json!({"Vehicle": {"@id": "https://example.test/Vehicle", "@context": {"speed": "https://example.test/secret"}}});

        assert!(refuse_scoped(&context).is_err());
    }

    #[test]
    fn a_property_scoped_context_inside_an_array_is_refused() {
        let context = json!(["https://example.test/ctx.jsonld", {"address": {"@id": "https://example.test/address", "@context": {"city": "https://example.test/secret"}}}]);

        assert!(refuse_scoped(&context).is_err());
    }

    #[test]
    fn a_propagate_keyword_is_refused_on_a_term_or_a_context() {
        assert!(refuse_scoped(&json!({"Vehicle": {"@id": "https://example.test/Vehicle", "@propagate": true}})).is_err());
        assert!(refuse_scoped(&json!({"@propagate": false, "Vehicle": "https://example.test/Vehicle"})).is_err());
    }

    #[test]
    fn an_import_is_refused() {
        assert!(refuse_scoped(&json!({"@import": "https://example.test/other.jsonld"})).is_err());
    }

    #[test]
    fn a_fetched_document_is_checked_under_its_context_member() {
        let scoped = json!({"@context": {"Vehicle": {"@id": "https://example.test/Vehicle", "@context": {}}}});
        let plain = json!({"@context": {"Vehicle": "https://example.test/Vehicle"}});

        assert!(refuse_scoped_document(&scoped).is_err());
        assert_eq!(refuse_scoped_document(&plain), Ok(()));
    }

    #[test]
    fn a_fetched_document_naming_its_context_twice_is_refused() {
        let document = parse_str_value(r#"{"@context":{"a":"https://example.test/a"},"@context":{"b":"https://example.test/b"}}"#).unwrap();

        assert!(refuse_scoped_document(&document).is_err());
    }
}
