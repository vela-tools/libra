//! Checking and narrowing the attributes a request names.
//!
//! A request names attributes in its path, in the projections that narrow the answer (`attrs`,
//! `pick`), and in a write's body. The path and a write are refused when they name a hidden
//! attribute; a projection is narrowed to what the policy allows. What a request filters or ranks
//! by is judged in [`crate::filters`], and a `Query` body in [`crate::query_body`].

use crate::{error::FilterError, names::is_structural};
use jstrict::Value;
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters, projection::Projection};
use libra_policy_model::attribute::{AttributeAction, CompiledAttributeRestriction};

/// The selectors that narrow a response to named attributes.
pub(crate) const SELECTORS: [ParameterName; 2] = [ParameterName::ATTRS, ParameterName::PICK];

/// Whether the restriction allows the attribute a term names.
///
/// # Errors
///
/// Returns [`FilterError::Unresolvable`] if the term has no meaning under the request's context.
pub(crate) fn allows(restriction: &CompiledAttributeRestriction, term: &Term, context: &ResolvedContext) -> Result<bool, FilterError> {
    // Cloned because the error owns the term and the request keeps its own.
    let iri = context.expand(term).ok_or_else(|| FilterError::Unresolvable { name: term.clone() })?;

    Ok(restriction.allows(&iri))
}

/// Whether a projection (`attrs`, `pick`) may name `term`.
///
/// `id` and `type` are what a projection names to keep the entity readable (NGSI-LD clause 4.21
/// and the `pick` row of clause 6.4.3.2), not attributes: they are structure every restriction
/// leaves in place, and under the core context they are keyword aliases that expand to no IRI at
/// all. Every other name is an attribute, and the restriction decides.
fn projects(restriction: &CompiledAttributeRestriction, term: &Term, context: &ResolvedContext) -> Result<bool, FilterError> {
    if is_structural(term.as_str()) {
        return Ok(true);
    }

    allows(restriction, term, context)
}

/// Refuses a request that addresses an attribute it may not see.
///
/// # Errors
///
/// Returns [`FilterError::AttributeDenied`] if the path names a forbidden attribute, or
/// [`FilterError::Unresolvable`] if the name has no meaning under the request's context.
pub fn check_path_attribute(attribute: Option<&Term>, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    attribute.map_or(Ok(()), |attribute| check_attribute(attribute, restriction, context))
}

/// Refuses a request about one attribute the policy does not allow.
///
/// # Errors
///
/// Returns [`FilterError::AttributeDenied`] if it is forbidden, and [`FilterError::Unresolvable`]
/// if the name has no meaning under the request's context.
pub(crate) fn check_attribute(name: &Term, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    if allows(restriction, name, context)? {
        return Ok(());
    }

    // Cloned because the error owns the name while the caller's value is only borrowed.
    Err(FilterError::AttributeDenied { attribute: name.clone() })
}

/// The attribute names a selector member holds, written either as a list or as one string.
///
/// Each string is a projection (NGSI-LD clause 4.21), so `speed|brand` is two names. Only the
/// attributes of the projected entity itself are returned: a linked-entity term contributes the
/// Relationship it starts at, and the names inside it are filtered out of the linked entity in the
/// answer.
///
/// # Errors
///
/// Returns [`FilterError::MalformedFilter`] if a string does not fit the projection grammar.
pub(crate) fn terms_in(named: &Value) -> Result<Vec<Term>, FilterError> {
    let strings: Vec<&str> = match named {
        Value::Array(values) => values.iter().filter_map(Value::as_str).collect(),
        Value::String(value) => vec![value.as_str()],
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Object(_) => Vec::new(),
    };

    let mut terms = Vec::new();
    for value in strings {
        // Each name is cloned out of a projection that is dropped at the end of the iteration.
        terms.extend(projection_of(value)?.attributes().cloned());
    }

    Ok(terms)
}

/// Parses a projection, as a filter error.
fn projection_of(value: &str) -> Result<Projection, FilterError> {
    Projection::parse(value).map_err(|error| FilterError::MalformedFilter { reason: error.to_string() })
}

/// Narrows the request's attribute selectors to what the policy allows.
///
/// A caller that named no selector and a policy that picks produces an injected one; a caller that
/// named some has theirs reduced. `omit` is left alone: it can only remove more, never widen.
///
/// # Errors
///
/// Returns [`FilterError::NothingAllowed`] if nothing the caller asked for survives,
/// [`FilterError::MalformedFilter`] if a selector does not fit the projection grammar of NGSI-LD
/// clause 4.21, [`FilterError::Unresolvable`] if a name has no meaning under the request's context,
/// and [`FilterError::Inexpressible`] if an allowed attribute has no name under it.
pub fn narrow_selectors(parameters: &mut QueryParameters, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let mut narrowed_any = false;

    for selector in SELECTORS {
        let Some(value) = parameters.get(&selector) else {
            continue;
        };

        let narrowed = narrow_projection(value, restriction, context)?.ok_or(FilterError::NothingAllowed)?;
        parameters.set(selector, narrowed);
        narrowed_any = true;
    }

    if narrowed_any {
        return Ok(());
    }

    // The caller asked for everything. Under a pick, say what "everything" is, but never as an
    // empty parameter: `?attrs=` is read by brokers as no filter at all, which would turn an empty
    // allowed set into full access.
    if matches!(restriction.action(), AttributeAction::Pick) {
        if restriction.attributes().is_empty() {
            return Err(FilterError::NothingAllowed);
        }

        let names = restricted_names(restriction, context)?;
        parameters.set(ParameterName::ATTRS, names.join(","));
    }

    Ok(())
}

/// The names of the attributes a restriction lists, compacted under the request's context.
///
/// # Errors
///
/// Returns [`FilterError::Inexpressible`] if an attribute has no name that the context expands
/// back to it.
pub fn restricted_names(restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<Vec<String>, FilterError> {
    restriction
        .attributes()
        .iter()
        .map(|iri| context.compact(iri).map(|name| name.as_str().to_owned()).ok_or(FilterError::Inexpressible))
        .collect()
}

/// One projection (NGSI-LD clause 4.21) narrowed to the terms the policy allows.
///
/// `id` and `type` are kept, as `projects` says. A linked-entity term is kept when the
/// Relationship it starts at is allowed; the names inside it are filtered out of the linked
/// entity in the answer. `None` means no term survives.
///
/// # Errors
///
/// Returns [`FilterError::MalformedFilter`] if the value does not fit the projection grammar, and
/// [`FilterError::Unresolvable`] if a name has no meaning under the request's context.
pub fn narrow_projection(value: &str, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<Option<String>, FilterError> {
    let mut allowed = Vec::new();
    for term in projection_of(value)?.terms() {
        if projects(restriction, term.attribute(), context)? {
            allowed.push(term.to_string());
        }
    }

    Ok((!allowed.is_empty()).then(|| allowed.join(",")))
}

/// Refuses a write that carries an attribute the policy does not allow.
///
/// # Errors
///
/// Returns [`FilterError::AttributeDenied`] for a forbidden member, and
/// [`FilterError::Unresolvable`] if a member's name has no meaning under the request's context.
pub fn check_write(document: &Value, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    match document {
        Value::Array(entities) => {
            for entity in entities {
                check_write(entity, restriction, context)?;
            }
            Ok(())
        }
        Value::Object(entity) => {
            // Every occurrence of a repeated member is checked under its one name, so a repeated
            // member cannot carry a forbidden attribute past this check.
            for entry in entity {
                if is_structural(&entry.key) {
                    continue;
                }

                let term = Term::new(entry.key.as_str());
                if !allows(restriction, &term, context)? {
                    return Err(FilterError::AttributeDenied { attribute: term });
                }
            }
            Ok(())
        }
        // A batch delete sends an array of identifiers, not entities. Nothing to check.
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures::{context, omitting, picking, query},
        query_body::narrow_query_body,
    };
    use jstrict::json;
    use libra_jsonld_term_expansion::name::ExpandedIri;
    use pretty_assertions::assert_eq;

    /// A pick of `urn:example:speed` under a caller context that defines `urn` without marking it a
    /// prefix: JSON-LD 1.1 reads `urn:example:speed` as itself, JSON-LD 1.0 as the term `urn`
    /// followed by `example:speed`, so the IRI has no name both read the same way.
    fn inexpressible() -> (CompiledAttributeRestriction, ResolvedContext) {
        (
            CompiledAttributeRestriction::new(AttributeAction::Pick, vec![ExpandedIri::new("urn:example:speed")]),
            ResolvedContext::from_json(r#"{"urn": "https://elsewhere.test/x", "@s": "urn:example:speed"}"#).unwrap(),
        )
    }

    #[test]
    fn a_projection_naming_the_entitys_id_and_type_keeps_them() {
        // Under the core context `id` and `type` are keyword aliases that expand to no IRI. They are
        // entity structure, not attributes, and narrowing them as attributes refused the request.
        let core = ResolvedContext::from_json(r#"{"id": "@id", "type": "@type", "speed": "https://uri.fiware.org/ns/data-models#speed"}"#).unwrap();
        let mut parameters = query("pick=id,type,speed");

        narrow_selectors(&mut parameters, &picking(&["speed"]), &core).unwrap();

        assert_eq!(parameters.get(&ParameterName::PICK), Some("id,type,speed"));

        let mut body = json!({ "type": "Query", "pick": ["id", "type", "speed"] });
        assert_eq!(narrow_query_body(&mut body, &picking(&["speed"]), &core), Ok(()));
        assert_eq!(body, json!({ "type": "Query", "pick": ["id", "type", "speed"] }));
    }

    #[test]
    fn addressing_a_forbidden_attribute_by_path_is_refused() {
        let refused = check_path_attribute(Some(&Term::new("location")), &omitting(&["location"]), &context());

        assert_eq!(
            refused,
            Err(FilterError::AttributeDenied {
                attribute: Term::new("location")
            })
        );
    }

    #[test]
    fn a_deny_on_the_json_ld_1_0_expansion_cannot_be_bypassed_with_a_plain_prefix() {
        // `ex` names Secret without ending in a gen-delim, so a 1.0 processor would read `ex:ret`
        // as Secret where 1.1 reads no compact IRI at all. Expansion refuses the term rather than
        // answer a question whose meaning depends on the reader, and the request fails closed:
        // the one answer that must never come out of this is a bare "allowed".
        let context = ResolvedContext::from_json(r#"{"ex": "https://host/Sec"}"#).expect("the test context should process");

        assert_eq!(
            allows(&omitting(&["Secret"]), &Term::new("ex:ret"), &context),
            Err(FilterError::Unresolvable { name: Term::new("ex:ret") })
        );
    }

    #[test]
    fn a_named_selector_is_reduced_to_what_is_allowed() {
        let mut parameters = query("attrs=speed,location");

        narrow_selectors(&mut parameters, &omitting(&["location"]), &context()).expect("it should narrow");

        assert_eq!(parameters.get(&ParameterName::ATTRS), Some("speed"));
    }

    #[test]
    fn asking_only_for_forbidden_attributes_is_refused_rather_than_emptied() {
        // `?attrs=` is read by brokers as no filter at all, so an emptied selector would turn a request
        // for exactly the hidden attributes into a request for everything.
        let mut parameters = query("attrs=location");
        let refused = narrow_selectors(&mut parameters, &omitting(&["location"]), &context());

        assert_eq!(refused, Err(FilterError::NothingAllowed));
    }

    #[test]
    fn a_pick_says_what_it_allows_when_the_caller_asked_for_everything() {
        let mut parameters = query("type=Vehicle");

        narrow_selectors(&mut parameters, &picking(&["speed", "brand"]), &context()).expect("it should narrow");

        let selected: Vec<&str> = parameters
            .get(&ParameterName::ATTRS)
            .map(|value| value.split(',').collect())
            .unwrap_or_default();

        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&"speed"));
        assert!(selected.contains(&"brand"));
    }

    #[test]
    fn a_pick_whose_attribute_has_no_name_under_the_callers_context_is_refused_rather_than_forwarded() {
        let (restriction, context) = inexpressible();
        let mut parameters = query("type=Vehicle");

        assert_eq!(narrow_selectors(&mut parameters, &restriction, &context), Err(FilterError::Inexpressible));
        assert_eq!(parameters.get(&ParameterName::ATTRS), None);
    }

    #[test]
    fn a_pick_that_allows_nothing_refuses_rather_than_emitting_an_empty_selector() {
        let mut parameters = query("type=Vehicle");

        assert_eq!(narrow_selectors(&mut parameters, &picking(&[]), &context()), Err(FilterError::NothingAllowed));
        assert_eq!(parameters.get(&ParameterName::ATTRS), None);
    }

    #[test]
    fn an_omit_leaves_the_query_alone_and_relies_on_the_response_being_filtered() {
        // There is no way to write "everything except these" as an `attrs` list without knowing
        // every attribute the broker holds, which the proxy does not.
        let mut parameters = query("type=Vehicle");

        narrow_selectors(&mut parameters, &omitting(&["location"]), &context()).expect("it should narrow");

        assert_eq!(parameters.get(&ParameterName::ATTRS), None);
    }

    #[test]
    fn a_write_carrying_a_forbidden_attribute_is_refused() {
        let document = json!({ "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle", "location": { "type": "GeoProperty" } });

        assert!(check_write(&document, &omitting(&["location"]), &context()).is_err());
    }

    #[test]
    fn a_batch_of_writes_is_checked_entity_by_entity() {
        let document = json!([
            { "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle", "speed": 1 },
            { "id": "urn:ngsi-ld:Vehicle:2", "type": "Vehicle", "location": 2 }
        ]);

        assert!(check_write(&document, &omitting(&["location"]), &context()).is_err());
    }

    #[test]
    fn a_batch_delete_of_identifiers_carries_no_attributes_to_check() {
        // The body is an array of strings, not entities. Read as entities with no attributes, they
        // would refuse the whole request.
        let document = json!(["urn:ngsi-ld:Vehicle:1", "urn:ngsi-ld:Vehicle:2"]);

        assert!(check_write(&document, &picking(&["speed"]), &context()).is_ok());
    }

    #[test]
    fn structural_members_never_make_a_write_forbidden() {
        // `id`, `type` and `@context` appear in every write. Treating them as attributes would make a
        // pick policy refuse every create that does not list them.
        let document = json!({ "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle", "@context": [], "speed": 1 });

        assert!(check_write(&document, &picking(&["speed"]), &context()).is_ok());
    }

    #[test]
    fn a_name_the_context_cannot_resolve_is_refused_rather_than_assumed_harmless() {
        let bare = ResolvedContext::from_json(r#"{"speed": "https://uri.fiware.org/ns/data-models#speed"}"#).expect("the context should process");
        let refused = check_path_attribute(Some(&Term::new("@id")), &omitting(&["location"]), &bare);

        assert!(matches!(refused, Err(FilterError::Unresolvable { .. })), "{refused:?}");
    }

    #[test]
    fn a_write_that_repeats_a_forbidden_attribute_is_refused_whichever_occurrence_is_read() {
        let document = json!({ "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle", "speed": 1, "location": 2, "location": 3 });

        assert!(check_write(&document, &omitting(&["location"]), &context()).is_err());
    }
}
