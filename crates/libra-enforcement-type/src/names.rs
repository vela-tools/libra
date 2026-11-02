//! Comparing the request's type names with the policy's, as IRIs.
//!
//! This is the whole point of the crate. `CompiledTypeRestriction` already holds IRIs, expanded
//! against the policy's own context when the policy loaded, so the policy's half is settled
//! at the model level. What is left is the other half: every type name in the request has to
//! be expanded against the *request's* context before it can be compared, and a name that cannot
//! be expanded has to be refused rather than treated as a type that simply matches nothing.
//!
//! A caller chooses their own `@context`, so `Vehicle` in a policy and `Vehicle` in a request are
//! the same type only if both mean the same IRI. Comparing the words is bypassable: a caller
//! sends the expanded IRI, or aliases the term, and a proxy matching strings sees something its
//! policy never mentioned.

use crate::error::TypeError;
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};
use libra_ngsi_ld_query::type_selection::TypeSelection;
use libra_policy_model::entity_type::CompiledTypeRestriction;

/// Expands one authored name against the request's context.
///
/// # Errors
///
/// Returns [`TypeError::Unresolvable`] if the name has no meaning in this context.
pub fn expand(name: &Term, context: &ResolvedContext) -> Result<ExpandedIri, TypeError> {
    // Cloned because the error owns the term and the request keeps its own.
    context.expand(name).ok_or_else(|| TypeError::Unresolvable { name: name.clone() })
}

/// Whether the policy allows the type this name refers to here.
///
/// # Errors
///
/// As [`expand`].
pub fn allows(restriction: &CompiledTypeRestriction, name: &Term, context: &ResolvedContext) -> Result<bool, TypeError> {
    Ok(restriction.allows(&expand(name, context)?))
}

/// Narrows a selection to the types the policy allows.
///
/// `Vehicle,Building` under a restriction of `Vehicle` asks for vehicles alone: a disjunction keeps the
/// allowed sides. A conjunction keeps nothing unless both its operands are allowed. `A;B` selects
/// entities carrying both types, so allowing `A` alone would in fact be enough, but "enough"
/// here rests on the broker agreeing about what a conjunction means, and an entity of a forbidden
/// type is not readable for also being of an allowed one.
///
/// # Errors
///
/// Returns [`TypeError::TypeDenied`], naming the first type outside the restriction, when nothing of the
/// selection remains, and [`TypeError::Unresolvable`] for a name the request's context cannot
/// expand.
pub fn narrow_selection(selection: &TypeSelection, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<TypeSelection, TypeError> {
    let mut first_forbidden = None;
    let narrowed = selection.narrowed(|name| -> Result<bool, TypeError> {
        let allowed = allows(restriction, name, context)?;
        if !allowed && first_forbidden.is_none() {
            // Cloned because the error owns the term and the request keeps its own.
            first_forbidden = Some(name.clone());
        }

        Ok(allowed)
    })?;

    match (narrowed, first_forbidden) {
        (Some(narrowed), _) => Ok(narrowed),
        (None, Some(entity_type)) => Err(TypeError::TypeDenied { entity_type }),
        // A selection loses every leaf only by having one refused, so this is never reached; it
        // names the selection whole rather than invent a type.
        (None, None) => Err(TypeError::TypeDenied {
            entity_type: Term::new(selection.to_string()),
        }),
    }
}

/// The types the policy allows.
///
/// # Errors
///
/// Returns [`TypeError::EmptyAllowList`] if it allows none. That is stated rather than worked
/// around: answering an empty allow list with an invented type name and hoping the broker matches
/// nothing would be a guess, dressed as a filter, about data the proxy has never seen.
pub fn allowed(restriction: &CompiledTypeRestriction) -> Result<&[ExpandedIri], TypeError> {
    if restriction.allowed().is_empty() {
        return Err(TypeError::EmptyAllowList);
    }

    Ok(restriction.allowed())
}

/// The types the policy allows, written as a selector a request can carry.
///
/// Expanded IRIs, joined with `,`. Two decisions worth stating: the comma form because every
/// broker understands it and the 1.8 connectives are newer, and IRIs rather than terms compacted
/// against the caller's context because an IRI means the same thing whatever context the broker
/// applies to it. Asking for the term would let the caller's own `@context` decide what Libra had
/// asked for.
///
/// # Errors
///
/// As [`allowed`].
pub fn allowed_selector(restriction: &CompiledTypeRestriction) -> Result<String, TypeError> {
    let types: Vec<&str> = allowed(restriction)?.iter().map(ExpandedIri::as_str).collect();

    Ok(types.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_policy_model::{entity_type::TypeRestriction, member_on_write::MemberOnWrite, policy::PolicyId};
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Building": "https://uri.fiware.org/ns/data-models#Building"
            }"#,
        )
        .expect("the test context should process")
    }

    fn restriction(allowed: &[&str]) -> CompiledTypeRestriction {
        TypeRestriction {
            allowed: allowed.iter().map(|name| Term::new(*name)).collect(),
            type_on_write: MemberOnWrite::Required,
        }
        .compile(&PolicyId::new("test").unwrap(), &context())
        .expect("the test restriction should compile")
    }

    fn selection(source: &str) -> TypeSelection {
        TypeSelection::parse(source).expect("the test selection should parse")
    }

    fn narrowed(source: &str, allowed: &[&str]) -> Result<String, TypeError> {
        narrow_selection(&selection(source), &restriction(allowed), &context()).map(|narrowed| narrowed.to_string())
    }

    #[test]
    fn an_alias_of_an_allowed_type_is_allowed() {
        // `Car` and `Vehicle` are one type under this context, and a proxy comparing words would
        // see a type its policy never mentioned.
        assert_eq!(narrowed("Car", &["Vehicle"]), Ok("Car".to_owned()));
    }

    #[test]
    fn sending_the_expanded_iri_reaches_the_same_comparison() {
        assert_eq!(
            narrowed("https://uri.fiware.org/ns/data-models#Vehicle", &["Vehicle"]),
            Ok("https://uri.fiware.org/ns/data-models#Vehicle".to_owned())
        );
    }

    #[test]
    fn a_type_outside_the_restriction_is_refused() {
        assert_eq!(
            narrowed("Building", &["Vehicle"]),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
    }

    #[test]
    fn a_disjunction_is_narrowed_to_its_allowed_types() {
        assert_eq!(narrowed("Vehicle,Building", &["Vehicle"]), Ok("Vehicle".to_owned()));
        assert_eq!(narrowed("Building|Car", &["Vehicle"]), Ok("Car".to_owned()));
        assert_eq!(narrowed("(Vehicle;Building)|Vehicle", &["Vehicle"]), Ok("Vehicle".to_owned()));
    }

    #[test]
    fn a_conjunction_with_a_forbidden_operand_is_refused_naming_it() {
        assert_eq!(
            narrowed("Vehicle;Building", &["Vehicle"]),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
        assert_eq!(
            narrowed("Building|Mystery;Building", &["Vehicle"]),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            }),
            "the first forbidden type is named"
        );
        assert_eq!(
            narrowed("Building;Mystery", &["Vehicle"]),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            }),
            "a later forbidden type does not displace the first"
        );
    }

    #[test]
    fn a_name_the_context_cannot_expand_is_refused_rather_than_assumed_to_match_nothing() {
        let bare = ResolvedContext::from_json(r#"{"Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle"}"#).expect("the context should process");

        assert_eq!(
            narrow_selection(&selection("Vehicle|Mystery"), &restriction(&["Vehicle"]), &bare),
            Err(TypeError::Unresolvable { name: Term::new("Mystery") })
        );
    }

    #[test]
    fn the_restriction_is_written_out_as_iris_the_callers_context_cannot_redefine() {
        assert_eq!(
            allowed_selector(&restriction(&["Vehicle", "Building"])).expect("the restriction should render"),
            "https://uri.fiware.org/ns/data-models#Building,https://uri.fiware.org/ns/data-models#Vehicle"
        );
    }

    #[test]
    fn a_restriction_that_allows_nothing_cannot_be_built_at_all() {
        // No empty allow list reaches enforcement. The model refuses it when a policy is read *and* when
        // one is compiled, so `allowed_selector`'s own guard is a floor rather than the check.
        let empty = TypeRestriction {
            allowed: Vec::new(),
            type_on_write: MemberOnWrite::Required,
        }
        .compile(&PolicyId::new("test").unwrap(), &context());

        assert!(empty.is_err(), "an empty allow list must not compile into a restriction");
    }
}
