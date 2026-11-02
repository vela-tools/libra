//! Context source registrations under an attribute restriction.
//!
//! A registration (NGSI-LD 5.2.9) is not an entity, and its members are not attributes: its
//! `endpoint`, `information` and `scope` are what the registration is, and filtering them as if
//! they were attributes stripped every registration bare under a `pick` and refused every
//! registration write. What a registration says about attributes is in the `propertyNames` and
//! `relationshipNames` of its `RegistrationInfo` objects (5.2.10), and that is what this restriction
//! narrows: forbidden names are removed from an answer, and a write may name only allowed ones.

use crate::{
    document,
    error::FilterError,
    request::{allows, terms_in},
};
use axum::{extract::Request, http::header::ACCEPT_ENCODING, response::Response};
use jstrict::{Value, object::Object};
use libra_json_body::request_body::RequestBody;
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_ngsi_ld_operation::{operation::Mode, resource::Resource};
use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters};
use libra_ngsi_ld_query_layer::parsed::parameters;
use libra_ngsi_ld_registration::{
    attribute_names::{attribute_names, retain_names},
    registration::{Visibility, for_each_registration},
};
use libra_policy_model::attribute::CompiledAttributeRestriction;
use libra_response_json::{error::RewriteError, rewrite::rewrite};
use tracing::debug;

/// A registration the answer to a retrieval withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Withheld;

/// Checks a registration request before it is forwarded.
///
/// A read is sent without `Accept-Encoding`, because its answer is filtered and a compressed body
/// cannot be, and an `attrs` filter (NGSI-LD 5.10.2) naming a forbidden attribute is refused: which
/// registrations come back says which sources provide it. A write must name only allowed
/// attributes.
///
/// # Errors
///
/// Returns [`FilterError::AttributeDenied`] for a forbidden attribute,
/// [`FilterError::UnreadableRegistration`] and [`FilterError::MalformedBody`] for a body that
/// cannot be read as a registration, [`FilterError::Body`] for a write whose body no layer
/// above read or that is not JSON, [`FilterError::MalformedFilter`] for an unreadable `attrs`, and
/// [`FilterError::Unparsed`] for a read whose query no layer above parsed.
pub fn check_request(request: Request, mode: Mode, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<Request, FilterError> {
    let (mut parts, body) = request.into_parts();

    match mode {
        Mode::Read => {
            check_attribute_filter(parameters(&parts.extensions)?, restriction, context)?;
            parts.headers.remove(ACCEPT_ENCODING);
        }
        Mode::Write => match RequestBody::document_in(&parts)? {
            None => {}
            Some(Value::Object(registration)) => check_write(registration, restriction, context)?,
            Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_)) => return Err(FilterError::MalformedBody),
        },
    }

    Ok(Request::from_parts(parts, body))
}

/// Refuses an `attrs` filter that names a forbidden attribute.
fn check_attribute_filter(parameters: &QueryParameters, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let Some(named) = parameters.get(&ParameterName::ATTRS) else {
        return Ok(());
    };

    for term in terms_in(&Value::String(named.into()))? {
        if !allows(restriction, &term, context)? {
            return Err(FilterError::AttributeDenied { attribute: term });
        }
    }

    Ok(())
}

/// Refuses a registration, or an update fragment of one, that names a forbidden attribute.
///
/// # Errors
///
/// Returns [`FilterError::AttributeDenied`] for the first forbidden name,
/// [`FilterError::Unresolvable`] for a name the request's context cannot expand, and
/// [`FilterError::UnreadableRegistration`] for `information` that cannot be read.
pub fn check_write(registration: &Object, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    for name in attribute_names(registration)? {
        if !allows(restriction, &name, context)? {
            return Err(FilterError::AttributeDenied { attribute: name });
        }
    }

    Ok(())
}

/// Removes the forbidden attribute names from every registration of an answer.
///
/// A registration left registering nothing is withheld, and a retrieval (NGSI-LD 5.10.1) whose
/// registration is withheld is answered as one the broker does not hold, so a hidden registration
/// cannot be told from an absent one.
///
/// # Errors
///
/// Returns [`FilterError::Withheld`] when a retrieval's registration is withheld, and
/// [`FilterError::Unfilterable`] when the body cannot be read or a listing is answered with one
/// registration the restriction withholds.
pub async fn filter_response(
    response: Response,
    resource: &Resource,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
    max_body_bytes: usize,
) -> Result<Response, FilterError> {
    rewrite(response, max_body_bytes, |document, _media_type| {
        filter_document(document, restriction, context)
    })
    .await
    .map_err(|error| match error {
        RewriteError::Unreadable(unreadable) => FilterError::Unfilterable { reason: unreadable.reason() },
        RewriteError::Edit(Withheld) => withheld(resource),
    })
}

/// The refusal for a registration answer the restriction withholds whole.
///
/// Only a retrieval answers with one registration, and it answers 404 with the identifier the caller
/// sent: a 403 here would tell the caller that a registration they may not see exists.
fn withheld(resource: &Resource) -> FilterError {
    let Resource::ContextSourceRegistration { id } = resource else {
        return FilterError::Unfilterable {
            reason: "a registration listing was answered with a single registration",
        };
    };

    // Cloned because the error owns the identifier and the operation keeps its own.
    FilterError::Withheld { id: id.clone() }
}

/// Narrows the registrations of one answer document, or says the one it holds is withheld.
///
/// A registration whose `information` cannot be read cannot be shown to name only allowed
/// attributes, and is withheld. A name that does not expand under the request's context is removed.
fn filter_document(document: &mut Value, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), Withheld> {
    let mut removed = 0;
    let visibility = for_each_registration(document, |registration| {
        let visibility = match retain_names(registration, |name| document::allows(restriction, name.as_str(), context)) {
            Ok(retained) => {
                removed += retained.removed;
                retained.visibility
            }
            Err(_) => Visibility::Withhold,
        };

        Ok::<_, Withheld>(visibility)
    })?;

    debug!(removed, "filtered attribute names out of the registrations");

    match visibility {
        Visibility::Show => Ok(()),
        Visibility::Withhold => Err(Withheld),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use libra_jsonld_term_expansion::name::Term;
    use libra_ngsi_ld_operation::resource::ResourceId;
    use libra_policy_model::attribute::AttributeAction;
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(r#"{ "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/" }"#).expect("the test context should process")
    }

    fn restricted(action: AttributeAction, terms: &[&str]) -> CompiledAttributeRestriction {
        let context = context();

        CompiledAttributeRestriction::new(
            action,
            terms
                .iter()
                .map(|term| context.expand(&Term::new(*term)).expect("the term should expand"))
                .collect(),
        )
    }

    fn registration(property_names: &[&str]) -> Value {
        let property_names: Value = property_names.iter().map(|name| Value::String((*name).into())).collect::<Vec<_>>().into();

        json!({ "id": "urn:r:1", "type": "ContextSourceRegistration", "endpoint": "http://source.test",
            "information": [{ "entities": [{ "type": "Vehicle" }], "propertyNames": property_names }] })
    }

    #[test]
    fn a_listing_keeps_the_registration_structure_and_narrows_its_names() {
        let mut document = json!([registration(&["speed", "location"])]);

        assert_eq!(
            filter_document(&mut document, &restricted(AttributeAction::Pick, &["speed"]), &context()),
            Ok(())
        );
        assert_eq!(document, json!([registration(&["speed"])]));
    }

    #[test]
    fn a_retrieval_left_registering_nothing_is_withheld() {
        let mut document = registration(&["location"]);

        assert_eq!(
            filter_document(&mut document, &restricted(AttributeAction::Omit, &["location"]), &context()),
            Err(Withheld)
        );
    }

    #[test]
    fn a_withheld_retrieval_is_answered_as_an_absent_registration() {
        let id = ResourceId::new("urn:r:1");

        assert_eq!(withheld(&Resource::ContextSourceRegistration { id: id.clone() }), FilterError::Withheld { id });
        assert!(matches!(withheld(&Resource::ContextSourceRegistrations), FilterError::Unfilterable { .. }));
    }

    #[test]
    fn a_write_naming_a_forbidden_attribute_is_refused() {
        let omit_location = restricted(AttributeAction::Omit, &["location"]);
        let check = |document: &Value| check_write(document.as_object().expect("an object"), &omit_location, &context());

        assert_eq!(
            check(&registration(&["location"])),
            Err(FilterError::AttributeDenied {
                attribute: Term::new("location")
            })
        );
        assert_eq!(check(&registration(&["speed"])), Ok(()));
        assert_eq!(check(&json!({ "endpoint": "http://elsewhere.test" })), Ok(()), "a fragment naming no attribute");
    }

    #[test]
    fn an_attribute_filter_naming_a_forbidden_attribute_is_refused() {
        let omit_location = restricted(AttributeAction::Omit, &["location"]);
        let check = |query: &str| check_attribute_filter(&QueryParameters::parse(query).unwrap(), &omit_location, &context());

        assert_eq!(
            check("attrs=speed,location"),
            Err(FilterError::AttributeDenied {
                attribute: Term::new("location")
            })
        );
        assert_eq!(check("attrs=speed&type=Vehicle"), Ok(()));
    }
}
