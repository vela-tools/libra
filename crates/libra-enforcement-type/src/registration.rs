//! Context source registrations under an entity type restriction.
//!
//! A registration (NGSI-LD 5.2.9) names the entity types a context source provides. A
//! type-restricted caller is shown a registration only when every type it registers is allowed: a
//! registration that also registers a forbidden type discloses that a source provides it, and one
//! whose `RegistrationInfo` names no entities registers its attributes for every type there is. A
//! write is held to the same rule, against the registration as written and, for an update or a
//! delete, against the registration as it exists.

use crate::{error::TypeError, names};
use axum::{extract::Request, http::header::ACCEPT_ENCODING, response::Response};
use jstrict::{Value, object::Object};
use libra_entity_preflight::{batch_write::StoredEntity, preflight::Preflight};
use libra_json_body::request_body::RequestBody;
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_ngsi_ld_operation::{
    operation::{Mode, Operation},
    resource::Resource,
};
use libra_ngsi_ld_registration::{
    coverage::{Coverage, entity_types},
    error::Unreadable,
    registration::{Visibility, carries_information, for_each_registration},
};
use libra_policy_model::entity_type::CompiledTypeRestriction;
use libra_response_json::{error::RewriteError, rewrite::rewrite};
use tracing::debug;

/// What a registration body is expected to be, phrased for the caller.
const EXPECTED: &str = "a context source registration";

/// A registration the answer to a retrieval withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Withheld;

/// Checks a registration request before it is forwarded.
///
/// A read is sent without `Accept-Encoding`, because its answer is filtered and a compressed body
/// cannot be. A create is checked against what it registers, and an update or a delete against the
/// registration that exists (pre-flighted, since the path names it by identifier alone) and, for
/// an update carrying `information`, against what it is about to register.
///
/// # Errors
///
/// Returns [`TypeError::Withheld`] for an addressed registration the broker does not hold or the
/// restriction does not cover, [`TypeError::TypeDenied`] or [`TypeError::RegistrationDenied`] for a
/// body registering what the restriction does not cover, [`TypeError::UnreadableRegistration`] and [`TypeError::MalformedBody`] for
/// a body that cannot be read as one, [`TypeError::Unenforceable`] when the pre-flight fails, and
/// [`TypeError::Body`] when no layer above read the body or it is not JSON.
pub async fn check_request(
    request: Request,
    operation: &Operation,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    preflight: &Preflight,
) -> Result<Request, TypeError> {
    let (mut parts, body) = request.into_parts();

    if matches!(operation.mode, Mode::Read) {
        parts.headers.remove(ACCEPT_ENCODING);
        return Ok(Request::from_parts(parts, body));
    }

    let document = RequestBody::document_in(&parts)?;

    if let Resource::ContextSourceRegistration { id } = &operation.resource {
        // Cloned because the error owns the identifier and the request keeps its own.
        let withheld = || TypeError::Withheld { id: id.clone() };
        // A registration the broker does not hold is refused exactly as one this caller may not
        // change, naming neither its types nor whether it exists.
        let existing = match StoredEntity::of(preflight.registration(id, &parts.headers).await)? {
            StoredEntity::Held(existing) => existing,
            StoredEntity::Absent => return Err(withheld()),
        };
        let Value::Object(existing) = &existing else {
            return Err(withheld());
        };

        // The broker's own document: one this layer cannot read is one it cannot show is allowed.
        check_coverage(&entity_types(existing).map_err(|_| withheld())?, restriction, context).map_err(|_| withheld())?;
        debug!(registration = %id, "the addressed registration registers allowed types only");
    }

    check_body(document, &operation.resource, restriction, context)?;

    Ok(Request::from_parts(parts, body))
}

/// Checks what a registration write registers.
///
/// A create registers what its body says. An update fragment without `information` leaves what the
/// registration registers as the pre-flight found it, and a delete carries no body at all.
fn check_body(document: Option<&Value>, resource: &Resource, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<(), TypeError> {
    let addressed = matches!(resource, Resource::ContextSourceRegistration { .. });

    let Some(document) = document else {
        return if addressed {
            Ok(())
        } else {
            Err(TypeError::MalformedBody { expected: EXPECTED })
        };
    };

    let Value::Object(registration) = document else {
        return Err(TypeError::MalformedBody { expected: EXPECTED });
    };

    if addressed && !carries_information(registration) {
        return Ok(());
    }

    check_coverage(&entity_types(registration)?, restriction, context)
}

/// Refuses a coverage the restriction does not include in full.
fn check_coverage(coverage: &Coverage, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<(), TypeError> {
    let Coverage::Types(types) = coverage else {
        return Err(TypeError::RegistrationDenied);
    };

    for name in types {
        if !names::allows(restriction, name, context)? {
            // Cloned because the error owns the term and the registration keeps its own.
            return Err(TypeError::TypeDenied { entity_type: name.clone() });
        }
    }

    Ok(())
}

/// Withholds from a registration answer every registration the restriction does not cover in full.
///
/// A retrieval (NGSI-LD 5.10.1) whose registration is withheld is answered as one the broker does
/// not hold, so a hidden registration cannot be told from an absent one.
///
/// # Errors
///
/// Returns [`TypeError::Withheld`] when a retrieval's registration is withheld, and
/// [`TypeError::Unfilterable`] when the body cannot be read or a listing is answered with one
/// registration the restriction withholds.
pub async fn filter_response(
    response: Response,
    resource: &Resource,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    max_body_bytes: usize,
) -> Result<Response, TypeError> {
    rewrite(response, max_body_bytes, |document, _media_type| {
        filter_document(document, restriction, context)
    })
    .await
    .map_err(|error| match error {
        RewriteError::Unreadable(unreadable) => TypeError::Unfilterable { reason: unreadable.reason() },
        RewriteError::Edit(Withheld) => withheld(resource),
    })
}

/// The refusal for a registration answer the restriction withholds whole.
///
/// Only a retrieval answers with one registration, and it answers 404 with the identifier the caller
/// sent: a 403 here would tell the caller that a registration they may not see exists.
fn withheld(resource: &Resource) -> TypeError {
    let Resource::ContextSourceRegistration { id } = resource else {
        return TypeError::Unfilterable {
            reason: "a registration listing was answered with a single registration",
        };
    };

    // Cloned because the error owns the identifier and the operation keeps its own.
    TypeError::Withheld { id: id.clone() }
}

/// Withholds from one answer document the registrations the restriction does not cover in full.
fn filter_document(document: &mut Value, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Result<(), Withheld> {
    let visibility = for_each_registration(document, |registration| Ok::<_, Withheld>(judge(registration, restriction, context)))?;

    match visibility {
        Visibility::Show => Ok(()),
        Visibility::Withhold => Err(Withheld),
    }
}

/// Shown when every type the registration registers, expanded under the request's context, is
/// allowed; withheld when one is not, when it registers every type, or when it cannot be read.
fn judge(registration: &Object, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Visibility {
    match entity_types(registration) {
        Ok(Coverage::Types(types)) if types.iter().all(|name| names::allows(restriction, name, context).unwrap_or(false)) => Visibility::Show,
        Ok(Coverage::Types(_) | Coverage::Every) | Err(Unreadable { .. }) => Visibility::Withhold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use libra_jsonld_term_expansion::name::Term;
    use libra_ngsi_ld_operation::resource::ResourceId;
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

    fn vehicles() -> CompiledTypeRestriction {
        TypeRestriction {
            allowed: vec![Term::new("Vehicle")],
            type_on_write: MemberOnWrite::Optional,
        }
        .compile(&PolicyId::new("test").unwrap(), &context())
        .expect("the test restriction should compile")
    }

    fn registering(entity_type: &str) -> Value {
        json!({ "id": format!("urn:r:{entity_type}"), "type": "ContextSourceRegistration", "endpoint": "http://source.test",
            "information": [{ "entities": [{ "type": entity_type }] }] })
    }

    fn attributes_only() -> Value {
        json!({ "id": "urn:r:speed", "type": "ContextSourceRegistration", "endpoint": "http://source.test",
            "information": [{ "propertyNames": ["speed"] }] })
    }

    #[test]
    fn a_listing_keeps_only_registrations_of_allowed_types() {
        let mut document = json!([registering("Vehicle"), registering("Building"), attributes_only(), registering("Car")]);

        assert_eq!(filter_document(&mut document, &vehicles(), &context()), Ok(()));
        assert_eq!(document, json!([registering("Vehicle"), registering("Car")]));
    }

    #[test]
    fn a_retrieval_of_a_forbidden_registration_is_withheld() {
        assert_eq!(filter_document(&mut registering("Building"), &vehicles(), &context()), Err(Withheld));
        assert_eq!(filter_document(&mut attributes_only(), &vehicles(), &context()), Err(Withheld));
        assert_eq!(filter_document(&mut registering("Vehicle"), &vehicles(), &context()), Ok(()));
    }

    #[test]
    fn a_withheld_retrieval_is_answered_as_an_absent_registration() {
        let id = ResourceId::new("urn:r:Building");

        assert_eq!(withheld(&Resource::ContextSourceRegistration { id: id.clone() }), TypeError::Withheld { id });
        assert!(matches!(withheld(&Resource::ContextSourceRegistrations), TypeError::Unfilterable { .. }));
    }

    #[test]
    fn a_registration_of_an_allowed_and_a_forbidden_type_is_withheld() {
        let mut both = json!({ "information": [{ "entities": [{ "type": ["Vehicle", "Building"] }] }] });

        assert_eq!(filter_document(&mut both, &vehicles(), &context()), Err(Withheld));
    }

    #[test]
    fn a_create_is_checked_against_what_it_registers() {
        let check = |document: &Value| check_body(Some(document), &Resource::ContextSourceRegistrations, &vehicles(), &context());

        assert_eq!(check(&registering("Vehicle")), Ok(()));
        assert_eq!(
            check(&registering("Building")),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
        assert_eq!(check(&attributes_only()), Err(TypeError::RegistrationDenied));
        assert!(matches!(
            check(&json!({ "endpoint": "http://source.test" })),
            Err(TypeError::UnreadableRegistration(_))
        ));
        assert_eq!(
            check_body(None, &Resource::ContextSourceRegistrations, &vehicles(), &context()),
            Err(TypeError::MalformedBody { expected: EXPECTED }),
            "a create carries the registration it creates"
        );
    }

    #[test]
    fn an_update_fragment_is_checked_only_when_it_changes_what_is_registered() {
        let addressed = Resource::ContextSourceRegistration {
            id: ResourceId::new("urn:r:1"),
        };
        let check = |document: &Value| check_body(Some(document), &addressed, &vehicles(), &context());

        assert_eq!(check(&json!({ "endpoint": "http://elsewhere.test" })), Ok(()));
        assert_eq!(
            check(&json!({ "information": [{ "entities": [{ "type": "Building" }] }] })),
            Err(TypeError::TypeDenied {
                entity_type: Term::new("Building")
            })
        );
        assert_eq!(check_body(None, &addressed, &vehicles(), &context()), Ok(()), "a delete carries no body");
    }
}
