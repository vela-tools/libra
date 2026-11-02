//! Context source registrations under a scope restriction.
//!
//! A registration (NGSI-LD 5.2.9) carries a `scope` member of its own: the scopes its context source
//! provides entities in. A scope-restricted caller sees a registration the way it sees an entity
//! read by identifier: shown when any of its scopes is allowed, with the others removed, and
//! withheld when none is or when it has no scope at all. A write is held to the rules an entity
//! write is: what a create declares, and for an update or a delete the registration that exists,
//! must be inside the restriction.

use crate::{
    document::{check_entity, check_existing},
    error::ScopeError,
    filtering::judge_entity,
};
use axum::{extract::Request, http::header::ACCEPT_ENCODING, response::Response};
use jstrict::Value;
use libra_enforcement_member::location::Location;
use libra_entity_preflight::preflight::Preflight;
use libra_json_body::request_body::RequestBody;
use libra_ngsi_ld_entity_document::{entities::Entity, linked::Visibility as EntityVisibility};
use libra_ngsi_ld_operation::{
    operation::{Mode, Operation},
    resource::Resource,
};
use libra_ngsi_ld_registration::registration::{Visibility, for_each_registration};
use libra_policy_model::{
    member_on_write::MemberOnWrite,
    scope::{ScopePattern, ScopeRestriction},
};
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
/// cannot be. A create is held to `scope-on-write` and must declare only allowed scopes.
/// An update or a delete is judged by the registration that exists (pre-flighted, every scope of
/// it allowed) and an update's own `scope`, if it carries one, must be allowed too.
///
/// # Errors
///
/// Returns [`ScopeError::ScopeDenied`], [`ScopeError::MissingScope`] or [`ScopeError::Withheld`]
/// for a registration outside the restriction,
/// [`ScopeError::MalformedBody`] for a body that is not a registration, [`ScopeError::Unenforceable`]
/// when the pre-flight fails, and [`ScopeError::Body`] when no layer above read the body or it is not
/// JSON.
pub async fn check_request(request: Request, operation: &Operation, restriction: &ScopeRestriction, preflight: &Preflight) -> Result<Request, ScopeError> {
    let (mut parts, body) = request.into_parts();

    if matches!(operation.mode, Mode::Read) {
        parts.headers.remove(ACCEPT_ENCODING);
        return Ok(Request::from_parts(parts, body));
    }

    let document = RequestBody::document_in(&parts)?;

    let on_write = if let Resource::ContextSourceRegistration { id } = &operation.resource {
        check_existing(preflight.registration(id, &parts.headers).await, restriction, Mode::Write, id)?;
        debug!(registration = %id, "the addressed registration lies inside the allowed scopes");

        // The pre-flight met the requirement; an update that names no scope keeps the one found.
        MemberOnWrite::Optional
    } else {
        restriction.scope_on_write
    };

    match (document, on_write) {
        (Some(document), MemberOnWrite::Required | MemberOnWrite::Optional) => check_entity(document, restriction, on_write, &Location::Registration)?,
        // A delete carries no body, and its registration was judged above.
        (None, MemberOnWrite::Optional) => {}
        (None, MemberOnWrite::Required) => return Err(ScopeError::MalformedBody { expected: EXPECTED }),
    }

    Ok(Request::from_parts(parts, body))
}

/// Reduces every registration of an answer to its allowed scopes, and withholds those with none.
///
/// A retrieval (NGSI-LD 5.10.1) whose registration is withheld is answered as one the broker does
/// not hold, so a hidden registration cannot be told from an absent one.
///
/// # Errors
///
/// Returns [`ScopeError::Withheld`] when a retrieval's registration is withheld, and
/// [`ScopeError::ResponseUnfilterable`] when the body cannot be read or a listing is answered with
/// one registration the restriction withholds.
pub async fn filter_response(response: Response, resource: &Resource, allowed: &[ScopePattern], max_body_bytes: usize) -> Result<Response, ScopeError> {
    rewrite(response, max_body_bytes, |document, _media_type| filter_document(document, allowed))
        .await
        .map_err(|error| match error {
            RewriteError::Unreadable(unreadable) => ScopeError::ResponseUnfilterable { reason: unreadable.reason() },
            RewriteError::Edit(Withheld) => withheld(resource),
        })
}

/// The refusal for a registration answer the restriction withholds whole.
///
/// Only a retrieval answers with one registration, and it answers 404 with the identifier the caller
/// sent: a 403 here would tell the caller that a registration they may not see exists.
fn withheld(resource: &Resource) -> ScopeError {
    let Resource::ContextSourceRegistration { id } = resource else {
        return ScopeError::ResponseUnfilterable {
            reason: "a registration listing was answered with a single registration",
        };
    };

    // Cloned because the error owns the identifier and the operation keeps its own.
    ScopeError::Withheld { id: id.clone() }
}

/// Reduces the registrations of one answer document, or says the one it holds is withheld.
///
/// A registration is judged as a linked entity is: the semantics of a read by identifier, where any
/// allowed scope admits it and the answer shows only the allowed ones, and where a registration
/// without `scope` is in no allowed scope.
fn filter_document(document: &mut Value, allowed: &[ScopePattern]) -> Result<(), Withheld> {
    let visibility = for_each_registration(document, |registration| {
        Ok::<_, Withheld>(match judge_entity(Entity::Plain(registration), allowed) {
            EntityVisibility::Show => Visibility::Show,
            EntityVisibility::Withhold => Visibility::Withhold,
        })
    })?;

    match visibility {
        Visibility::Show => Ok(()),
        Visibility::Withhold => Err(Withheld),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use libra_ngsi_ld_operation::resource::ResourceId;
    use pretty_assertions::assert_eq;

    fn madrid() -> Vec<ScopePattern> {
        vec![ScopePattern::new("/Madrid/#").expect("the test pattern should be well formed")]
    }

    fn scoped(id: &str, scope: Value) -> Value {
        json!({ "id": id, "type": "ContextSourceRegistration", "scope": scope,
            "information": [{ "entities": [{ "type": "Vehicle" }] }], "endpoint": "http://source.test" })
    }

    fn unscoped(id: &str) -> Value {
        json!({ "id": id, "type": "ContextSourceRegistration",
            "information": [{ "entities": [{ "type": "Vehicle" }] }], "endpoint": "http://source.test" })
    }

    #[test]
    fn a_listing_keeps_the_allowed_registrations_reduced_to_their_allowed_scopes() {
        let mut document = json!([
            scoped("urn:r:1", json!("/Madrid/A")),
            scoped("urn:r:2", json!("/Berlin/B")),
            scoped("urn:r:3", json!(["/Madrid/A", "/Berlin/B"])),
            unscoped("urn:r:4"),
        ]);

        assert_eq!(filter_document(&mut document, &madrid()), Ok(()));
        assert_eq!(
            document,
            json!([scoped("urn:r:1", json!("/Madrid/A")), scoped("urn:r:3", json!(["/Madrid/A"]))])
        );
    }

    #[test]
    fn a_withheld_retrieval_is_answered_as_an_absent_registration() {
        let id = ResourceId::new("urn:r:2");

        assert_eq!(withheld(&Resource::ContextSourceRegistration { id: id.clone() }), ScopeError::Withheld { id });
        assert!(matches!(
            withheld(&Resource::ContextSourceRegistrations),
            ScopeError::ResponseUnfilterable { .. }
        ));
    }

    #[test]
    fn a_retrieval_outside_the_restriction_or_without_a_scope_is_withheld() {
        assert_eq!(filter_document(&mut scoped("urn:r:2", json!("/Berlin/B")), &madrid()), Err(Withheld));
        assert_eq!(filter_document(&mut unscoped("urn:r:4"), &madrid()), Err(Withheld));
        assert_eq!(filter_document(&mut scoped("urn:r:1", json!("/Madrid/A")), &madrid()), Ok(()));
    }
}
