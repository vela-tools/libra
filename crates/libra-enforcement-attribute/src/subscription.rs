//! Applying an attribute restriction to a Subscription body.
//!
//! A subscription is the one request that makes the broker emit entity data on a channel Libra
//! never sees: the broker delivers notifications straight to the callback endpoint, not back
//! through the proxy. A restriction enforced only on the query path is therefore bypassed by
//! subscribing, which is the disclosure this module closes.
//!
//! NGSI-LD (ETSI GS CIM 009 v1.9.1) gives the enforcement everything it needs in the subscription
//! itself. The `NotificationParams` object (clause 5.2.14.1) carries a `pick` member ("every Entity
//! within the payload body is reduced down to only contain the specified Entity members") and an
//! `omit` member ("the specified Entity members are removed from each Entity"). Those are exactly
//! the two projections an attribute restriction expresses, so the notification is narrowed rather
//! than the subscription refused: a pick restriction becomes `notification.pick`, an omit restriction is merged
//! into `notification.omit`. The deprecated `attributes` member is a synonym for `pick` and is
//! treated as one.
//!
//! The selectors that decide *which* entities trigger a notification are `q` (clause 4.9),
//! `watchedAttributes`, and `geoQ` (clause 5.2.13). They are refused when they name a forbidden
//! attribute, exactly as the query path refuses a `q` or `geoQ` that reads a hidden attribute:
//! filtering on an attribute you cannot see still discloses it through which notifications arrive.

use crate::{
    error::FilterError,
    filters::{DEFAULT_GEOPROPERTY, check_filter_names},
    member::{member, member_mut, remove_member},
    request::{allows, restricted_names, terms_in},
};
use jstrict::{Value, object::Object};
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_policy_model::attribute::{AttributeAction, CompiledAttributeRestriction};

/// Narrows a subscription body to what the caller's attribute restriction allows.
///
/// The notification projection is rewritten so the broker can only emit allowed attributes, and
/// the subscription is refused if it triggers on an attribute the restriction hides.
///
/// # Errors
///
/// Returns [`FilterError::AttributeDenied`] if a trigger names a forbidden attribute,
/// [`FilterError::MalformedFilter`] if the `q` trigger does not parse, [`FilterError::NothingAllowed`]
/// if the notification would be left projecting nothing the restriction allows,
/// [`FilterError::Unresolvable`] if a name has no meaning under the request's context, and
/// [`FilterError::MalformedBody`] if the subscription names a member read here more than once.
pub fn enforce(document: &mut Value, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let Some(subscription) = document.as_object_mut() else {
        // Not an object. The broker validates the subscription's shape; this layer only narrows the
        // attributes a well-formed subscription would disclose.
        return Ok(());
    };

    refuse_forbidden_triggers(subscription, restriction, context)?;
    narrow_notification(subscription, restriction, context)
}

/// Refuses a subscription that triggers on an attribute the restriction hides.
fn refuse_forbidden_triggers(subscription: &Object, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    if let Some(watched) = member(subscription, "watchedAttributes")? {
        for term in terms_in(watched)? {
            if !allows(restriction, &term, context)? {
                return Err(FilterError::AttributeDenied { attribute: term });
            }
        }
    }

    if let Some(expression) = member(subscription, "q")?.and_then(Value::as_str) {
        check_filter_names(expression, restriction, context)?;
    }

    if let Some(geo) = member(subscription, "geoQ")?.and_then(Value::as_object) {
        // A geoQ always filters, so its geoproperty is always read, named or the default when it
        // names none, matching how the broker resolves it.
        let named = member(geo, "geoproperty")?
            .and_then(Value::as_str)
            .map_or_else(|| Term::new(DEFAULT_GEOPROPERTY), Term::new);

        if !allows(restriction, &named, context)? {
            return Err(FilterError::AttributeDenied { attribute: named });
        }
    }

    Ok(())
}

/// Rewrites the notification projection so the broker emits only allowed attributes.
fn narrow_notification(subscription: &mut Object, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let Some(notification) = member_mut(subscription, "notification")?.and_then(Value::as_object_mut) else {
        // A subscription with no notification object is invalid and the broker will refuse it;
        // there is no projection to narrow.
        return Ok(());
    };

    match restriction.action() {
        AttributeAction::Omit => narrow_by_omission(notification, restriction, context),
        AttributeAction::Pick => narrow_by_selection(notification, restriction, context),
    }
}

/// Under an omit restriction, adds the hidden attributes to `notification.omit` and drops any that a
/// caller-supplied allowlist named.
fn narrow_by_omission(notification: &mut Object, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let mut omitted: Vec<String> = match member(notification, "omit")? {
        Some(omit) => terms_in(omit)?.iter().map(|term| term.as_str().to_owned()).collect(),
        None => Vec::new(),
    };

    for name in restricted_names(restriction, context)? {
        if !omitted.contains(&name) {
            omitted.push(name);
        }
    }
    set_names(notification, "omit", omitted);

    // An allowlist the caller supplied must not name a hidden attribute. Reducing it to the
    // allowed names is the same narrowing the query path applies to `attrs`/`pick`; a list that
    // named only hidden attributes is refused rather than silently widened to everything.
    for key in ["pick", "attributes"] {
        let kept = match member(notification, key)? {
            Some(list) => Some(retain_allowed(list, restriction, context)?),
            None => None,
        };

        if let Some(kept) = kept {
            if kept.is_empty() {
                return Err(FilterError::NothingAllowed);
            }
            set_names(notification, key, kept);
        }
    }

    Ok(())
}

/// Under a pick restriction, sets `notification.pick` to the allowed set (intersected with whatever the
/// caller asked for) and removes the projections that cannot be bounded to it.
fn narrow_by_selection(notification: &mut Object, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let allowed = restricted_names(restriction, context)?;
    if allowed.is_empty() {
        // A pick that allows nothing cannot be expressed as a non-empty projection, and an empty
        // one reads to the broker as "all attributes".
        return Err(FilterError::NothingAllowed);
    }

    let names = {
        // The deprecated `attributes` member is a synonym for `pick`; either narrows to the restriction.
        let requested = match member(notification, "pick")? {
            Some(pick) => Some(pick),
            None => member(notification, "attributes")?,
        };
        match requested {
            Some(list) => {
                let kept = retain_allowed(list, restriction, context)?;
                if kept.is_empty() {
                    return Err(FilterError::NothingAllowed);
                }
                kept
            }
            None => allowed,
        }
    };

    // A caller-supplied `omit` is a denylist and cannot bound the payload to the allowed set, so
    // the pick replaces it outright.
    remove_member(notification, "attributes")?;
    remove_member(notification, "omit")?;
    set_names(notification, "pick", names);

    Ok(())
}

/// The allowed subset of the attribute names a projection member holds.
fn retain_allowed(list: &Value, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<Vec<String>, FilterError> {
    let mut kept = Vec::new();

    for term in terms_in(list)? {
        if allows(restriction, &term, context)? {
            kept.push(term.as_str().to_owned());
        }
    }

    Ok(kept)
}

/// Writes a projection member as a JSON array of names.
///
/// Inserting replaces every member already called `key`, so the projection written is the only one
/// the broker can read.
fn set_names(notification: &mut Object, key: &str, names: Vec<String>) {
    notification.insert(key.into(), Value::Array(names.into_iter().map(Value::from).collect()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pointer::at;
    use jstrict::json;
    use libra_jsonld_term_expansion::name::ExpandedIri;
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "speed": "https://uri.fiware.org/ns/data-models#speed",
                "brand": "https://uri.fiware.org/ns/data-models#brand",
                "location": "https://uri.etsi.org/ngsi-ld/location"
            }"#,
        )
        .expect("the test context should process")
    }

    fn iri(term: &str) -> ExpandedIri {
        context().expand(&Term::new(term)).expect("the term should expand")
    }

    fn omitting(terms: &[&str]) -> CompiledAttributeRestriction {
        CompiledAttributeRestriction::new(AttributeAction::Omit, terms.iter().map(|term| iri(term)).collect())
    }

    fn picking(terms: &[&str]) -> CompiledAttributeRestriction {
        CompiledAttributeRestriction::new(AttributeAction::Pick, terms.iter().map(|term| iri(term)).collect())
    }

    fn names(document: &Value, pointer: &str) -> Vec<String> {
        at(document, pointer)
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default()
    }

    #[test]
    fn an_omit_restriction_adds_the_hidden_attribute_to_the_notification_omit() {
        let mut document = json!({
            "type": "Subscription",
            "entities": [{ "type": "Vehicle" }],
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &omitting(&["location"]), &context()).expect("it should narrow");

        assert_eq!(names(&document, "/notification/omit"), vec!["location".to_owned()]);
    }

    #[test]
    fn an_omit_whose_attribute_has_no_name_under_the_callers_context_is_refused_rather_than_left_out() {
        // JSON-LD 1.0 reads `urn:example:secret` as the term `urn` followed by `example:secret`, so
        // writing it into `omit` would hide a different attribute at a 1.0 broker.
        let restriction = CompiledAttributeRestriction::new(AttributeAction::Omit, vec![ExpandedIri::new("urn:example:secret")]);
        let caller = ResolvedContext::from_json(r#"{"urn": "https://elsewhere.test/x"}"#).unwrap();
        let mut document = json!({
            "type": "Subscription",
            "entities": [{ "type": "Vehicle" }],
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        assert_eq!(enforce(&mut document, &restriction, &caller), Err(FilterError::Inexpressible));
    }

    #[test]
    fn an_omit_restriction_merges_with_a_caller_supplied_omit() {
        let mut document = json!({
            "type": "Subscription",
            "notification": { "omit": ["speed"], "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &omitting(&["location"]), &context()).expect("it should narrow");

        let omit = names(&document, "/notification/omit");
        assert!(omit.contains(&"speed".to_owned()), "{omit:?}");
        assert!(omit.contains(&"location".to_owned()), "{omit:?}");
    }

    #[test]
    fn an_omit_restriction_drops_a_hidden_attribute_from_a_caller_supplied_pick() {
        let mut document = json!({
            "type": "Subscription",
            "notification": { "pick": ["speed", "location"], "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &omitting(&["location"]), &context()).expect("it should narrow");

        assert_eq!(names(&document, "/notification/pick"), vec!["speed".to_owned()]);
    }

    #[test]
    fn an_omit_restriction_refuses_a_pick_of_only_hidden_attributes() {
        let mut document = json!({
            "type": "Subscription",
            "notification": { "pick": ["location"], "endpoint": { "uri": "http://sink.test" } }
        });

        assert_eq!(enforce(&mut document, &omitting(&["location"]), &context()), Err(FilterError::NothingAllowed));
    }

    #[test]
    fn a_pick_restriction_sets_the_notification_pick_when_the_caller_asked_for_everything() {
        let mut document = json!({
            "type": "Subscription",
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &picking(&["speed", "brand"]), &context()).expect("it should narrow");

        let pick = names(&document, "/notification/pick");
        assert_eq!(pick.len(), 2);
        assert!(pick.contains(&"speed".to_owned()), "{pick:?}");
        assert!(pick.contains(&"brand".to_owned()), "{pick:?}");
    }

    #[test]
    fn a_pick_restriction_reduces_a_caller_supplied_pick_to_the_allowed_set() {
        let mut document = json!({
            "type": "Subscription",
            "notification": { "pick": ["speed", "location"], "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &picking(&["speed"]), &context()).expect("it should narrow");

        assert_eq!(names(&document, "/notification/pick"), vec!["speed".to_owned()]);
    }

    #[test]
    fn a_pick_restriction_narrows_the_deprecated_attributes_member_into_pick() {
        let mut document = json!({
            "type": "Subscription",
            "notification": { "attributes": ["speed", "location"], "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &picking(&["speed"]), &context()).expect("it should narrow");

        assert_eq!(names(&document, "/notification/pick"), vec!["speed".to_owned()]);
        assert!(
            at(&document, "/notification/attributes").is_none(),
            "the deprecated member is consolidated into pick"
        );
    }

    #[test]
    fn a_pick_restriction_removes_a_caller_supplied_omit_that_cannot_bound_the_payload() {
        let mut document = json!({
            "type": "Subscription",
            "notification": { "omit": ["speed"], "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &picking(&["speed", "brand"]), &context()).expect("it should narrow");

        assert!(at(&document, "/notification/omit").is_none(), "a denylist cannot bound a pick restriction");
        assert_eq!(names(&document, "/notification/pick").len(), 2);
    }

    #[test]
    fn watching_a_hidden_attribute_is_refused() {
        let mut document = json!({
            "type": "Subscription",
            "watchedAttributes": ["location"],
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        assert_eq!(
            enforce(&mut document, &omitting(&["location"]), &context()),
            Err(FilterError::AttributeDenied {
                attribute: Term::new("location")
            })
        );
    }

    #[test]
    fn a_q_trigger_on_a_hidden_attribute_is_refused() {
        let mut document = json!({
            "type": "Subscription",
            "q": "location==%22here%22",
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        assert!(matches!(
            enforce(&mut document, &omitting(&["location"]), &context()),
            Err(FilterError::AttributeDenied { .. })
        ));
    }

    #[test]
    fn a_geoq_on_a_hidden_attribute_is_refused() {
        let mut document = json!({
            "type": "Subscription",
            "geoQ": { "georel": "near;maxDistance==2000", "geometry": "Point", "coordinates": [0, 0], "geoproperty": "location" },
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        assert!(matches!(
            enforce(&mut document, &omitting(&["location"]), &context()),
            Err(FilterError::AttributeDenied { .. })
        ));
    }

    #[test]
    fn a_geoq_naming_no_geoproperty_is_checked_against_the_default() {
        let mut document = json!({
            "type": "Subscription",
            "geoQ": { "georel": "near;maxDistance==2000", "geometry": "Point", "coordinates": [0, 0] },
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        assert!(matches!(
            enforce(&mut document, &omitting(&["location"]), &context()),
            Err(FilterError::AttributeDenied { .. })
        ));
    }

    #[test]
    fn a_subscription_that_is_not_an_object_is_left_to_the_broker() {
        let mut document = json!(["not", "a", "subscription"]);

        assert_eq!(enforce(&mut document, &omitting(&["location"]), &context()), Ok(()));
    }

    #[test]
    fn a_subscription_allowed_in_full_is_untouched_apart_from_the_projection() {
        let mut document = json!({
            "type": "Subscription",
            "entities": [{ "type": "Vehicle" }],
            "q": "speed>40",
            "notification": { "endpoint": { "uri": "http://sink.test" } }
        });

        enforce(&mut document, &omitting(&["location"]), &context()).expect("it should narrow");

        assert_eq!(at(&document, "/q").and_then(Value::as_str), Some("speed>40"));
        assert_eq!(names(&document, "/notification/omit"), vec!["location".to_owned()]);
    }

    #[test]
    fn a_subscription_that_repeats_a_member_read_here_is_refused() {
        let repeated = [
            json!({ "type": "Subscription", "q": "speed>40", "q": "location!=null" }),
            json!({ "type": "Subscription", "watchedAttributes": ["speed"], "watchedAttributes": ["location"] }),
            json!({ "type": "Subscription", "notification": { "pick": ["speed"], "pick": ["location"] } }),
            json!({ "type": "Subscription", "notification": {}, "notification": { "pick": ["location"] } }),
        ];

        for mut document in repeated {
            assert_eq!(
                enforce(&mut document, &omitting(&["location"]), &context()),
                Err(FilterError::MalformedBody),
                "{document}"
            );
        }
    }
}
