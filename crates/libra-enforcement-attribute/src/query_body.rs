//! Narrowing and judging the query a `Query` body carries.
//!
//! `POST /entityOperations/query` and `POST /temporal/entityOperations/query` carry the same
//! selectors a `GET` writes in its query string, because the specification provides the body for
//! queries too long for a URL (clause 5.2.23). A check that only reads the query string is a check
//! with a documented way around it.

use crate::{
    error::FilterError,
    filters::{DEFAULT_GEOPROPERTY, check_filter_names, check_ordering},
    member::{member, member_mut},
    request::{SELECTORS, allows, check_attribute, narrow_projection},
};
use jstrict::{Array, Value, object::Object};
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_ngsi_ld_query::parameter_name::ParameterName;
use libra_policy_model::attribute::CompiledAttributeRestriction;

/// The `OrderingParams` member of a `Query` (clause 5.2.23), which holds its `orderBy`.
const ORDERING: &str = "ordering";

/// Narrows a query body's projections and refuses one that filters or ranks on a forbidden
/// attribute.
///
/// The projections are narrowed as the query string's are: `attrs` and `pick` keep the names the
/// policy allows, element by element when they are an array, and an element left with none is
/// dropped. `omit` can only remove more and is left alone. A filter is refused rather than
/// narrowed: it discloses through which entities come back, and a filter with a term taken out
/// selects something the caller never asked for.
///
/// # Errors
///
/// Returns [`FilterError::NothingAllowed`] if a projection that named something keeps nothing,
/// [`FilterError::MalformedFilter`] if a projection or a `q` expression does not parse,
/// [`FilterError::MalformedOrdering`] if an `orderBy` does not, [`FilterError::AttributeDenied`] if
/// the body filters, ranks or projects a geometry by a forbidden attribute, and
/// [`FilterError::MalformedBody`] if it names a member read here more than once or an ordering
/// member of the wrong shape.
pub fn narrow_query_body(document: &mut Value, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let Some(query) = document.as_object_mut() else {
        return Ok(());
    };

    // A `Query` body names its members after the query parameters they stand for (NGSI-LD
    // clause 5.2.23).
    for selector in &SELECTORS {
        narrow_projection_member(query, selector, restriction, context)?;
    }

    if let Some(expression) = member(query, "q")?.and_then(Value::as_str) {
        check_filter_names(expression, restriction, context)?;
    }

    if let Some(geo) = member(query, "geoQ")?.and_then(Value::as_object) {
        let named = member(geo, "geoproperty")?
            .and_then(Value::as_str)
            .map_or_else(|| Term::new(DEFAULT_GEOPROPERTY), Term::new);

        if !allows(restriction, &named, context)? {
            return Err(FilterError::AttributeDenied { attribute: named });
        }
    }

    // Clause 5.2.43 puts `orderBy` in the `ordering` member. A top-level `orderBy` is judged too: a
    // broker that reads one there ranks by it.
    check_order_by(member(query, ParameterName::ORDER_BY.as_str())?, restriction, context)?;
    match member(query, ORDERING)? {
        None | Some(Value::Null) => {}
        Some(Value::Object(ordering)) => check_order_by(member(ordering, ParameterName::ORDER_BY.as_str())?, restriction, context)?,
        Some(Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_)) => return Err(FilterError::MalformedBody),
    }

    match member(query, ParameterName::GEOMETRY_PROPERTY.as_str())? {
        None | Some(Value::Null) => {}
        Some(Value::String(geometry)) => check_attribute(&Term::new(geometry.as_str()), restriction, context)?,
        Some(Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => return Err(FilterError::MalformedBody),
    }

    Ok(())
}

/// Judges an `orderBy` member, written as one ordering or as a list of them (clause 5.2.43).
fn check_order_by(written: Option<&Value>, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    match written {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(ordering)) => check_ordering(ordering, restriction, context),
        Some(Value::Array(orderings)) => orderings.iter().try_for_each(|ordering| match ordering {
            Value::String(ordering) => check_ordering(ordering, restriction, context),
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => Err(FilterError::MalformedBody),
        }),
        Some(Value::Boolean(_) | Value::Number(_) | Value::Object(_)) => Err(FilterError::MalformedBody),
    }
}

/// Narrows one projection member of a body, written either as a list or as one string.
fn narrow_projection_member(
    query: &mut Object,
    selector: &ParameterName,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
) -> Result<(), FilterError> {
    match member_mut(query, selector.as_str())? {
        Some(Value::String(value)) => {
            *value = narrow_projection(value, restriction, context)?.ok_or(FilterError::NothingAllowed)?.into();
        }
        Some(Value::Array(elements)) => {
            let named = elements.iter().any(Value::is_string);
            let mut narrowed = Array::with_capacity(elements.len());

            for element in elements.drain(..) {
                match element {
                    Value::String(value) => narrowed.extend(narrow_projection(&value, restriction, context)?.map(Value::from)),
                    // An element that is not a string names nothing, and is the broker's to refuse.
                    other @ (Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => narrowed.push(other),
                }
            }

            if named && !narrowed.iter().any(Value::is_string) {
                return Err(FilterError::NothingAllowed);
            }

            *elements = narrowed;
        }
        None | Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Object(_)) => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures::{context, omitting, picking},
        pointer::at,
    };
    use jstrict::json;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_query_body_filtering_on_a_forbidden_attribute_is_refused() {
        // The documented way round the query-string check: `POST /entityOperations/query` carries
        // the same `q` in a body, for queries too long for a URL.
        let mut body = json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "q": "location!=null" });
        let refused = narrow_query_body(&mut body, &omitting(&["location"]), &context());

        assert!(matches!(refused, Err(FilterError::AttributeDenied { .. })), "{refused:?}");
    }
    #[test]
    fn a_query_body_projection_is_narrowed_element_by_element() {
        let mut body = json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "attrs": ["speed", "location"] });

        assert_eq!(narrow_query_body(&mut body, &omitting(&["location"]), &context()), Ok(()));
        assert_eq!(at(&body, "/attrs"), Some(&json!(["speed"])));

        let mut joined = json!({ "type": "Query", "pick": ["speed|location", "brand"] });
        assert_eq!(narrow_query_body(&mut joined, &omitting(&["location"]), &context()), Ok(()));
        assert_eq!(at(&joined, "/pick"), Some(&json!(["speed", "brand"])));
    }
    #[test]
    fn a_query_body_projection_written_as_one_string_is_narrowed_as_one() {
        let mut body = json!({ "type": "Query", "attrs": "speed,location" });

        assert_eq!(narrow_query_body(&mut body, &omitting(&["location"]), &context()), Ok(()));
        assert_eq!(at(&body, "/attrs"), Some(&json!("speed")));
    }
    #[test]
    fn a_query_body_projection_left_with_nothing_is_refused() {
        for mut body in [
            json!({ "type": "Query", "pick": ["location"] }),
            json!({ "type": "Query", "attrs": "location" }),
        ] {
            assert_eq!(
                narrow_query_body(&mut body, &omitting(&["location"]), &context()),
                Err(FilterError::NothingAllowed),
                "{body}"
            );
        }
    }
    #[test]
    fn a_query_body_omit_is_left_alone() {
        let mut body = json!({ "type": "Query", "omit": ["location", "speed"] });

        assert_eq!(narrow_query_body(&mut body, &picking(&["speed"]), &context()), Ok(()));
        assert_eq!(at(&body, "/omit"), Some(&json!(["location", "speed"])));
    }
    #[test]
    fn a_query_body_with_a_geo_filter_on_a_forbidden_attribute_is_refused() {
        let mut body = json!({
            "type": "Query",
            "entities": [{ "type": "Vehicle" }],
            "geoQ": { "geometry": "Point", "coordinates": [0, 0], "georel": "near;maxDistance==2000", "geoproperty": "location" }
        });
        let refused = narrow_query_body(&mut body, &omitting(&["location"]), &context());

        assert!(matches!(refused, Err(FilterError::AttributeDenied { .. })), "{refused:?}");
    }
    #[test]
    fn a_query_body_with_a_geo_filter_naming_no_geoproperty_is_checked_against_the_default() {
        let mut body = json!({
            "type": "Query",
            "entities": [{ "type": "Vehicle" }],
            "geoQ": { "geometry": "Point", "coordinates": [0, 0], "georel": "near;maxDistance==2000" }
        });
        let refused = narrow_query_body(&mut body, &omitting(&["location"]), &context());

        assert!(matches!(refused, Err(FilterError::AttributeDenied { .. })), "{refused:?}");
    }
    #[test]
    fn a_query_body_within_what_the_policy_allows_is_allowed() {
        let mut body = json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "attrs": ["speed"], "q": "speed>40" });

        assert_eq!(narrow_query_body(&mut body, &omitting(&["location"]), &context()), Ok(()));
    }
    #[test]
    fn a_query_body_that_is_not_an_object_is_left_to_the_broker() {
        // Not this layer's job to validate the shape of a query document; it only has to refuse
        // the attributes it can see.
        assert_eq!(narrow_query_body(&mut json!([1, 2, 3]), &omitting(&["location"]), &context()), Ok(()));
    }
    #[test]
    fn a_query_body_that_repeats_a_member_read_here_is_refused() {
        let repeated = [
            json!({ "type": "Query", "q": "speed>40", "q": "location!=null" }),
            json!({ "type": "Query", "attrs": ["speed"], "attrs": ["location"] }),
            json!({ "type": "Query", "geoQ": { "geoproperty": "speed", "geoproperty": "location" } }),
        ];

        for mut body in repeated {
            assert_eq!(
                narrow_query_body(&mut body, &omitting(&["location"]), &context()),
                Err(FilterError::MalformedBody),
                "{body}"
            );
        }
    }

    #[test]
    fn an_order_by_in_a_query_body_is_judged_like_the_query_string() {
        for mut body in [
            json!({ "type": "Query", "ordering": { "orderBy": ["speed", "salary;desc"] } }),
            json!({ "type": "Query", "ordering": { "orderBy": "salary" } }),
            json!({ "type": "Query", "orderBy": "salary;desc" }),
            json!({ "type": "Query", "orderBy": ["address[city]", "salary.observedAt"] }),
        ] {
            assert_eq!(
                narrow_query_body(&mut body, &omitting(&["salary"]), &context()),
                Err(FilterError::AttributeDenied {
                    attribute: Term::new("salary")
                }),
                "{body}"
            );
        }

        let mut allowed = json!({ "type": "Query", "ordering": { "orderBy": ["speed;desc", "id"], "collation": "und-x-icu" } });
        assert_eq!(narrow_query_body(&mut allowed, &omitting(&["salary"]), &context()), Ok(()));
    }

    #[test]
    fn an_unreadable_order_by_in_a_query_body_is_refused() {
        assert!(matches!(
            narrow_query_body(&mut json!({ "ordering": { "orderBy": ["speed;up"] } }), &omitting(&["salary"]), &context()),
            Err(FilterError::MalformedOrdering { .. })
        ));
        for mut body in [
            json!({ "ordering": "speed" }),
            json!({ "ordering": { "orderBy": 3 } }),
            json!({ "orderBy": [3] }),
            json!({ "ordering": { "orderBy": "speed", "orderBy": "salary" } }),
        ] {
            assert_eq!(
                narrow_query_body(&mut body, &omitting(&["salary"]), &context()),
                Err(FilterError::MalformedBody),
                "{body}"
            );
        }
    }

    #[test]
    fn a_geometry_property_in_a_query_body_is_judged() {
        assert_eq!(
            narrow_query_body(
                &mut json!({ "type": "Query", "geometryProperty": "location" }),
                &omitting(&["location"]),
                &context()
            ),
            Err(FilterError::AttributeDenied {
                attribute: Term::new("location")
            })
        );
        assert_eq!(
            narrow_query_body(
                &mut json!({ "type": "Query", "geometryProperty": "location" }),
                &picking(&["location"]),
                &context()
            ),
            Ok(())
        );
        assert_eq!(
            narrow_query_body(&mut json!({ "type": "Query", "geometryProperty": 3 }), &picking(&["location"]), &context()),
            Err(FilterError::MalformedBody)
        );
    }
}
