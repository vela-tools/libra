//! Refusing a request that filters, ranks or projects a geometry by a hidden attribute.
//!
//! None of these return a hidden value as a member of the answer, and every one of them discloses
//! it anyway: through which entities come back (`q`, a geospatial query), the order they come back
//! in (`orderBy`, clause 4.23.3), or the `geometry` a `GeoJSON` answer lifts out of an attribute
//! (`geometryProperty`, clause 4.5.16.1). They are refused rather than narrowed, since a filter or
//! an ordering with a name taken out selects or ranks by something the caller never asked for.

use crate::{
    error::FilterError,
    request::{allows, check_attribute},
};
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_ngsi_ld_query::{filter::Filter, ordering::Ordering, parameter_name::ParameterName, parameters::QueryParameters};
use libra_policy_model::attribute::CompiledAttributeRestriction;

/// The attribute a geospatial query filters on when it names none.
///
/// `location` is the default `geoproperty`, so `georel`/`geometry`/`coordinates` with no
/// `geoproperty` still filters on it. Checking only the written parameter would leave the default
/// case open, which is the case every ordinary geospatial query uses.
pub(crate) const DEFAULT_GEOPROPERTY: &str = "location";

/// Refuses a request whose query string filters, ranks or projects a geometry by an attribute it
/// may not see.
///
/// Four parameters do this, and every one has to be closed for the restriction to mean anything. A
/// `q` expression names attributes directly. A geospatial query names one in `geoproperty`, or
/// names none and gets the default, `location`. An `orderBy` ranks by the attributes it names. A
/// `geometryProperty` lifts one into a `GeoJSON` answer's `geometry`. In each case the caller learns
/// the attribute's value, through which entities come back, the order they come back in, or the
/// geometry they carry.
///
/// # Errors
///
/// Returns [`FilterError::MalformedFilter`] if a `q` expression does not parse and
/// [`FilterError::MalformedOrdering`] if an `orderBy` does not (a filter or an ordering Libra
/// cannot read is one whose references it cannot check, while the broker applies it regardless),
/// and [`FilterError::AttributeDenied`] if the request reads a forbidden attribute.
pub fn check_filters(parameters: &QueryParameters, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    if let Some(expression) = parameters.get(&ParameterName::Q) {
        check_filter_names(expression, restriction, context)?;
    }

    if let Some(geoproperty) = geoproperty_filtered_on(parameters)
        && !allows(restriction, &geoproperty, context)?
    {
        return Err(FilterError::AttributeDenied { attribute: geoproperty });
    }

    if let Some(ordering) = parameters.get(&ParameterName::ORDER_BY) {
        check_ordering(ordering, restriction, context)?;
    }

    if let Some(geometry) = parameters.get(&ParameterName::GEOMETRY_PROPERTY) {
        check_attribute(&Term::new(geometry), restriction, context)?;
    }

    Ok(())
}

/// The attribute a request's geospatial query filters on, if it has one.
fn geoproperty_filtered_on(parameters: &QueryParameters) -> Option<Term> {
    let filtering = parameters.contains(&ParameterName::GEOPROPERTY) || parameters.contains(&ParameterName::GEOREL);

    filtering.then(|| {
        parameters
            .get(&ParameterName::GEOPROPERTY)
            .map_or_else(|| Term::new(DEFAULT_GEOPROPERTY), Term::new)
    })
}

/// Refuses a `q` expression that filters on an attribute the policy does not allow.
///
/// Every attribute name a path tests is checked. For a path on the queried entity that is the
/// attribute it starts at. A linked-entity path (clause 4.9) is checked in full: the Relationship
/// it follows, every Relationship it follows further, and the attribute the final path starts at
/// all have to be allowed, because the linked entity's values decide which entities come back
/// just as the queried entity's own do. The `Type,Type:` prefix names entity types, not
/// attributes, and is not this restriction's to judge.
///
/// # Errors
///
/// Returns [`FilterError::MalformedFilter`] if the expression does not parse, and
/// [`FilterError::AttributeDenied`] if it filters on a forbidden attribute.
pub(crate) fn check_filter_names(expression: &str, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let filter = Filter::parse(expression).map_err(|error| FilterError::MalformedFilter { reason: error.to_string() })?;

    for attribute in filter.attributes() {
        for name in attribute.attribute_names() {
            if !allows(restriction, name, context)? {
                // Cloned because the error owns the name while the caller's value is only borrowed.
                return Err(FilterError::AttributeDenied { attribute: name.clone() });
            }
        }
    }

    Ok(())
}

/// Refuses an `orderBy` that ranks by an attribute the policy does not allow.
///
/// `id`, `type` and `scope` are entity members, not attributes, and pass. A trailing key path, as in
/// `address[city]`, reads inside the attribute in front of it, which is the one judged. A dotted
/// path, as in `name.observedAt`, is judged by every name in it, so a ranking by a name the policy
/// hides is refused wherever in the path it sits. A distance ranking (`dist-asc`, `dist-desc`)
/// ranks by the `GeoProperty` it names, judged the same way; `orderFrom` and `orderGeometry` take
/// no attribute and only take effect with one.
///
/// # Errors
///
/// Returns [`FilterError::MalformedOrdering`] if the value does not fit the grammar of clause
/// 4.23.3, and [`FilterError::AttributeDenied`] if it ranks by a forbidden attribute.
pub(crate) fn check_ordering(written: &str, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Result<(), FilterError> {
    let ordering = Ordering::parse(written).map_err(|error| FilterError::MalformedOrdering { reason: error.to_string() })?;

    for path in ordering.attributes() {
        for name in path.segments() {
            check_attribute(name, restriction, context)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{context, omitting, picking, query};
    use pretty_assertions::assert_eq;

    #[test]
    fn an_existence_check_in_q_is_checked() {
        // `q=location` has no operator and still reads `location`: the set of entities that comes
        // back tells the caller which ones have the attribute the policy is hiding.
        let refused = check_filters(&query("q=location"), &omitting(&["location"]), &context());

        assert_eq!(
            refused,
            Err(FilterError::AttributeDenied {
                attribute: Term::new("location")
            })
        );
    }
    #[test]
    fn a_comparison_in_q_is_checked_too() {
        assert!(check_filters(&query("q=location==%22here%22"), &omitting(&["location"]), &context()).is_err());
        assert!(check_filters(&query("q=speed>40"), &omitting(&["location"]), &context()).is_ok());
    }
    #[test]
    fn a_linked_filter_path_is_checked_name_by_name() {
        // Clause 4.9: every Relationship followed and the attribute tested inside the linked entity
        // decide which entities come back.
        assert_eq!(
            check_filters(&query("q=isParked{name}==%22x%22"), &picking(&["isParked", "name"]), &context()),
            Ok(())
        );
        assert_eq!(
            check_filters(&query("q=isParked{name}==%22x%22"), &picking(&["isParked"]), &context()),
            Err(FilterError::AttributeDenied { attribute: Term::new("name") })
        );
        assert_eq!(
            check_filters(
                &query("q=isParked{Building,Garage:owner{name}}==%22x%22"),
                &picking(&["isParked", "name"]),
                &context()
            ),
            Err(FilterError::AttributeDenied { attribute: Term::new("owner") })
        );
        assert_eq!(
            check_filters(
                &query("q=isParked{Building,Garage:owner{name}}==%22x%22"),
                &picking(&["isParked", "owner", "name"]),
                &context()
            ),
            Ok(()),
            "the type prefix is not an attribute"
        );
    }
    #[test]
    fn a_geospatial_query_on_a_forbidden_attribute_is_refused() {
        // The same disclosure as `q`, through a different parameter: which entities come back tells
        // the caller where the entity is, which is the thing the policy hid.
        let refused = check_filters(&query("geoproperty=location&georel=near"), &omitting(&["location"]), &context());

        assert!(matches!(refused, Err(FilterError::AttributeDenied { .. })), "{refused:?}");
    }
    #[test]
    fn a_geospatial_query_naming_no_geoproperty_is_checked_against_the_default() {
        // `location` is the default geoproperty, so an ordinary geo query filters on it without
        // ever writing its name. Checking only the written parameter leaves the common case open.
        let refused = check_filters(
            &query("georel=near;maxDistance==2000&geometry=Point&coordinates=[0,0]"),
            &omitting(&["location"]),
            &context(),
        );

        assert!(matches!(refused, Err(FilterError::AttributeDenied { .. })), "{refused:?}");
    }
    #[test]
    fn a_geospatial_query_on_an_allowed_attribute_is_allowed() {
        let allowed = check_filters(&query("geoproperty=location&georel=near"), &picking(&["location"]), &context());

        assert_eq!(allowed, Ok(()));
    }
    #[test]
    fn naming_a_geoproperty_without_a_geospatial_query_is_still_checked() {
        // A `geoproperty` with no `georel` selects which attribute a geometry is read from rather
        // than filtering, but it is still a request about that attribute.
        let refused = check_filters(&query("geoproperty=location"), &omitting(&["location"]), &context());

        assert!(matches!(refused, Err(FilterError::AttributeDenied { .. })), "{refused:?}");
    }
    #[test]
    fn a_sub_attribute_is_checked_at_its_root() {
        // `location.observedAt` reads `location`. The policy is written about attributes, so the
        // root is what it governs.
        assert!(check_filters(&query("q=location.observedAt>2026-01-01T00:00:00Z"), &omitting(&["location"]), &context()).is_err());
    }
    #[test]
    fn a_q_expression_that_cannot_be_parsed_is_refused() {
        // The broker would apply it whole; Libra must not forward one it could not read.
        let refused = check_filters(&query("q=speed>"), &omitting(&["location"]), &context());

        assert!(matches!(refused, Err(FilterError::MalformedFilter { .. })), "{refused:?}");
    }

    #[test]
    fn an_order_by_a_hidden_attribute_is_refused() {
        assert_eq!(
            check_filters(&query("orderBy=salary;desc"), &omitting(&["salary"]), &context()),
            Err(FilterError::AttributeDenied {
                attribute: Term::new("salary")
            })
        );
        assert!(check_filters(&query("orderBy=speed,salary"), &omitting(&["salary"]), &context()).is_err());
    }

    #[test]
    fn an_order_by_an_allowed_attribute_is_forwarded() {
        assert_eq!(check_filters(&query("orderBy=speed;desc,brand"), &omitting(&["salary"]), &context()), Ok(()));
        assert_eq!(check_filters(&query("orderBy=speed"), &picking(&["speed"]), &context()), Ok(()));
    }

    #[test]
    fn an_order_by_id_type_or_scope_is_forwarded() {
        // Entity members, not attributes: under `pick` they are not in the allow list and still pass.
        assert_eq!(check_filters(&query("orderBy=id,type;desc,scope"), &picking(&["speed"]), &context()), Ok(()));
    }

    #[test]
    fn a_distance_order_on_a_hidden_geo_property_is_refused() {
        assert_eq!(
            check_filters(&query("orderBy=secretLoc;dist-asc&orderFrom=[8,40]"), &omitting(&["secretLoc"]), &context()),
            Err(FilterError::AttributeDenied {
                attribute: Term::new("secretLoc")
            })
        );
    }

    #[test]
    fn an_order_by_a_trailing_path_is_judged_by_its_root() {
        assert!(check_filters(&query("orderBy=address[city]"), &omitting(&["address"]), &context()).is_err());
        assert_eq!(check_filters(&query("orderBy=address[city]"), &omitting(&["city"]), &context()), Ok(()));
    }

    #[test]
    fn an_order_by_a_dotted_path_is_judged_by_each_name() {
        assert!(check_filters(&query("orderBy=name.observedAt"), &omitting(&["name"]), &context()).is_err());
        assert!(check_filters(&query("orderBy=name.secret"), &omitting(&["secret"]), &context()).is_err());
        assert_eq!(check_filters(&query("orderBy=name.observedAt"), &omitting(&["salary"]), &context()), Ok(()));
    }

    #[test]
    fn an_unparsable_order_by_is_refused() {
        for written in ["orderBy=", "orderBy=speed;sideways", "orderBy=speed,,brand", "orderBy=a%7Cb"] {
            assert!(
                matches!(
                    check_filters(&query(written), &omitting(&["salary"]), &context()),
                    Err(FilterError::MalformedOrdering { .. })
                ),
                "{written}"
            );
        }
    }

    #[test]
    fn a_hidden_geometry_property_is_refused() {
        assert_eq!(
            check_filters(&query("geometryProperty=location"), &omitting(&["location"]), &context()),
            Err(FilterError::AttributeDenied {
                attribute: Term::new("location")
            })
        );
    }

    #[test]
    fn an_allowed_geometry_property_is_forwarded() {
        assert_eq!(check_filters(&query("geometryProperty=location"), &picking(&["location"]), &context()), Ok(()));
    }
}
