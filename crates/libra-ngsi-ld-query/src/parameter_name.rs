//! The name of a URI query parameter.
//!
//! Names are compared exactly. RFC 3986 gives a query no case-insensitivity, and NGSI-LD spells its
//! parameters in camel case (`scopeQ`, `timeAt`), so `scopeq` is a different parameter to Libra.
//! A broker that matches names case-insensitively would read it as `scopeQ`, so a query naming a
//! parameter Libra reads in another case is refused when it is parsed, rather than left for each
//! layer to remember.

use derive_more::Display;
use std::borrow::Cow;

/// The name of one query parameter, decoded.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{_0}")]
pub struct ParameterName(Cow<'static, str>);

impl ParameterName {
    /// `type`, the entity type selection (NGSI-LD clause 4.17).
    pub const TYPE: ParameterName = ParameterName::from_static("type");
    /// `attrs`, the attributes to return.
    pub const ATTRS: ParameterName = ParameterName::from_static("attrs");
    /// `pick`, the entity members to return (NGSI-LD clause 4.21).
    pub const PICK: ParameterName = ParameterName::from_static("pick");
    /// `omit`, the entity members to leave out (NGSI-LD clause 4.21).
    pub const OMIT: ParameterName = ParameterName::from_static("omit");
    /// `q`, the query language expression (NGSI-LD clause 4.9).
    pub const Q: ParameterName = ParameterName::from_static("q");
    /// `scopeQ`, the scope query language expression (NGSI-LD clause 4.19).
    ///
    /// Capital `Q`. A broker that treats query parameter names as case-sensitive reads `scopeq` as
    /// an unknown parameter and applies no scope filter at all.
    pub const SCOPE_Q: ParameterName = ParameterName::from_static("scopeQ");
    /// `geoproperty`, the `GeoProperty` a geo-query is evaluated against (NGSI-LD clause 4.10).
    pub const GEOPROPERTY: ParameterName = ParameterName::from_static("geoproperty");
    /// `georel`, the geospatial relationship of a geo-query (NGSI-LD clause 4.10).
    pub const GEOREL: ParameterName = ParameterName::from_static("georel");
    /// `timeproperty`, the temporal property a temporal query is evaluated against (NGSI-LD clause 4.11).
    pub const TIMEPROPERTY: ParameterName = ParameterName::from_static("timeproperty");
    /// `timerel`, the temporal relationship of a temporal query (NGSI-LD clause 4.11).
    pub const TIMEREL: ParameterName = ParameterName::from_static("timerel");
    /// `timeAt`, the instant a temporal query starts from (NGSI-LD clause 4.11).
    pub const TIME_AT: ParameterName = ParameterName::from_static("timeAt");
    /// `endTimeAt`, the instant a `between` temporal query ends at (NGSI-LD clause 4.11).
    pub const END_TIME_AT: ParameterName = ParameterName::from_static("endTimeAt");
    /// `options`, the representation and behaviour options (NGSI-LD clause 6.3.7).
    pub const OPTIONS: ParameterName = ParameterName::from_static("options");
    /// `format`, the representation format (NGSI-LD clause 6.3.7).
    pub const FORMAT: ParameterName = ParameterName::from_static("format");
    /// `join`, Linked Entity Retrieval (NGSI-LD clause 4.5.23).
    pub const JOIN: ParameterName = ParameterName::from_static("join");
    /// `joinLevel`, the depth of Linked Entity Retrieval (NGSI-LD clause 4.5.23).
    pub const JOIN_LEVEL: ParameterName = ParameterName::from_static("joinLevel");
    /// `aggrMethods`, the aggregation functions of an aggregated temporal query (NGSI-LD clause 6.3.12).
    pub const AGGR_METHODS: ParameterName = ParameterName::from_static("aggrMethods");
    /// `aggrPeriodDuration`, the aggregation period of an aggregated temporal query (NGSI-LD clause 6.3.12).
    pub const AGGR_PERIOD_DURATION: ParameterName = ParameterName::from_static("aggrPeriodDuration");
    /// `orderBy`, the attributes an answer's entities are ranked by (NGSI-LD clause 4.23.3).
    pub const ORDER_BY: ParameterName = ParameterName::from_static("orderBy");
    /// `geometryProperty`, the `GeoProperty` a `GeoJSON` answer's `geometry` is taken from
    /// (NGSI-LD clauses 4.5.16.1 and 6.3.15).
    pub const GEOMETRY_PROPERTY: ParameterName = ParameterName::from_static("geometryProperty");

    /// Every parameter a layer reads.
    pub const READ: [ParameterName; 20] = [
        ParameterName::TYPE,
        ParameterName::ATTRS,
        ParameterName::PICK,
        ParameterName::OMIT,
        ParameterName::Q,
        ParameterName::SCOPE_Q,
        ParameterName::GEOPROPERTY,
        ParameterName::GEOREL,
        ParameterName::TIMEPROPERTY,
        ParameterName::TIMEREL,
        ParameterName::TIME_AT,
        ParameterName::END_TIME_AT,
        ParameterName::OPTIONS,
        ParameterName::FORMAT,
        ParameterName::JOIN,
        ParameterName::JOIN_LEVEL,
        ParameterName::AGGR_METHODS,
        ParameterName::AGGR_PERIOD_DURATION,
        ParameterName::ORDER_BY,
        ParameterName::GEOMETRY_PROPERTY,
    ];

    /// A name known when the binary is built.
    #[must_use]
    pub const fn from_static(name: &'static str) -> ParameterName {
        ParameterName(Cow::Borrowed(name))
    }

    /// A name read off a request, already percent-decoded.
    #[must_use]
    pub(crate) const fn decoded(name: String) -> ParameterName {
        ParameterName(Cow::Owned(name))
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the two names differ at most in ASCII case.
    ///
    /// For refusing a second spelling of a parameter a layer enforces: a broker that matched the
    /// name loosely would read the spelling the layer did not check.
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &ParameterName) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::parameter_name::ParameterName;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_decoded_name_equals_the_constant_spelled_the_same() {
        assert_eq!(ParameterName::decoded("scopeQ".to_owned()), ParameterName::SCOPE_Q);
    }

    #[test]
    fn names_differing_in_case_are_different_parameters() {
        assert_ne!(ParameterName::decoded("scopeq".to_owned()), ParameterName::SCOPE_Q);
        assert!(ParameterName::decoded("scopeq".to_owned()).eq_ignore_ascii_case(&ParameterName::SCOPE_Q));
    }

    #[test]
    fn names_order_by_their_text_whether_static_or_decoded() {
        assert!(ParameterName::ATTRS < ParameterName::decoded("type".to_owned()));
        assert!(ParameterName::decoded("attrs".to_owned()) < ParameterName::TYPE);
    }

    #[test]
    fn a_name_displays_as_written() {
        assert_eq!(ParameterName::END_TIME_AT.to_string(), "endTimeAt");
    }
}
