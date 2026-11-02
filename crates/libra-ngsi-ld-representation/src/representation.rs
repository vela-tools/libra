//! The three NGSI-LD entity representations, and whether system attributes ride along.

use derive_more::Display;

/// How an entity is rendered in a response body, per ETSI GS CIM 009 clause 4.5.
///
/// The names here are the specification's names for the shapes, not for the request tokens that
/// select them. The specification calls the simplified shape `keyValues` on the wire; it is
/// spelled [`Representation::Simplified`] in Rust because that is what clause 4.5.4 calls the
/// representation itself, and because the wire token is already available from
/// [`Representation::as_token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
#[display("{}", self.as_token())]
pub enum Representation {
    /// Clause 4.5.1. Every attribute is an object with `type`, `value`, and its own metadata.
    ///
    /// The default, because it is what a request that asks for nothing gets. It is also the only
    /// shape in which an attribute's metadata is visible, which is why anything inspecting a
    /// response for policy purposes wants to know when it is *not* looking at one.
    #[default]
    Normalized,
    /// Clause 4.5.5. Normalized with the redundant `type` and `value` keys elided.
    Concise,
    /// Clause 4.5.4, requested as `keyValues`. Each attribute collapses to its value alone.
    Simplified,
}

impl Representation {
    /// The token that names this representation in `options` and in `format`.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Normalized => "normalized",
            Self::Concise => "concise",
            Self::Simplified => "keyValues",
        }
    }

    /// Whether an attribute keeps its own structure in this representation.
    ///
    /// False for [`Representation::Simplified`], where an attribute is replaced by its value.
    /// Anything that reads or rewrites attribute metadata out of a response body has to check
    /// this first: in the simplified shape the metadata is not merely elsewhere, it is absent.
    #[must_use]
    pub const fn keeps_attribute_structure(self) -> bool {
        match self {
            Self::Normalized | Self::Concise => true,
            Self::Simplified => false,
        }
    }
}

/// Which temporal representation a temporal read is answered in (NGSI-LD clause 6.3.12).
///
/// Orthogonal to [`Representation`]: the temporal evolution of an entity is a list of attribute
/// instances in whichever of the three shapes was asked for, unless one of the two temporal formats
/// replaces those instances with something else altogether.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
#[display("{}", self.as_token())]
pub enum TemporalRepresentation {
    /// The default: every attribute is a list of its instances (clause 4.5.7).
    #[default]
    Instances,
    /// `temporalValues`: each attribute is reduced to value and time pairs (clause 4.5.9).
    Simplified,
    /// `aggregatedValues`: each attribute is reduced to aggregates over periods (clause 4.5.19).
    Aggregated,
}

impl TemporalRepresentation {
    /// The token that names this representation in `options` and in `format`.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Instances => "instances",
            Self::Simplified => "temporalValues",
            Self::Aggregated => "aggregatedValues",
        }
    }
}

/// Whether `createdAt` and `modifiedAt` appear on entities and attributes.
///
/// A typed flag rather than a `bool`, because it is read at the point where a body is inspected
/// and a bare `true` there says nothing about which of several flags it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SystemAttributes {
    /// The default: `createdAt` and `modifiedAt` are not in the response.
    #[default]
    Omitted,
    /// Requested with `options=sysAttrs`.
    Included,
}

impl SystemAttributes {
    /// The `options` token that asks for `createdAt` and `modifiedAt`.
    ///
    /// [`SystemAttributes::Omitted`] is what a request without it gets, so it has no token of its
    /// own.
    pub const TOKEN: &'static str = "sysAttrs";

    /// Whether `createdAt` and `modifiedAt` are included.
    #[must_use]
    pub const fn is_included(self) -> bool {
        match self {
            Self::Included => true,
            Self::Omitted => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::RepresentationSelection;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_default_representation_is_normalized() {
        // A request that asks for nothing gets the full shape. Any other default would mean Libra
        // assuming attribute metadata is absent when the broker is still sending it.
        assert_eq!(Representation::default(), Representation::Normalized);
    }

    #[test]
    fn the_simplified_representation_is_spelled_key_values_on_the_wire() {
        assert_eq!(Representation::Simplified.as_token(), "keyValues");
        assert_eq!(Representation::Concise.as_token(), "concise");
        assert_eq!(Representation::Normalized.as_token(), "normalized");
    }

    #[test]
    fn only_the_simplified_representation_loses_attribute_structure() {
        assert!(Representation::Normalized.keeps_attribute_structure());
        assert!(Representation::Concise.keeps_attribute_structure());
        assert!(!Representation::Simplified.keeps_attribute_structure());
    }

    #[test]
    fn system_attributes_are_omitted_unless_asked_for() {
        assert_eq!(SystemAttributes::default(), SystemAttributes::Omitted);
        assert!(!SystemAttributes::default().is_included());
        assert!(SystemAttributes::Included.is_included());
    }

    #[test]
    fn system_attributes_are_asked_for_with_the_sys_attrs_token() {
        assert_eq!(SystemAttributes::TOKEN, "sysAttrs");
        assert_eq!(
            RepresentationSelection::parse(Some(SystemAttributes::TOKEN), None).map(RepresentationSelection::system_attributes),
            Ok(SystemAttributes::Included)
        );
    }

    #[test]
    fn a_representation_displays_as_its_wire_token() {
        assert_eq!(Representation::Simplified.to_string(), "keyValues");
    }
}
