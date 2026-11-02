//! Turning the `options` and `format` query parameters into one typed selection.
//!
//! NGSI-LD names the response shape twice: with tokens inside `options`, and, since version
//! 1.8, with a `format` parameter of its own. A request may carry both, and nothing stops it
//! carrying two tokens that disagree. This module refuses every disagreement rather than resolving
//! it, because there is no reading that is right: brokers differ, and the one Libra picked would
//! be the shape Libra then reasoned about while the broker sent another.

use crate::{
    accept::MediaType,
    error::RepresentationError,
    representation::{Representation, SystemAttributes, TemporalRepresentation},
};

/// What the caller asked a response to look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RepresentationSelection {
    representation: Representation,
    system_attributes: SystemAttributes,
    temporal: TemporalRepresentation,
}

impl RepresentationSelection {
    /// Builds a selection directly, for callers that already know every part of it.
    #[must_use]
    pub const fn new(representation: Representation, system_attributes: SystemAttributes, temporal: TemporalRepresentation) -> Self {
        Self {
            representation,
            system_attributes,
            temporal,
        }
    }

    /// The shape entities are rendered in.
    #[must_use]
    pub const fn representation(self) -> Representation {
        self.representation
    }

    /// Whether `createdAt` and `modifiedAt` are included.
    #[must_use]
    pub const fn system_attributes(self) -> SystemAttributes {
        self.system_attributes
    }

    /// Which temporal representation a temporal read is answered in.
    #[must_use]
    pub const fn temporal(self) -> TemporalRepresentation {
        self.temporal
    }

    /// Reads the `options` and `format` query parameters.
    ///
    /// Both are taken already percent-decoded, as `libra-ngsi-ld-query` hands them over. Tokens in
    /// `options` that this crate does not own (`noOverwrite`, `update`, `replace` and the rest,
    /// which select an *operation* rather than a representation) are passed over rather than
    /// refused, so a batch upsert is not broken by a parameter it is entitled to send.
    ///
    /// # Errors
    ///
    /// Returns [`RepresentationError::ContradictoryOptions`] when `options` names two different
    /// representations, [`RepresentationError::ContradictoryFormat`] when `options` and `format`
    /// disagree, [`RepresentationError::ContradictoryTemporalOptions`] when `options` names both
    /// temporal formats, [`RepresentationError::MisspelledOption`] when a token differs from a
    /// known one only in case, and [`RepresentationError::UnknownFormat`] when `format` is not a
    /// representation at all.
    pub fn parse(options: Option<&str>, format: Option<&str>) -> Result<Self, RepresentationError> {
        let mut from_options: Option<Representation> = None;
        let mut temporal_from_options: Option<TemporalRepresentation> = None;
        let mut system_attributes = SystemAttributes::Omitted;

        for token in options.unwrap_or_default().split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            match classify(token)? {
                // `options=keyValues,concise` is the case this refusal exists for.
                Some(OptionToken::Shape(shape)) => match from_options {
                    Some(already) if already != shape => {
                        return Err(RepresentationError::ContradictoryOptions { first: already, second: shape });
                    }
                    Some(_) | None => from_options = Some(shape),
                },
                // Clause 6.3.12: "Only one of the two keywords can be present".
                Some(OptionToken::Temporal(temporal)) => match temporal_from_options {
                    Some(already) if already != temporal => {
                        return Err(RepresentationError::ContradictoryTemporalOptions {
                            first: already,
                            second: temporal,
                        });
                    }
                    Some(_) | None => temporal_from_options = Some(temporal),
                },
                Some(OptionToken::SysAttrs) => system_attributes = SystemAttributes::Included,
                None => {}
            }
        }

        let format = format.map(str::trim).filter(|value| !value.is_empty());
        let (from_format, temporal_from_format) = match format {
            None => (None, None),
            Some(value) => match (shape_from_token(value), temporal_from_token(value)) {
                (Some(shape), _) => (Some(shape), None),
                (None, Some(temporal)) => (None, Some(temporal)),
                (None, None) => return Err(RepresentationError::UnknownFormat { format: value.to_owned() }),
            },
        };

        let representation = match (from_options, from_format) {
            (Some(from_options), Some(from_format)) => {
                if from_options != from_format {
                    return Err(RepresentationError::ContradictoryFormat {
                        options: from_options,
                        format: from_format,
                    });
                }

                from_options
            }
            (Some(only), None) | (None, Some(only)) => only,
            (None, None) => Representation::default(),
        };

        Ok(Self {
            representation,
            system_attributes,
            // Clause 6.3.12: "If both format and options are present, the value of the format
            // parameter shall take precedence."
            temporal: temporal_from_format.or(temporal_from_options).unwrap_or_default(),
        })
    }
}

/// Everything about a response that is decided before the broker answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ResponseRepresentation {
    selection: RepresentationSelection,
    media_type: MediaType,
}

impl ResponseRepresentation {
    /// Builds one from an already decided selection and media type.
    #[must_use]
    pub const fn new(selection: RepresentationSelection, media_type: MediaType) -> Self {
        Self { selection, media_type }
    }

    /// Reads the whole decision out of a request.
    ///
    /// # Errors
    ///
    /// Returns whatever [`RepresentationSelection::parse`] and
    /// [`MediaType::negotiate`] return.
    pub fn parse(accept: Option<&str>, options: Option<&str>, format: Option<&str>) -> Result<Self, RepresentationError> {
        Ok(Self {
            selection: RepresentationSelection::parse(options, format)?,
            media_type: MediaType::negotiate(accept)?,
        })
    }

    /// The shape entities are rendered in.
    #[must_use]
    pub const fn representation(self) -> Representation {
        self.selection.representation()
    }

    /// Whether `createdAt` and `modifiedAt` are included.
    #[must_use]
    pub const fn system_attributes(self) -> SystemAttributes {
        self.selection.system_attributes()
    }

    /// Which temporal representation a temporal read is answered in.
    #[must_use]
    pub const fn temporal(self) -> TemporalRepresentation {
        self.selection.temporal()
    }

    /// The negotiated media type.
    #[must_use]
    pub const fn media_type(self) -> MediaType {
        self.media_type
    }

    /// The selection on its own.
    #[must_use]
    pub const fn selection(self) -> RepresentationSelection {
        self.selection
    }

    /// Whether the response body will carry its own `@context`.
    ///
    /// Read this before rewriting a body: with `application/json` the context is in a `Link`
    /// header, and adding an `@context` member to that body would produce something the broker
    /// never sent.
    #[must_use]
    pub const fn carries_inline_context(self) -> bool {
        self.media_type.carries_inline_context()
    }
}

/// What one `options` token means to this crate.
enum OptionToken {
    Shape(Representation),
    Temporal(TemporalRepresentation),
    SysAttrs,
}

/// The representation a token names, if it names one.
fn shape_from_token(token: &str) -> Option<Representation> {
    match token {
        "keyValues" => Some(Representation::Simplified),
        "concise" => Some(Representation::Concise),
        "normalized" => Some(Representation::Normalized),
        _ => None,
    }
}

/// The temporal representation a token names, if it names one (clause 6.3.12).
fn temporal_from_token(token: &str) -> Option<TemporalRepresentation> {
    match token {
        "temporalValues" => Some(TemporalRepresentation::Simplified),
        "aggregatedValues" => Some(TemporalRepresentation::Aggregated),
        _ => None,
    }
}

/// Classifies one `options` token.
///
/// A token that matches a known one only when case is ignored is refused rather than passed over.
/// Brokers compare these tokens exactly, so `keyvalues` selects nothing at the broker; passing it
/// over here would leave Libra and the broker agreeing, but a later correction of the spelling
/// would silently change the response shape. Refusing tells the caller which of the two they meant.
fn classify(token: &str) -> Result<Option<OptionToken>, RepresentationError> {
    if let Some(shape) = shape_from_token(token) {
        return Ok(Some(OptionToken::Shape(shape)));
    }

    if let Some(temporal) = temporal_from_token(token) {
        return Ok(Some(OptionToken::Temporal(temporal)));
    }

    if token == SystemAttributes::TOKEN {
        return Ok(Some(OptionToken::SysAttrs));
    }

    if KNOWN_TOKENS.iter().any(|known| known.eq_ignore_ascii_case(token)) {
        return Err(RepresentationError::MisspelledOption { option: token.to_owned() });
    }

    // An option belonging to another part of the API: `noOverwrite`, `update`, `replace`, and
    // whatever a later version adds. Not this crate's business.
    Ok(None)
}

/// Every token this crate owns, used only to tell a misspelling from a stranger.
const KNOWN_TOKENS: &[&str] = &[
    "keyValues",
    "concise",
    "normalized",
    "temporalValues",
    "aggregatedValues",
    SystemAttributes::TOKEN,
];

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn parse(options: &str) -> RepresentationSelection {
        RepresentationSelection::parse(Some(options), None).expect("the options should parse")
    }

    #[test]
    fn a_request_with_no_options_is_normalized_without_system_attributes() {
        let selection = RepresentationSelection::parse(None, None).unwrap();

        assert_eq!(selection.representation(), Representation::Normalized);
        assert_eq!(selection.system_attributes(), SystemAttributes::Omitted);
        assert_eq!(selection, RepresentationSelection::default());
    }

    #[test]
    fn each_representation_token_selects_its_representation() {
        assert_eq!(parse("keyValues").representation(), Representation::Simplified);
        assert_eq!(parse("concise").representation(), Representation::Concise);
        assert_eq!(parse("normalized").representation(), Representation::Normalized);
    }

    #[test]
    fn sys_attrs_is_independent_of_the_representation() {
        let selection = parse("keyValues,sysAttrs");

        assert_eq!(selection.representation(), Representation::Simplified);
        assert!(selection.system_attributes().is_included());
        assert!(!parse("keyValues").system_attributes().is_included());
    }

    #[test]
    fn key_values_together_with_concise_is_refused_rather_than_resolved() {
        // Brokers disagree about which token wins, so a proxy that picked one would be describing a
        // response the broker did not send.
        assert_eq!(
            RepresentationSelection::parse(Some("keyValues,concise"), None),
            Err(RepresentationError::ContradictoryOptions {
                first: Representation::Simplified,
                second: Representation::Concise,
            })
        );
        assert_eq!(
            RepresentationSelection::parse(Some("concise,keyValues"), None),
            Err(RepresentationError::ContradictoryOptions {
                first: Representation::Concise,
                second: Representation::Simplified,
            })
        );
    }

    #[test]
    fn any_two_disagreeing_representation_tokens_are_refused() {
        assert!(matches!(
            RepresentationSelection::parse(Some("normalized,concise"), None),
            Err(RepresentationError::ContradictoryOptions { .. })
        ));
        assert!(matches!(
            RepresentationSelection::parse(Some("normalized,keyValues"), None),
            Err(RepresentationError::ContradictoryOptions { .. })
        ));
    }

    #[test]
    fn a_representation_token_repeated_is_not_a_contradiction() {
        assert_eq!(parse("concise,concise").representation(), Representation::Concise);
    }

    #[test]
    fn a_temporal_format_is_read_from_options_or_from_format() {
        // Clause 6.3.12 names both, and `format` takes precedence over `options`.
        assert_eq!(parse("temporalValues").temporal(), TemporalRepresentation::Simplified);
        assert_eq!(parse("aggregatedValues,sysAttrs").temporal(), TemporalRepresentation::Aggregated);
        assert_eq!(parse("sysAttrs").temporal(), TemporalRepresentation::Instances);
        assert_eq!(
            RepresentationSelection::parse(None, Some("temporalValues")).map(RepresentationSelection::temporal),
            Ok(TemporalRepresentation::Simplified)
        );
        assert_eq!(
            RepresentationSelection::parse(Some("temporalValues"), Some("aggregatedValues")).map(RepresentationSelection::temporal),
            Ok(TemporalRepresentation::Aggregated)
        );
    }

    #[test]
    fn a_temporal_format_leaves_the_entity_shape_to_options() {
        let selection = RepresentationSelection::parse(Some("concise"), Some("temporalValues")).unwrap();

        assert_eq!(selection.representation(), Representation::Concise);
        assert_eq!(selection.temporal(), TemporalRepresentation::Simplified);
    }

    #[test]
    fn both_temporal_formats_in_options_are_refused() {
        assert_eq!(
            RepresentationSelection::parse(Some("temporalValues,aggregatedValues"), None),
            Err(RepresentationError::ContradictoryTemporalOptions {
                first: TemporalRepresentation::Simplified,
                second: TemporalRepresentation::Aggregated,
            })
        );
    }

    #[test]
    fn options_belonging_to_other_operations_are_passed_over() {
        // `options=noOverwrite` is legal on a batch upsert. Refusing it here would break a call
        // that has nothing to do with representations.
        let selection = parse("noOverwrite,sysAttrs,update");

        assert_eq!(selection.representation(), Representation::Normalized);
        assert!(selection.system_attributes().is_included());
    }

    #[test]
    fn a_token_that_differs_only_in_case_is_refused() {
        // Brokers compare these exactly, so `keyvalues` asks the broker for nothing at all.
        assert_eq!(
            RepresentationSelection::parse(Some("keyvalues"), None),
            Err(RepresentationError::MisspelledOption {
                option: "keyvalues".to_owned()
            })
        );
        assert!(matches!(
            RepresentationSelection::parse(Some("SysAttrs"), None),
            Err(RepresentationError::MisspelledOption { .. })
        ));
    }

    #[test]
    fn whitespace_and_empty_tokens_do_not_change_the_selection() {
        assert_eq!(parse(" keyValues , sysAttrs ").representation(), Representation::Simplified);
        assert!(parse(" keyValues , sysAttrs ").system_attributes().is_included());
        assert_eq!(parse(",,").representation(), Representation::Normalized);
        assert_eq!(parse("").representation(), Representation::Normalized);
    }

    #[test]
    fn the_format_parameter_selects_a_representation_on_its_own() {
        let selection = RepresentationSelection::parse(None, Some("concise")).unwrap();

        assert_eq!(selection.representation(), Representation::Concise);
    }

    #[test]
    fn format_and_options_agreeing_is_not_a_contradiction() {
        let selection = RepresentationSelection::parse(Some("keyValues,sysAttrs"), Some("keyValues")).unwrap();

        assert_eq!(selection.representation(), Representation::Simplified);
        assert!(selection.system_attributes().is_included());
    }

    #[test]
    fn format_disagreeing_with_options_is_refused() {
        assert_eq!(
            RepresentationSelection::parse(Some("keyValues"), Some("concise")),
            Err(RepresentationError::ContradictoryFormat {
                options: Representation::Simplified,
                format: Representation::Concise,
            })
        );
    }

    #[test]
    fn a_format_that_is_not_a_representation_is_refused() {
        assert_eq!(
            RepresentationSelection::parse(None, Some("pretty")),
            Err(RepresentationError::UnknownFormat { format: "pretty".to_owned() })
        );
        // Case matters here for the same reason it matters in `options`.
        assert!(matches!(
            RepresentationSelection::parse(None, Some("KeyValues")),
            Err(RepresentationError::UnknownFormat { .. })
        ));
    }

    #[test]
    fn an_empty_format_parameter_is_no_preference() {
        assert_eq!(
            RepresentationSelection::parse(None, Some("")).unwrap().representation(),
            Representation::Normalized
        );
        assert_eq!(
            RepresentationSelection::parse(Some("concise"), Some("  ")).unwrap().representation(),
            Representation::Concise
        );
    }

    #[test]
    fn a_response_representation_carries_both_halves_of_the_decision() {
        let response = ResponseRepresentation::parse(Some("application/ld+json"), Some("concise,sysAttrs"), None).unwrap();

        assert_eq!(response.representation(), Representation::Concise);
        assert!(response.system_attributes().is_included());
        assert_eq!(response.media_type(), MediaType::JsonLd);
        assert!(response.carries_inline_context());
        assert_eq!(
            response.selection(),
            RepresentationSelection::new(Representation::Concise, SystemAttributes::Included, TemporalRepresentation::Instances)
        );
    }

    #[test]
    fn a_plain_json_response_carries_its_context_in_a_link_header() {
        let response = ResponseRepresentation::parse(None, None, None).unwrap();

        assert_eq!(response.media_type(), MediaType::Json);
        assert!(!response.carries_inline_context());
    }

    #[test]
    fn a_contradiction_is_reported_before_the_accept_header_is_looked_at() {
        // The options are the caller's mistake; reporting an unacceptable media type instead would
        // send them looking in the wrong place.
        assert!(matches!(
            ResponseRepresentation::parse(Some("text/csv"), Some("keyValues,concise"), None),
            Err(RepresentationError::ContradictoryOptions { .. })
        ));
    }
}
