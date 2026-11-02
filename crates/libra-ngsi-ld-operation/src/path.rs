//! Splitting a request path into segments the broker would agree with.
//!
//! This is the part of classification that is a security decision rather than a parsing detail.
//! The proxy and the broker have to divide the same URL into the same segments, because the
//! segments are what say which resource is being touched. Anywhere the two could disagree, this
//! module refuses instead of picking a reading.
//!
//! Splitting happens on the **raw** path and decoding happens afterwards, per segment. Doing it
//! the other way round (decode, then split) turns an encoded separator into a real one and
//! changes which resource the path names. Some brokers do exactly that, which is why the check in
//! [`Segments::parse`] exists.

use crate::error::OperationError;
use derive_more::Display;
use percent_encoding::percent_decode_str;

/// The NGSI-LD API root, fixed by ETSI GS CIM 009.
pub const API_PREFIX: &str = "/ngsi-ld/v1";

/// One path segment, already percent-decoded and checked for traversal.
///
/// Distinct from a raw path piece: a decoded segment may legitimately contain `/` (an IRI-named
/// attribute), so it must never be spliced back into a path or split again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("{_0}")]
pub struct PathSegment(String);

impl PathSegment {
    /// The decoded segment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A request path already split, checked, and decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segments {
    segments: Vec<PathSegment>,
}

impl Segments {
    /// Splits an NGSI-LD path into its decoded segments.
    ///
    /// Returns `Ok(None)` when the path is not under the NGSI-LD API root at all (a management
    /// endpoint, a health probe, anything else the router owns). That is not an error; it is a
    /// statement that this crate has nothing to say about the path.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] when a segment is a dot segment, hides one behind percent
    /// encoding, or does not decode to UTF-8. Each of those is a case where another hop could read
    /// the path differently.
    pub fn parse(path: &str) -> Result<Option<Self>, OperationError> {
        // Tolerated rather than required: callers pass `Uri::path`, which never carries either.
        // Accepting them costs nothing and turns a caller's slip into correct behaviour instead of
        // a silent `None`, which here would mean "not an NGSI-LD request" and skip every check.
        let path = path.split(['?', '#']).next().unwrap_or(path);

        let Some(rest) = path.strip_prefix(API_PREFIX) else {
            return Ok(None);
        };
        // `/ngsi-ld/v1beta` must not be read as the API root followed by `beta`.
        if !rest.is_empty() && !rest.starts_with('/') {
            return Ok(None);
        }

        let pieces: Vec<&str> = rest.split('/').collect();
        let last = pieces.len().saturating_sub(1);
        let mut segments = Vec::new();
        for (index, raw) in pieces.into_iter().enumerate() {
            // A leading and a trailing slash each produce an empty piece. NGSI-LD has no empty
            // segment, so dropping them makes `/entities` and `/entities/` the same resource,
            // which is what brokers do. An empty piece between two segments is different: one
            // server collapses `//` and another keeps it, so the two would name different paths.
            if raw.is_empty() {
                if index != 0 && index != last {
                    return Err(OperationError::AmbiguousSegment {
                        reason: "it is empty, between two others",
                    });
                }
                continue;
            }

            let decoded = percent_decode_str(raw)
                .decode_utf8()
                .map_err(|_| OperationError::UndecodableSegment { segment: raw.to_owned() })?;

            reject_hidden_traversal(&decoded)?;
            reject_truncation(&decoded)?;

            segments.push(PathSegment(decoded.into_owned()));
        }

        Ok(Some(Self { segments }))
    }

    /// The decoded segments, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[PathSegment] {
        &self.segments
    }

    /// How many segments follow the API root.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.segments.len()
    }

    /// Whether the path was the bare API root.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// The segment at `index`, if there is one.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&PathSegment> {
        self.segments.get(index)
    }
}

/// Refuses a decoded segment that would traverse if it were split again.
///
/// A decoded separator is not itself a problem: an attribute name is an IRI, so
/// `https%3A%2F%2Fexample.test%23speed` is both legal and routine, and refusing it would make
/// IRI-named attributes unreachable. What is a problem is a decoded separator next to a dot
/// segment. `urn:x%2F..%2F..%2Fsubscriptions` splits, raw, into one entity identifier, so Libra
/// enforces entity rules, while a broker that decodes before splitting resolves it to
/// `/subscriptions` and serves something else entirely.
fn reject_hidden_traversal(decoded: &str) -> Result<(), OperationError> {
    if decoded.split('/').any(|piece| piece == "." || piece == "..") {
        return Err(OperationError::RelativeSegment);
    }

    Ok(())
}

/// Refuses a decoded segment another hop could cut short.
///
/// Servlet containers strip `;`-introduced path parameters before routing, a NUL or another control
/// character ends the segment for C-based servers, and a backslash is read as a separator by some. Each
/// would have the broker serve a resource other than the one whose segment Libra judged.
fn reject_truncation(decoded: &str) -> Result<(), OperationError> {
    if decoded.contains(';') {
        return Err(OperationError::AmbiguousSegment {
            reason: "it contains ';', which some servers read as the start of path parameters",
        });
    }
    if decoded.contains('\\') {
        return Err(OperationError::AmbiguousSegment {
            reason: "it contains '\\', which some servers read as a separator",
        });
    }
    if decoded.chars().any(char::is_control) {
        return Err(OperationError::AmbiguousSegment {
            reason: "it contains a control character",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn segments(path: &str) -> Vec<String> {
        Segments::parse(path)
            .expect("the path should parse")
            .expect("the path should be under the API root")
            .as_slice()
            .iter()
            .map(|segment| segment.as_str().to_owned())
            .collect()
    }

    #[test]
    fn a_path_outside_the_api_root_is_not_this_crates_business() {
        assert_eq!(Segments::parse("/health"), Ok(None));
        assert_eq!(Segments::parse("/metrics"), Ok(None));
    }

    #[test]
    fn a_prefix_that_only_looks_like_the_api_root_is_not_one() {
        // `/ngsi-ld/v1beta/entities` shares the first characters but is a different API. Reading
        // it as the root plus `beta` would apply entity rules to something else.
        assert_eq!(Segments::parse("/ngsi-ld/v1beta/entities"), Ok(None));
    }

    #[test]
    fn a_trailing_slash_does_not_change_the_resource() {
        assert_eq!(segments("/ngsi-ld/v1/entities"), segments("/ngsi-ld/v1/entities/"));
    }

    #[test]
    fn a_query_string_is_not_part_of_the_path() {
        assert_eq!(segments("/ngsi-ld/v1/entities?type=Vehicle"), vec!["entities".to_owned()]);
    }

    #[test]
    fn segments_are_percent_decoded() {
        // Attribute names are IRIs on the wire, so they arrive encoded, separators included.
        assert_eq!(
            segments("/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/https%3A%2F%2Fexample.test%23speed"),
            vec![
                "entities".to_owned(),
                "urn:ngsi-ld:Vehicle:1".to_owned(),
                "attrs".to_owned(),
                "https://example.test#speed".to_owned(),
            ],
            "an encoded IRI attribute must decode to the IRI"
        );
    }

    #[test]
    fn splitting_happens_before_decoding() {
        // Raw-split, this is two segments; decode-split, it would be four. The proxy must read
        // the first, because that is what the path literally says.
        assert_eq!(segments("/ngsi-ld/v1/entities%2Ffoo/bar"), vec!["entities/foo".to_owned(), "bar".to_owned()]);
    }

    #[test]
    fn an_encoded_separator_next_to_a_dot_segment_is_refused() {
        // The bypass this check exists for: raw-split it is one entity identifier, so Libra would
        // enforce entity rules, while a broker that decodes before splitting resolves it to
        // `/subscriptions` and answers with something no entity policy governs.
        let refused = Segments::parse("/ngsi-ld/v1/entities/urn:x%2F..%2F..%2Fsubscriptions");

        assert_eq!(refused, Err(OperationError::RelativeSegment));
    }

    #[test]
    fn a_dot_segment_is_refused() {
        assert_eq!(Segments::parse("/ngsi-ld/v1/entities/../types"), Err(OperationError::RelativeSegment));
        assert_eq!(Segments::parse("/ngsi-ld/v1/entities/%2E%2E/types"), Err(OperationError::RelativeSegment));
    }

    #[test]
    fn the_bare_api_root_has_no_segments() {
        assert!(
            Segments::parse("/ngsi-ld/v1")
                .expect("the path should parse")
                .expect("the path should be under the API root")
                .is_empty()
        );
    }

    fn ambiguous(path: &str) -> bool {
        matches!(Segments::parse(path), Err(OperationError::AmbiguousSegment { .. }))
    }

    #[test]
    fn a_segment_carrying_path_parameters_is_refused_raw_or_encoded() {
        assert!(ambiguous("/ngsi-ld/v1/entities/urn:secret;x"));
        assert!(ambiguous("/ngsi-ld/v1/entities/urn:secret%3Bx"));
    }

    #[test]
    fn a_segment_carrying_a_backslash_is_refused() {
        assert!(ambiguous("/ngsi-ld/v1/entities/urn:a%5C..%5Csubscriptions"));
    }

    #[test]
    fn a_segment_carrying_a_nul_or_a_control_character_is_refused() {
        assert!(ambiguous("/ngsi-ld/v1/entities/urn:secret%00.public"));
        assert!(ambiguous("/ngsi-ld/v1/entities/urn:a%0Ab"));
    }

    #[test]
    fn an_empty_interior_segment_is_refused() {
        assert!(ambiguous("/ngsi-ld/v1/entities//urn:a"));
    }

    #[test]
    fn a_trailing_slash_still_names_the_same_resource() {
        assert_eq!(segments("/ngsi-ld/v1/entities/"), vec!["entities".to_owned()]);
    }
}
