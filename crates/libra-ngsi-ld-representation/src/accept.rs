//! Negotiating the response media type from an `Accept` header.
//!
//! Normalisation here is deliberately the same as the context layer's `Content-Type` handling:
//! split at `;`, trim, compare case-insensitively. The two have to agree. That one decides where a
//! *request* carries its context, this one decides
//! where a *response* will carry it, and a proxy that read `application/ld+json` one way going in
//! and another way coming out would resolve a request against a context it then failed to find.

use crate::error::RepresentationError;
use derive_more::Display;

/// A media type Libra is able to produce for an NGSI-LD response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
#[display("{}", self.as_str())]
pub enum MediaType {
    /// `application/json`. The JSON-LD context travels in a `Link` header, not in the body.
    ///
    /// The default: NGSI-LD names it as the representation a request with no stated preference
    /// receives.
    #[default]
    Json,
    /// `application/ld+json`. The context is an `@context` member of the body.
    JsonLd,
    /// `application/geo+json`. The `GeoJSON` encoding, whose body also carries the context inline.
    GeoJson,
}

impl MediaType {
    /// The media type as it is written in a header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::JsonLd => "application/ld+json",
            Self::GeoJson => "application/geo+json",
        }
    }

    /// Whether the response body carries its own `@context`.
    ///
    /// This is the question anything that rewrites a response body has to answer before it edits
    /// one. `application/ld+json` and `application/geo+json` put the context in the body, so a
    /// rewrite has to preserve that member; `application/json` puts it in a `Link` header
    /// instead, so a rewrite that added an `@context` member to the body would produce a response
    /// the broker would never have sent, and one the NGSI-LD rules for `application/json` forbid.
    #[must_use]
    pub const fn carries_inline_context(self) -> bool {
        match self {
            Self::JsonLd | Self::GeoJson => true,
            Self::Json => false,
        }
    }

    /// Picks the response media type for an `Accept` header.
    ///
    /// An absent or empty header means no preference, which is `application/json`. A header that
    /// states preferences is resolved by RFC 9110 section 12.5.1: the most specific matching range
    /// supplies a candidate's quality, the highest quality wins, and ties go to whichever the
    /// caller listed first. A quality of zero rejects a type outright.
    ///
    /// # Errors
    ///
    /// Returns [`RepresentationError::NotAcceptable`] when every type Libra can produce is either
    /// unmatched or explicitly rejected.
    pub fn negotiate(accept: Option<&str>) -> Result<Self, RepresentationError> {
        let Some(header) = accept else {
            return Ok(Self::Json);
        };

        if header.trim().is_empty() {
            return Ok(Self::Json);
        }

        let ranges = parse_ranges(header);

        // Listed in the order a tie is broken in: with `Accept: */*` every candidate matches the
        // same range with the same quality, and NGSI-LD's default is plain JSON.
        let candidates = [Self::Json, Self::JsonLd, Self::GeoJson];

        let mut best: Option<(Match, Self)> = None;

        for candidate in candidates {
            let Some(matched) = best_match(&ranges, candidate) else {
                continue;
            };

            // Quality zero is not a weak preference, it is a refusal.
            if matched.quality == 0 {
                continue;
            }

            let better = match &best {
                None => true,
                Some((incumbent, _)) => matched.beats(*incumbent),
            };

            if better {
                best = Some((matched, candidate));
            }
        }

        best.map(|(_, candidate)| candidate).ok_or_else(|| RepresentationError::NotAcceptable {
            accept: header.trim().to_owned(),
        })
    }

    /// Reads the media type a `Content-Type` header names, if Libra can produce it.
    ///
    /// [`MediaType::negotiate`] answers what the caller asked for; this answers what the broker
    /// actually sent, which is the authoritative question for anything that rewrites a response
    /// body. The two are not the same answer: a broker is entitled to send `application/json` to a
    /// caller who asked for `application/ld+json`, and a rewrite driven by the request would then
    /// edit a document of a shape that never arrived.
    ///
    /// A type outside the three is `None` rather than a default, because a body Libra cannot name
    /// is a body it must not edit.
    #[must_use]
    pub fn from_content_type(value: Option<&str>) -> Option<Self> {
        Self::from_essence(essence_of(value?))
    }

    /// The media type whose essence (no parameters) is `essence`, compared case-insensitively.
    fn from_essence(essence: &str) -> Option<Self> {
        [Self::Json, Self::JsonLd, Self::GeoJson]
            .into_iter()
            .find(|candidate| essence.eq_ignore_ascii_case(candidate.as_str()))
    }
}

/// The media type without its parameters.
///
/// Split at `;`, trimmed, and left for a case-insensitive comparison, the same normalisation
/// [`MediaType::negotiate`] applies to a range in an `Accept` header, and the same one
/// the context channel check applies to a request's `Content-Type`. All three have to
/// agree about what `application/ld+json` is.
fn essence_of(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

/// What a media range in an `Accept` header names, among the types Libra can produce.
#[derive(Clone, Copy)]
enum RangeKind {
    /// `*/*`.
    Wildcard,
    /// `application/*`. Every type Libra produces is an `application` type.
    Application,
    /// A type Libra can produce, named outright.
    Exact(MediaType),
}

impl RangeKind {
    /// Reads a range's type part. A range naming a type Libra cannot produce is `None`: it can
    /// never match a candidate, so it takes no part in negotiation.
    fn parse(range: &str) -> Option<Self> {
        if range == "*/*" {
            return Some(Self::Wildcard);
        }

        if range.eq_ignore_ascii_case("application/*") {
            return Some(Self::Application);
        }

        MediaType::from_essence(range).map(Self::Exact)
    }

    /// How specifically this range names `candidate`, or `None` if it does not name it.
    fn specificity_for(self, candidate: MediaType) -> Option<u8> {
        match self {
            Self::Exact(named) if named == candidate => Some(2),
            Self::Exact(_) => None,
            Self::Application => Some(1),
            Self::Wildcard => Some(0),
        }
    }
}

/// One media range from the header, reduced to what negotiation needs.
struct Range {
    kind: RangeKind,
    /// Thousandths, so two qualities compare as integers. RFC 9110 allows at most three decimals,
    /// so nothing is lost, and comparing floats for equality here would make a tie-break depend
    /// on how `0.7` happens to round.
    quality: u16,
    position: usize,
}

/// How well one range matched one candidate.
#[derive(Clone, Copy)]
struct Match {
    quality: u16,
    /// 2 for an exact type, 1 for `application/*`, 0 for `*/*`. RFC 9110 section 12.5.1 gives the
    /// most specific matching range precedence, so this decides which range supplies the quality.
    specificity: u8,
    position: usize,
}

impl Match {
    /// Whether this match should win over one already held.
    fn beats(self, other: Self) -> bool {
        (self.quality, self.specificity) > (other.quality, other.specificity)
            || (self.quality, self.specificity) == (other.quality, other.specificity) && self.position < other.position
    }
}

/// Splits the header into ranges, dropping any whose quality cannot be read.
///
/// A malformed `q` is dropped rather than treated as full preference: the range says the caller
/// meant something by it, and guessing which end of the scale they meant is how a client that
/// asked for one type gets another.
fn parse_ranges(header: &str) -> Vec<Range> {
    let mut ranges = Vec::new();

    for (position, entry) in header.split(',').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let mut pieces = entry.split(';');
        let media_type = pieces.next().unwrap_or_default().trim();

        if media_type.is_empty() {
            continue;
        }

        let mut quality = 1000;
        let mut malformed = false;

        for parameter in pieces {
            let Some((name, value)) = parameter.split_once('=') else {
                continue;
            };

            if !name.trim().eq_ignore_ascii_case("q") {
                continue;
            }

            match parse_quality(value.trim()) {
                Some(parsed) => quality = parsed,
                None => malformed = true,
            }
        }

        if malformed {
            continue;
        }

        let Some(kind) = RangeKind::parse(media_type) else {
            continue;
        };

        ranges.push(Range { kind, quality, position });
    }

    ranges
}

/// Reads an RFC 9110 qvalue into thousandths.
///
/// `0`, `0.5`, `0.750` and `1` are qvalues; `1.5`, `high` and `0.5000` are not.
fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));

    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let scaled = match whole {
        "0" => 0,
        // A qvalue above one does not exist, so `1.5` is not a strong preference but a malformed
        // header, and `1.001` is the same mistake written smaller.
        "1" if fraction.bytes().all(|byte| byte == b'0') => 1000,
        _ => return None,
    };

    if scaled == 1000 {
        return Some(1000);
    }

    // `0.5` and `0.500` are the same qvalue, so the fraction is read as thousandths either way.
    format!("{fraction:0<3}").parse::<u16>().ok()
}

/// The most specific range matching this candidate, if any matches at all.
fn best_match(ranges: &[Range], candidate: MediaType) -> Option<Match> {
    let mut best: Option<Match> = None;

    for range in ranges {
        let Some(specificity) = range.kind.specificity_for(candidate) else {
            continue;
        };

        let matched = Match {
            quality: range.quality,
            specificity,
            position: range.position,
        };

        let better = match &best {
            None => true,
            // Precedence is by specificity alone here: a `*/*; q=1` must not override an
            // `application/json; q=0` that names the type outright.
            Some(incumbent) => matched.specificity > incumbent.specificity,
        };

        if better {
            best = Some(matched);
        }
    }

    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn negotiate(accept: &str) -> MediaType {
        MediaType::negotiate(Some(accept)).expect("the header should be acceptable")
    }

    #[test]
    fn an_absent_accept_header_is_plain_json() {
        assert_eq!(MediaType::negotiate(None).unwrap(), MediaType::Json);
    }

    #[test]
    fn an_empty_accept_header_is_plain_json() {
        assert_eq!(negotiate(""), MediaType::Json);
        assert_eq!(negotiate("   "), MediaType::Json);
    }

    #[test]
    fn a_wildcard_accept_header_is_plain_json() {
        assert_eq!(negotiate("*/*"), MediaType::Json);
        assert_eq!(negotiate("application/*"), MediaType::Json);
    }

    #[test]
    fn each_producible_type_is_negotiable_by_name() {
        assert_eq!(negotiate("application/json"), MediaType::Json);
        assert_eq!(negotiate("application/ld+json"), MediaType::JsonLd);
        assert_eq!(negotiate("application/geo+json"), MediaType::GeoJson);
    }

    #[test]
    fn media_type_parameters_do_not_change_the_match() {
        // Split at `;`, trimmed and compared case-insensitively, as the context channel check does for
        // Content-Type. The two must agree about what ld+json is.
        assert_eq!(negotiate("application/ld+json; charset=utf-8"), MediaType::JsonLd);
        assert_eq!(negotiate("  application/ld+json  "), MediaType::JsonLd);
    }

    #[test]
    fn a_media_type_matches_case_insensitively() {
        assert_eq!(negotiate("APPLICATION/LD+JSON"), MediaType::JsonLd);
        assert_eq!(negotiate("Application/Geo+Json"), MediaType::GeoJson);
    }

    #[test]
    fn the_highest_quality_wins() {
        assert_eq!(negotiate("application/json;q=0.5, application/ld+json;q=0.9"), MediaType::JsonLd);
        assert_eq!(negotiate("application/ld+json;q=0.2, application/json;q=0.8"), MediaType::Json);
    }

    #[test]
    fn a_tie_goes_to_whichever_the_caller_listed_first() {
        assert_eq!(negotiate("application/ld+json, application/json"), MediaType::JsonLd);
        assert_eq!(negotiate("application/json, application/ld+json"), MediaType::Json);
    }

    #[test]
    fn a_named_type_overrides_a_wildcard_that_would_score_higher() {
        // RFC 9110 section 12.5.1: the most specific matching range supplies the quality. Reading
        // it the other way round would serve ld+json to a caller who explicitly refused it.
        assert_eq!(negotiate("*/*, application/ld+json;q=0"), MediaType::Json);
        assert_eq!(negotiate("application/*;q=0.1, application/geo+json;q=0.9"), MediaType::GeoJson);
    }

    #[test]
    fn a_quality_of_zero_refuses_the_type() {
        assert_eq!(negotiate("application/json;q=0, application/ld+json"), MediaType::JsonLd);

        let refused = MediaType::negotiate(Some("application/json;q=0"));
        assert_eq!(
            refused,
            Err(RepresentationError::NotAcceptable {
                accept: "application/json;q=0".to_owned()
            })
        );
    }

    #[test]
    fn a_type_libra_cannot_produce_is_not_acceptable() {
        assert!(matches!(MediaType::negotiate(Some("text/csv")), Err(RepresentationError::NotAcceptable { .. })));
        assert!(matches!(
            MediaType::negotiate(Some("text/*, image/png")),
            Err(RepresentationError::NotAcceptable { .. })
        ));
    }

    #[test]
    fn an_unproducible_type_alongside_a_producible_one_is_ignored() {
        assert_eq!(negotiate("text/csv;q=1.0, application/geo+json;q=0.1"), MediaType::GeoJson);
    }

    #[test]
    fn a_quality_parameter_is_read_case_insensitively() {
        assert_eq!(negotiate("application/json;Q=0.1, application/ld+json;q=0.2"), MediaType::JsonLd);
    }

    #[test]
    fn a_malformed_quality_drops_the_range_rather_than_guessing_at_it() {
        // `q=high` could mean anything. Treating it as full preference would hand the caller a
        // type they may have been trying to rank last.
        assert_eq!(negotiate("application/json;q=high, application/ld+json;q=0.1"), MediaType::JsonLd);
        assert!(matches!(
            MediaType::negotiate(Some("application/json;q=2")),
            Err(RepresentationError::NotAcceptable { .. })
        ));
    }

    #[test]
    fn qvalues_outside_the_legal_range_are_malformed() {
        assert_eq!(parse_quality("0"), Some(0));
        assert_eq!(parse_quality("1"), Some(1000));
        assert_eq!(parse_quality("1.0"), Some(1000));
        assert_eq!(parse_quality("1.000"), Some(1000));
        assert_eq!(parse_quality("0.5"), Some(500));
        assert_eq!(parse_quality("0.05"), Some(50));
        assert_eq!(parse_quality("0.750"), Some(750));
        assert_eq!(parse_quality("1.5"), None);
        assert_eq!(parse_quality("1.001"), None);
        assert_eq!(parse_quality("0.5000"), None);
        assert_eq!(parse_quality("-0.5"), None);
        assert_eq!(parse_quality(""), None);
        assert_eq!(parse_quality("high"), None);
    }

    #[test]
    fn only_ld_json_and_geo_json_carry_their_context_in_the_body() {
        assert!(!MediaType::Json.carries_inline_context());
        assert!(MediaType::JsonLd.carries_inline_context());
        assert!(MediaType::GeoJson.carries_inline_context());
    }

    #[test]
    fn an_empty_range_between_commas_is_skipped() {
        assert_eq!(negotiate("application/json, , application/ld+json"), MediaType::Json);
    }

    #[test]
    fn a_content_type_names_a_producible_media_type() {
        assert_eq!(MediaType::from_content_type(Some("application/json")), Some(MediaType::Json));
        assert_eq!(MediaType::from_content_type(Some("application/ld+json")), Some(MediaType::JsonLd));
        assert_eq!(MediaType::from_content_type(Some("application/geo+json")), Some(MediaType::GeoJson));
    }

    #[test]
    fn a_content_type_parameter_does_not_change_the_type() {
        assert_eq!(
            MediaType::from_content_type(Some("application/ld+json; charset=utf-8")),
            Some(MediaType::JsonLd)
        );
        assert_eq!(MediaType::from_content_type(Some("  application/geo+json  ")), Some(MediaType::GeoJson));
    }

    #[test]
    fn a_content_type_is_matched_without_regard_to_case() {
        assert_eq!(MediaType::from_content_type(Some("APPLICATION/JSON")), Some(MediaType::Json));
        assert_eq!(MediaType::from_content_type(Some("Application/Geo+Json")), Some(MediaType::GeoJson));
    }

    #[test]
    fn a_content_type_libra_cannot_produce_is_not_one() {
        // `None` rather than a default: a body whose type Libra cannot name is a body it must not
        // edit, and defaulting to JSON here would be deciding to edit it anyway.
        assert_eq!(MediaType::from_content_type(Some("text/csv")), None);
        assert_eq!(MediaType::from_content_type(Some("application/problem+json")), None);
        assert_eq!(MediaType::from_content_type(None), None);
    }
}
