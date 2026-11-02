//! RFC 8288 `Link` header parsing, enough of it to find a context.
//!
//! An `application/json` NGSI-LD request carries its context in a `Link` header rather than in the
//! body. Getting this parse wrong is not a formatting problem: miss a link and the request is
//! interpreted against the wrong context, which is how a policy written for one term ends up
//! matching another.

use iri_rs::{Iri, IriRefBuf};
use std::str::FromStr;
use strum::EnumString;

/// The name of a link-param (RFC 8288 section 3).
///
/// Parameter names are case-insensitive (RFC 8288 section 3), so the names the specification
/// defines are matched without regard to case, and any other name is kept lowercased so two
/// spellings of one extension parameter compare equal.
#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum ParamName {
    /// `rel`, the relation types (RFC 8288 section 3.3).
    Rel,
    /// `anchor`, the context IRI (RFC 8288 section 3.2).
    Anchor,
    /// `rev`, the deprecated reverse relation (RFC 8288 section 3.3).
    Rev,
    /// `hreflang`, the target's language (RFC 8288 section 3.4.1).
    Hreflang,
    /// `media`, the target's intended media (RFC 8288 section 3.4.1).
    Media,
    /// `title`, a human-readable label (RFC 8288 section 3.4.1).
    Title,
    /// `title*`, a label in another character set (RFC 8288 section 3.4.1).
    #[strum(serialize = "title*")]
    TitleExtended,
    /// `type`, a hint at the target's media type (RFC 8288 section 3.4.1).
    Type,
    /// A target attribute this parser does not define, lowercased.
    #[strum(default)]
    Extension(String),
}

/// One link-value from a `Link` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The URI reference between the angle brackets. It may be relative, so it is a reference rather
    /// than an absolute IRI.
    pub target: IriRefBuf,
    /// Parameters, in the order they appeared.
    pub params: Vec<(ParamName, String)>,
}

impl Link {
    /// The first value of `name`, if present.
    #[must_use]
    pub fn param(&self, name: &ParamName) -> Option<&str> {
        self.params.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// Whether this link declares the given extension relation type.
    ///
    /// A `rel` parameter holds a space-separated list, so a link can declare several relations at
    /// once and still be the one Libra is looking for. Relation types are compared case-insensitively
    /// (RFC 8288 section 2.1.1).
    #[must_use]
    pub fn has_relation(&self, relation: &Iri<&str>) -> bool {
        self.param(&ParamName::Rel)
            .is_some_and(|value| value.split_whitespace().any(|candidate| candidate.eq_ignore_ascii_case(relation.as_str())))
    }
}

/// A `Link` header that is not a well-formed RFC 8288 header.
#[derive(Debug, Clone, thiserror::Error)]
#[error("malformed Link header: {reason}")]
pub struct MalformedLink {
    /// What was wrong with it.
    pub reason: String,
}

/// Parses a `Link` header into its link-values.
///
/// A header that cannot be parsed is an error, not an empty result. Returning "no links" for
/// something the proxy failed to understand would let a caller supply a context that Libra reads
/// as absent and the broker reads as present: the two would then be enforcing and storing under
/// different meanings for the same names. Failing here turns that into a 400.
///
/// # Errors
///
/// Returns [`MalformedLink`] if the header contains anything that is not a link-value: text
/// outside angle brackets, a target with no closing bracket, or a target that is not a URI
/// reference.
pub fn parse(header: &str) -> Result<Vec<Link>, MalformedLink> {
    let mut links = Vec::new();
    let mut rest = header;

    loop {
        let trimmed = rest.trim_start().trim_start_matches(',').trim_start();
        if trimmed.is_empty() {
            return Ok(links);
        }

        let Some(after_open) = trimmed.strip_prefix('<') else {
            return Err(MalformedLink {
                reason: "expected a link-value beginning with '<'".to_owned(),
            });
        };

        let Some(close) = after_open.find('>') else {
            return Err(MalformedLink {
                reason: "a link target has no closing '>'".to_owned(),
            });
        };

        let target_text = after_open[..close].trim();
        let target = IriRefBuf::new(target_text.to_owned()).map_err(|_| MalformedLink {
            reason: "a link target is not a valid URI reference".to_owned(),
        })?;
        let tail = &after_open[close + 1..];

        // Parameters run to the comma that separates this link-value from the next, but a comma
        // inside a quoted string belongs to the parameter, not to the header.
        let (params_text, remainder) = split_at_unquoted_comma(tail);

        links.push(Link {
            target,
            params: parse_params(params_text),
        });
        rest = remainder;
    }
}

/// Splits at the first comma that is not inside a quoted string.
fn split_at_unquoted_comma(text: &str) -> (&str, &str) {
    let mut quoted = false;
    let mut escaped = false;

    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => return (&text[..index], &text[index + 1..]),
            _ => {}
        }
    }

    (text, "")
}

fn parse_params(text: &str) -> Vec<(ParamName, String)> {
    let mut params = Vec::new();
    let mut rest = text;

    while !rest.is_empty() {
        let trimmed = rest.trim_start().trim_start_matches(';');
        if trimmed.is_empty() {
            break;
        }

        let (segment, remainder) = split_at_unquoted_semicolon(trimmed);
        rest = remainder;

        let Some((name, value)) = segment.split_once('=') else {
            continue;
        };

        // The `Extension` variant is the parse default, so the parse cannot fail.
        let Ok(name) = ParamName::from_str(&name.trim().to_ascii_lowercase());

        params.push((name, unquote(value.trim())));
    }

    params
}

fn split_at_unquoted_semicolon(text: &str) -> (&str, &str) {
    let mut quoted = false;
    let mut escaped = false;

    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => return (&text[..index], &text[index + 1..]),
            _ => {}
        }
    }

    (text, "")
}

fn unquote(value: &str) -> String {
    let Some(inner) = value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) else {
        return value.to_owned();
    };

    let mut unescaped = String::with_capacity(inner.len());
    let mut escaped = false;

    for character in inner.chars() {
        if escaped {
            unescaped.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            unescaped.push(character);
        }
    }

    unescaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use iri_rs::iri;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_a_single_link() {
        let links = parse(r#"<https://example.test/context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json""#).unwrap();

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].target.as_str(), "https://example.test/context.jsonld");
        assert_eq!(links[0].param(&ParamName::Rel), Some("http://www.w3.org/ns/json-ld#context"));
        assert_eq!(links[0].param(&ParamName::Type), Some("application/ld+json"));
    }

    #[test]
    fn parses_several_links() {
        let links = parse(r#"<https://a.test/one.jsonld>; rel="ctx", <https://b.test/two.jsonld>; rel="ctx""#).unwrap();

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].target.as_str(), "https://a.test/one.jsonld");
        assert_eq!(links[1].target.as_str(), "https://b.test/two.jsonld");
    }

    #[test]
    fn a_comma_inside_a_quoted_parameter_does_not_split_the_header() {
        let links = parse(r#"<https://a.test/one.jsonld>; title="one, two"; rel="ctx""#).unwrap();

        assert_eq!(links.len(), 1, "a quoted comma must not be read as a link separator");
        assert_eq!(links[0].param(&ParamName::Title), Some("one, two"));
        assert_eq!(links[0].param(&ParamName::Rel), Some("ctx"));
    }

    #[test]
    fn a_semicolon_inside_a_quoted_parameter_does_not_split_the_parameters() {
        let links = parse(r#"<https://a.test/one.jsonld>; title="a; b"; rel="ctx""#).unwrap();

        assert_eq!(links[0].param(&ParamName::Title), Some("a; b"));
        assert_eq!(links[0].param(&ParamName::Rel), Some("ctx"));
    }

    #[test]
    fn escaped_quotes_survive() {
        let links = parse(r#"<https://a.test/one.jsonld>; title="say \"hi\""; rel="ctx""#).unwrap();

        assert_eq!(links[0].param(&ParamName::Title), Some(r#"say "hi""#));
        assert_eq!(links[0].param(&ParamName::Rel), Some("ctx"));
    }

    #[test]
    fn parameter_names_are_case_insensitive() {
        let links = parse(r#"<https://a.test/one.jsonld>; REL="ctx"; Type="application/ld+json""#).unwrap();

        assert_eq!(links[0].param(&ParamName::Rel), Some("ctx"));
        assert_eq!(links[0].param(&ParamName::Type), Some("application/ld+json"));
    }

    #[test]
    fn a_relation_list_matches_any_of_its_members() {
        let links = parse(r#"<https://a.test/one.jsonld>; rel="alternate http://www.w3.org/ns/json-ld#context https://example.test/rel""#).unwrap();

        assert!(links[0].has_relation(&iri!("http://www.w3.org/ns/json-ld#context")));
        assert!(links[0].has_relation(&iri!("https://example.test/rel")));
        assert!(!links[0].has_relation(&iri!("https://example.test/other")));
        assert_eq!(
            links[0].param(&ParamName::Rel),
            Some("alternate http://www.w3.org/ns/json-ld#context https://example.test/rel")
        );
    }

    #[test]
    fn an_unknown_parameter_name_is_kept_lowercased() {
        let links = parse(r#"<https://a.test/one.jsonld>; X-Custom="value""#).unwrap();

        assert_eq!(links[0].param(&ParamName::Extension("x-custom".to_owned())), Some("value"));
    }

    #[test]
    fn the_extended_title_is_its_own_parameter() {
        let links = parse(r#"<https://a.test/one.jsonld>; title*="UTF-8'en'one"; title="two""#).unwrap();

        assert_eq!(links[0].param(&ParamName::TitleExtended), Some("UTF-8'en'one"));
        assert_eq!(links[0].param(&ParamName::Title), Some("two"));
    }

    #[test]
    fn an_unterminated_link_is_an_error_rather_than_no_links() {
        // Silently reading this as "no context supplied" would resolve the request against the
        // core context while the broker resolves it against whatever it managed to read.
        let error = parse(r#"<https://a.test/one.jsonld; rel="ctx""#).expect_err("must not be treated as absent");

        assert!(error.reason.contains("closing"));
    }

    #[test]
    fn a_target_that_is_not_a_uri_reference_is_an_error() {
        let error = parse(r#"<https://a.test/one two.jsonld>; rel="ctx""#).expect_err("a space is not legal in a URI reference");

        assert!(error.reason.contains("URI reference"));
    }

    #[test]
    fn a_relative_target_is_a_valid_uri_reference() {
        let links = parse(r#"</entities?page=2>; rel="next""#).unwrap();

        assert_eq!(links[0].target.as_str(), "/entities?page=2");
    }

    #[test]
    fn text_outside_a_link_value_is_an_error() {
        assert!(parse("garbage").is_err());
        assert!(parse(r#"<https://a.test/one.jsonld>; rel="ctx", garbage"#).is_err());
    }

    #[test]
    fn an_empty_header_yields_nothing() {
        assert_eq!(parse("").unwrap(), [] as [_; 0]);
        assert_eq!(parse("   ").unwrap(), [] as [_; 0]);
    }
}
