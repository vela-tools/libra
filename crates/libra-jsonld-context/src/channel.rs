//! Which channel a request is allowed to carry its context on.
//!
//! NGSI-LD gives a request exactly one way to supply a context, decided by the content type. The
//! rules here are not a simplification of the specification: they are what a running Scorpio
//! broker does with each content type and context channel.
//!
//! Mirroring the broker exactly is the point. A request the broker would reject must not be
//! resolved by Libra under some context of its own choosing, because then the policy is evaluated
//! against a meaning the broker never agreed to.

use crate::error::ContextError;
use iri_rs::IriRefBuf;
use jstrict::Value;

/// Where the context for a request comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextChannel {
    /// An `@context` entry in an `application/ld+json` body.
    Body,
    /// A context `Link` header on an `application/json` request.
    LinkHeader,
    /// Nothing supplied: the configured default, or the core context alone.
    None,
}

/// Whether a request is `application/ld+json`, as far as context handling is concerned.
#[must_use]
pub fn is_ld_json(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        // Parameters such as `; charset=utf-8` are not part of the media type.
        let media_type = value.split(';').next().unwrap_or_default().trim();
        media_type.eq_ignore_ascii_case("application/ld+json")
    })
}

/// Decides which channel supplies this request's context, refusing the combinations the broker
/// refuses.
///
/// # Errors
///
/// Returns [`ContextError::LinkHeaderNotAllowed`] for an `application/ld+json` request that also
/// carries a context `Link` header, and [`ContextError::BodyContextNotAllowed`] for an
/// `application/json` request whose body contains `@context`. Both are 400s at the broker.
pub fn channel_for(content_type: Option<&str>, body_context: Option<&Value>, context_links: &[IriRefBuf]) -> Result<ContextChannel, ContextError> {
    if is_ld_json(content_type) {
        if !context_links.is_empty() {
            return Err(ContextError::LinkHeaderNotAllowed);
        }

        return Ok(body_context.map_or(ContextChannel::None, |_| ContextChannel::Body));
    }

    if body_context.is_some() {
        return Err(ContextError::BodyContextNotAllowed);
    }

    Ok(if context_links.is_empty() {
        ContextChannel::None
    } else {
        ContextChannel::LinkHeader
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::Parse;
    use pretty_assertions::assert_eq;

    const LD_JSON: Option<&str> = Some("application/ld+json");
    const JSON: Option<&str> = Some("application/json");
    const LINK: &str = "https://example.test/context.jsonld";

    /// The channel for a request carrying this body context and these context links.
    fn channel(content_type: Option<&str>, body_context: Option<&str>, links: &[&str]) -> Result<ContextChannel, ContextError> {
        let body_context = body_context.map(|source| Value::parse_str(source).unwrap().0);
        let links: Vec<IriRefBuf> = links.iter().map(|link| IriRefBuf::new((*link).to_owned()).unwrap()).collect();

        channel_for(content_type, body_context.as_ref(), &links)
    }

    #[test]
    fn an_ld_json_body_carries_its_own_context() {
        assert_eq!(channel(LD_JSON, Some("{}"), &[]).unwrap(), ContextChannel::Body);
    }

    #[test]
    fn a_json_request_carries_its_context_in_a_link_header() {
        assert_eq!(channel(JSON, None, &[LINK]).unwrap(), ContextChannel::LinkHeader);
    }

    #[test]
    fn a_link_header_with_ld_json_is_refused() {
        // Scorpio answers 400 "You can not have a Link to a context is content-type
        // application/ld+json".
        assert!(matches!(channel(LD_JSON, Some("{}"), &[LINK]), Err(ContextError::LinkHeaderNotAllowed)));
        assert!(matches!(channel(LD_JSON, None, &[LINK]), Err(ContextError::LinkHeaderNotAllowed)));
    }

    #[test]
    fn a_body_context_with_plain_json_is_refused() {
        // Scorpio answers 400 "@context entry in body is not allowed".
        assert!(matches!(channel(JSON, Some("{}"), &[]), Err(ContextError::BodyContextNotAllowed)));
    }

    #[test]
    fn no_context_anywhere_is_not_an_error_here() {
        // The core context still applies, so this is resolvable; it is the resolver's decision,
        // not this function's.
        assert_eq!(channel(JSON, None, &[]).unwrap(), ContextChannel::None);
        assert_eq!(channel(LD_JSON, None, &[]).unwrap(), ContextChannel::None);
        assert_eq!(channel(None, None, &[]).unwrap(), ContextChannel::None);
    }

    #[test]
    fn media_type_parameters_do_not_change_the_channel() {
        assert_eq!(
            channel(Some("application/ld+json; charset=utf-8"), Some("{}"), &[]).unwrap(),
            ContextChannel::Body
        );
        assert!(matches!(
            channel(Some("APPLICATION/LD+JSON"), None, &[LINK]),
            Err(ContextError::LinkHeaderNotAllowed)
        ));
    }

    #[test]
    fn an_unknown_content_type_is_treated_as_plain_json() {
        // Anything that is not ld+json cannot carry a body context, so the strict rule applies.
        assert!(matches!(channel(Some("text/plain"), Some("{}"), &[]), Err(ContextError::BodyContextNotAllowed)));
    }
}
