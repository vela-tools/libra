//! The address every forwarded request is built on.

use crate::error::ProxyError;
use derive_more::Display;
use http::{Uri, uri::InvalidUri};
use std::sync::Arc;
use url::Url;

/// An upstream checked to be forwardable, without its trailing slash.
///
/// Kept as text rather than as a [`Url`] because a request target is appended to it verbatim:
/// the path and query a request arrived with are still percent-encoded, and joining them through a
/// URL parser could decode and re-encode a separator, so Libra would have enforced the rules for
/// one resource while the broker served another.
///
/// Shared, because every clone of the proxy service carries it.
#[derive(Debug, Clone, PartialEq, Eq, Display)]
#[display("{_0}")]
pub struct UpstreamBase(Arc<str>);

impl UpstreamBase {
    /// The upstream target for a request's path and query, as they arrived.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidUri`] if the joined text is not a URI.
    pub fn target(&self, path_and_query: &str) -> Result<Uri, InvalidUri> {
        Uri::try_from(format!("{}{path_and_query}", self.0))
    }

    /// What is left of `reference` once this upstream is taken off its front, or `None` if
    /// `reference` does not start with it.
    ///
    /// The scheme and authority compare without regard to case (RFC 3986 section 6.2.2.1), the
    /// path exactly. The upstream must end where a path segment, a query, a fragment or a `Link`
    /// target ends, so `http://broker:90901` is not taken for `http://broker:9090`.
    #[must_use]
    pub fn strip_from<'reference>(&self, reference: &'reference str) -> Option<&'reference str> {
        let authority_start = self.0.find("://").map_or(0, |separator| separator + 3);
        let path_start = self.0[authority_start..].find('/').map_or(self.0.len(), |slash| authority_start + slash);
        let (origin, path) = self.0.split_at(path_start);

        let rest = reference
            .get(..origin.len())
            .filter(|head| head.eq_ignore_ascii_case(origin))
            .and_then(|_| reference[origin.len()..].strip_prefix(path))?;

        matches!(rest.chars().next(), None | Some('/' | '?' | '#' | '>')).then_some(rest)
    }
}

impl TryFrom<&Url> for UpstreamBase {
    type Error = ProxyError;

    /// Checks the upstream once and strips its trailing slash.
    ///
    /// Without a host there is nothing to connect to (`http:///path` parses as a URL and has
    /// none); with a query, the request's own query would be appended after it and one of the two
    /// would be silently lost; a fragment would end up in the middle of the forwarded target.
    fn try_from(upstream: &Url) -> Result<UpstreamBase, ProxyError> {
        let forwardable = matches!(upstream.scheme(), "http" | "https") && upstream.has_host() && upstream.query().is_none() && upstream.fragment().is_none();

        if !forwardable {
            return Err(ProxyError::InvalidUpstream {
                upstream: upstream.clone(), // the error owns the URL, the settings are borrowed
            });
        }

        Ok(UpstreamBase(Arc::from(upstream.as_str().trim_end_matches('/'))))
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::ProxyError, upstream_base::UpstreamBase};
    use pretty_assertions::assert_eq;
    use url::Url;

    fn base(upstream: &str) -> Result<UpstreamBase, ProxyError> {
        UpstreamBase::try_from(&Url::parse(upstream).expect("the test upstream is a URL"))
    }

    #[test]
    fn an_upstream_that_is_not_an_http_url_is_refused_at_startup() {
        // Text that is not an absolute URL never gets this far: `Url` refuses it where the
        // configuration is read.
        for upstream in ["ftp://broker:9090", "broker:9090", "file:///etc/libra"] {
            assert!(
                matches!(base(upstream), Err(ProxyError::InvalidUpstream { .. })),
                "'{upstream}' must not be accepted as an upstream"
            );
        }
    }

    #[test]
    fn an_upstream_query_is_refused_because_the_request_query_would_replace_it() {
        assert!(matches!(base("http://broker:9090/?tenant=acme"), Err(ProxyError::InvalidUpstream { .. })));
    }

    #[test]
    fn a_trailing_slash_on_the_upstream_does_not_double_up() {
        let shown = |upstream: &str| base(upstream).expect("a forwardable upstream").to_string();

        assert_eq!(shown("http://broker:9090/"), "http://broker:9090");
        assert_eq!(shown("http://broker:9090"), "http://broker:9090");
        assert_eq!(shown("https://broker/base/"), "https://broker/base");
    }

    #[test]
    fn a_reference_into_the_upstream_loses_the_upstream() {
        let upstream = base("http://broker:9090/base").expect("a forwardable upstream");

        assert_eq!(
            upstream.strip_from("http://broker:9090/base/ngsi-ld/v1/entities/urn:a"),
            Some("/ngsi-ld/v1/entities/urn:a")
        );
        assert_eq!(upstream.strip_from("HTTP://Broker:9090/base?x=1"), Some("?x=1"));
        assert_eq!(upstream.strip_from("http://broker:9090/base"), Some(""));
    }

    #[test]
    fn a_reference_elsewhere_is_not_taken_for_the_upstream() {
        let upstream = base("http://broker:9090/base").expect("a forwardable upstream");

        for elsewhere in [
            "http://broker:90901/base/x",
            "http://broker:9090/basement",
            "http://broker:9090/Base/x",
            "https://broker:9090/base/x",
            "/ngsi-ld/v1/entities",
            "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        ] {
            assert_eq!(upstream.strip_from(elsewhere), None, "{elsewhere}");
        }
    }

    #[test]
    fn a_request_target_is_appended_verbatim() {
        let target = base("https://broker/base/")
            .expect("a forwardable upstream")
            .target("/ngsi-ld/v1/entities/urn%3Ax%2Fy?type=T");

        assert_eq!(
            target.map(|uri| uri.to_string()).ok(),
            Some("https://broker/base/ngsi-ld/v1/entities/urn%3Ax%2Fy?type=T".to_owned())
        );
    }
}
