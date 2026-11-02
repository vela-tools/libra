//! What the broker's answer may tell the caller about the broker.
//!
//! The caller talks to Libra; the broker's address, product and session state are the operator's
//! topology. Headers that describe the broker are removed, and a reference that points into the
//! broker (a created entity's `Location`, a `Link` to the next page) is rewritten relative to the
//! root, which is where the caller reaches the same resource through Libra. A reference anywhere
//! else, such as a JSON-LD context `Link`, is the caller's to follow and is kept as sent.
//!
//! A reference written with another spelling of the broker's address (an IP address for a host
//! name, an elided default port) is not recognised; the broker is configured with the address it
//! uses in its own answers.

use crate::upstream_base::UpstreamBase;
use http::{
    HeaderMap,
    HeaderName,
    HeaderValue,
    header::{CONTENT_LOCATION, LINK, LOCATION, SERVER, SET_COOKIE},
};

/// Headers that describe the broker rather than the answer. A cookie the broker sets belongs to a
/// session with the broker, which the caller does not have.
const BROKER_DESCRIPTION: [HeaderName; 3] = [SERVER, HeaderName::from_static("x-powered-by"), SET_COOKIE];

/// Headers whose value holds URI references (RFC 9110 sections 10.2.2 and 8.7, RFC 8288 section 3).
const REFERENCES: [HeaderName; 3] = [LOCATION, CONTENT_LOCATION, LINK];

/// Removes what describes the broker and rewrites every reference into it relative to the root.
pub fn conceal_broker(headers: &mut HeaderMap, upstream: &UpstreamBase) {
    for name in BROKER_DESCRIPTION {
        headers.remove(name);
    }

    for name in REFERENCES {
        let rewritten: Vec<HeaderValue> = headers.get_all(&name).iter().filter_map(|value| rewrite(value, upstream)).collect();
        headers.remove(&name);
        for value in rewritten {
            headers.append(&name, value);
        }
    }
}

/// One header value with every reference into the broker made relative, or `None` to drop it.
///
/// A `Link` value writes each target between `<` and `>`, and a `Location` is a reference on its
/// own, so the text before the first `<` and the text after each one are the places a reference
/// starts. A value that is not visible ASCII is dropped: it is malformed, and Libra cannot tell
/// what it addresses.
fn rewrite(value: &HeaderValue, upstream: &UpstreamBase) -> Option<HeaderValue> {
    let text = value.to_str().ok()?;

    let pieces: Vec<String> = text
        .split('<')
        .map(|piece| match upstream.strip_from(piece) {
            Some(rest) if rest.starts_with('/') => rest.to_owned(),
            Some(rest) => format!("/{rest}"),
            None => piece.to_owned(),
        })
        .collect();

    HeaderValue::from_str(&pieces.join("<")).ok()
}

#[cfg(test)]
mod tests {
    use crate::{response_headers::conceal_broker, upstream_base::UpstreamBase};
    use http::{
        HeaderMap,
        HeaderName,
        HeaderValue,
        header::{CONTENT_LOCATION, CONTENT_TYPE, LINK, LOCATION, SERVER, SET_COOKIE},
    };
    use pretty_assertions::assert_eq;
    use url::Url;

    fn concealed(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let upstream = UpstreamBase::try_from(&Url::parse("http://scorpio.internal:9090").unwrap()).unwrap();
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_static(value));
        }

        conceal_broker(&mut headers, &upstream);

        headers
    }

    fn values<'map>(headers: &'map HeaderMap, name: &HeaderName) -> Vec<&'map str> {
        headers.get_all(name).iter().map(|value| value.to_str().unwrap()).collect()
    }

    #[test]
    fn headers_that_describe_the_broker_are_removed() {
        let headers = concealed(&[
            ("server", "Quarkus"),
            ("x-powered-by", "Vert.x"),
            ("set-cookie", "session=abc; Path=/"),
            ("content-type", "application/ld+json"),
        ]);

        assert!(!headers.contains_key(SERVER));
        assert!(!headers.contains_key("x-powered-by"));
        assert!(!headers.contains_key(SET_COOKIE));
        assert_eq!(values(&headers, &CONTENT_TYPE), ["application/ld+json"]);
    }

    #[test]
    fn a_location_into_the_broker_becomes_a_path_on_libra() {
        let headers = concealed(&[
            ("location", "http://scorpio.internal:9090/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:A"),
            ("content-location", "http://scorpio.internal:9090"),
        ]);

        assert_eq!(values(&headers, &LOCATION), ["/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:A"]);
        assert_eq!(values(&headers, &CONTENT_LOCATION), ["/"]);
    }

    #[test]
    fn a_relative_location_is_left_as_sent() {
        let headers = concealed(&[("location", "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:A")]);

        assert_eq!(values(&headers, &LOCATION), ["/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:A"]);
    }

    #[test]
    fn a_link_into_the_broker_is_rewritten_and_a_context_link_is_kept() {
        let headers = concealed(&[
            (
                "link",
                r#"<http://scorpio.internal:9090/ngsi-ld/v1/entities?type=T&offset=20>; rel="next", <https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld>; rel="http://www.w3.org/ns/json-ld#context""#,
            ),
            ("link", "<http://scorpio.internal:9090>; rel=\"up\""),
        ]);

        assert_eq!(
            values(&headers, &LINK),
            [
                r#"</ngsi-ld/v1/entities?type=T&offset=20>; rel="next", <https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld>; rel="http://www.w3.org/ns/json-ld#context""#,
                "</>; rel=\"up\"",
            ]
        );
    }

    #[test]
    fn a_reference_value_that_is_not_visible_ascii_is_dropped() {
        let upstream = UpstreamBase::try_from(&Url::parse("http://scorpio.internal:9090").unwrap()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, HeaderValue::from_bytes(b"http://scorpio.internal:9090/\xff").unwrap());

        conceal_broker(&mut headers, &upstream);

        assert!(!headers.contains_key(LOCATION));
    }
}
