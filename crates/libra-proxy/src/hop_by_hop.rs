//! Removing the headers that belong to one connection rather than to the message.
//!
//! RFC 9110 section 7.6.1 divides headers into two kinds. Most describe the message and travel
//! end to end. A few describe the connection the message arrived on (how it is framed, whether it
//! is kept alive, what it might be upgraded to) and a proxy that copies those onto a *different*
//! connection is describing a connection that does not exist.
//!
//! Forwarding everything except `Host` would let a client hand the broker a `Transfer-Encoding` that
//! does not match the body hyper is about to write, or a `Connection: keep-alive` naming a connection
//! the broker has never seen. The fixed list below is the first half of the answer. The second half
//! is that `Connection` itself names further headers to drop, and those are only knowable at run
//! time.

use http::{
    HeaderMap,
    HeaderName,
    header::{
        ACCEPT,
        AUTHORIZATION,
        CONNECTION,
        CONTENT_ENCODING,
        CONTENT_LENGTH,
        CONTENT_TYPE,
        LINK,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    },
};
use libra_hardening::identity_headers::PROPAGATED_HEADERS;
use libra_tenant::TENANT_HEADER;

/// The headers that are always specific to one hop.
///
/// `Proxy-Authenticate` and `Proxy-Authorization` are on the list because RFC 9110 section 11.7
/// scopes them to the immediate connection: forwarding a caller's proxy credentials to the broker
/// would offer it an authentication attempt the caller never aimed at it. `Proxy-Connection` is not
/// in any specification, but it is common enough in the wild that leaving it in would let it reach
/// the broker as a plain unknown header.
const HOP_BY_HOP: [HeaderName; 9] = [
    CONNECTION,
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("keep-alive"),
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
];

/// Which way a message is travelling through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The caller's request on its way to the broker.
    Request,
    /// The broker's answer on its way back to the caller.
    Response,
}

/// Request headers that a `Connection` field is not allowed to have removed.
///
/// Each of these was read by a layer above the proxy, and a decision was made from it. Dropping one
/// afterwards makes the broker act on a request Libra never looked at:
///
/// - `NGSILD-Tenant`: the caller is authorized for the tenant they named and the broker serves the
///   default one.
/// - `Link`: the caller's `@context` is what Libra authorized against, and the broker resolves
///   under the core context instead.
/// - `Content-Type`, `Content-Length`, `Content-Encoding`, `Accept`, `Options` and `Prefer`: the
///   broker reads the body or answers in a different shape from the one Libra decided on.
/// - `Authorization`: the broker sees an unauthenticated request that Libra let through.
/// - every [`PROPAGATED_HEADERS`] entry: the broker sees an anonymous or default-tenant caller.
///
/// RFC 9110 section 7.6.1 limits `Connection` to fields "intended only for the immediate
/// connection", so nothing legitimate is being kept here.
const NEVER_CONNECTION_STRIPPED: [HeaderName; 9] = [
    AUTHORIZATION,
    CONTENT_ENCODING,
    CONTENT_LENGTH,
    CONTENT_TYPE,
    ACCEPT,
    LINK,
    TENANT_HEADER,
    HeaderName::from_static("options"),
    HeaderName::from_static("prefer"),
];

/// Whether a request header named by `Connection` must be left alone.
fn is_protected(name: &HeaderName) -> bool {
    NEVER_CONNECTION_STRIPPED.contains(name) || PROPAGATED_HEADERS.contains(name)
}

/// Removes every header that must not cross to the next connection.
///
/// Two sets are removed: the fixed list from RFC 9110 section 7.6.1, and whatever the message's
/// own `Connection` header names. Applies to requests and responses alike: a response arriving
/// with `Transfer-Encoding: chunked` describes the broker's connection, not the one the answer
/// goes back on. In the request direction a `Connection` header cannot name a header Libra has
/// already acted on, so those names are never stripped on its say-so.
pub fn strip(headers: &mut HeaderMap, direction: Direction) {
    // Collected before anything is removed: `Connection` is itself on the fixed list, so removing
    // that first would throw away the list of what else to remove.
    let listed = connection_options(headers);

    for name in &HOP_BY_HOP {
        headers.remove(name);
    }

    for name in &listed {
        if direction == Direction::Request && is_protected(name) {
            continue;
        }

        headers.remove(name);
    }
}

/// The field names a message's `Connection` header asks to have dropped.
///
/// `close` and `keep-alive` appear here too. They are connection options rather than field names,
/// so removing a header by those names finds nothing, which is the right outcome without needing
/// a special case. An option that is not a legal field name names nothing that could be present,
/// so it is skipped.
fn connection_options(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut options = Vec::new();

    for value in headers.get_all(CONNECTION) {
        // A `Connection` header that is not visible ASCII names nothing that could be a header,
        // and it is about to be removed anyway.
        let Ok(text) = value.to_str() else {
            continue;
        };

        // `HeaderName` lowercases what it parses, so `Connection: X-Foo` names `x-foo`.
        options.extend(
            text.split(',')
                .map(str::trim)
                .filter_map(|option| HeaderName::from_bytes(option.as_bytes()).ok()),
        );
    }

    options
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderValue, header::HOST};
    use pretty_assertions::assert_eq;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();

        for (name, value) in pairs {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
                HeaderValue::from_str(value).expect("a valid header value"),
            );
        }

        headers
    }

    #[test]
    fn every_fixed_hop_by_hop_header_is_removed() {
        let mut map = headers(&[
            ("connection", "keep-alive"),
            ("proxy-connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("trailer", "expires"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("proxy-authenticate", "Basic"),
            ("proxy-authorization", "Basic Zm9v"),
        ]);

        strip(&mut map, Direction::Request);

        assert!(map.is_empty(), "no connection-specific header may reach the broker: {map:?}");
    }

    #[test]
    fn an_end_to_end_header_survives() {
        let mut map = headers(&[
            ("authorization", "Bearer token"),
            ("accept", "application/ld+json"),
            (HOST.as_str(), "libra.test"),
            ("connection", "keep-alive"),
        ]);

        strip(&mut map, Direction::Request);

        assert_eq!(map.len(), 3);
        assert_eq!(map.get("authorization").unwrap(), "Bearer token");
        assert_eq!(map.get("accept").unwrap(), "application/ld+json");
        assert_eq!(map.get(HOST).unwrap(), "libra.test");
    }

    #[test]
    fn a_header_named_by_the_connection_header_is_removed() {
        // RFC 9110 section 7.6.1 makes the `Connection` header a list of further field names that must not
        // be forwarded.
        let mut map = headers(&[("connection", "X-Custom"), ("x-custom", "secret"), ("accept", "application/json")]);

        strip(&mut map, Direction::Request);

        assert!(map.get("x-custom").is_none(), "a header named in Connection must not reach the broker");
        assert!(map.get("connection").is_none());
        assert_eq!(map.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn several_names_in_one_connection_header_are_all_removed() {
        let mut map = headers(&[
            ("connection", "X-Custom, X-Another , close"),
            ("x-custom", "one"),
            ("x-another", "two"),
            ("accept", "application/json"),
        ]);

        strip(&mut map, Direction::Request);

        assert!(map.get("x-custom").is_none());
        assert!(map.get("x-another").is_none());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn names_in_a_repeated_connection_header_are_all_removed() {
        let mut map = headers(&[
            ("connection", "X-Custom"),
            ("connection", "X-Another"),
            ("x-custom", "one"),
            ("x-another", "two"),
        ]);

        strip(&mut map, Direction::Request);

        assert!(map.is_empty(), "each Connection field line names headers to drop: {map:?}");
    }

    #[test]
    fn a_name_in_the_connection_header_matches_case_insensitively() {
        let mut map = headers(&[("connection", "X-CUSTOM"), ("x-custom", "one")]);

        strip(&mut map, Direction::Request);

        assert!(map.get("x-custom").is_none());
    }

    #[test]
    fn every_value_of_a_repeated_header_named_in_connection_goes() {
        let mut map = headers(&[("connection", "X-Custom"), ("x-custom", "one"), ("x-custom", "two")]);

        strip(&mut map, Direction::Request);

        assert_eq!(map.get_all("x-custom").iter().count(), 0);
    }

    #[test]
    fn a_header_libra_acted_on_cannot_be_stripped_by_a_connection_header() {
        // Each of these was read above the proxy and a decision was made from it. A caller who
        // could have one dropped on the way out would be judged on one request and served another.
        let protected = [
            "NGSILD-Tenant",
            "Link",
            "Content-Type",
            "Content-Length",
            "Content-Encoding",
            "Accept",
            "Authorization",
            "Options",
            "Prefer",
            "X-Auth-Subject",
            "X-Auth-Username",
            "X-Auth-Email",
            "X-Auth-Tenant-State",
            "X-Auth-Groups",
            "X-Auth-Roles",
            "X-Auth-Machine",
        ];

        for name in protected {
            let mut map = headers(&[("connection", name), (name, "value")]);

            strip(&mut map, Direction::Request);

            assert_eq!(map.get(name).unwrap(), "value", "{name} must survive a Connection header naming it");
            assert!(map.get("connection").is_none(), "{name}: Connection itself is still removed");
        }
    }

    #[test]
    fn a_response_may_have_any_header_removed_by_its_connection_header() {
        // The broker's own `Connection` field describes the broker's connection; nothing Libra
        // decided from is in the response.
        let mut map = headers(&[("connection", "Link, X-Custom"), ("link", "<ctx>"), ("x-custom", "one")]);

        strip(&mut map, Direction::Response);

        assert!(map.is_empty(), "{map:?}");
    }

    #[test]
    fn an_unreadable_connection_header_removes_nothing_but_itself() {
        let mut map = HeaderMap::new();
        map.insert(CONNECTION, HeaderValue::from_bytes(&[0xff, 0xfe]).expect("bytes are a valid header value"));
        map.insert("accept", HeaderValue::from_static("application/json"));

        strip(&mut map, Direction::Request);

        assert!(map.get(CONNECTION).is_none());
        assert_eq!(map.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn stripping_an_empty_map_is_not_an_error() {
        let mut map = HeaderMap::new();

        strip(&mut map, Direction::Request);

        assert!(map.is_empty());
    }
}
