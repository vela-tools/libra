//! The headers a proxy is supposed to add on its way through.
//!
//! Without them a request reaching the broker looks, to the broker, exactly like a request from
//! the client (same headers, no record of the hop), which makes a loop undetectable, makes a
//! broker-side access log useless for finding out who actually called, and leaves out `Via`, which
//! RFC 9110 section 7.6.3 requires of an intermediary.

use http::{
    HeaderMap,
    HeaderName,
    HeaderValue,
    Version,
    header::{FORWARDED, VIA},
};
use libra_forwarding::{
    forwarding_headers::{X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PROTO, X_REAL_IP},
    inbound_scheme::InboundScheme,
    trusted_proxies::TrustedProxies,
};
use std::net::IpAddr;

/// Adds `Via` for this hop, keeping every hop already recorded.
///
/// RFC 9110 section 7.6.3 wants each intermediary to append `<received-protocol> <received-by>`,
/// in order, so the chain reads from the origin outwards. `version` is the protocol of the message
/// as it *arrived*, which for a response is the broker's, not the client's.
pub fn add_via(headers: &mut HeaderMap, version: Version, pseudonym: &HeaderValue) {
    let Ok(element) = HeaderValue::from_str(&format!("{} {}", protocol_version(version), value_as_str(pseudonym))) else {
        return;
    };

    append_to_list(headers, &VIA, element);
}

/// Settles the forwarding headers on a request on its way upstream.
///
/// What an inbound forwarding header means depends on who sent it. The peer address is the only
/// thing Libra observes itself; every forwarding header is a claim, and it is a claim Libra can
/// pass on only when the peer is a proxy the operator named in `trusted_proxies`.
///
/// **A trusted peer** wrote them, so they are kept: the peer address is appended to
/// `X-Forwarded-For`, which makes the chain record every hop, and `X-Forwarded-Proto` and
/// `X-Forwarded-Host` are set only when absent, so a TLS terminator in front of Libra keeps the
/// naming rights to what the client originally asked for. `Forwarded` and `X-Real-IP` are left as
/// the proxy sent them.
///
/// **Any other peer, or none known,** is a client talking to Libra directly, so whatever it wrote
/// is its own claim about itself and is not forwarded as a record. `X-Forwarded-For` is replaced
/// by the observed peer alone, or removed when there is none, so the broker's log cannot carry
/// hops an attacker chose next to the one Libra saw. `X-Forwarded-Proto` is overwritten with the
/// configured inbound scheme and `X-Forwarded-Host` with the `Host` the request arrived with, or
/// removed if it had none, because a broker that builds absolute links from them, such as the
/// `Link` header of a paginated answer, would otherwise build them from the caller's words.
/// `Forwarded` and `X-Real-IP` are removed outright: Libra writes neither, so nothing in either
/// can be its own observation.
pub fn add_forwarded(headers: &mut HeaderMap, peer: Option<IpAddr>, trusted: &TrustedProxies, scheme: InboundScheme, host: Option<HeaderValue>) {
    match peer {
        Some(peer) if trusted.contains(peer) => extend_trusted_chain(headers, peer, scheme, host),
        other => replace_untrusted_claims(headers, other, scheme, host),
    }
}

/// Keeps what a trusted proxy wrote and adds this hop to it.
fn extend_trusted_chain(headers: &mut HeaderMap, peer: IpAddr, scheme: InboundScheme, host: Option<HeaderValue>) {
    if let Ok(element) = HeaderValue::from_str(&peer.to_string()) {
        append_to_list(headers, &X_FORWARDED_FOR, element);
    }

    if !headers.contains_key(&X_FORWARDED_PROTO) {
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(scheme.into()));
    }

    if let Some(host) = host
        && !headers.contains_key(&X_FORWARDED_HOST)
    {
        headers.insert(X_FORWARDED_HOST, host);
    }
}

/// Discards what a client wrote about itself and records only what Libra observed.
fn replace_untrusted_claims(headers: &mut HeaderMap, peer: Option<IpAddr>, scheme: InboundScheme, host: Option<HeaderValue>) {
    headers.remove(&FORWARDED);
    headers.remove(&X_REAL_IP);

    match peer.and_then(|peer| HeaderValue::from_str(&peer.to_string()).ok()) {
        Some(element) => {
            headers.insert(X_FORWARDED_FOR, element);
        }
        None => {
            headers.remove(&X_FORWARDED_FOR);
        }
    }

    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(scheme.into()));

    match host {
        Some(host) => {
            headers.insert(X_FORWARDED_HOST, host);
        }
        None => {
            headers.remove(&X_FORWARDED_HOST);
        }
    }
}

/// Adds one element to the end of a comma-separated list header, keeping what was there.
fn append_to_list(headers: &mut HeaderMap, name: &HeaderName, element: HeaderValue) {
    // `collect` into an `Option` gives `None` as soon as one existing value is not readable text.
    let existing: Option<Vec<String>> = headers.get_all(name).iter().map(|value| value.to_str().ok().map(str::to_owned)).collect();

    let Some(existing) = existing else {
        // Re-joining would have to drop the unreadable value. A separate field line keeps it, and
        // RFC 9110 section 5.3 makes that identical in meaning for a list-based field.
        headers.append(name, element);
        return;
    };

    let mut joined: Vec<&str> = existing.iter().map(String::as_str).filter(|value| !value.is_empty()).collect();
    let element_text = value_as_str(&element);
    joined.push(element_text);

    match HeaderValue::from_str(&joined.join(", ")) {
        Ok(value) => {
            headers.insert(name, value);
        }
        Err(_) => {
            headers.append(name, element);
        }
    }
}

/// A header value as text, or the empty string if it is not visible ASCII.
fn value_as_str(value: &HeaderValue) -> &str {
    value.to_str().unwrap_or_default()
}

/// The `Via` received-protocol for a message that arrived over this HTTP version.
///
/// An unrecognised version is reported as `1.1`: `Via` has to name something, and the proxy only
/// ever speaks HTTP/1.1 to the broker.
fn protocol_version(version: Version) -> &'static str {
    if version == Version::HTTP_09 {
        "0.9"
    } else if version == Version::HTTP_10 {
        "1.0"
    } else if version == Version::HTTP_2 {
        "2"
    } else if version == Version::HTTP_3 {
        "3"
    } else {
        "1.1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;

    fn pseudonym() -> HeaderValue {
        HeaderValue::from_static("libra")
    }

    #[test]
    fn via_names_this_hop_when_there_was_none() {
        let mut headers = HeaderMap::new();

        add_via(&mut headers, Version::HTTP_11, &pseudonym());

        assert_eq!(headers.get(VIA).unwrap(), "1.1 libra");
    }

    #[test]
    fn via_appends_rather_than_replacing_an_earlier_hop() {
        // The chain has to read from the origin outwards, or it says nothing about the route.
        let mut headers = HeaderMap::new();
        headers.insert(VIA, HeaderValue::from_static("1.1 edge"));

        add_via(&mut headers, Version::HTTP_11, &pseudonym());

        assert_eq!(headers.get(VIA).unwrap(), "1.1 edge, 1.1 libra");
        assert_eq!(headers.get_all(VIA).iter().count(), 1);
    }

    #[test]
    fn via_folds_several_earlier_field_lines_into_the_chain() {
        let mut headers = HeaderMap::new();
        headers.append(VIA, HeaderValue::from_static("1.0 first"));
        headers.append(VIA, HeaderValue::from_static("1.1 second"));

        add_via(&mut headers, Version::HTTP_11, &pseudonym());

        assert_eq!(headers.get(VIA).unwrap(), "1.0 first, 1.1 second, 1.1 libra");
    }

    #[test]
    fn via_reports_the_protocol_the_message_arrived_on() {
        for (version, expected) in [
            (Version::HTTP_09, "0.9 libra"),
            (Version::HTTP_10, "1.0 libra"),
            (Version::HTTP_11, "1.1 libra"),
            (Version::HTTP_2, "2 libra"),
            (Version::HTTP_3, "3 libra"),
        ] {
            let mut headers = HeaderMap::new();
            add_via(&mut headers, version, &pseudonym());
            assert_eq!(headers.get(VIA).unwrap(), expected);
        }
    }

    const PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

    fn proxies() -> TrustedProxies {
        TrustedProxies::new(vec!["10.0.0.0/8".parse().unwrap()])
    }

    fn host(text: &'static str) -> HeaderValue {
        HeaderValue::from_static(text)
    }

    /// Headers a caller wrote to claim a client, a scheme and a host that Libra never observed.
    fn spoofed() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(&X_FORWARDED_FOR, HeaderValue::from_static("192.0.2.1, 192.0.2.2"));
        headers.insert(&X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        headers.insert(&X_FORWARDED_HOST, HeaderValue::from_static("evil.example"));
        headers.insert(&FORWARDED, HeaderValue::from_static("for=192.0.2.1;host=evil.example;proto=https"));
        headers.insert(&X_REAL_IP, HeaderValue::from_static("192.0.2.1"));
        headers
    }

    #[test]
    fn an_untrusted_peers_scheme_and_host_claims_are_overwritten_with_what_libra_observed() {
        let mut headers = spoofed();

        add_forwarded(&mut headers, Some(CLIENT), &proxies(), InboundScheme::Http, Some(host("libra.test")));

        assert_eq!(headers.get(&X_FORWARDED_PROTO).unwrap(), "http");
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "libra.test");
    }

    #[test]
    fn an_untrusted_peers_forwarded_chain_is_replaced_by_the_peer_alone() {
        // Appending would leave attacker-chosen hops in the broker's record next to the one hop Libra
        // saw, written in the same format and indistinguishable from it.
        let mut headers = spoofed();

        add_forwarded(&mut headers, Some(CLIENT), &proxies(), InboundScheme::Http, None);

        assert_eq!(headers.get(&X_FORWARDED_FOR).unwrap(), "198.51.100.2");
        assert_eq!(headers.get_all(&X_FORWARDED_FOR).iter().count(), 1);
    }

    #[test]
    fn an_untrusted_peers_forwarded_and_real_ip_headers_are_stripped() {
        let mut headers = spoofed();

        add_forwarded(&mut headers, Some(CLIENT), &proxies(), InboundScheme::Http, None);

        assert!(!headers.contains_key(&FORWARDED));
        assert!(!headers.contains_key(&X_REAL_IP));
    }

    #[test]
    fn an_untrusted_request_with_no_host_loses_the_forwarded_host_it_claimed() {
        let mut headers = spoofed();

        add_forwarded(&mut headers, Some(CLIENT), &proxies(), InboundScheme::Http, None);

        assert!(!headers.contains_key(&X_FORWARDED_HOST), "a host Libra did not see must not be passed on");
    }

    #[test]
    fn the_configured_inbound_scheme_is_what_an_untrusted_peer_is_told() {
        let mut headers = spoofed();
        headers.insert(&X_FORWARDED_PROTO, HeaderValue::from_static("http"));

        add_forwarded(&mut headers, Some(CLIENT), &proxies(), InboundScheme::Https, None);

        assert_eq!(headers.get(&X_FORWARDED_PROTO).unwrap(), "https");
    }

    #[test]
    fn an_unknown_peer_is_treated_as_untrusted() {
        // No `ConnectInfo` means no address to match against the list. The claims are discarded, and
        // no hop is invented in their place.
        let mut headers = spoofed();

        add_forwarded(&mut headers, None, &proxies(), InboundScheme::Http, Some(host("libra.test")));

        assert!(!headers.contains_key(&X_FORWARDED_FOR));
        assert!(!headers.contains_key(&FORWARDED));
        assert!(!headers.contains_key(&X_REAL_IP));
        assert_eq!(headers.get(&X_FORWARDED_PROTO).unwrap(), "http");
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "libra.test");
    }

    #[test]
    fn with_no_trusted_proxies_every_peer_is_untrusted() {
        let mut headers = spoofed();

        add_forwarded(
            &mut headers,
            Some(PROXY),
            &TrustedProxies::default(),
            InboundScheme::Http,
            Some(host("libra.test")),
        );

        assert_eq!(headers.get(&X_FORWARDED_FOR).unwrap(), "10.0.0.1");
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "libra.test");
    }

    #[test]
    fn a_trusted_peers_chain_is_extended_rather_than_replaced() {
        // Replacing it would erase every hop before Libra from the broker's record.
        let mut headers = HeaderMap::new();
        headers.insert(&X_FORWARDED_FOR, HeaderValue::from_static("203.0.113.7"));

        add_forwarded(&mut headers, Some(PROXY), &proxies(), InboundScheme::Http, None);

        assert_eq!(headers.get(&X_FORWARDED_FOR).unwrap(), "203.0.113.7, 10.0.0.1");
    }

    #[test]
    fn a_trusted_peer_that_forwarded_nothing_starts_the_chain() {
        let mut headers = HeaderMap::new();

        add_forwarded(&mut headers, Some(PROXY), &proxies(), InboundScheme::Http, None);

        assert_eq!(headers.get(&X_FORWARDED_FOR).unwrap(), "10.0.0.1");
    }

    #[test]
    fn a_trusted_peers_scheme_and_host_are_not_overwritten() {
        // Libra is not the first hop here, and the client asked the outer proxy, not Libra.
        let mut headers = HeaderMap::new();
        headers.insert(&X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        headers.insert(&X_FORWARDED_HOST, HeaderValue::from_static("api.example.test"));

        add_forwarded(&mut headers, Some(PROXY), &proxies(), InboundScheme::Http, Some(host("libra.internal")));

        assert_eq!(headers.get(&X_FORWARDED_PROTO).unwrap(), "https");
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "api.example.test");
    }

    #[test]
    fn a_trusted_peer_that_sent_no_scheme_or_host_is_told_what_libra_observed() {
        let mut headers = HeaderMap::new();

        add_forwarded(&mut headers, Some(PROXY), &proxies(), InboundScheme::Https, Some(host("libra.test")));

        assert_eq!(headers.get(&X_FORWARDED_PROTO).unwrap(), "https");
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "libra.test");
    }

    #[test]
    fn a_trusted_peers_forwarded_and_real_ip_headers_are_left_as_sent() {
        let mut headers = spoofed();

        add_forwarded(&mut headers, Some(PROXY), &proxies(), InboundScheme::Http, None);

        assert_eq!(headers.get(&FORWARDED).unwrap(), "for=192.0.2.1;host=evil.example;proto=https");
        assert_eq!(headers.get(&X_REAL_IP).unwrap(), "192.0.2.1");
    }

    #[test]
    fn an_unreadable_earlier_value_is_kept_on_its_own_field_line() {
        let mut headers = HeaderMap::new();
        headers.insert(VIA, HeaderValue::from_bytes(&[0xff]).expect("bytes are a valid header value"));

        add_via(&mut headers, Version::HTTP_11, &pseudonym());

        let values: Vec<&HeaderValue> = headers.get_all(VIA).iter().collect();
        assert_eq!(values.len(), 2, "nothing may be dropped from the chain");
        assert_eq!(values[1], "1.1 libra");
    }
}
