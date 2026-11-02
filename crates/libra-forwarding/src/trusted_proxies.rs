//! The peers whose forwarding headers are believed.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};

/// The networks of the proxies the operator runs in front of Libra.
///
/// A request from a peer inside one of these networks may carry forwarding headers that proxy
/// wrote. A request from any other peer is a client talking to Libra directly, and whatever
/// forwarding headers it carries were written by that client. Empty, the default, trusts no peer.
///
/// Shared by handle: every proxy service holds one, and none of them mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrustedProxies(Arc<[IpNet]>);

impl TrustedProxies {
    /// Trusts the peers inside any of `networks`.
    #[must_use]
    pub fn new(networks: Vec<IpNet>) -> TrustedProxies {
        TrustedProxies(Arc::from(networks))
    }

    /// Whether `address` belongs to a trusted proxy.
    ///
    /// The address is read in its canonical form, so an IPv4 peer that a dual-stack listener
    /// reports as `::ffff:a.b.c.d` is matched by an IPv4 network, as it would be on an IPv4-only
    /// listener.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();

        self.0.iter().any(|network| network.contains(&address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn trusted(networks: &[&str]) -> TrustedProxies {
        TrustedProxies::new(networks.iter().map(|network| network.parse().unwrap()).collect())
    }

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn no_peer_is_trusted_by_default() {
        assert!(!TrustedProxies::default().contains(address("10.0.0.1")));
    }

    #[test]
    fn a_peer_inside_a_listed_network_is_trusted_and_one_outside_is_not() {
        let proxies = trusted(&["10.0.0.0/8", "fd00::/8"]);

        assert!(proxies.contains(address("10.1.2.3")));
        assert!(proxies.contains(address("fd00::7")));
        assert!(!proxies.contains(address("203.0.113.5")));
        assert!(!proxies.contains(address("2001:db8::1")));
    }

    #[test]
    fn an_ipv4_peer_reported_in_mapped_form_matches_an_ipv4_network() {
        assert!(trusted(&["10.0.0.0/8"]).contains(address("::ffff:10.0.0.1")));
    }

    #[test]
    fn networks_are_read_from_a_list_of_cidr_strings() {
        let proxies: TrustedProxies = serde_json::from_str(r#"["10.0.0.0/8","fd00::/8"]"#).unwrap();

        assert_eq!(proxies, trusted(&["10.0.0.0/8", "fd00::/8"]));
    }

    #[test]
    fn an_entry_that_is_not_a_network_is_refused() {
        assert!(serde_json::from_str::<TrustedProxies>(r#"["not-a-network"]"#).is_err());
    }
}
