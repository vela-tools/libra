//! `[libra]`: where the proxy listens.

use crate::listen_host::ListenHost;
use libra_forwarding::trusted_proxies::TrustedProxies;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Server listening configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Libra {
    /// Host name or IP address to bind to.
    pub host: ListenHost,
    /// Port to listen on.
    pub port: u16,
    /// The proxies in front of Libra, whose forwarding headers are believed.
    ///
    /// A request from a peer outside every one of these networks is a client talking to Libra
    /// directly: its `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded` and
    /// `X-Real-IP` do not reach the broker as claims. Empty, the default, trusts no peer.
    pub trusted_proxies: TrustedProxies,
    /// How long a stopping Libra waits for in-flight requests before it gives up on them, in
    /// seconds.
    ///
    /// Counted from the first termination signal. Keep it below the orchestrator's own grace period
    /// (`terminationGracePeriodSeconds` in Kubernetes, 30 seconds unless set): past that the process
    /// is killed with requests still open, which is the outcome this limit exists to avoid.
    pub shutdown_grace_seconds: u64,
    /// How long a client may take to send the start of a request, in seconds.
    ///
    /// Covers a connection that sends nothing and a request whose headers arrive a byte at a time.
    /// Without it each such connection is held open indefinitely and also holds a shutdown drain
    /// open for its whole grace period.
    pub header_read_timeout_seconds: u64,
}

impl Default for Libra {
    fn default() -> Self {
        Self {
            host: ListenHost::from_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: 5667,
            trusted_proxies: TrustedProxies::default(),
            shutdown_grace_seconds: 25,
            header_read_timeout_seconds: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use pretty_assertions::assert_eq;

    #[test]
    fn no_proxy_is_trusted_by_default() {
        assert_eq!(Libra::default().trusted_proxies, TrustedProxies::default());
    }

    #[test]
    fn trusted_proxies_are_read_as_networks() {
        let libra: Libra = serde_json::from_str(
            r#"{"host":"0.0.0.0","port":5667,"trusted-proxies":["10.0.0.0/8","fd00::/8"],"shutdown-grace-seconds":25,"header-read-timeout-seconds":10}"#,
        )
        .unwrap();

        assert_eq!(
            libra.trusted_proxies,
            TrustedProxies::new(vec!["10.0.0.0/8".parse::<IpNet>().unwrap(), "fd00::/8".parse::<IpNet>().unwrap()])
        );
    }

    #[test]
    fn a_trusted_proxy_that_is_not_a_network_is_refused() {
        assert!(
            serde_json::from_str::<Libra>(
                r#"{"host":"0.0.0.0","port":5667,"trusted-proxies":["not-a-network"],"shutdown-grace-seconds":25,"header-read-timeout-seconds":10}"#
            )
            .is_err()
        );
    }

    #[test]
    fn the_drain_ends_before_a_thirty_second_orchestrator_grace_period_does() {
        // The orchestrator's default is thirty seconds; a drain that outlasts it is a kill, not a
        // drain.
        assert!(Libra::default().shutdown_grace_seconds < 30);
    }

    #[test]
    fn the_header_read_timeout_is_shorter_than_the_drain() {
        let libra = Libra::default();

        assert!(libra.header_read_timeout_seconds < libra.shutdown_grace_seconds);
    }

    #[test]
    fn the_shutdown_grace_and_the_header_timeout_are_read_by_their_kebab_case_keys() {
        let libra: Libra =
            serde_json::from_str(r#"{"host":"0.0.0.0","port":5667,"trusted-proxies":[],"shutdown-grace-seconds":7,"header-read-timeout-seconds":3}"#).unwrap();

        assert_eq!((libra.shutdown_grace_seconds, libra.header_read_timeout_seconds), (7, 3));
    }
}
