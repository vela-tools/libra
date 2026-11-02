//! The address the proxy binds to.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;
use url::{Host, ParseError};

/// A bind address that is neither an IP address nor a host name.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{host}' is not an IP address or a host name: {source}")]
pub struct InvalidListenHost {
    /// What was written.
    pub host: String,
    /// What the host parser said.
    #[source]
    pub source: ParseError,
}

/// A host name or an IP address to listen on.
///
/// An IPv6 address is written bare, as in `::1`, which is what the listener's address resolution
/// takes. A bracketed `[::1]` is accepted too and means the same thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ListenHost(Host<String>);

impl ListenHost {
    /// Listens on one IP address.
    #[must_use]
    pub const fn from_address(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) => Self(Host::Ipv4(address)),
            IpAddr::V6(address) => Self(Host::Ipv6(address)),
        }
    }

    /// Checks and wraps a host written in a file.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidListenHost`] if the text is empty or is neither an IP address nor a legal
    /// host name.
    pub fn new(host: String) -> Result<Self, InvalidListenHost> {
        match host.parse::<IpAddr>() {
            Ok(address) => Ok(Self::from_address(address)),
            Err(_) => Host::parse(&host).map(Self).map_err(|source| InvalidListenHost { host, source }),
        }
    }

    /// The host, as the URL crate models it.
    #[must_use]
    pub const fn host(&self) -> &Host<String> {
        &self.0
    }
}

impl TryFrom<String> for ListenHost {
    type Error = InvalidListenHost;

    fn try_from(host: String) -> Result<Self, Self::Error> {
        Self::new(host)
    }
}

/// A derive cannot express this: `Host`'s own text form brackets an IPv6 address, and the file form
/// and the listener both take it bare.
impl From<ListenHost> for String {
    fn from(host: ListenHost) -> Self {
        match host.0 {
            Host::Domain(name) => name,
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn an_ip_address_is_kept_as_an_address() {
        assert_eq!(
            ListenHost::new("0.0.0.0".to_owned()).unwrap().host(),
            &Host::<String>::Ipv4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(ListenHost::new("::1".to_owned()).unwrap().host(), &Host::<String>::Ipv6(Ipv6Addr::LOCALHOST));
        assert_eq!(ListenHost::new("[::1]".to_owned()).unwrap().host(), &Host::<String>::Ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn a_host_name_is_kept_as_a_name() {
        assert_eq!(ListenHost::new("localhost".to_owned()).unwrap().host(), &Host::Domain("localhost".to_owned()));
    }

    #[test]
    fn text_that_is_no_host_is_refused() {
        for hostile in ["", "bad host", "a/b", "host:80"] {
            assert!(ListenHost::new(hostile.to_owned()).is_err(), "{hostile:?} must not be a listen host");
        }
    }

    #[test]
    fn a_host_is_written_back_the_way_it_was_read() {
        for written in ["127.0.0.1", "::1", "localhost"] {
            let host = ListenHost::new(written.to_owned()).unwrap();

            assert_eq!(String::from(host), written);
        }
    }
}
