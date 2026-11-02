//! The peer address of a request.

use derive_more::Display;
use std::net::IpAddr;

/// Who the request came from, as the transport reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum ClientIp {
    /// The peer address.
    #[display("{_0}")]
    Known(IpAddr),
    /// The server was built without connection info. Written as `-` so a log field is never empty.
    #[display("-")]
    Unknown,
}

impl From<Option<IpAddr>> for ClientIp {
    fn from(address: Option<IpAddr>) -> Self {
        address.map_or(Self::Unknown, Self::Known)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_known_address_is_written_as_the_address() {
        assert_eq!(ClientIp::from(Some("10.0.0.7".parse::<IpAddr>().unwrap())).to_string(), "10.0.0.7");
        assert_eq!(ClientIp::from(Some("::1".parse::<IpAddr>().unwrap())).to_string(), "::1");
    }

    #[test]
    fn an_unknown_address_is_written_as_a_dash() {
        assert_eq!(ClientIp::from(None).to_string(), "-");
    }
}
