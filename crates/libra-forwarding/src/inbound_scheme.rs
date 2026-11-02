//! The scheme clients use to reach Libra.

use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;

/// The scheme clients use to reach Libra itself.
///
/// Libra's own listener is plain HTTP; a deployment that terminates TLS in front of it says so
/// here. It is only ever used to fill in `X-Forwarded-Proto`, which is why it is a fixed pair
/// rather than a free string. It describes the hop Libra can vouch for, so it is what the broker is
/// told whenever the peer is not a trusted proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum InboundScheme {
    /// Libra is reached over plain HTTP.
    #[default]
    Http,
    /// Something in front of Libra terminates TLS.
    Https,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_inbound_scheme_defaults_to_plain_http() {
        assert_eq!(InboundScheme::default(), InboundScheme::Http);
    }

    #[test]
    fn the_scheme_is_written_as_it_appears_in_x_forwarded_proto() {
        assert_eq!(<&'static str>::from(InboundScheme::Http), "http");
        assert_eq!(<&'static str>::from(InboundScheme::Https), "https");
    }

    #[test]
    fn the_scheme_is_read_in_kebab_case() {
        assert_eq!(serde_json::from_str::<InboundScheme>(r#""https""#).unwrap(), InboundScheme::Https);
        assert!(serde_json::from_str::<InboundScheme>(r#""HTTPS""#).is_err());
    }
}
