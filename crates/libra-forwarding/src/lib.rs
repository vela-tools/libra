//! The decisions Libra makes about forwarding headers, owned in one place.
//!
//! A forwarding header is a claim by whoever sent it. The proxy writes `X-Forwarded-*` for the
//! broker, and a layer that keys on the client, such as a rate limiter, reads `X-Forwarded-For` to
//! find it. Every reader has to agree on which peers are believed, or a caller is trusted by one and
//! distrusted by another, so the answer lives here and each of them asks it.

pub mod forwarding_headers;
pub mod inbound_scheme;
pub mod trusted_proxies;
