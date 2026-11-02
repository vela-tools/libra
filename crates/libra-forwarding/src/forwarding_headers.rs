//! The non-standard forwarding headers, named once for every crate that reads or writes them.
//!
//! `Forwarded` (RFC 7239) is not here: `http::header::FORWARDED` already names it.

use http::HeaderName;

/// `X-Forwarded-For`: the chain of client addresses, oldest first.
pub const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// `X-Forwarded-Proto`: the scheme the original client used.
pub const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// `X-Forwarded-Host`: the `Host` the original client asked for.
pub const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

/// `X-Real-IP`: a single-address spelling of the client address, written by some proxies.
pub const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
