//! Request hardening: what Libra refuses to pass on, and what it adds to every answer.
//!
//! Five concerns that share a theme: none of them is about who the caller is, all of them are
//! about what a request is allowed to look like before the rest of the stack reasons over it.
//!
//! * [`identity_headers`] removes the `X-Auth-*` headers Libra itself injects, so the broker can
//!   trust that any it receives came from the proxy and not from the caller.
//! * [`in_flight`] refuses a request arriving while the in-flight ceiling is held.
//! * [`method_override`] refuses a request asking another hop to run it as another method.
//! * [`payload`] refuses bodies larger than the deployment allows, before they are buffered.
//! * [`security_headers`] adds the standard browser hardening headers to every response.

pub mod identity_headers;
pub mod in_flight;
pub mod method_override;
pub mod payload;
pub mod security_headers;
