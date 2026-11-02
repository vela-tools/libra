//! RFC 9457 problem details for Libra.
//!
//! Two things live here: the taxonomy of proxy-level errors, and the outermost Tower layer that
//! turns any error escaping the stack into a response.
//!
//! Libra errors carry their own type URIs, distinct from the NGSI-LD API errors the broker itself
//! emits under `https://uri.etsi.org/ngsi-ld/errors/`. A client can therefore tell a proxy refusal
//! apart from a broker refusal by the `type` field alone. Broker errors pass through untouched.

pub mod challenge;
pub mod layer;
pub mod problem;
