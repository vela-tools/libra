//! Assembling and serving the Libra proxy.
//!
//! No enforcement logic lives here. Every security rule belongs to its own crate; this one decides
//! which of them run, in what order, and hands a binary the places where it may add more. The order
//! is the security-relevant part and is documented on the `router` module.
//!
//! A binary calls [`launch::launch`] with a function that accepts the configuration and returns an
//! [`extensions::Extensions`]. The binary in this repository returns an empty one. Anything beyond that, such as a response
//! cache or extra management routes, is added through the extension points and never by editing
//! the stack.

mod connections;
mod cors;
pub mod extensions;
pub mod launch;
mod lease;
mod management;
mod management_routes;
mod request_id;
mod router;
pub mod run;
mod server;
mod shutdown;
pub mod startup;
