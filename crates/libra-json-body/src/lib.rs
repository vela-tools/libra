//! The one strict parse of a JSON body, and the parsed request body every layer reads.
//!
//! A proxy that reads a body one way and forwards it to a broker that reads it another has checked
//! a body nobody acts on. Two shapes make that possible with JSON alone, before any meaning is
//! assigned to a member: a member written twice, which RFC 8259 section 4 leaves to each parser to
//! resolve, and nesting deep enough that one reader gives up where another carries on. Both are
//! refused here, once, for every body Libra parses.

pub mod error;
pub mod narrowing;
pub mod nesting;
pub mod request_body;
pub mod strict;
