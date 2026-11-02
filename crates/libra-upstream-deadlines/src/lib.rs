//! Bounding how long the upstream broker may take to answer.
//!
//! [`timeout`] bounds how long any single request may wait, so a hung broker cannot accumulate
//! connections until the proxy runs out of them, and [`response_deadline`] carries the same
//! deadline on into the response body, so a broker that sends its headers and then stalls cannot
//! hold the connection either.

pub mod response_deadline;
#[cfg(test)]
mod stalled_body;
pub mod timeout;
