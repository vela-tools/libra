//! Why a registration could not be read.

use thiserror::Error;

/// A member of a registration is not in a shape NGSI-LD 5.2.8 to 5.2.10 defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the context source registration cannot be read: {reason}")]
pub struct Unreadable {
    /// Which member was not readable, phrased for the caller.
    pub reason: &'static str,
}
