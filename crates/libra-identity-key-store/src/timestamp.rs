//! Timestamps as the store keeps them: Unix seconds.

use crate::error::StoreError;
use jiff::Timestamp;

/// A timestamp as stored.
pub fn to_stored(timestamp: Timestamp) -> i64 {
    timestamp.as_second()
}

/// A stored timestamp, read back.
pub fn from_stored(seconds: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_second(seconds).map_err(|_| StoreError::CorruptRow {
        reason: "a timestamp is out of range",
    })
}
