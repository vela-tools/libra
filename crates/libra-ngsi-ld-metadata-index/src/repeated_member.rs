//! A member a metadata-index document names more than once.

use crate::index_member::IndexMember;
use thiserror::Error;

/// A metadata-index document names one of its members twice.
///
/// RFC 8259 section 4 leaves the meaning of a repeated member name to each parser, so a member
/// read here may not be the one the caller acts on. It is reported rather than resolved by picking
/// one occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the metadata-index document repeats its `{member}` member")]
pub struct RepeatedMember {
    /// The member named twice.
    pub member: IndexMember,
}
