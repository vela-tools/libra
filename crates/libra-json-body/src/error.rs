//! Why a body is not one Libra will read.

use thiserror::Error;

/// A body the strict parse refuses.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// The bytes are not UTF-8, which RFC 8259 section 8.1 requires of JSON exchanged between
    /// systems.
    #[error("the body is not valid UTF-8")]
    NotUtf8,

    /// The text is not JSON.
    #[error("the body is not valid JSON")]
    NotJson,

    /// Arrays and objects nest deeper than any NGSI-LD document does.
    #[error("the body nests arrays and objects more than {limit} levels deep")]
    TooDeep {
        /// The deepest nesting accepted.
        limit: usize,
    },

    /// An object names the same member twice.
    #[error("the body repeats the member \"{member}\" in one object")]
    RepeatedMember {
        /// The repeated member name, as written.
        member: String,
    },
}

/// Why a layer cannot read the request's JSON document from the extensions.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DocumentError {
    /// No layer above read the body. A wiring fault: every layer that reads a document sits below
    /// the one that parses it, and continuing without it would judge a body nobody read.
    #[error("the request body was not read before this layer")]
    Unread,

    /// The body is not JSON.
    #[error("the request body is not a JSON document")]
    NotJson,
}
