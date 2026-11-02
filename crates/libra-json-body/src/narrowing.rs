//! Whether narrowing a document changed it.

/// The outcome of narrowing a document against a restriction.
///
/// A document left as the caller wrote it is forwarded as the caller's bytes; only one that was
/// narrowed is printed again, so what was not touched reaches the broker exactly as it was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Narrowing {
    /// Everything was inside the restriction as written.
    Unchanged,
    /// Something was dropped, rewritten or added.
    Narrowed,
}
