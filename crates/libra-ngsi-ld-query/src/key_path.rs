//! The bracketed key path of a `q` attribute path.

use derive_more::Display;

/// The key path written in square brackets after an attribute, as in the `city` of `address[city]`.
///
/// It addresses a key inside the attribute's value rather than naming a term, so it is carried as
/// written and never expanded. Non-empty and free of brackets, which is what keeps `a[b][c]` and
/// `a[]` out of the filter model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("{_0}")]
pub struct KeyPath(String);

impl KeyPath {
    /// Wraps the text between the brackets, or `None` when it is empty or itself contains a
    /// bracket.
    #[must_use]
    pub fn new(inner: &str) -> Option<Self> {
        if inner.is_empty() || inner.contains(['[', ']']) {
            return None;
        }

        Some(Self(inner.to_owned()))
    }

    /// The key path as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_key_path_is_kept_as_written() {
        assert_eq!(KeyPath::new("city").map(|path| path.to_string()), Some("city".to_owned()));
    }

    #[test]
    fn an_empty_key_path_is_refused() {
        assert_eq!(KeyPath::new(""), None);
    }

    #[test]
    fn a_nested_bracket_is_refused() {
        assert_eq!(KeyPath::new("a[b"), None);
        assert_eq!(KeyPath::new("a]b"), None);
    }
}
