//! A `[cors]` list: either everything, or a named set of one kind of entry.

use http::{HeaderName, HeaderValue, Method};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use std::{borrow::Cow, fmt::Display, str::FromStr};

/// The entry that stands for every value.
const WILDCARD: &str = "*";

/// An entry of an [`AllowList`]: something that is written in a file as text and used as a typed
/// value.
pub trait AllowListEntry: FromStr<Err: Display> {
    /// The entry as it is written in a file.
    fn text(&self) -> Cow<'_, str>;
}

impl AllowListEntry for HeaderValue {
    fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.as_bytes())
    }
}

impl AllowListEntry for HeaderName {
    fn text(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl AllowListEntry for Method {
    fn text(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

/// Everything, or exactly these entries.
///
/// Written as a list of strings. A `*` anywhere in the list makes it [`AllowList::Any`], and the
/// other entries are then not read: the wildcard already says everything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowList<T> {
    /// Every value.
    Any,
    /// Only these values.
    Only(Vec<T>),
}

/// A derive cannot express this: the wire form is a list of strings in which one entry changes the
/// meaning of the whole list, and the entries are parsed into `T` as they are read.
impl<'de, T: AllowListEntry> Deserialize<'de> for AllowList<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = Vec::<String>::deserialize(deserializer)?;

        if entries.iter().any(|entry| entry == WILDCARD) {
            return Ok(Self::Any);
        }

        entries
            .into_iter()
            .map(|entry| {
                entry
                    .parse::<T>()
                    .map_err(|error| DeError::custom(format_args!("'{entry}' is not valid: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self::Only)
    }
}

/// A derive cannot express this, for the reason given on the `Deserialize` implementation.
impl<T: AllowListEntry> Serialize for AllowList<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Any => [WILDCARD].serialize(serializer),
            Self::Only(entries) => serializer.collect_seq(entries.iter().map(AllowListEntry::text)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn parse<T: AllowListEntry>(json: &str) -> Result<AllowList<T>, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn a_wildcard_anywhere_makes_the_list_open() {
        assert_eq!(parse::<Method>(r#"["*"]"#).unwrap(), AllowList::Any);
        assert_eq!(parse::<HeaderName>(r#"["Link", "*"]"#).unwrap(), AllowList::Any);
    }

    #[test]
    fn entries_are_parsed_into_their_types() {
        assert_eq!(
            parse::<Method>(r#"["GET", "PATCH"]"#).unwrap(),
            AllowList::Only(vec![Method::GET, Method::PATCH])
        );
        assert_eq!(
            parse::<HeaderValue>(r#"["https://app.example.test"]"#).unwrap(),
            AllowList::Only(vec![HeaderValue::from_static("https://app.example.test")])
        );
        assert_eq!(parse::<HeaderName>("[]").unwrap(), AllowList::Only(Vec::new()));
    }

    #[test]
    fn an_entry_that_does_not_parse_is_refused_and_named() {
        let error = parse::<Method>(r#"["GET", "NOT A METHOD"]"#).unwrap_err().to_string();
        assert!(error.contains("NOT A METHOD"), "{error}");

        assert!(parse::<HeaderName>(r#"["not a header"]"#).is_err());
        assert!(parse::<HeaderValue>(r#"["https://bad\u007f.test"]"#).is_err());
    }

    #[test]
    fn a_list_is_written_back_as_the_strings_it_was_read_from() {
        assert_eq!(serde_json::to_string(&AllowList::<Method>::Any).unwrap(), r#"["*"]"#);
        assert_eq!(
            serde_json::to_string(&AllowList::Only(vec![Method::GET, Method::DELETE])).unwrap(),
            r#"["GET","DELETE"]"#
        );
    }
}
