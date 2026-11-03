//! The attribute path of a `q` term: an attribute of the matched entity, and optionally a
//! sub-attribute of it and a key path into its value (NGSI-LD clause 4.9 production `ValuePath`).

use crate::{error::QueryError, expansion::expand_term, key_path::KeyPath, parameter_name::ParameterName};
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// A dotted path to an attribute or one of its sub-attributes, as authored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttributePath {
    segments: Vec<Term>,
    trailing: Option<KeyPath>,
}

impl AttributePath {
    /// Builds a path from its segments.
    #[must_use]
    pub const fn new(segments: Vec<Term>) -> Self {
        Self { segments, trailing: None }
    }

    /// Adds the key path written in square brackets after the attribute, as in `address[city]`.
    ///
    /// It addresses a key inside the attribute's value, so it is kept as written and never
    /// expanded: the part that names the attribute is `segments`.
    #[must_use]
    pub fn with_trailing(mut self, trailing: Option<KeyPath>) -> Self {
        self.trailing = trailing;
        self
    }

    /// The key path inside the attribute's value, if the path had a bracketed part.
    #[must_use]
    pub const fn trailing(&self) -> Option<&KeyPath> {
        self.trailing.as_ref()
    }

    /// The segments, outermost first.
    #[must_use]
    pub fn segments(&self) -> &[Term] {
        &self.segments
    }

    /// The attribute this path is rooted at.
    ///
    /// The one a policy's attribute restriction is written about; the rest of the path names
    /// sub-attributes of it.
    #[must_use]
    pub fn root(&self) -> Option<&Term> {
        self.segments.first()
    }

    /// Expands every segment against a context.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::UnexpandableTerm`] if any segment has no meaning in this context.
    pub fn expand(&self, context: &ResolvedContext) -> Result<ExpandedAttributePath, QueryError> {
        let mut expanded = Vec::with_capacity(self.segments.len());

        for segment in &self.segments {
            expanded.push(expand_term(&ParameterName::Q, segment, context)?);
        }

        Ok(ExpandedAttributePath {
            segments: expanded,
            trailing: self.trailing.clone(), // an owned copy for the expanded path, which outlives this one
        })
    }
}

impl Display for AttributePath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        write_segments(formatter, &self.segments)?;

        if let Some(trailing) = &self.trailing {
            write!(formatter, "[{trailing}]")?;
        }

        Ok(())
    }
}

/// Separates a trailing `[...]` path from the attribute path in front of it.
///
/// NGSI-LD 4.9 writes a path into the value of a structured property in square brackets, as in
/// `address[city]`, and clause 4.23.3 ranks by one the same way. The bracketed part is a key path
/// in a JSON value rather than a term, so it is carried as written; only the part in front of it is
/// expanded and checked, which is what lets an attribute restriction on `address` see a filter or
/// an ordering that reads inside it.
pub(crate) fn split_trailing(raw: &str) -> Result<(&str, Option<KeyPath>), &'static str> {
    let Some(open) = raw
        .char_indices()
        .find(|(index, character)| *character == '[' && !raw[..*index].ends_with('\\'))
        .map(|(index, _)| index)
    else {
        return if raw.contains(']') {
            Err("a ']' with no '[' before it")
        } else {
            Ok((raw, None))
        };
    };

    let Some(inner) = raw[open + 1..].strip_suffix(']') else {
        return Err("a '[' trailing path must end the attribute path with ']'");
    };
    let Some(key_path) = KeyPath::new(inner) else {
        return Err("a '[' trailing path must name a key path and cannot nest");
    };
    if raw[..open].is_empty() {
        return Err("expected an attribute name before '['");
    }

    Ok((&raw[..open], Some(key_path)))
}

/// Splits a raw attribute path into its segments.
///
/// A path whose head is an absolute IRI is left whole. An IRI contains dots (`example.test`)
/// and splitting on them would invent sub-attributes out of a hostname, then fail to expand them
/// and refuse a request that was perfectly well formed. The cost is that a sub-attribute of an
/// IRI-named attribute cannot be addressed in `q` or `orderBy`; the term form has to be used for that, which is
/// what a caller with a context does anyway.
pub(crate) fn split_segments(raw: &str) -> Vec<Term> {
    let unescaped = raw.replace("\\.", "\u{0}");

    if Term::new(raw).looks_absolute() {
        return vec![Term::new(raw)];
    }

    unescaped.split('.').map(|segment| Term::new(segment.replace('\u{0}', "."))).collect()
}

/// Writes segments back as the raw path [`split_segments`] reads them from.
///
/// A path that is one absolute IRI is read whole and never split on its dots, so it is written as
/// it is: escaping its dots would add a backslash on every round trip and forward an IRI the broker
/// does not know. Any other path escapes a literal dot inside a name, so rendering round-trips
/// through parsing.
pub(crate) fn write_segments(formatter: &mut Formatter<'_>, segments: &[Term]) -> FmtResult {
    if let [only] = segments
        && only.looks_absolute()
    {
        return formatter.write_str(only.as_str());
    }

    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            formatter.write_str(".")?;
        }
        formatter.write_str(&segment.as_str().replace('.', "\\."))?;
    }

    Ok(())
}

/// An attribute path after expansion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExpandedAttributePath {
    segments: Vec<ExpandedIri>,
    trailing: Option<KeyPath>,
}

impl Display for ExpandedAttributePath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        for (index, segment) in self.segments.iter().enumerate() {
            if index > 0 {
                formatter.write_str(".")?;
            }
            formatter.write_str(segment.as_str())?;
        }

        if let Some(trailing) = &self.trailing {
            write!(formatter, "[{trailing}]")?;
        }

        Ok(())
    }
}

impl ExpandedAttributePath {
    /// The segments, outermost first.
    #[must_use]
    pub fn segments(&self) -> &[ExpandedIri] {
        &self.segments
    }

    /// The attribute this path is rooted at.
    #[must_use]
    pub fn root(&self) -> Option<&ExpandedIri> {
        self.segments.first()
    }
}
