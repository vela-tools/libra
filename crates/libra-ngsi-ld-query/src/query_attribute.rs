//! What a `q` term tests: an attribute of the matched entity, or one reached by following a
//! Relationship into the entity it links to (NGSI-LD clause 4.9 production `Attribute`).
//!
//! ```text
//! Attribute = LinkedEntityRelation
//! LinkedEntityRelation = AttrName %x7B LinkedEntityPath %x7D      ; AttrName{LinkedEntityPath}
//! LinkedEntityRelation =/ ValuePath
//! LinkedEntityPath = *1(EntityType 1*(%x2C EntityType) %x3A) AttrName %x7B LinkedEntityPath %x7D
//! LinkedEntityPath =/ ValuePath
//! ```
//!
//! A linked path filters the matched entities by the attributes of entities of another type, in
//! another scope, that the caller never asked for. Telling it apart from an ordinary path is what
//! lets an enforcement layer refuse it for a caller whose restriction does not reach those entities.

use crate::{
    attribute_path::{AttributePath, ExpandedAttributePath},
    error::QueryError,
    expansion::expand_term,
    parameter_name::ParameterName,
};
use libra_jsonld_term_expansion::{
    name::{ExpandedIri, Term},
    resolved::ResolvedContext,
};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// The attribute a `q` term tests, as authored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QueryAttribute {
    /// A path inside the matched entity, as in `speed.observedAt` or `address[city]`.
    Value(AttributePath),
    /// A Relationship followed into the entity it links to, as in `sensor{humidity}`.
    Linked(LinkedAttribute),
}

/// A Relationship of the matched entity, and the path tested inside the entity it links to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkedAttribute {
    relationship: Term,
    entity_types: Vec<Term>,
    target: Box<QueryAttribute>,
}

impl LinkedAttribute {
    /// Builds a linked path.
    ///
    /// `entity_types` is the `Type,Type:` prefix written before a further Relationship inside the
    /// braces; the grammar allows it only there, so it must be empty when `target` is a
    /// [`QueryAttribute::Value`].
    #[must_use]
    pub fn new(relationship: Term, entity_types: Vec<Term>, target: QueryAttribute) -> Self {
        Self {
            relationship,
            entity_types,
            target: Box::new(target),
        }
    }

    /// The Relationship of the matched entity that is followed.
    #[must_use]
    pub const fn relationship(&self) -> &Term {
        &self.relationship
    }

    /// The entity types written before the next Relationship inside the braces.
    #[must_use]
    pub fn entity_types(&self) -> &[Term] {
        &self.entity_types
    }

    /// What is tested inside the linked entity.
    #[must_use]
    pub fn target(&self) -> &QueryAttribute {
        &self.target
    }
}

impl QueryAttribute {
    /// The attribute of the matched entity this path starts at.
    ///
    /// For a linked path that is the Relationship followed; everything past it belongs to another
    /// entity.
    #[must_use]
    pub fn root(&self) -> Option<&Term> {
        match self {
            Self::Value(path) => path.root(),
            Self::Linked(linked) => Some(&linked.relationship),
        }
    }

    /// Every attribute name the path tests, one for each entity it passes through: each
    /// Relationship followed, outermost first, then the attribute the final path is rooted at.
    ///
    /// The `Type,Type:` prefixes name entity types, not attributes, and are not among them. A
    /// sub-attribute below the final root belongs to that root.
    #[must_use]
    pub fn attribute_names(&self) -> Vec<&Term> {
        let mut names = Vec::new();
        let mut current = self;

        loop {
            match current {
                Self::Value(path) => {
                    names.extend(path.root());
                    return names;
                }
                Self::Linked(linked) => {
                    names.push(&linked.relationship);
                    current = &linked.target;
                }
            }
        }
    }

    /// Whether the path follows a Relationship into another entity.
    #[must_use]
    pub const fn is_linked(&self) -> bool {
        matches!(self, Self::Linked(_))
    }

    /// Expands every name in the path against a context.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::UnexpandableTerm`] if any name has no meaning in this context.
    pub fn expand(&self, context: &ResolvedContext) -> Result<ExpandedQueryAttribute, QueryError> {
        match self {
            Self::Value(path) => Ok(ExpandedQueryAttribute::Value(path.expand(context)?)),
            Self::Linked(linked) => Ok(ExpandedQueryAttribute::Linked(ExpandedLinkedAttribute {
                relationship: expand_term(&ParameterName::Q, &linked.relationship, context)?,
                entity_types: linked
                    .entity_types
                    .iter()
                    .map(|name| expand_term(&ParameterName::Q, name, context))
                    .collect::<Result<_, _>>()?,
                target: Box::new(linked.target.expand(context)?),
            })),
        }
    }
}

impl Display for QueryAttribute {
    /// Renders the path back to `q` syntax.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Value(path) => write!(formatter, "{path}"),
            Self::Linked(linked) => {
                // Escaped as a path segment is, so rendering round-trips through parsing.
                write!(formatter, "{}{{", linked.relationship.as_str().replace('.', "\\."))?;
                write_entity_types(formatter, linked.entity_types.iter().map(Term::as_str))?;
                write!(formatter, "{}}}", linked.target)
            }
        }
    }
}

/// An attribute path after expansion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExpandedQueryAttribute {
    /// A path inside the matched entity.
    Value(ExpandedAttributePath),
    /// A Relationship followed into the entity it links to.
    Linked(ExpandedLinkedAttribute),
}

/// A linked path after expansion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExpandedLinkedAttribute {
    relationship: ExpandedIri,
    entity_types: Vec<ExpandedIri>,
    target: Box<ExpandedQueryAttribute>,
}

impl ExpandedQueryAttribute {
    /// The attribute of the matched entity this path starts at.
    #[must_use]
    pub fn root(&self) -> Option<&ExpandedIri> {
        match self {
            Self::Value(path) => path.root(),
            Self::Linked(linked) => Some(&linked.relationship),
        }
    }
}

impl Display for ExpandedQueryAttribute {
    /// Renders the path with its names as IRIs, shaped exactly as [`QueryAttribute`] renders.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Value(path) => write!(formatter, "{path}"),
            Self::Linked(linked) => {
                write!(formatter, "{}{{", linked.relationship)?;
                write_entity_types(formatter, linked.entity_types.iter().map(ExpandedIri::as_str))?;
                write!(formatter, "{}}}", linked.target)
            }
        }
    }
}

/// Writes a `Type,Type:` prefix, or nothing when there are no types.
fn write_entity_types<'name>(formatter: &mut Formatter<'_>, names: impl Iterator<Item = &'name str>) -> FmtResult {
    let mut wrote_any = false;

    for name in names {
        if wrote_any {
            formatter.write_str(",")?;
        }
        formatter.write_str(name)?;
        wrote_any = true;
    }

    if wrote_any {
        formatter.write_str(":")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::filter::Filter;
    use pretty_assertions::assert_eq;

    fn names(source: &str) -> Vec<Vec<String>> {
        Filter::parse(source)
            .expect("the test filter should parse")
            .attributes()
            .iter()
            .map(|attribute| attribute.attribute_names().iter().map(ToString::to_string).collect())
            .collect()
    }

    #[test]
    fn a_path_on_the_entity_itself_names_its_root() {
        assert_eq!(names("speed.observedAt>2020-01-01T00:00:00Z"), vec![vec!["speed".to_owned()]]);
        assert_eq!(names("address[city]==\"Madrid\""), vec![vec!["address".to_owned()]]);
    }

    #[test]
    fn a_linked_path_names_every_relationship_and_the_final_root() {
        assert_eq!(names("isParked{name}==\"x\""), vec![vec!["isParked".to_owned(), "name".to_owned()]]);
        assert_eq!(
            names("isParked{Building,Garage:owner{name.observedAt}}==\"x\""),
            vec![vec!["isParked".to_owned(), "owner".to_owned(), "name".to_owned()]],
            "the type prefix names types, not attributes"
        );
    }
}
