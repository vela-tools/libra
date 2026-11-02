//! The `q` filter, parsed rather than carried as text.
//!
//! A `q` expression names attributes, and an attribute name is a term. Treating the expression as
//! an opaque string means the proxy never sees those names, so a policy that hides an attribute
//! cannot notice a filter that reads it, and a policy written about `speed` cannot notice a filter
//! written about the IRI `speed` expands to. Parsing is what makes both visible.
//!
//! The grammar follows ETSI GS CIM 009 clause 4.9. `;` is conjunction, `|` is disjunction, `;`
//! binds tighter, and parentheses group.

use crate::{
    control_character::refuse_control_characters,
    error::QueryError,
    parameter_name::ParameterName,
    parser::Parser,
    query_attribute::{ExpandedQueryAttribute, QueryAttribute},
};
use libra_jsonld_term_expansion::{name::ExpandedIri, resolved::ResolvedContext};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display)]
pub enum Operator {
    /// `==`
    #[strum(serialize = "==")]
    Equal,
    /// `!=`
    #[strum(serialize = "!=")]
    NotEqual,
    /// `>`
    #[strum(serialize = ">")]
    Greater,
    /// `>=`
    #[strum(serialize = ">=")]
    GreaterOrEqual,
    /// `<`
    #[strum(serialize = "<")]
    Less,
    /// `<=`
    #[strum(serialize = "<=")]
    LessOrEqual,
    /// `~=`, a pattern match.
    #[strum(serialize = "~=")]
    Matches,
    /// `!~=`, a negated pattern match.
    #[strum(serialize = "!~=")]
    NotMatches,
}

/// One comparison, or a bare existence check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterTerm {
    /// What is being tested.
    pub path: QueryAttribute,
    /// The operator and the value it is compared against. `None` is an existence check.
    pub comparison: Option<(Operator, String)>,
}

/// A parsed `q` expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// A leaf.
    Term(FilterTerm),
    /// `;`: both sides must hold.
    And(Box<Filter>, Box<Filter>),
    /// `|`: either side may hold.
    Or(Box<Filter>, Box<Filter>),
}

impl Filter {
    /// Parses a `q` expression.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::ControlCharacter`] when the expression holds a control character, and
    /// [`QueryError::MalformedFilter`] when it does not fit the grammar. The caller must refuse the
    /// request: an expression Libra cannot read is one whose attribute references it cannot check.
    pub fn parse(source: &str) -> Result<Self, QueryError> {
        refuse_control_characters(source)?;
        let mut parser = Parser::new(source, ParameterName::Q);
        let filter = parser.parse_disjunction(0)?;
        parser.expect_end()?;

        Ok(filter)
    }

    /// Every attribute the expression tests, in order of appearance.
    ///
    /// The attribute enforcement layer needs this: a filter that reads an attribute a policy omits
    /// leaks that attribute's values through the set of entities that come back, even though the
    /// attribute itself never appears in the response.
    #[must_use]
    pub fn attributes(&self) -> Vec<&QueryAttribute> {
        let mut paths = Vec::new();
        self.collect_paths(&mut paths);

        paths
    }

    /// Whether any term follows a Relationship into the entity it links to (clause 4.9
    /// `LinkedEntityRelation`), which filters on entities the query did not select.
    #[must_use]
    pub fn traverses_linked_entities(&self) -> bool {
        self.attributes().iter().any(|attribute| attribute.is_linked())
    }

    fn collect_paths<'filter>(&'filter self, into: &mut Vec<&'filter QueryAttribute>) {
        match self {
            Self::Term(term) => into.push(&term.path),
            Self::And(left, right) | Self::Or(left, right) => {
                left.collect_paths(into);
                right.collect_paths(into);
            }
        }
    }

    /// Expands every attribute path against a context.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::UnexpandableTerm`] if any name has no meaning in this context.
    pub fn expand(&self, context: &ResolvedContext) -> Result<ExpandedFilter, QueryError> {
        Ok(match self {
            Self::Term(term) => ExpandedFilter::Term(ExpandedFilterTerm {
                path: term.path.expand(context)?,
                comparison: term.comparison.clone(), // expansion borrows the parsed filter, which is reused across requests
            }),
            Self::And(left, right) => ExpandedFilter::And(Box::new(left.expand(context)?), Box::new(right.expand(context)?)),
            Self::Or(left, right) => ExpandedFilter::Or(Box::new(left.expand(context)?), Box::new(right.expand(context)?)),
        })
    }
}

impl Display for Filter {
    /// Renders the expression back to `q` syntax.
    ///
    /// Parenthesised where precedence requires it, so a rendered expression parses back to the
    /// same tree. A layer that narrows a filter has to be able to write the narrowed one out.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Term(term) => {
                write!(formatter, "{}", term.path)?;
                if let Some((operator, value)) = &term.comparison {
                    write!(formatter, "{operator}{value}")?;
                }
                Ok(())
            }
            Self::And(left, right) => {
                // `;` binds tighter than `|`, so a disjunction under a conjunction needs brackets
                // and a conjunction never does.
                write_bracketed_if_or(formatter, left)?;
                formatter.write_str(";")?;
                write_bracketed_if_or(formatter, right)
            }
            Self::Or(left, right) => write!(formatter, "{left}|{right}"),
        }
    }
}

/// Brackets a disjunction appearing as an operand of a conjunction.
fn write_bracketed_if_or(formatter: &mut Formatter<'_>, filter: &Filter) -> FmtResult {
    if matches!(filter, Filter::Or(_, _)) {
        write!(formatter, "({filter})")
    } else {
        write!(formatter, "{filter}")
    }
}

/// One comparison, with its path expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedFilterTerm {
    /// What is being tested.
    pub path: ExpandedQueryAttribute,
    /// The operator and the value it is compared against.
    pub comparison: Option<(Operator, String)>,
}

/// A `q` expression whose attribute names are IRIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandedFilter {
    /// A leaf.
    Term(ExpandedFilterTerm),
    /// `;`
    And(Box<ExpandedFilter>, Box<ExpandedFilter>),
    /// `|`
    Or(Box<ExpandedFilter>, Box<ExpandedFilter>),
}

impl Display for ExpandedFilter {
    /// Renders the expression with its names as IRIs.
    ///
    /// Bracketed exactly as [`Filter`] is, so the two renderings differ only in the names.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Term(term) => {
                write!(formatter, "{}", term.path)?;
                if let Some((operator, value)) = &term.comparison {
                    write!(formatter, "{operator}{value}")?;
                }
                Ok(())
            }
            Self::And(left, right) => {
                write_expanded_bracketed_if_or(formatter, left)?;
                formatter.write_str(";")?;
                write_expanded_bracketed_if_or(formatter, right)
            }
            Self::Or(left, right) => write!(formatter, "{left}|{right}"),
        }
    }
}

/// Brackets a disjunction appearing as an operand of a conjunction.
fn write_expanded_bracketed_if_or(formatter: &mut Formatter<'_>, filter: &ExpandedFilter) -> FmtResult {
    if matches!(filter, ExpandedFilter::Or(_, _)) {
        write!(formatter, "({filter})")
    } else {
        write!(formatter, "{filter}")
    }
}

impl ExpandedFilter {
    /// Every attribute the expression reads, rooted, deduplicated, in order of appearance.
    #[must_use]
    pub fn root_attributes(&self) -> Vec<ExpandedIri> {
        let mut roots = Vec::new();
        self.collect_roots(&mut roots);
        roots.dedup();

        roots
    }

    fn collect_roots(&self, into: &mut Vec<ExpandedIri>) {
        match self {
            Self::Term(term) => {
                if let Some(root) = term.path.root() {
                    into.push(root.clone()); // the collected roots outlive this borrowed expression
                }
            }
            Self::And(left, right) | Self::Or(left, right) => {
                left.collect_roots(into);
                right.collect_roots(into);
            }
        }
    }
}
