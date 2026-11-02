//! The Entity Ordering Language of `orderBy` (NGSI-LD clause 4.23.3), parsed into terms.
//!
//! An ordering ranks an answer's entities by the values of the attributes it names, so the order
//! the entities come back in discloses those values just as the entities a `q` filter selects do.
//! Every attribute an ordering names is therefore read here, once, by the same path rules a `q`
//! term uses (clause 4.9 `Attribute`), so a reader judging the ordering sees every name the broker
//! will rank by.
//!
//! ```text
//! thenOp = %x2C                                        ; ,
//! directionOp ::= asc | desc | dist-asc | dist-desc
//! OrderingTerm = AttrName *1(DirectionTerm) *(thenOp OrderingTerm)
//! DirectionTerm = %x3B directionOp                     ; ;
//! ```
//!
//! Clause 4.23.3 examples 4 and 5 rank by `address[city]` and `name.observedAt`, so a term's name
//! is an attribute path with an optional trailing key path, as in a `q` term. Table 5.2.43-1 also
//! lets a term name the entity members `id`, `type` and `scope`, which are not attributes.

use crate::{
    attribute_path::{AttributePath, split_segments, split_trailing},
    entity_member::EntityMember,
    error::QueryError,
};
use std::str::FromStr;
use strum::{Display, EnumString};

/// How many terms one ordering may hold.
///
/// An ordering arrives before anything has been authorised, and every term costs an expansion and a
/// judgement downstream.
const MAX_TERMS: usize = 128;

/// Characters no attribute name contains (NGSI-LD clause 4.9 `nameChar`).
///
/// Refused rather than carried into a name: a broker that trims or splits on one of them would rank
/// by a different attribute than the one judged here.
const FORBIDDEN: [char; 12] = ['(', ')', '{', '}', '|', '=', '!', '<', '>', '~', '"', '\''];

/// A parsed `orderBy`: the terms an answer is ranked by, in the order they apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ordering {
    terms: Vec<OrderingTerm>,
}

/// One ranking key of an ordering, and the direction it ranks in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderingTerm {
    key: OrderingKey,
    direction: SortDirection,
}

/// What one ordering term ranks by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderingKey {
    /// An entity member that is not an attribute (`id`, `type` or `scope`).
    Member(EntityMember),
    /// An attribute, possibly a dotted path to a sub-attribute and a trailing key path into its value.
    Attribute(AttributePath),
}

/// The sorting style of an ordering term (NGSI-LD clause 4.23.3 `directionOp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Display, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum SortDirection {
    /// Ascending by value, the default when a term names no direction.
    #[default]
    Asc,
    /// Descending by value.
    Desc,
    /// Ascending by distance from `orderFrom`, which ranks by a `GeoProperty`.
    DistAsc,
    /// Descending by distance from `orderFrom`, which ranks by a `GeoProperty`.
    DistDesc,
}

impl Ordering {
    /// Parses an `orderBy` value.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::MalformedOrdering`] when the value is empty, holds an empty term, a
    /// sorting style the grammar does not define, a name with a character no attribute name
    /// carries, a malformed trailing key path, or more terms than one ordering may hold.
    pub fn parse(source: &str) -> Result<Self, QueryError> {
        let mut terms = Vec::new();
        let mut offset = 0;

        for element in source.split(',') {
            if terms.len() == MAX_TERMS {
                return Err(malformed(offset, "too many ordering terms"));
            }

            terms.push(OrderingTerm::parse(element).map_err(|reason| malformed(offset, reason))?);
            offset += element.len() + ','.len_utf8();
        }

        Ok(Self { terms })
    }

    /// The terms, in the order they rank by.
    #[must_use]
    pub fn terms(&self) -> &[OrderingTerm] {
        &self.terms
    }

    /// Every attribute path the ordering ranks by, entity members left out.
    pub fn attributes(&self) -> impl Iterator<Item = &AttributePath> {
        self.terms.iter().filter_map(|term| term.key.attribute())
    }
}

impl OrderingTerm {
    /// Parses one term, or says why it is not one.
    fn parse(element: &str) -> Result<Self, &'static str> {
        let (name, direction) = match element.split_once(';') {
            Some((name, written)) => (name, SortDirection::from_str(written).map_err(|_| "unknown sorting style")?),
            None => (element, SortDirection::default()),
        };

        if name.is_empty() {
            return Err("expected an attribute name");
        }
        if name
            .chars()
            .any(|character| character.is_whitespace() || character.is_control() || FORBIDDEN.contains(&character))
        {
            return Err("a character no attribute name carries");
        }

        let (head, trailing) = split_trailing(name)?;
        let segments = split_segments(head);

        if segments.iter().any(|segment| segment.as_str().is_empty()) {
            return Err("an empty name in a dotted attribute path");
        }

        let key = match (segments.as_slice(), &trailing) {
            ([only], None) => EntityMember::from_str(only.as_str()).map_or_else(|_| OrderingKey::Attribute(AttributePath::new(segments)), OrderingKey::Member),
            _ => OrderingKey::Attribute(AttributePath::new(segments).with_trailing(trailing)),
        };

        Ok(Self { key, direction })
    }

    /// What the term ranks by.
    #[must_use]
    pub const fn key(&self) -> &OrderingKey {
        &self.key
    }

    /// The direction the term ranks in.
    #[must_use]
    pub const fn direction(&self) -> SortDirection {
        self.direction
    }
}

impl OrderingKey {
    /// The attribute path, when the key is an attribute rather than an entity member.
    #[must_use]
    pub const fn attribute(&self) -> Option<&AttributePath> {
        match self {
            Self::Attribute(path) => Some(path),
            Self::Member(_) => None,
        }
    }
}

/// The refusal of an ordering, at the term that failed.
const fn malformed(offset: usize, reason: &'static str) -> QueryError {
    QueryError::MalformedOrdering { offset, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_path::KeyPath;
    use libra_jsonld_term_expansion::name::Term;
    use pretty_assertions::assert_eq;

    fn parse(source: &str) -> Ordering {
        Ordering::parse(source).unwrap_or_else(|error| panic!("{source} should parse: {error}"))
    }

    fn names(path: &AttributePath) -> Vec<&str> {
        path.segments().iter().map(Term::as_str).collect()
    }

    #[test]
    fn a_single_name_ranks_ascending_by_default() {
        let ordering = parse("name");

        assert_eq!(ordering.terms().len(), 1);
        assert_eq!(ordering.terms()[0].direction(), SortDirection::Asc);
        assert_eq!(ordering.attributes().map(names).collect::<Vec<_>>(), [["name"]]);
    }

    #[test]
    fn terms_separated_by_commas_each_carry_their_own_direction() {
        // Clause 4.23.3 example 3.
        let ordering = parse("name,age;desc");

        assert_eq!(
            ordering.terms().iter().map(OrderingTerm::direction).collect::<Vec<_>>(),
            [SortDirection::Asc, SortDirection::Desc]
        );
        assert_eq!(ordering.attributes().map(names).collect::<Vec<_>>(), [["name"], ["age"]]);
    }

    #[test]
    fn every_sorting_style_of_the_grammar_is_read() {
        for (written, direction) in [
            ("asc", SortDirection::Asc),
            ("desc", SortDirection::Desc),
            ("dist-asc", SortDirection::DistAsc),
            ("dist-desc", SortDirection::DistDesc),
        ] {
            assert_eq!(parse(&format!("location;{written}")).terms()[0].direction(), direction, "{written}");
        }
    }

    #[test]
    fn a_trailing_key_path_is_kept_apart_from_the_attribute_it_reads() {
        // Clause 4.23.3 example 4: `city` is a key inside the value of `address`, not a term.
        let ordering = parse("address[city];desc");
        let path = ordering.attributes().next().expect("one attribute");

        assert_eq!(names(path), ["address"]);
        assert_eq!(path.trailing().map(KeyPath::as_str), Some("city"));
    }

    #[test]
    fn a_dotted_path_keeps_every_name_it_passes_through() {
        // Clause 4.23.3 example 5.
        let ordering = parse("name.observedAt");

        assert_eq!(ordering.attributes().map(names).collect::<Vec<_>>(), [["name", "observedAt"]]);
    }

    #[test]
    fn the_entity_members_are_not_attributes() {
        let ordering = parse("id,type;desc,scope,speed");

        assert_eq!(
            ordering.terms().iter().map(|term| term.key().clone()).take(3).collect::<Vec<_>>(),
            [
                OrderingKey::Member(EntityMember::Id),
                OrderingKey::Member(EntityMember::Type),
                OrderingKey::Member(EntityMember::Scope)
            ]
        );
        assert_eq!(ordering.attributes().map(names).collect::<Vec<_>>(), [["speed"]]);
    }

    #[test]
    fn a_path_under_an_entity_member_name_is_an_attribute_path() {
        assert!(parse("type.observedAt").attributes().next().is_some());
        assert!(parse("id[x]").attributes().next().is_some());
    }

    #[test]
    fn an_absolute_iri_is_one_name_despite_its_dots() {
        let ordering = parse("https://example.test/speed;desc");

        assert_eq!(ordering.attributes().map(names).collect::<Vec<_>>(), [["https://example.test/speed"]]);
    }

    #[test]
    fn an_ordering_outside_the_grammar_is_refused() {
        for malformed in [
            "",
            "name,",
            ",name",
            "name;",
            "name;up",
            "name;DESC",
            "name;asc;desc",
            "name age",
            "name{x}",
            "a|b",
            "name..x",
            ".name",
            "address[]",
            "address[city",
            "[city]",
        ] {
            assert!(
                matches!(Ordering::parse(malformed), Err(QueryError::MalformedOrdering { .. })),
                "{malformed:?} must be refused"
            );
        }
    }

    #[test]
    fn the_refusal_points_at_the_term_that_failed() {
        assert_eq!(
            Ordering::parse("name,age;sideways"),
            Err(QueryError::MalformedOrdering {
                offset: 5,
                reason: "unknown sorting style"
            })
        );
    }

    #[test]
    fn an_ordering_with_too_many_terms_is_refused() {
        let many = vec!["a"; MAX_TERMS + 1].join(",");

        assert!(Ordering::parse(&vec!["a"; MAX_TERMS].join(",")).is_ok());
        assert!(matches!(Ordering::parse(&many), Err(QueryError::MalformedOrdering { .. })));
    }
}
