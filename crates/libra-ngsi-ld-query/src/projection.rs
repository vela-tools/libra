//! The attribute projection language (NGSI-LD clause 4.21), parsed rather than split on commas.
//!
//! `pick`, `omit` and `attrs` name the attributes a response is reduced to. Clause 4.21 lets a list
//! separate its names with `|` as well as `,`, and lets a Relationship name be followed by a
//! `{...}` projection of the entity it links to, as in `observation{temperature,humidity}`.
//! Splitting on `,` read `temperature|humidity` as one name that no context defines, refusing a
//! well-formed request, and cut `observation{temperature,humidity}` into two names neither of which
//! is an attribute. The grammar is parsed here, once, so every reader of a projection sees the same
//! list of names.
//!
//! ```text
//! orOp = %x7C / %x2C                                   ; | ,
//! ProjectionTerm = AttrName *1(LinkedEntityTerm) *(orOp ProjectionTerm)
//! LinkedEntityTerm = %x7B ProjectionTerm %x7D          ; {ProjectionTerm}
//! ```

use crate::{
    control_character::refuse_control_characters,
    cursor::{Cursor, Grammar, MAX_DEPTH},
    entity_member::EntityMember,
    error::QueryError,
    expansion::expand_term,
    parameter_name::ParameterName,
};
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// The query parameters whose value is written in the projection language.
///
/// A `Query` body (clause 5.2.23) carries members of the same names.
pub const PROJECTION_PARAMETERS: [ParameterName; 3] = [ParameterName::ATTRS, ParameterName::PICK, ParameterName::OMIT];

/// Characters that end an attribute name.
const NAME_TERMINATORS: [char; 4] = [',', '|', '{', '}'];

/// Which of the two projections a value was written for (NGSI-LD clause 4.21).
///
/// The same list of names means opposite things under the two: `pick` keeps what it lists and
/// removes the rest, `omit` removes what it lists and keeps the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionKind {
    /// `pick`: every entity is reduced to the listed members.
    Pick,
    /// `omit`: the listed members are removed from every entity.
    Omit,
}

/// A parsed projection: the attributes a response is reduced to, in the order they were written.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Projection {
    terms: Vec<ProjectionTerm>,
}

/// One attribute of a projection, with the projection of the entity it links to if there is one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectionTerm {
    attribute: Term,
    linked: Option<Projection>,
}

impl Projection {
    /// Parses a projection.
    ///
    /// An empty piece between two separators is dropped: `speed,,brand` names two attributes, and
    /// an empty name is not a name.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::ControlCharacter`] when the value holds a control character, and
    /// [`QueryError::MalformedProjection`] when it does not fit the grammar or nests too deeply.
    pub fn parse(source: &str) -> Result<Self, QueryError> {
        refuse_control_characters(source)?;
        let mut parser = Parser {
            cursor: Cursor::new(source, Grammar::Projection),
        };
        let terms = parser.parse_terms(0)?;
        parser.cursor.expect_end()?;

        Ok(Self { terms })
    }

    /// The terms, in the order they were written.
    #[must_use]
    pub fn terms(&self) -> &[ProjectionTerm] {
        &self.terms
    }

    /// The attributes of the projected entity itself, in the order they were written.
    pub fn attributes(&self) -> impl Iterator<Item = &Term> {
        self.terms.iter().map(ProjectionTerm::attribute)
    }

    /// Whether any term reaches into a linked entity, which implies Linked Entity Retrieval
    /// (clause 4.5.23) to produce it.
    #[must_use]
    pub fn reaches_linked_entities(&self) -> bool {
        self.terms.iter().any(|term| term.linked.is_some())
    }

    /// Whether this projection removes `member` from some entity of the answer.
    ///
    /// A `pick` level that does not list the member removes it from the entities at that level, and
    /// an `omit` level that lists it does. Linked-entity terms count: `pick=type,isParked{name}`
    /// keeps `type` on the queried entity but removes it from the entity `isParked` points at. The
    /// member is compared as written, because `id`, `type` and `scope` are keywords of the
    /// projection language rather than terms a context defines.
    #[must_use]
    pub fn removes(&self, member: EntityMember, kind: ProjectionKind) -> bool {
        let listed = self.terms.iter().any(|term| term.attribute.as_str() == member.as_str());
        let removed_here = match kind {
            ProjectionKind::Pick => !listed,
            ProjectionKind::Omit => listed,
        };

        removed_here || self.terms.iter().filter_map(ProjectionTerm::linked).any(|linked| linked.removes(member, kind))
    }

    /// The same projection with every name replaced by the IRI it expands to, ordered and
    /// deduplicated at every level.
    ///
    /// `|` and `,` are one operator, and the order of a disjunction is not part of what it asks
    /// for, so two projections that select the same attributes expand to the same value. `id`,
    /// `type` and `scope` are kept as written: they are entity members a projection names (clause
    /// 6.4.3.2), not attribute terms, and the core context aliases `id` and `type` to keywords that
    /// expand to no IRI at all.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::UnexpandableTerm`] if any name has no meaning in this context.
    pub fn expanded(&self, parameter: &ParameterName, context: &ResolvedContext) -> Result<Self, QueryError> {
        let mut terms = Vec::with_capacity(self.terms.len());

        for term in &self.terms {
            let attribute = if term.linked.is_none() && term.attribute.as_str().parse::<EntityMember>().is_ok() {
                Term::new(term.attribute.as_str())
            } else {
                Term::new(expand_term(parameter, &term.attribute, context)?.as_str())
            };
            let linked = term.linked.as_ref().map(|linked| linked.expanded(parameter, context)).transpose()?;

            terms.push(ProjectionTerm { attribute, linked });
        }

        terms.sort();
        terms.dedup();

        Ok(Self { terms })
    }
}

impl ProjectionTerm {
    /// The attribute of the projected entity this term names.
    #[must_use]
    pub const fn attribute(&self) -> &Term {
        &self.attribute
    }

    /// The projection of the entity the attribute links to, if the term reaches into one.
    #[must_use]
    pub const fn linked(&self) -> Option<&Projection> {
        self.linked.as_ref()
    }
}

impl Display for Projection {
    /// Renders the projection with `,` between its terms, which clause 4.21 makes equivalent to `|`.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        for (index, term) in self.terms.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{term}")?;
        }

        Ok(())
    }
}

impl Display for ProjectionTerm {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(self.attribute.as_str())?;

        if let Some(linked) = &self.linked {
            write!(formatter, "{{{linked}}}")?;
        }

        Ok(())
    }
}

/// A parse of one projection.
struct Parser<'source> {
    cursor: Cursor<'source>,
}

impl<'source> Parser<'source> {
    /// `terms := term ( ( "|" | "," ) term )*`, with empty terms dropped.
    fn parse_terms(&mut self, depth: usize) -> Result<Vec<ProjectionTerm>, QueryError> {
        let mut terms = Vec::new();

        loop {
            if let Some(term) = self.parse_term(depth)? {
                terms.push(term);
            }

            if !(self.cursor.eat(',') || self.cursor.eat('|')) {
                return Ok(terms);
            }
        }
    }

    /// `term := name [ "{" terms "}" ]`, or nothing at all between two separators.
    fn parse_term(&mut self, depth: usize) -> Result<Option<ProjectionTerm>, QueryError> {
        let name = self.parse_name();

        if !self.cursor.eat('{') {
            return Ok((!name.is_empty()).then(|| ProjectionTerm {
                attribute: Term::new(name),
                linked: None,
            }));
        }

        if name.is_empty() {
            return Err(self.cursor.error("expected a Relationship name before '{'"));
        }
        if depth >= MAX_DEPTH {
            return Err(self.cursor.error("linked-entity terms nest too deeply"));
        }

        let linked = self.parse_terms(depth + 1)?;
        if linked.is_empty() {
            return Err(self.cursor.error("a linked-entity term must name an attribute"));
        }
        if !self.cursor.eat('}') {
            return Err(self.cursor.error("expected '}'"));
        }

        // Whitespace may follow the closing brace, as it may follow a name; anything else must be a
        // separator or the end.
        self.skip_whitespace();

        Ok(Some(ProjectionTerm {
            attribute: Term::new(name),
            linked: Some(Projection { terms: linked }),
        }))
    }

    /// Reads a name, trimmed of the whitespace around it.
    fn parse_name(&mut self) -> &'source str {
        self.cursor.take_until(&NAME_TERMINATORS).trim()
    }

    fn skip_whitespace(&mut self) {
        while let Some(character) = self.cursor.peek().filter(|character| character.is_whitespace()) {
            self.cursor.advance(character.len_utf8());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn parse(source: &str) -> Projection {
        Projection::parse(source).unwrap_or_else(|error| panic!("{source} should parse: {error}"))
    }

    fn attributes(source: &str) -> Vec<String> {
        parse(source).attributes().map(|term| term.as_str().to_owned()).collect()
    }

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(r#"{"@vocab": "https://example.test/"}"#).unwrap()
    }

    #[test]
    fn a_comma_separated_value_is_a_list_of_names() {
        assert_eq!(attributes("speed,brand"), ["speed", "brand"]);
        assert_eq!(attributes("speed, brand"), ["speed", "brand"]);
        assert_eq!(attributes("speed,,brand"), ["speed", "brand"]);
        assert_eq!(attributes(""), Vec::<String>::new());
    }

    #[test]
    fn a_pipe_separates_names_as_a_comma_does() {
        // Clause 4.21: "either a comma or a pipe character can be used". Read as one name,
        // `speed|brand` would expand to nothing and the request would be refused for every caller.
        assert_eq!(attributes("speed|brand"), ["speed", "brand"]);
        assert_eq!(attributes("speed|brand,colour"), ["speed", "brand", "colour"]);
    }

    #[test]
    fn a_linked_entity_term_keeps_its_inner_list_together() {
        // Clause 4.21 example 3. Split on commas this would be `observation{temperature` and `humidity}`.
        let projection = parse("observation{temperature,humidity},speed");

        assert_eq!(attributes("observation{temperature,humidity},speed"), ["observation", "speed"]);
        let linked = projection.terms()[0].linked().expect("observation reaches into a linked entity");
        assert_eq!(linked.attributes().map(Term::as_str).collect::<Vec<_>>(), ["temperature", "humidity"]);
        assert_eq!(projection.terms()[1].linked(), None);
    }

    #[test]
    fn linked_entity_terms_may_nest() {
        let projection = parse("a{b{c|d}}");

        let inner = projection.terms()[0]
            .linked()
            .and_then(|linked| linked.terms()[0].linked())
            .expect("two levels");
        assert_eq!(inner.attributes().map(Term::as_str).collect::<Vec<_>>(), ["c", "d"]);
    }

    #[test]
    fn only_a_linked_entity_term_reaches_into_a_linked_entity() {
        assert!(parse("speed,observation{temperature}").reaches_linked_entities());
        assert!(!parse("speed|brand").reaches_linked_entities());
        assert!(!parse("").reaches_linked_entities());
    }

    #[test]
    fn a_pick_that_does_not_list_a_member_removes_it() {
        assert!(parse("name").removes(EntityMember::Type, ProjectionKind::Pick));
        assert!(parse("name").removes(EntityMember::Scope, ProjectionKind::Pick));
        assert!(!parse("type,scope,name").removes(EntityMember::Type, ProjectionKind::Pick));
        assert!(!parse("type,scope,name").removes(EntityMember::Scope, ProjectionKind::Pick));
    }

    #[test]
    fn an_omit_removes_only_the_members_it_lists() {
        assert!(parse("type").removes(EntityMember::Type, ProjectionKind::Omit));
        assert!(!parse("type").removes(EntityMember::Scope, ProjectionKind::Omit));
        assert!(!parse("speed").removes(EntityMember::Type, ProjectionKind::Omit));
    }

    #[test]
    fn a_linked_term_removes_a_member_from_the_linked_entity() {
        // `type` is kept on the queried entity and removed from the one `isParked` points at.
        assert!(parse("type,isParked{name}").removes(EntityMember::Type, ProjectionKind::Pick));
        assert!(!parse("type,isParked{type,name}").removes(EntityMember::Type, ProjectionKind::Pick));
        assert!(parse("speed,isParked{type}").removes(EntityMember::Type, ProjectionKind::Omit));
    }

    #[test]
    fn a_member_spelled_differently_is_not_the_member() {
        assert!(parse("Type,scope").removes(EntityMember::Type, ProjectionKind::Pick));
    }

    #[test]
    fn rendering_writes_every_separator_as_a_comma() {
        assert_eq!(parse("speed|brand").to_string(), "speed,brand");
        assert_eq!(parse("a{b|c}, d").to_string(), "a{b,c},d");
    }

    #[test]
    fn expansion_orders_and_deduplicates_at_every_level() {
        let one = parse("b|a{y,x},a{x|y}").expanded(&ParameterName::PICK, &context()).unwrap();
        let other = parse("a{x,y},b").expanded(&ParameterName::PICK, &context()).unwrap();

        assert_eq!(one, other);
        assert_eq!(
            other.to_string(),
            "https://example.test/a{https://example.test/x,https://example.test/y},https://example.test/b"
        );
    }

    #[test]
    fn entity_members_are_kept_as_written_rather_than_expanded() {
        // The core context aliases `id` and `type` to `@id` and `@type`, which expand to no IRI;
        // expanded as attribute terms, `pick=id,type,name` would be refused for every caller.
        let core = ResolvedContext::from_json(r#"{"id": "@id", "type": "@type", "@vocab": "https://example.test/"}"#).unwrap();

        assert_eq!(
            parse("name,type,id,scope,a{type}").expanded(&ParameterName::PICK, &core).unwrap().to_string(),
            "https://example.test/a{type},https://example.test/name,id,scope,type"
        );
    }

    #[test]
    fn a_name_inside_a_linked_term_that_cannot_be_expanded_is_an_error() {
        let bare = ResolvedContext::from_json(r#"{"a": "https://example.test/a"}"#).unwrap();

        assert!(matches!(
            parse("a{mystery}").expanded(&ParameterName::PICK, &bare),
            Err(QueryError::UnexpandableTerm { term, .. }) if term == Term::new("mystery")
        ));
    }

    #[test]
    fn a_malformed_projection_is_refused_rather_than_half_read() {
        for source in ["a{", "a{b", "a{}", "{b}", "a}", "a{b}c", "a{b}}", ",{b}"] {
            assert!(
                matches!(Projection::parse(source), Err(QueryError::MalformedProjection { .. })),
                "{source:?} must not parse"
            );
        }
    }

    #[test]
    fn deeply_nested_terms_are_refused_rather_than_overflowing_the_stack() {
        let nested = format!("{}a{}", "a{".repeat(100_000), "}".repeat(100_000));

        assert!(Projection::parse(&nested).is_err());
    }
}
