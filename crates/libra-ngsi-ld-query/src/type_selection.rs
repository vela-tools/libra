//! The type selection expression, parsed rather than split on commas.
//!
//! `?type=Vehicle,Building` is the form everyone knows, and it is a disjunction. NGSI-LD 1.8 also
//! defines `A;B` for "has both types", `A|B` for "has either", and parentheses to group them. An
//! implementation that splits on `,` reads `Vehicle|Secret` as the single unknown type name
//! `Vehicle|Secret`, which matches nothing in a deny list while the broker behind it answers with
//! every `Secret` entity. So the grammar is parsed here, once, and the authorization decision and
//! the type enforcement layer both read the result: they cannot disagree about which types a
//! request names.
//!
//! Every leaf is a [`Term`], not a string: what `Vehicle` means is the caller's context's business,
//! and the comparison happens on IRIs.

use crate::{
    control_character::refuse_control_characters,
    cursor::{Cursor, Grammar, MAX_DEPTH},
    error::QueryError,
    expansion::expand_term,
    parameter_name::ParameterName,
};
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Characters that end a type name.
///
/// `,` is in the list because the comma form is a disjunction, and whitespace is because a type
/// name cannot contain any: stopping there turns `A B` into a parse failure rather than a type
/// nobody could have defined.
const NAME_TERMINATORS: [char; 8] = [';', '|', ',', '(', ')', ' ', '\t', '\n'];

/// How many type names one expression may carry.
///
/// A left-leaning chain such as `A|A|A|...` is deep without any parentheses, so depth alone does
/// not bound the tree.
const MAX_NAMES: usize = 64;

/// A parsed type selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSelection {
    /// A leaf: one type name, as authored.
    Type(Term),
    /// `;`: the entity has both types.
    And(Box<TypeSelection>, Box<TypeSelection>),
    /// `|` or `,`: the entity has either type.
    Or(Box<TypeSelection>, Box<TypeSelection>),
}

impl TypeSelection {
    /// Parses a type selection expression.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::ControlCharacter`] when the expression holds a control character, and
    /// [`QueryError::MalformedTypeSelection`] when it does not fit the grammar or exceeds the
    /// nesting or size limits.
    pub fn parse(source: &str) -> Result<Self, QueryError> {
        refuse_control_characters(source)?;
        let mut parser = Parser::new(source);
        let selection = parser.parse_disjunction(0)?;
        parser.cursor.expect_end()?;

        Ok(selection)
    }

    /// The same expression with every leaf replaced by the IRI it expands to.
    ///
    /// The structure is kept, so `A;B` and `A|B` stay different queries.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::UnexpandableTerm`] if any type has no meaning in this context.
    pub fn expanded(&self, context: &ResolvedContext) -> Result<Self, QueryError> {
        match self {
            Self::Type(name) => Ok(Self::Type(Term::new(expand_term(&ParameterName::TYPE, name, context)?.as_str()))),
            Self::And(left, right) => Ok(Self::And(Box::new(left.expanded(context)?), Box::new(right.expanded(context)?))),
            Self::Or(left, right) => Ok(Self::Or(Box::new(left.expanded(context)?), Box::new(right.expanded(context)?))),
        }
    }

    /// The same expression with every leaf `allows` refuses taken out.
    ///
    /// A disjunction keeps whichever of its sides remain, so `Vehicle|Building` narrowed to
    /// `Vehicle` asks for vehicles alone. A conjunction is gone as soon as either side is: an entity
    /// that has a forbidden type is not readable for also having an allowed one. `None` means nothing
    /// of the expression remains.
    ///
    /// # Errors
    ///
    /// Returns whatever `allows` fails with, as soon as it fails.
    pub fn narrowed<E>(&self, mut allows: impl FnMut(&Term) -> Result<bool, E>) -> Result<Option<Self>, E> {
        self.narrowed_by(&mut allows)
    }

    fn narrowed_by<E>(&self, allows: &mut impl FnMut(&Term) -> Result<bool, E>) -> Result<Option<Self>, E> {
        match self {
            Self::Type(name) => Ok(allows(name)?.then(|| Self::Type(name.clone()))), // the narrowed selection owns its leaves
            Self::And(left, right) => {
                let (Some(left), Some(right)) = (left.narrowed_by(allows)?, right.narrowed_by(allows)?) else {
                    return Ok(None);
                };

                Ok(Some(Self::And(Box::new(left), Box::new(right))))
            }
            Self::Or(left, right) => Ok(match (left.narrowed_by(allows)?, right.narrowed_by(allows)?) {
                (Some(left), Some(right)) => Some(Self::Or(Box::new(left), Box::new(right))),
                (Some(remaining), None) | (None, Some(remaining)) => Some(remaining),
                (None, None) => None,
            }),
        }
    }

    /// Every type the expression names, in order of appearance.
    #[must_use]
    pub fn types(&self) -> Vec<&Term> {
        let mut names = Vec::new();
        self.collect_types(&mut names);

        names
    }

    fn collect_types<'selection>(&'selection self, into: &mut Vec<&'selection Term>) {
        match self {
            Self::Type(name) => into.push(name),
            Self::And(left, right) | Self::Or(left, right) => {
                left.collect_types(into);
                right.collect_types(into);
            }
        }
    }
}

impl Display for TypeSelection {
    /// Renders the selection back to the syntax it was written in.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Type(name) => formatter.write_str(name.as_str()),
            Self::And(left, right) => {
                write_bracketed_if_or(formatter, left)?;
                formatter.write_str(";")?;
                write_bracketed_if_or(formatter, right)
            }
            Self::Or(left, right) => write!(formatter, "{left}|{right}"),
        }
    }
}

/// Brackets a disjunction appearing as an operand of a conjunction.
fn write_bracketed_if_or(formatter: &mut Formatter<'_>, selection: &TypeSelection) -> FmtResult {
    if matches!(selection, TypeSelection::Or(_, _)) {
        return write!(formatter, "({selection})");
    }

    write!(formatter, "{selection}")
}

/// A parse of one type selection expression.
struct Parser<'source> {
    cursor: Cursor<'source>,
    names: usize,
}

impl<'source> Parser<'source> {
    /// Starts a parse.
    const fn new(source: &'source str) -> Self {
        Self {
            cursor: Cursor::new(source, Grammar::TypeSelection),
            names: 0,
        }
    }

    /// `disjunction := conjunction ( ( "|" | "," ) conjunction )*`
    fn parse_disjunction(&mut self, depth: usize) -> Result<TypeSelection, QueryError> {
        let mut left = self.parse_conjunction(depth)?;

        while self.cursor.eat('|') || self.cursor.eat(',') {
            let right = self.parse_conjunction(depth)?;
            left = TypeSelection::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// `conjunction := primary ( ";" primary )*`
    fn parse_conjunction(&mut self, depth: usize) -> Result<TypeSelection, QueryError> {
        let mut left = self.parse_primary(depth)?;

        while self.cursor.eat(';') {
            let right = self.parse_primary(depth)?;
            left = TypeSelection::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// `primary := "(" disjunction ")" | name`
    fn parse_primary(&mut self, depth: usize) -> Result<TypeSelection, QueryError> {
        if self.cursor.eat('(') {
            if depth >= MAX_DEPTH {
                return Err(self.cursor.error("parentheses nest too deeply"));
            }

            let inner = self.parse_disjunction(depth + 1)?;
            if !self.cursor.eat(')') {
                return Err(self.cursor.error("expected ')'"));
            }

            return Ok(inner);
        }

        self.parse_name()
    }

    /// `name := <anything that is not a connective>`
    fn parse_name(&mut self) -> Result<TypeSelection, QueryError> {
        let raw = self.cursor.take_until(&NAME_TERMINATORS);
        if raw.is_empty() {
            return Err(self.cursor.error("expected an entity type"));
        }

        self.names += 1;
        if self.names > MAX_NAMES {
            return Err(self.cursor.error("too many entity types"));
        }

        Ok(TypeSelection::Type(Term::new(raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::convert::Infallible;

    fn parse(source: &str) -> TypeSelection {
        TypeSelection::parse(source).unwrap_or_else(|error| panic!("{source} should parse: {error}"))
    }

    fn named(source: &str) -> Vec<String> {
        parse(source).types().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_comma_list_is_a_disjunction() {
        assert_eq!(named("Vehicle,Building"), vec!["Vehicle".to_owned(), "Building".to_owned()]);
        assert_eq!(
            parse("Vehicle,Building"),
            TypeSelection::Or(Box::new(parse("Vehicle")), Box::new(parse("Building")))
        );
    }

    #[test]
    fn the_1_8_connectives_are_understood_rather_than_read_as_part_of_a_name() {
        // Splitting on `,` alone would make `Vehicle;Secret` a single type name that matched nothing, so
        // a deny on `Secret` would never see it.
        assert_eq!(named("Vehicle;Sensor"), vec!["Vehicle".to_owned(), "Sensor".to_owned()]);
        assert_eq!(named("Vehicle|Sensor"), vec!["Vehicle".to_owned(), "Sensor".to_owned()]);
        assert_eq!(named("A;(B|C)"), vec!["A".to_owned(), "B".to_owned(), "C".to_owned()]);
        assert_eq!(named("(Secret)"), vec!["Secret".to_owned()]);
    }

    #[test]
    fn conjunction_binds_tighter_than_disjunction() {
        assert_eq!(
            parse("A;B|C"),
            TypeSelection::Or(Box::new(TypeSelection::And(Box::new(parse("A")), Box::new(parse("B")))), Box::new(parse("C")),)
        );
    }

    #[test]
    fn an_expanded_iri_is_a_type_name_like_any_other() {
        // Sending the IRI instead of the term is legal on the wire, and is exactly the form that
        // slips past a proxy comparing words.
        assert_eq!(
            named("https://uri.fiware.org/ns/data-models#Vehicle"),
            vec!["https://uri.fiware.org/ns/data-models#Vehicle".to_owned()]
        );
    }

    #[test]
    fn a_malformed_selection_is_refused_rather_than_passed_through() {
        for source in ["", "A;", "A,", "(A", "A)", "A B", "A|", ";A"] {
            assert!(TypeSelection::parse(source).is_err(), "{source:?} must not parse");
        }
    }

    #[test]
    fn rendering_keeps_the_meaning_even_though_commas_become_bars() {
        assert_eq!(parse("A,B").to_string(), "A|B");
        assert_eq!(parse("A;(B|C)").to_string(), "A;(B|C)");
        assert_eq!(parse("A;B|C").to_string(), "A;B|C");
    }

    fn narrowed(source: &str, allowed: &[&str]) -> Option<String> {
        parse(source)
            .narrowed(|name: &Term| Ok::<_, Infallible>(allowed.contains(&name.as_str())))
            .unwrap_or_else(|error| match error {})
            .map(|selection| selection.to_string())
    }

    #[test]
    fn a_disjunction_keeps_its_allowed_sides() {
        assert_eq!(narrowed("Vehicle,Building", &["Vehicle"]), Some("Vehicle".to_owned()));
        assert_eq!(narrowed("Building|Vehicle", &["Vehicle"]), Some("Vehicle".to_owned()));
        assert_eq!(narrowed("Vehicle|Sensor|Building", &["Vehicle", "Sensor"]), Some("Vehicle|Sensor".to_owned()));
        assert_eq!(narrowed("Vehicle|Building", &["Vehicle", "Building"]), Some("Vehicle|Building".to_owned()));
    }

    #[test]
    fn a_conjunction_with_a_forbidden_side_is_gone() {
        // An entity of a forbidden type is not readable for having an allowed one too.
        assert_eq!(narrowed("Vehicle;Building", &["Vehicle"]), None);
        assert_eq!(narrowed("Vehicle;Sensor", &["Vehicle", "Sensor"]), Some("Vehicle;Sensor".to_owned()));
    }

    #[test]
    fn nothing_allowed_is_nothing_left() {
        assert_eq!(narrowed("Building", &["Vehicle"]), None);
        assert_eq!(narrowed("Building|Sensor", &["Vehicle"]), None);
    }

    #[test]
    fn narrowing_follows_the_brackets() {
        assert_eq!(narrowed("(Vehicle;Building)|Vehicle", &["Vehicle"]), Some("Vehicle".to_owned()));
        assert_eq!(narrowed("Vehicle;(Sensor|Building)", &["Vehicle", "Sensor"]), Some("Vehicle;Sensor".to_owned()));
        assert_eq!(narrowed("(Building|Sensor);Vehicle", &["Vehicle"]), None);
        assert_eq!(narrowed("((A|B);(C|D))|E", &["A", "C", "D"]), Some("A;(C|D)".to_owned()));
    }

    #[test]
    fn a_failing_judge_stops_the_narrowing() {
        let mut judged = Vec::new();
        let result = parse("A|B|C").narrowed(|name: &Term| {
            judged.push(name.to_string());
            if name.as_str() == "B" { Err("unjudgeable") } else { Ok(true) }
        });

        assert_eq!(result, Err("unjudgeable"));
        assert_eq!(judged, vec!["A".to_owned(), "B".to_owned()]);
    }

    #[test]
    fn deeply_nested_parentheses_are_refused_rather_than_overflowing_the_stack() {
        let nested = format!("{}A{}", "(".repeat(100_000), ")".repeat(100_000));

        assert!(TypeSelection::parse(&nested).is_err());
    }

    #[test]
    fn a_long_chain_of_names_is_refused_rather_than_building_a_deep_tree() {
        let chain = vec!["A"; 100_000].join("|");

        assert!(TypeSelection::parse(&chain).is_err());
        assert!(TypeSelection::parse(&vec!["A"; MAX_NAMES].join("|")).is_ok(), "the limit itself is allowed");
    }
}
