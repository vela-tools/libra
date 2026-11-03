//! A recursive-descent parser for the `q` grammar.
//!
//! Kept apart from the syntax tree so the tree stays readable. The grammar is small: two binary
//! operators, brackets, and a leaf, but the leaf is where the care goes: an attribute path is a
//! sequence of terms that may follow a Relationship into a linked entity, and a value can contain
//! anything at all as long as it is quoted.

use crate::{
    attribute_path::{AttributePath, split_segments, split_trailing},
    cursor::{Cursor, Grammar, MAX_DEPTH},
    error::QueryError,
    filter::{Filter, FilterTerm, Operator},
    parameter_name::ParameterName,
    query_attribute::{LinkedAttribute, QueryAttribute},
};
use libra_jsonld_term_expansion::name::Term;

/// Characters that end an attribute path.
///
/// Whitespace is in the list because an attribute name cannot contain any, and stopping there
/// turns `a b` into a path followed by something that is not an operator: a parse failure rather
/// than an attribute called `a b` that would never expand and never match. The braces delimit a
/// linked-entity path (clause 4.9 `LinkedEntityRelation`), which is parsed rather than left in a
/// name no context defines.
const PATH_TERMINATORS: [char; 14] = [';', '|', ')', '(', '=', '!', '>', '<', '{', '}', ' ', '\t', '\r', '\n'];

/// How many terms one expression may hold.
///
/// A left-leaning chain such as `a|a|a|...` is deep without any parentheses, so the nesting limit
/// alone does not bound the tree.
const MAX_TERMS: usize = 128;

/// A parse of one filter expression.
pub(crate) struct Parser<'source> {
    cursor: Cursor<'source>,
    terms: usize,
}

impl<'source> Parser<'source> {
    /// Starts a parse. `parameter` names the query parameter, for error messages.
    pub(crate) const fn new(source: &'source str, parameter: ParameterName) -> Self {
        Self {
            cursor: Cursor::new(source, Grammar::Filter(parameter)),
            terms: 0,
        }
    }

    /// `disjunction := conjunction ( "|" conjunction )*`
    pub(crate) fn parse_disjunction(&mut self, depth: usize) -> Result<Filter, QueryError> {
        let mut left = self.parse_conjunction(depth)?;

        while self.cursor.eat('|') {
            let right = self.parse_conjunction(depth)?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// `conjunction := primary ( ";" primary )*`
    fn parse_conjunction(&mut self, depth: usize) -> Result<Filter, QueryError> {
        let mut left = self.parse_primary(depth)?;

        while self.cursor.eat(';') {
            let right = self.parse_primary(depth)?;
            left = Filter::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// `primary := "(" disjunction ")" | term`
    fn parse_primary(&mut self, depth: usize) -> Result<Filter, QueryError> {
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

        self.parse_term()
    }

    /// `term := attributePath [ operator value ]`
    fn parse_term(&mut self) -> Result<Filter, QueryError> {
        self.terms += 1;
        if self.terms > MAX_TERMS {
            return Err(self.cursor.error("too many terms"));
        }

        let path = self.parse_attribute(0)?;
        let comparison = match self.parse_operator()? {
            Some(operator) => Some((operator, self.parse_value()?)),
            None => None,
        };

        Ok(Filter::Term(FilterTerm { path, comparison }))
    }

    /// `attribute := name "{" [ types ":" ] attribute "}" | valuePath`
    ///
    /// `nesting` counts the braces already open, which bounds the recursion.
    fn parse_attribute(&mut self, nesting: usize) -> Result<QueryAttribute, QueryError> {
        let raw = self.parse_path_text()?;
        let (head, trailing) = split_trailing(raw).map_err(|reason| self.cursor.error(reason))?;

        if !self.cursor.eat('{') {
            return Ok(QueryAttribute::Value(AttributePath::new(split_segments(head)).with_trailing(trailing)));
        }

        if nesting >= MAX_DEPTH {
            return Err(self.cursor.error("linked-entity paths nest too deeply"));
        }

        // `AttrName{`: the Relationship followed is one name of the entity, never a dotted path to a
        // sub-attribute or a key path into a value.
        let (Some(relationship), None) = (single_segment(head), trailing) else {
            return Err(self.cursor.error("a linked-entity path must start at a single Relationship name"));
        };

        let entity_types = self.parse_entity_types();
        let target = self.parse_attribute(nesting + 1)?;

        if !entity_types.is_empty() && !target.is_linked() {
            return Err(self.cursor.error("entity types may only qualify a further Relationship"));
        }
        if !self.cursor.eat('}') {
            return Err(self.cursor.error("expected '}'"));
        }

        Ok(QueryAttribute::Linked(LinkedAttribute::new(relationship, entity_types, target)))
    }

    /// Reads the `Type,Type:` prefix of a linked-entity path, if one is next.
    ///
    /// The grammar (`EntityType 1*(%x2C EntityType) %x3A`) requires at least two types, and reading
    /// it that strictly is what keeps a prefixed name such as `ex:speed` an attribute rather than an
    /// entity type `ex` followed by `speed`.
    fn parse_entity_types(&mut self) -> Vec<Term> {
        let rest = self.cursor.rest();
        let length = rest
            .find(|character: char| !(character.is_alphanumeric() || character == '_' || character == ','))
            .unwrap_or(rest.len());
        let candidate = &rest[..length];

        let names: Vec<&str> = candidate.split(',').collect();
        let is_prefix = rest[length..].starts_with(':') && names.len() >= 2 && names.iter().all(|name| name.chars().next().is_some_and(char::is_alphabetic));

        if !is_prefix {
            return Vec::new();
        }

        self.cursor.advance(length + ':'.len_utf8());

        names.into_iter().map(Term::new).collect()
    }

    /// Reads the text of an attribute path, up to whatever ends it.
    fn parse_path_text(&mut self) -> Result<&'source str, QueryError> {
        let start = self.cursor.offset();
        let mut escaped = false;

        while let Some(character) = self.cursor.peek() {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if PATH_TERMINATORS.contains(&character) || character == '~' {
                break;
            }
            self.cursor.advance(character.len_utf8());
        }

        let raw = self.cursor.since(start);
        if raw.is_empty() {
            return Err(self.cursor.error("expected an attribute name"));
        }

        Ok(raw)
    }

    /// Reads a comparison operator, if there is one.
    fn parse_operator(&mut self) -> Result<Option<Operator>, QueryError> {
        // Longest match first: `>=` must not be read as `>` followed by a value starting with `=`,
        // and `!~=` must not be read as `!=` followed by `~`.
        for (token, operator) in [
            ("!~=", Operator::NotMatches),
            ("==", Operator::Equal),
            ("!=", Operator::NotEqual),
            (">=", Operator::GreaterOrEqual),
            ("<=", Operator::LessOrEqual),
            ("~=", Operator::Matches),
            (">", Operator::Greater),
            ("<", Operator::Less),
        ] {
            if self.cursor.rest().starts_with(token) {
                self.cursor.advance(token.len());
                return Ok(Some(operator));
            }
        }

        match self.cursor.peek() {
            // An existence check: the term ends here, or the next thing is a connective.
            None | Some(';' | '|' | ')') => Ok(None),
            Some(_unexpected) => Err(self.cursor.error("expected a comparison operator")),
        }
    }

    /// Reads a value, respecting quotes.
    fn parse_value(&mut self) -> Result<String, QueryError> {
        let start = self.cursor.offset();
        let mut quoted = false;
        let mut escaped = false;

        while let Some(character) = self.cursor.peek() {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = !quoted;
            } else if !quoted && (character == ';' || character == '|' || character == ')') {
                break;
            }
            self.cursor.advance(character.len_utf8());
        }

        if quoted {
            return Err(self.cursor.error("unterminated quoted value"));
        }

        let raw = self.cursor.since(start);
        if raw.is_empty() {
            return Err(self.cursor.error("expected a value after the operator"));
        }

        Ok(raw.to_owned())
    }

    /// Fails unless the whole expression has been consumed.
    pub(crate) fn expect_end(&self) -> Result<(), QueryError> {
        self.cursor.expect_end()
    }
}

/// The one name a path consists of, or `None` when it is a dotted path.
fn single_segment(raw: &str) -> Option<Term> {
    <[Term; 1]>::try_from(split_segments(raw)).ok().map(|[only]| only)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{filter::Filter, key_path::KeyPath};
    use pretty_assertions::assert_eq;

    fn parse(source: &str) -> Filter {
        Filter::parse(source).unwrap_or_else(|error| panic!("{source} should parse: {error}"))
    }

    fn paths(source: &str) -> Vec<String> {
        parse(source).attributes().iter().map(ToString::to_string).collect()
    }

    /// The value path of an expression that is one term testing one.
    fn value_path(source: &str) -> AttributePath {
        let Filter::Term(FilterTerm {
            path: QueryAttribute::Value(path),
            ..
        }) = parse(source)
        else {
            panic!("{source} should be a single term testing a value path");
        };

        path
    }

    /// The linked path of an expression that is one term testing one.
    fn linked_path(source: &str) -> LinkedAttribute {
        let Filter::Term(FilterTerm {
            path: QueryAttribute::Linked(linked),
            ..
        }) = parse(source)
        else {
            panic!("{source} should be a single term testing a linked path");
        };

        linked
    }

    #[test]
    fn a_bare_attribute_is_an_existence_check() {
        assert_eq!(
            parse("speed"),
            Filter::Term(FilterTerm {
                path: QueryAttribute::Value(AttributePath::new(vec![Term::new("speed")])),
                comparison: None,
            })
        );
    }

    #[test]
    fn a_comparison_keeps_its_operator_and_value() {
        assert_eq!(
            parse("speed>40"),
            Filter::Term(FilterTerm {
                path: QueryAttribute::Value(AttributePath::new(vec![Term::new("speed")])),
                comparison: Some((Operator::Greater, "40".to_owned())),
            })
        );
    }

    #[test]
    fn the_longer_operator_wins() {
        // `>=` read as `>` would compare against the value `=40`, and `!~=` read as `!=` would
        // turn a negated pattern match into an inequality against a pattern.
        assert_eq!(parse("speed>=40").attributes().len(), 1);
        for (source, expected) in [
            ("a>=1", Operator::GreaterOrEqual),
            ("a<=1", Operator::LessOrEqual),
            ("a!~=1", Operator::NotMatches),
            ("a!=1", Operator::NotEqual),
            ("a==1", Operator::Equal),
            ("a~=1", Operator::Matches),
            ("a>1", Operator::Greater),
            ("a<1", Operator::Less),
        ] {
            let Filter::Term(term) = parse(source) else {
                panic!("{source} should be a single term");
            };
            assert_eq!(term.comparison.expect("a comparison").0, expected, "{source}");
        }
    }

    #[test]
    fn conjunction_binds_tighter_than_disjunction() {
        // `a;b|c` is `(a;b)|c`. Read the other way round it would demand `a` on both branches and
        // reject entities the caller is entitled to see, or, in a policy, allow ones it is not.
        assert_eq!(
            parse("a;b|c"),
            Filter::Or(Box::new(Filter::And(Box::new(parse("a")), Box::new(parse("b")),)), Box::new(parse("c")),)
        );
    }

    #[test]
    fn brackets_override_precedence() {
        assert_eq!(
            parse("a;(b|c)"),
            Filter::And(Box::new(parse("a")), Box::new(Filter::Or(Box::new(parse("b")), Box::new(parse("c")))),)
        );
    }

    #[test]
    fn a_dotted_path_becomes_segments() {
        assert_eq!(paths("speed.observedAt>2026-01-01T00:00:00Z"), vec!["speed.observedAt"]);

        assert_eq!(value_path("speed.observedAt").segments(), [Term::new("speed"), Term::new("observedAt")]);
    }

    #[test]
    fn an_escaped_dot_stays_inside_one_segment() {
        assert_eq!(value_path(r"my\.attr==1").segments(), [Term::new("my.attr")]);
    }

    #[test]
    fn an_iri_attribute_is_one_segment() {
        // Splitting `https://example.test#speed` on its dots would invent `test#speed` as a
        // sub-attribute of `https://example`, then refuse a well-formed request.
        assert_eq!(
            value_path("https://example.test#speed>40").segments(),
            [Term::new("https://example.test#speed")]
        );
    }

    #[test]
    fn a_quoted_value_may_contain_the_connectives() {
        // Splitting on the `;` inside the quotes would cut the expression in half and hand the
        // broker a filter the proxy never saw.
        let Filter::Term(term) = parse(r#"name=="a;b|c""#) else {
            panic!("expected a single term");
        };

        assert_eq!(term.comparison.expect("a comparison").1, r#""a;b|c""#);
    }

    #[test]
    fn every_attribute_mentioned_is_reachable() {
        assert_eq!(paths("a>1;(b==2|c.d~=\"x\")"), vec!["a", "b", "c.d"]);
    }

    #[test]
    fn rendering_round_trips_through_parsing() {
        for source in ["speed", "speed>40", "a;b|c", "a;(b|c)", r#"name=="a;b""#, r"my\.attr==1"] {
            assert_eq!(parse(source).to_string(), source, "{source} should render as it was written");
        }
    }

    #[test]
    fn a_trailing_path_does_not_hide_its_root() {
        // Read as one attribute named `address[city]`, which no context defines, the path would
        // hide a filter reading inside `address` from a restriction omitting it.
        let path = value_path("address[city]==Madrid");

        assert_eq!(path.segments(), [Term::new("address")]);
        assert_eq!(path.root(), Some(&Term::new("address")));
        assert_eq!(path.trailing().map(KeyPath::as_str), Some("city"));
        assert_eq!(parse("address[city]==Madrid").to_string(), "address[city]==Madrid");
        assert_eq!(parse("speed.observedAt[a.b]").to_string(), "speed.observedAt[a.b]");
    }

    #[test]
    fn a_relationship_in_braces_is_a_linked_entity_path() {
        // Clause 4.9 `LinkedEntityRelation`. Left in the name, `sensor{humidity}` would expand to
        // nothing and every caller would be refused a well-formed query.
        let linked = linked_path("sensor{humidity}>40");

        assert_eq!(linked.relationship(), &Term::new("sensor"));
        assert_eq!(linked.entity_types(), [] as [Term; 0]);
        assert_eq!(linked.target(), &QueryAttribute::Value(AttributePath::new(vec![Term::new("humidity")])));
    }

    #[test]
    fn the_root_of_a_linked_path_is_the_relationship_it_follows() {
        assert_eq!(parse("sensor{humidity.observedAt}").attributes()[0].root(), Some(&Term::new("sensor")));
    }

    #[test]
    fn a_linked_path_may_follow_further_relationships_through_named_types() {
        let linked = linked_path("sensor{Device,Sensor:location{address[city]}}==\"Berlin\"");

        let QueryAttribute::Linked(inner) = linked.target() else {
            panic!("the target should follow a further Relationship");
        };
        assert_eq!(linked.entity_types(), [Term::new("Device"), Term::new("Sensor")]);
        assert_eq!(inner.relationship(), &Term::new("location"));
        assert!(matches!(inner.target(), QueryAttribute::Value(path) if path.trailing().is_some()));
    }

    #[test]
    fn a_prefixed_name_inside_braces_stays_an_attribute() {
        // The type prefix needs two types, so `ex:humidity` is not a type `ex` and a name.
        let linked = linked_path("sensor{ex:humidity}");

        assert_eq!(linked.entity_types(), [] as [Term; 0]);
        assert_eq!(linked.target(), &QueryAttribute::Value(AttributePath::new(vec![Term::new("ex:humidity")])));
    }

    #[test]
    fn only_a_linked_path_traverses_linked_entities() {
        assert!(parse("speed>40;sensor{humidity}").traverses_linked_entities());
        assert!(!parse("speed>40;address[city]==\"Berlin\"").traverses_linked_entities());
    }

    #[test]
    fn an_absolute_iri_path_renders_without_escaping_its_dots() {
        // Found by the q_filter fuzz target: each round trip added a backslash before every dot.
        // The same holds for an IRI that names the Relationship of a linked-entity path.
        let sources = [
            "https://uri.etsi.org/ngsi-ldes\"",
            "https://example.test/speed>40",
            "urn:a.b==1",
            "https://example.test/a...b{c}",
            "https://example.test/rel.x{urn:a.b{speed}}>40",
        ];
        for source in sources {
            assert_eq!(parse(source).to_string(), source, "{source} should render as it was written");
        }
    }

    #[test]
    fn a_linked_path_renders_as_it_was_written() {
        for source in ["sensor{humidity}>40", "a{B,C:d{e.f[g]}}", "a;b{c}|d"] {
            assert_eq!(parse(source).to_string(), source, "{source} should render as it was written");
        }
    }

    #[test]
    fn a_malformed_linked_path_is_refused() {
        for source in ["a{", "a{b", "a{}", "{b}", "a}", "a.b{c}", "a[x]{c}", "a{B,C:d}", "a{b}c", "a{b}{c}"] {
            assert!(Filter::parse(source).is_err(), "{source:?} must not parse");
        }
    }

    #[test]
    fn deeply_nested_linked_paths_are_refused_rather_than_overflowing_the_stack() {
        let nested = format!("{}a{}", "a{".repeat(100_000), "}".repeat(100_000));

        assert!(Filter::parse(&nested).is_err());
    }

    #[test]
    fn deeply_nested_parentheses_are_refused_rather_than_overflowing_the_stack() {
        let nested = format!("{}a{}", "(".repeat(100_000), ")".repeat(100_000));

        assert!(Filter::parse(&nested).is_err());
    }

    #[test]
    fn a_long_chain_of_terms_is_refused_rather_than_building_a_deep_tree() {
        assert!(Filter::parse(&vec!["a"; 100_000].join("|")).is_err());
        assert!(Filter::parse(&vec!["a"; MAX_TERMS].join(";")).is_ok(), "the limit itself is allowed");
        assert!(Filter::parse(&vec!["a"; MAX_TERMS + 1].join(";")).is_err());
    }

    #[test]
    fn a_malformed_expression_is_refused_rather_than_half_read() {
        for source in [
            "",
            "a;",
            "(a",
            "a>",
            r#"name=="unterminated"#,
            "a b",
            "a[",
            "a[]",
            "a[b",
            "a]",
            "[b]",
            "a[b]c",
            "a[b[c]]",
        ] {
            assert!(
                Filter::parse(source).is_err(),
                "{source:?} must not parse: an expression Libra half-reads is one the broker reads whole"
            );
        }
    }
}
