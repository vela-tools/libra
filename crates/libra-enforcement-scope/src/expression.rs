//! The `scopeQ` grammar, parsed rather than split.
//!
//! `scopeQ` is a boolean expression over scope paths, not a list: `;` is conjunction, `|` is
//! disjunction, `;` binds tighter, and parentheses group, the same shape as `q`, which
//! `libra-ngsi-ld-query`'s parser handles and which this one is modelled on.
//!
//! Splitting the value on `[',', ';']` and re-joining the pieces with `,` would silently turn every
//! conjunction into a disjunction: a caller asking for entities in `/Madrid/Gardens` **and**
//! `/Madrid/Parks` would be answered with entities in either, a broader result set than the one they
//! asked for and than the one the proxy believed it had authorised. Parsing the expression is what
//! makes narrowing a leaf possible without changing the shape of the caller's filter around it.

use crate::{
    error::ScopeError,
    matching::{ScopeCoverage, evaluate_scope_request},
};
use libra_policy_model::scope::ScopePattern;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Characters that end a scope path.
///
/// Whitespace is included because a scope segment cannot contain any: stopping there turns
/// `/A /B` into a scope followed by input that is not a connective, which is a parse failure
/// rather than a scope nobody could ever have meant.
const SCOPE_TERMINATORS: [char; 8] = [';', '|', '(', ')', ' ', '\t', '\r', '\n'];

/// A parsed `scopeQ` expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeExpression {
    /// A leaf: one scope path, possibly with wildcards.
    Scope(ScopePattern),
    /// `;`: both sides must hold.
    And(Box<ScopeExpression>, Box<ScopeExpression>),
    /// `|`: either side may hold.
    Or(Box<ScopeExpression>, Box<ScopeExpression>),
}

impl ScopeExpression {
    /// Parses a `scopeQ` expression.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError::MalformedExpression`] when the expression does not fit the grammar,
    /// and [`ScopeError::MalformedScope`] when a leaf is not a usable scope path. Both are
    /// refusals: an expression Libra cannot read is one whose scopes it cannot check, while the
    /// broker behind it would apply the expression whole.
    pub fn parse(source: &str) -> Result<Self, ScopeError> {
        let mut parser = Parser::new(source);
        let expression = parser.parse_disjunction()?;
        parser.expect_end()?;

        Ok(expression)
    }

    /// Builds the disjunction of every pattern a policy allows.
    ///
    /// `None` for an empty list, which is what stops the layer emitting `scopeQ=`, which a broker reads
    /// as no filter at all.
    #[must_use]
    pub fn any_of(patterns: &[ScopePattern]) -> Option<Self> {
        let mut patterns = patterns.iter().rev();
        // The tree owns its leaves, and the policy's patterns are only borrowed.
        let mut expression = Self::Scope(patterns.next()?.clone());

        for pattern in patterns {
            expression = Self::Or(Box::new(Self::Scope(pattern.clone())), Box::new(expression));
        }

        Some(expression)
    }

    /// Every scope the expression names, in order of appearance.
    #[must_use]
    pub fn scopes(&self) -> Vec<&ScopePattern> {
        let mut scopes = Vec::new();
        self.collect_scopes(&mut scopes);

        scopes
    }

    fn collect_scopes<'expression>(&'expression self, into: &mut Vec<&'expression ScopePattern>) {
        match self {
            Self::Scope(scope) => into.push(scope),
            Self::And(left, right) | Self::Or(left, right) => {
                left.collect_scopes(into);
                right.collect_scopes(into);
            }
        }
    }

    /// Rewrites every leaf so the expression asks for no more than the policy allows.
    ///
    /// A leaf already inside the restriction is kept as written; one that is broader is replaced by the
    /// disjunction of the allowed patterns it covers. A leaf that overlaps nothing the policy allows
    /// is taken out: a disjunction keeps its other side, and a conjunction is gone with it, since
    /// an entity in a forbidden scope is not readable for also being in an allowed one. The
    /// surrounding structure is otherwise untouched, so a conjunction stays a conjunction, which
    /// is the whole reason this is a tree rather than a list.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError::ScopeDenied`], naming the first leaf that overlaps nothing, when
    /// nothing of the expression remains.
    pub fn narrow(&self, allowed: &[ScopePattern]) -> Result<Self, ScopeError> {
        let mut first_denied = None;

        match (self.narrowed(allowed, &mut first_denied)?, first_denied) {
            (Some(narrowed), _) => Ok(narrowed),
            (None, Some(scope)) => Err(ScopeError::ScopeDenied { scope }),
            // An expression loses every leaf only by having one denied, so this is never reached;
            // it is refused rather than answered with no filter at all.
            (None, None) => Err(ScopeError::EmptyAllowList),
        }
    }

    /// What remains of the expression under the restriction, recording the first leaf denied outright.
    fn narrowed(&self, allowed: &[ScopePattern], first_denied: &mut Option<ScopePattern>) -> Result<Option<Self>, ScopeError> {
        match self {
            Self::Scope(scope) => match evaluate_scope_request(allowed, scope) {
                // The narrowed tree is a new value; the request's tree is only borrowed.
                ScopeCoverage::Allowed => Ok(Some(Self::Scope(scope.clone()))),
                ScopeCoverage::Narrow(narrowed) => Self::any_of(&narrowed).map(Some).ok_or(ScopeError::EmptyAllowList),
                ScopeCoverage::Denied => {
                    // Cloned because the error owns the refused scope and the request keeps its own.
                    first_denied.get_or_insert_with(|| scope.clone());
                    Ok(None)
                }
            },
            Self::And(left, right) => {
                let (Some(left), Some(right)) = (left.narrowed(allowed, first_denied)?, right.narrowed(allowed, first_denied)?) else {
                    return Ok(None);
                };

                Ok(Some(Self::And(Box::new(left), Box::new(right))))
            }
            Self::Or(left, right) => Ok(match (left.narrowed(allowed, first_denied)?, right.narrowed(allowed, first_denied)?) {
                (Some(left), Some(right)) => Some(Self::Or(Box::new(left), Box::new(right))),
                (Some(remaining), None) | (None, Some(remaining)) => Some(remaining),
                (None, None) => None,
            }),
        }
    }
}

impl Display for ScopeExpression {
    /// Renders the expression back to `scopeQ` syntax.
    ///
    /// Bracketed where precedence requires it, so what is written out parses back to the same
    /// tree. Narrowing a leaf of a conjunction into a disjunction is exactly the case that needs
    /// this: `/Madrid/#;/X` narrowed on the left becomes `(/Madrid/A|/Madrid/B);/X`, and without
    /// the brackets it would mean something else entirely.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Scope(scope) => formatter.write_str(scope.as_str()),
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
fn write_bracketed_if_or(formatter: &mut Formatter<'_>, expression: &ScopeExpression) -> FmtResult {
    if matches!(expression, ScopeExpression::Or(_, _)) {
        return write!(formatter, "({expression})");
    }

    write!(formatter, "{expression}")
}

/// A cursor over a `scopeQ` expression.
struct Parser<'source> {
    source: &'source str,
    offset: usize,
}

impl<'source> Parser<'source> {
    /// Starts a parse.
    const fn new(source: &'source str) -> Self {
        Self { source, offset: 0 }
    }

    /// `disjunction := conjunction ( "|" conjunction )*`
    fn parse_disjunction(&mut self) -> Result<ScopeExpression, ScopeError> {
        let mut left = self.parse_conjunction()?;

        while self.eat('|') {
            let right = self.parse_conjunction()?;
            left = ScopeExpression::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// `conjunction := primary ( ";" primary )*`
    fn parse_conjunction(&mut self) -> Result<ScopeExpression, ScopeError> {
        let mut left = self.parse_primary()?;

        while self.eat(';') {
            let right = self.parse_primary()?;
            left = ScopeExpression::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// `primary := "(" disjunction ")" | scope`
    fn parse_primary(&mut self) -> Result<ScopeExpression, ScopeError> {
        if self.eat('(') {
            let inner = self.parse_disjunction()?;
            if !self.eat(')') {
                return Err(self.error("expected ')'"));
            }

            return Ok(inner);
        }

        self.parse_scope()
    }

    /// `scope := "/" segment ( "/" segment )*`
    fn parse_scope(&mut self) -> Result<ScopeExpression, ScopeError> {
        let rest = &self.source[self.offset..];
        let raw = &rest[..rest.find(SCOPE_TERMINATORS).unwrap_or(rest.len())];
        self.offset += raw.len();

        if raw.is_empty() {
            return Err(self.error("expected a scope path"));
        }

        // Validated here rather than carried as text: the same check the policy's own patterns
        // passed at load, so both sides of every comparison are known to be well formed.
        let scope = ScopePattern::new(raw).map_err(|error| ScopeError::MalformedScope {
            value: raw.to_owned(),
            reason: error.to_string(),
        })?;

        Ok(ScopeExpression::Scope(scope))
    }

    /// Fails unless the whole expression has been consumed.
    fn expect_end(&self) -> Result<(), ScopeError> {
        if self.offset == self.source.len() {
            return Ok(());
        }

        Err(self.error("unexpected trailing input"))
    }

    /// The next character, without consuming it.
    fn peek(&self) -> Option<char> {
        self.source[self.offset..].chars().next()
    }

    /// Consumes `expected` if it is next.
    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.offset += expected.len_utf8();
            return true;
        }

        false
    }

    /// Builds a parse failure that points at the current offset.
    fn error(&self, reason: &str) -> ScopeError {
        ScopeError::MalformedExpression {
            offset: self.offset,
            reason: reason.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn pattern(value: &str) -> ScopePattern {
        ScopePattern::new(value).expect("the test pattern should be well formed")
    }

    fn patterns(values: &[&str]) -> Vec<ScopePattern> {
        values.iter().map(|value| pattern(value)).collect()
    }

    fn parse(source: &str) -> ScopeExpression {
        ScopeExpression::parse(source).unwrap_or_else(|error| panic!("{source} should parse: {error}"))
    }

    fn narrowed(source: &str, allowed: &[&str]) -> String {
        parse(source).narrow(&patterns(allowed)).expect("it should narrow").to_string()
    }

    #[test]
    fn a_single_scope_is_a_leaf() {
        assert_eq!(parse("/Madrid/Gardens"), ScopeExpression::Scope(pattern("/Madrid/Gardens")));
    }

    #[test]
    fn conjunction_binds_tighter_than_disjunction() {
        assert_eq!(
            parse("/A;/B|/C"),
            ScopeExpression::Or(
                Box::new(ScopeExpression::And(Box::new(parse("/A")), Box::new(parse("/B")))),
                Box::new(parse("/C")),
            )
        );
    }

    #[test]
    fn brackets_override_precedence() {
        assert_eq!(
            parse("/A;(/B|/C)"),
            ScopeExpression::And(
                Box::new(parse("/A")),
                Box::new(ScopeExpression::Or(Box::new(parse("/B")), Box::new(parse("/C")))),
            )
        );
    }

    #[test]
    fn an_and_is_not_rewritten_as_an_or() {
        // Splitting on `[',', ';']` and re-joining with `,` would turn "in both of these scopes" into
        // "in either of them", broadening the caller's own filter and returning entities they had not
        // asked for.
        assert_eq!(narrowed("/Madrid/Gardens;/Madrid/Parks", &["/Madrid/#"]), "/Madrid/Gardens;/Madrid/Parks");
    }

    #[test]
    fn rendering_round_trips_through_parsing() {
        for source in ["/A", "/A;/B", "/A|/B", "/A;/B|/C", "/A;(/B|/C)", "/Madrid/+/Parterre1", "/Madrid/#"] {
            assert_eq!(parse(source).to_string(), source, "{source} should render as it was written");
        }
    }

    #[test]
    fn a_malformed_expression_is_refused_rather_than_half_read() {
        // An expression Libra half-reads is one the broker reads whole.
        for source in ["", "/A;", "(/A", "/A|", "/A /B", "/A)", "Madrid", "/A//B", "/A/#/B"] {
            assert!(ScopeExpression::parse(source).is_err(), "{source:?} must not parse");
        }
    }

    #[test]
    fn a_leaf_inside_the_restriction_is_kept_as_written() {
        assert_eq!(narrowed("/Madrid/Gardens/ParqueNorte", &["/Madrid/#"]), "/Madrid/Gardens/ParqueNorte");
    }

    #[test]
    fn a_leaf_broader_than_the_restriction_becomes_the_overlap() {
        assert_eq!(
            narrowed("/Madrid/#", &["/Madrid/Gardens/#", "/Madrid/Parks/#"]),
            "/Madrid/Gardens/#|/Madrid/Parks/#"
        );
    }

    #[test]
    fn narrowing_a_leaf_of_a_conjunction_brackets_the_result() {
        // Without the brackets `(/A|/B);/X` would render as `/A|/B;/X`, which parses as
        // `/A | (/B;/X)`, a strictly broader filter than the one the caller wrote.
        let output = narrowed("/Madrid/#;/Madrid/Gardens", &["/Madrid/Gardens", "/Madrid/Parks"]);

        assert_eq!(output, "(/Madrid/Gardens|/Madrid/Parks);/Madrid/Gardens");
        assert_eq!(parse(&output).to_string(), output, "the narrowed expression must parse back to itself");
    }

    #[test]
    fn a_leaf_that_overlaps_nothing_is_refused() {
        let refused = parse("/Barcelona/Port").narrow(&patterns(&["/Madrid/#"]));

        assert_eq!(
            refused,
            Err(ScopeError::ScopeDenied {
                scope: ScopePattern::new("/Barcelona/Port").unwrap()
            })
        );
    }

    #[test]
    fn a_disjunction_keeps_the_side_the_restriction_covers() {
        assert_eq!(narrowed("/Madrid/#|/Berlin/#", &["/Madrid/#"]), "/Madrid/#");
        assert_eq!(narrowed("/Berlin/B|/Madrid/A|/Paris", &["/Madrid/#"]), "/Madrid/A");
        assert_eq!(narrowed("(/Madrid/A;/Berlin/B)|/Madrid/C", &["/Madrid/#"]), "/Madrid/C");
    }

    #[test]
    fn a_conjunction_with_a_denied_side_is_refused_naming_it() {
        assert_eq!(
            parse("/Madrid/#;/Berlin/#").narrow(&patterns(&["/Madrid/#"])),
            Err(ScopeError::ScopeDenied { scope: pattern("/Berlin/#") })
        );
        assert_eq!(
            parse("/Paris|/Madrid/A;/Berlin").narrow(&patterns(&["/Madrid/#"])),
            Err(ScopeError::ScopeDenied { scope: pattern("/Paris") }),
            "the first denied leaf is named"
        );
    }

    #[test]
    fn the_disjunction_of_a_restriction_is_the_restriction_itself() {
        assert_eq!(
            ScopeExpression::any_of(&patterns(&["/Madrid/#", "/Barcelona/#"])).map(|expression| expression.to_string()),
            Some("/Madrid/#|/Barcelona/#".to_owned())
        );
    }

    #[test]
    fn an_empty_restriction_has_no_expression_rather_than_an_empty_one() {
        // `scopeQ=` is read by brokers as no filter at all, so there must be no way to produce it.
        assert_eq!(ScopeExpression::any_of(&[]), None);
    }

    #[test]
    fn every_scope_in_the_expression_is_reachable() {
        assert_eq!(parse("/A;(/B|/C)").scopes(), vec![&pattern("/A"), &pattern("/B"), &pattern("/C")]);
    }

    #[test]
    fn a_scope_q_holding_a_control_character_is_refused_without_repeating_it_raw() {
        for forged in ["/\u{0}/#", "/Madrid\u{1b}[2J", "/Madrid|/Ba\u{7f}rcelona"] {
            let refused = ScopeExpression::parse(forged).unwrap_err().to_string();

            assert!(!refused.chars().any(char::is_control), "{forged:?}: {refused:?}");
        }
    }
}
