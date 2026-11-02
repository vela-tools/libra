//! Whether one scope pattern subsumes another.
//!
//! NGSI-LD borrows MQTT 5.0 topic-filter semantics for scopes (ETSI GS CIM 009 clause 4.18): `#`
//! stands for the remaining levels and may only be the last segment, `+` stands for exactly one
//! level. The subtlety, and the reason this is its own module with its own tests, is that the
//! *requested* scope may carry wildcards too: a caller may ask for `/Emergency/#`. Subsumption is
//! then a question about sets of scopes rather than about one path matching one pattern, and a
//! narrower pattern must not be taken to cover a broader request.

use libra_policy_model::scope::ScopePattern;

/// What a requested scope amounts to, given the scopes a policy allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeCoverage {
    /// The request lies entirely inside what the policy allows.
    Allowed,

    /// The request is broader than the policy allows, but overlaps it. The listed patterns are the
    /// part of the request the caller may have, and are what the layer sends upstream instead.
    Narrow(Vec<ScopePattern>),

    /// The request and the policy have nothing in common.
    Denied,
}

/// Whether every scope `requested` covers is also covered by `allowed`.
///
/// Both arguments are patterns, not paths: a concrete scope is simply a pattern with no wildcard
/// in it, so one function answers both "may this entity be seen" and "is this filter within
/// bounds".
#[must_use]
pub fn scope_matches(allowed: &ScopePattern, requested: &ScopePattern) -> bool {
    let allowed: Vec<&str> = allowed.segments().collect();
    let requested: Vec<&str> = requested.segments().collect();

    let mut left = 0;
    let mut right = 0;

    while left < allowed.len() && right < requested.len() {
        match (allowed[left], requested[right]) {
            // `#` on the allowing side covers every remaining level, wildcards included.
            ("#", _) => return true,
            // `#` on the requested side is open-ended. Anything but a `#` covers finitely many
            // levels, so it cannot subsume it; this is the case that lets a caller widen their
            // own allowed scopes if it is got wrong.
            (_, "#") => return false,
            // `+` on the allowing side covers any single level, a literal or a `+` alike.
            ("+", _) => {
                left += 1;
                right += 1;
            }
            (allowed, asked) if allowed == asked => {
                left += 1;
                right += 1;
            }
            // Includes a `+` on the requested side against a literal: the `+` stands for every
            // possible level, and the literal names one.
            _ => return false,
        }
    }

    // A trailing `#` also covers zero remaining levels, so `/Madrid/Gardens/#` includes
    // `/Madrid/Gardens` itself.
    if allowed.get(left) == Some(&"#") {
        return true;
    }

    left == allowed.len() && right == requested.len()
}

/// Judges one requested scope against everything a policy allows.
#[must_use]
pub fn evaluate_scope_request(allowed: &[ScopePattern], requested: &ScopePattern) -> ScopeCoverage {
    if allowed.iter().any(|pattern| scope_matches(pattern, requested)) {
        return ScopeCoverage::Allowed;
    }

    // The request is not inside any single allowed pattern. It may still overlap several of them, in which
    // case the overlap is what the caller is entitled to and the layer substitutes it.
    let narrowed: Vec<ScopePattern> = allowed.iter().filter(|pattern| scope_matches(requested, pattern)).cloned().collect();

    if narrowed.is_empty() {
        return ScopeCoverage::Denied;
    }

    ScopeCoverage::Narrow(narrowed)
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

    #[test]
    fn an_identical_scope_matches_and_a_sibling_does_not() {
        assert!(scope_matches(&pattern("/Madrid/Gardens"), &pattern("/Madrid/Gardens")));
        assert!(!scope_matches(&pattern("/Madrid/Gardens"), &pattern("/Madrid/Parks")));
    }

    #[test]
    fn a_trailing_hash_covers_the_levels_below_it() {
        assert!(scope_matches(&pattern("/Madrid/Gardens/#"), &pattern("/Madrid/Gardens/ParqueNorte")));
        assert!(scope_matches(&pattern("/Madrid/Gardens/#"), &pattern("/Madrid/Gardens/A/B/C")));
    }

    #[test]
    fn a_trailing_hash_also_covers_zero_levels() {
        // `/Madrid/Gardens/#` allows the garden collection itself, not only what is under it.
        assert!(scope_matches(&pattern("/Madrid/Gardens/#"), &pattern("/Madrid/Gardens")));
    }

    #[test]
    fn a_hash_does_not_reach_upwards_or_sideways() {
        assert!(!scope_matches(&pattern("/Madrid/Gardens/#"), &pattern("/Madrid")));
        assert!(!scope_matches(&pattern("/Madrid/Gardens/#"), &pattern("/Barcelona/Parks")));
    }

    #[test]
    fn a_plus_covers_exactly_one_level() {
        assert!(scope_matches(&pattern("/Madrid/+/Parterre1"), &pattern("/Madrid/Gardens/Parterre1")));
        assert!(scope_matches(&pattern("/Madrid/+/Parterre1"), &pattern("/Madrid/Parks/Parterre1")));
        assert!(!scope_matches(&pattern("/Madrid/+/Parterre1"), &pattern("/Madrid/A/B/Parterre1")));
        assert!(!scope_matches(&pattern("/Madrid/+"), &pattern("/Madrid")));
    }

    #[test]
    fn a_root_hash_covers_everything() {
        assert!(scope_matches(&pattern("/#"), &pattern("/Anything/At/All")));
        assert!(scope_matches(&pattern("/#"), &pattern("/X")));
        assert!(scope_matches(&pattern("/#"), &pattern("/Emergency/+")));
        assert!(scope_matches(&pattern("/#"), &pattern("/Emergency/#")));
    }

    #[test]
    fn a_scope_without_a_wildcard_does_not_reach_its_children() {
        assert!(!scope_matches(&pattern("/Madrid/Gardens"), &pattern("/Madrid/Gardens/Sub")));
    }

    #[test]
    fn a_wildcard_in_the_request_is_not_subsumed_by_a_narrower_pattern() {
        // The case that decides whether a caller can widen their own restriction by writing a wildcard
        // into scopeQ. `/Emergency/+` covers exactly one level and `/Emergency/#` covers
        // arbitrarily many, so the first cannot stand in for the second; and a literal covers one
        // named level, not the whole range a `+` stands for.
        assert!(!scope_matches(&pattern("/Emergency/+"), &pattern("/Emergency/#")));
        assert!(!scope_matches(&pattern("/Emergency/ICU"), &pattern("/Emergency/+")));
        assert!(!scope_matches(&pattern("/Emergency/ICU"), &pattern("/Emergency/#")));
    }

    #[test]
    fn a_broader_pattern_does_subsume_a_narrower_request() {
        assert!(scope_matches(&pattern("/Emergency/#"), &pattern("/Emergency/+")));
        assert!(scope_matches(&pattern("/Emergency/+"), &pattern("/Emergency/+")));
        assert!(scope_matches(&pattern("/Emergency/#"), &pattern("/Emergency/#")));
    }

    #[test]
    fn a_plus_in_the_middle_still_has_to_line_up_to_the_end() {
        assert!(!scope_matches(&pattern("/Madrid/+/Parterre1"), &pattern("/Madrid/Gardens")));
        assert!(!scope_matches(&pattern("/Madrid/+"), &pattern("/Madrid/Gardens/Parterre1")));
    }

    #[test]
    fn a_request_inside_a_restriction_is_allowed() {
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Madrid/Gardens/#"]), &pattern("/Madrid/Gardens/ParqueNorte")),
            ScopeCoverage::Allowed
        );
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Madrid/Gardens"]), &pattern("/Madrid/Gardens")),
            ScopeCoverage::Allowed
        );
    }

    #[test]
    fn a_request_that_overlaps_nothing_is_denied() {
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Madrid/Gardens/#"]), &pattern("/Barcelona")),
            ScopeCoverage::Denied
        );
    }

    #[test]
    fn a_request_broader_than_the_restriction_is_narrowed_to_the_overlap() {
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Madrid/Gardens/#"]), &pattern("/Madrid/#")),
            ScopeCoverage::Narrow(patterns(&["/Madrid/Gardens/#"]))
        );
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Madrid/Gardens/#", "/Madrid/Parks/#"]), &pattern("/Madrid/#")),
            ScopeCoverage::Narrow(patterns(&["/Madrid/Gardens/#", "/Madrid/Parks/#"]))
        );
    }

    #[test]
    fn a_wildcard_request_narrows_to_the_literal_allowed_scopes_it_covers() {
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Emergency/ICU"]), &pattern("/Emergency/#")),
            ScopeCoverage::Narrow(patterns(&["/Emergency/ICU"]))
        );
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Emergency/ICU"]), &pattern("/Emergency/+")),
            ScopeCoverage::Narrow(patterns(&["/Emergency/ICU"]))
        );
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Emergency/+"]), &pattern("/Emergency/#")),
            ScopeCoverage::Narrow(patterns(&["/Emergency/+"]))
        );
    }

    #[test]
    fn a_wildcard_request_inside_a_wildcard_allowed_scope_needs_no_narrowing() {
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Emergency/#"]), &pattern("/Emergency/+")),
            ScopeCoverage::Allowed
        );
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Emergency/+"]), &pattern("/Emergency/+")),
            ScopeCoverage::Allowed
        );
    }

    #[test]
    fn any_one_of_several_allowed_scopes_is_enough() {
        assert_eq!(
            evaluate_scope_request(&patterns(&["/Madrid/Gardens/#", "/Barcelona/Port/#"]), &pattern("/Barcelona/Port/Dock1")),
            ScopeCoverage::Allowed
        );
    }
}
