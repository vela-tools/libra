//! A processed context, and the two operations Libra needs from it.
//!
//! Expansion is delegated to the `json-ld` crate's own implementation of the specification
//! algorithm rather than reimplemented here. That is a deliberate choice: a broker runs a real
//! JSON-LD processor, and a hand-written subset would agree with it right up until the case nobody
//! thought of (a compact IRI, a `@vocab` fallback, a term that is also a keyword). Every one of
//! those disagreements is a policy that silently stops applying.
//!
//! What this crate adds is the type discipline. The `json-ld` API deals in strings and its own
//! `Term` enum; [`Term`] and [`ExpandedIri`] make the authored form and the comparable form
//! impossible to confuse.

use crate::name::{ExpandedIri, Term};
use futures::executor::block_on;
use iri_rs::IriBuf;
use jsonld::{
    Container,
    Context,
    Environment,
    Id,
    NoLoader,
    Term as JsonLdTerm,
    context::{BindingRef, inverse::Selection},
    context_processing::{
        Options as ProcessingOptions,
        Process,
        algorithm::{Action, MalformedIri, expand_iri_simple},
    },
    syntax::{ExpandableRef, Nullable, TryFromJson, context::Context as SyntaxContext},
};
use jstrict::{Parse, Value};
use rdfx::BlankIdBuf;
use std::fmt::{Debug, Formatter, Result as FmtResult};

/// A context could not be processed.
#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    /// The context is not well-formed JSON.
    #[error("the context is not valid JSON: {reason}")]
    Json { reason: String },

    /// The JSON is not a well-formed `@context`.
    #[error("the value is not a valid JSON-LD context: {reason}")]
    Syntax { reason: String },

    /// Context processing itself failed.
    #[error("context processing failed: {reason}")]
    Processing { reason: String },
}

/// A context that has been processed and can resolve names.
#[derive(Clone)]
pub struct ResolvedContext {
    context: Context<IriBuf, BlankIdBuf>,
}

impl Debug for ResolvedContext {
    /// Deliberately opaque. A processed context is large, and dumping one into a log line would
    /// bury the request it belongs to; the term count is what is actually diagnostic.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.debug_struct("ResolvedContext").field("definitions", &self.context.len()).finish()
    }
}

impl ResolvedContext {
    /// Wraps an already-processed context.
    ///
    /// The resolver in `libra-jsonld-context` produces these, because it is the part that is
    /// allowed to fetch remote contexts.
    #[must_use]
    pub const fn from_processed(context: Context<IriBuf, BlankIdBuf>) -> Self {
        Self { context }
    }

    /// Processes a self-contained `@context` value, with no remote fetching.
    ///
    /// A context that references a remote document fails here rather than reaching the network:
    /// fetching is the resolver's job, where the allow list and the timeout live.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessingError`] if the value is not valid JSON, is not a valid context, or
    /// cannot be processed without loading something.
    pub fn from_json(source: &str) -> Result<Self, ProcessingError> {
        let (json, _) = Value::parse_str(source).map_err(|error| ProcessingError::Json { reason: error.to_string() })?;

        Self::from_value(&json)
    }

    /// Processes an already-parsed `@context` value, with no remote fetching.
    ///
    /// # Errors
    ///
    /// As [`ResolvedContext::from_json`].
    pub fn from_value(json: &Value) -> Result<Self, ProcessingError> {
        let syntax = SyntaxContext::try_from_json(json).map_err(|error| ProcessingError::Syntax { reason: error.to_string() })?;

        // Processing is async only so that a loader *can* fetch. With no loader every future is
        // already complete, so this blocks on nothing and needs no runtime.
        let processed = block_on(syntax.process_with(&mut (), &Context::default(), &NoLoader, None::<IriBuf>, ProcessingOptions::default()))
            .map_err(|error| ProcessingError::Processing { reason: error.to_string() })?;

        Ok(Self {
            context: processed.into_processed(),
        })
    }

    /// The processed context, for the compaction and expansion the whole-document path needs.
    #[must_use]
    pub const fn as_json_ld(&self) -> &Context<IriBuf, BlankIdBuf> {
        &self.context
    }

    /// Expands a term to the IRI it means in this context.
    ///
    /// `None` means the term has no meaning here, in one of three ways. It may be a name no
    /// definition and no vocabulary reaches. It may expand to a keyword or to an invalid IRI,
    /// neither of which is a name a policy can be written about. Or it is a term of the form
    /// `prefix:suffix` whose prefix is a defined term that JSON-LD 1.1 (section 6.3) does not
    /// treat as a compact-IRI prefix, because its IRI ends in no gen-delim and it carries no
    /// `@prefix: true` flag, while a JSON-LD 1.0 processor (JSON-LD 1.0, section 6.3) treats any
    /// defined term as one. The two readings name different IRIs, so the term is refused rather
    /// than guessed at, and a caller holding `None` must fail the request in every one of the
    /// three cases: a name it cannot resolve is a name it cannot make an authorization decision
    /// about.
    #[must_use]
    pub fn expand(&self, term: &Term) -> Option<ExpandedIri> {
        if self.reads_differently_under_json_ld_1_0(term) {
            return None;
        }

        let mut vocabulary = ();
        let loader = NoLoader;
        let mut warnings = ();
        let mut environment = Environment {
            vocabulary: &mut vocabulary,
            loader: &loader,
            warnings: &mut warnings,
        };

        // `document_relative` is false and `vocab` is Keep: these are the defaults the
        // specification prescribes for expanding a value in key position, which is what an entity
        // type, an attribute name and a query term all are.
        let expanded = expand_iri_simple::<MalformedIri, (), NoLoader, ()>(
            &mut environment,
            &self.context,
            Nullable::Some(ExpandableRef::from(term.as_str())),
            false,
            Some(Action::Keep),
        )
        .ok()??;

        // The fork memoizes term resolution, so the result is shared rather than owned.
        match expanded.as_ref() {
            JsonLdTerm::Id(Id::Valid(id)) => Some(ExpandedIri::new(id.to_string())),
            // A keyword, an invalid IRI, or null: none of these is a name a policy can be written
            // about, so none of them may be compared.
            JsonLdTerm::Id(Id::Invalid(_)) | JsonLdTerm::Keyword(_) | JsonLdTerm::Null => None,
        }
    }

    /// Whether a term would expand to different IRIs under JSON-LD 1.0 and 1.1.
    ///
    /// The disagreement exists only for the compact-IRI reading of `prefix:suffix`: 1.1 makes a
    /// defined term a compact-IRI prefix when its IRI ends in a gen-delim or it is marked with
    /// `@prefix: true`, and 1.0 makes any defined term one. Term lookup precedes compact-IRI
    /// parsing in both, so a term that is itself defined is not ambiguous; context processing
    /// refuses a term definition of that overlapping shape outright, which reaches the same
    /// refusal earlier than this check would. An undefined prefix, a leading colon and a
    /// blank-node shape go through the ordinary expansion, which both versions agree on.
    fn reads_differently_under_json_ld_1_0(&self, term: &Term) -> bool {
        let Some((prefix, suffix)) = term.as_str().split_once(':') else {
            return false;
        };

        // Both versions return a value whose suffix begins with `//` as an absolute IRI before
        // looking the prefix up (JSON-LD 1.0 and 1.1 IRI expansion, the `_` or `//` step), so
        // `https://...` is absolute even under a context defining `https`. A scheme without `//`,
        // such as `urn:`, gets no such step: a context defining `urn` makes `urn:...` a compact IRI
        // to a 1.0 processor, and the disagreement below applies to it like any other prefix.
        if prefix.is_empty() || prefix == "_" || suffix.starts_with("//") {
            return false;
        }

        if self.defines(term) {
            return false;
        }

        // The prefix is a defined term, and `prefix` is false: 1.1 does not treat it as a
        // compact-IRI prefix, 1.0 does, and the two expansions disagree. An empty suffix (`ex:`)
        // is the same disagreement and is refused with the rest.
        self.context.get_normal(prefix).is_some_and(|definition| !definition.prefix)
    }

    /// The terms this context defines itself, rather than expanding through its vocabulary.
    pub fn defined_terms(&self) -> impl Iterator<Item = Term> + '_ {
        self.context.definitions().iter().filter_map(|binding| match binding {
            BindingRef::Normal(key, _) => Some(Term::new(key.as_str())),
            // `@type` is a keyword's entry, not a term anybody names a type or an attribute with.
            BindingRef::Type(_) => None,
        })
    }

    /// Whether this context defines `term` itself, rather than expanding it through its
    /// vocabulary.
    #[must_use]
    pub fn defines(&self, term: &Term) -> bool {
        self.context.contains_term(term.as_str())
    }

    /// Compacts an IRI to a name that this context expands back to that IRI.
    ///
    /// The term the inverse context selects is used when it reads back; otherwise the IRI itself,
    /// a legal NGSI-LD representation, when that reads back. `None` means neither does, and a
    /// caller holding it must refuse the request: a name that expands to another IRI, or to none,
    /// is a name the broker may read as a different attribute than the one Libra meant.
    ///
    /// A caller's context can make both fail. A term starting with `@` is preferred whenever it is
    /// the shortest candidate, and expands to nothing, since JSON-LD 1.1 reserves the shape for
    /// keywords. An IRI such as `ex:speed` reads as a compact IRI under a JSON-LD 1.0 processor once
    /// the context defines a term `ex`, so it is ambiguous between the versions and refused by
    /// [`ResolvedContext::expand`].
    #[must_use]
    pub fn compact(&self, iri: &ExpandedIri) -> Option<Term> {
        let selected = IriBuf::new(iri.as_str().to_owned()).ok().and_then(|parsed| {
            self.context
                .inverse()
                .select(&JsonLdTerm::Id(Id::iri(parsed)), &[Container::None], &Selection::Any)
                .map(|key| Term::new(key.as_str()))
        });

        selected
            .into_iter()
            .chain([Term::new(iri.as_str())])
            .find(|name| self.expand(name).as_ref() == Some(iri))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// A context in the shape a caller actually sends: an alias, a duplicate alias, a prefix, and
    /// the default-context vocabulary NGSI-LD falls back to.
    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
                "speed": "https://uri.fiware.org/ns/data-models#speed",
                "ex": "https://example.test/"
            }"#,
        )
        .expect("the test context should process")
    }

    #[test]
    fn a_defined_term_expands_to_its_definition() {
        assert_eq!(
            context().expand(&Term::new("Vehicle")).unwrap(),
            ExpandedIri::new("https://uri.fiware.org/ns/data-models#Vehicle")
        );
        assert_eq!(
            context().expand(&Term::new("speed")).unwrap(),
            ExpandedIri::new("https://uri.fiware.org/ns/data-models#speed")
        );
    }

    #[test]
    fn an_absolute_iri_passes_through_unchanged() {
        // Sending the expanded form instead of the term is legal on the wire, and the broker
        // accepts it in a type filter, so both forms must reach the same comparison.
        let sent = Term::new("https://uri.fiware.org/ns/data-models#Vehicle");

        assert_eq!(
            context().expand(&sent).unwrap(),
            ExpandedIri::new("https://uri.fiware.org/ns/data-models#Vehicle")
        );
    }

    #[test]
    fn a_compact_iri_expands_through_its_prefix() {
        assert_eq!(
            context().expand(&Term::new("ex:Thing")).unwrap(),
            ExpandedIri::new("https://example.test/Thing")
        );
    }

    #[test]
    fn a_plain_iri_prefix_used_as_a_compact_iri_is_refused() {
        // The 1.1 context leaves `ex` an ordinary term: its IRI ends in no gen-delim. Expanding
        // `ex:ret` would name https://host/Secret for a 1.0 processor and nothing here, and the
        // deny written about Secret must not miss whichever caller guesses the older reading.
        let context = ResolvedContext::from_json(r#"{"ex": "https://host/Sec"}"#).unwrap();

        assert!(
            context.expand(&Term::new("ex:ret")).is_none(),
            "a prefix a 1.0 processor reads differently must not expand at all"
        );
    }

    #[test]
    fn an_absolute_iri_whose_scheme_is_a_defined_term_passes_through_unchanged() {
        // The suffix begins with `//`, which both JSON-LD 1.0 and 1.1 return as an absolute IRI
        // before the prefix is looked up.
        let context = ResolvedContext::from_json(r#"{"https": "https://host/Sec", "http": "https://host/Other"}"#).unwrap();

        assert_eq!(
            context.expand(&Term::new("https://uri.etsi.org/ngsi-ld/default-context/Vehicle")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/default-context/Vehicle")
        );
        assert_eq!(
            context.expand(&Term::new("http://example.test/Vehicle")).unwrap(),
            ExpandedIri::new("http://example.test/Vehicle")
        );
    }

    #[test]
    fn a_urn_whose_scheme_is_a_plain_defined_term_is_refused() {
        // `urn:ngsi-ld:Vehicle` is an absolute IRI to JSON-LD 1.1, since `urn` is no prefix, and
        // `https://host/Sec` + `ngsi-ld:Vehicle` to JSON-LD 1.0, which has no `//` to stop it.
        let context = ResolvedContext::from_json(r#"{"urn": "https://host/Sec"}"#).unwrap();

        assert!(context.expand(&Term::new("urn:ngsi-ld:Vehicle")).is_none());
    }

    #[test]
    fn a_urn_passes_through_unchanged_when_no_term_is_named_urn() {
        assert_eq!(
            context().expand(&Term::new("urn:ngsi-ld:Vehicle")).unwrap(),
            ExpandedIri::new("urn:ngsi-ld:Vehicle")
        );
    }

    #[test]
    fn the_same_prefix_marked_prefix_true_expands() {
        // `@prefix: true` is the 1.1 way to say the term is a prefix, and then both versions agree.
        let context = ResolvedContext::from_json(r#"{"ex": {"@id": "https://host/", "@prefix": true}}"#).unwrap();

        assert_eq!(context.expand(&Term::new("ex:ret")).unwrap(), ExpandedIri::new("https://host/ret"));
    }

    #[test]
    fn an_empty_suffix_on_a_plain_iri_prefix_is_refused() {
        // `ex:` on a 1.1 non-prefix term is exactly the disagreement `ex:ret` is, with nothing
        // after the colon to hide it.
        let context = ResolvedContext::from_json(r#"{"ex": "https://host/Sec"}"#).unwrap();

        assert!(context.expand(&Term::new("ex:")).is_none(), "the empty suffix rides on the same refusal");
    }

    #[test]
    fn an_undefined_prefix_still_expands_without_a_veto() {
        // Nothing is defined under `nope`, so neither version reads it as a compact IRI, and both
        // keep the term as the relative IRI it is. The refusal must not reach it.
        let context = ResolvedContext::from_json(r#"{"@vocab": "https://example.test/"}"#).unwrap();

        assert_eq!(context.expand(&Term::new("nope:Thing")).unwrap(), ExpandedIri::new("nope:Thing"));
    }

    #[test]
    fn a_leading_colon_is_not_a_compact_iri() {
        // `:ret` has no prefix, so the 1.0 disagreement never starts, and the ordinary expansion
        // answers. It must reach that expansion rather than being caught by the refusal.
        let context = ResolvedContext::from_json(r#"{"@vocab": "https://example.test/"}"#).unwrap();

        assert_eq!(context.expand(&Term::new(":ret")).unwrap(), ExpandedIri::new("https://example.test/:ret"));
    }

    #[test]
    fn an_undefined_term_falls_back_to_the_vocabulary() {
        // Matches Scorpio: an entity created with type `Widget` and no context is findable at
        // https://uri.etsi.org/ngsi-ld/default-context/Widget.
        assert_eq!(
            context().expand(&Term::new("Widget")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/default-context/Widget")
        );
    }

    #[test]
    fn without_a_vocabulary_an_undefined_term_has_no_meaning() {
        let bare = ResolvedContext::from_json(r#"{"Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle"}"#).unwrap();

        assert!(
            bare.expand(&Term::new("Unknown")).is_none(),
            "an unexpandable term must not silently become anything"
        );
    }

    #[test]
    fn a_keyword_is_not_a_name_a_policy_can_match() {
        // `@type` and friends are structural, not names. Returning an IRI for one would let a
        // policy be written against a keyword and match something it should not.
        assert!(context().expand(&Term::new("@type")).is_none());
        assert!(context().expand(&Term::new("@id")).is_none());
    }

    #[test]
    fn an_alias_expands_to_the_same_iri_as_the_term_it_aliases() {
        // This is the bypass in miniature: `Car` and `Vehicle` are one thing, and a policy naming
        // either must catch a request naming the other.
        let context = context();

        assert_eq!(context.expand(&Term::new("Car")).unwrap(), context.expand(&Term::new("Vehicle")).unwrap());
    }

    #[test]
    fn compaction_is_deterministic_across_runs() {
        // Two terms share one IRI. Whichever the inverse context picks, it must pick the same one
        // every time, or responses and cache keys become unstable between processes.
        let iri = ExpandedIri::new("https://uri.fiware.org/ns/data-models#Vehicle");
        let first = context().compact(&iri);
        assert!(first.is_some());

        for _ in 0..32 {
            assert_eq!(ResolvedContext::compact(&context(), &iri), first);
        }
    }

    #[test]
    fn an_iri_whose_shortest_term_is_keyword_shaped_stays_an_iri_and_expands_back() {
        // `@x` is the shortest term for the IRI, and a term of a keyword's shape expands to nothing.
        let context = ResolvedContext::from_json(r#"{"@x":"https://e.test/","Vv":"https://e.test/"}"#).unwrap();
        let iri = ExpandedIri::new("https://e.test/");

        let compacted = context.compact(&iri);

        assert_eq!(compacted, Some(Term::new("https://e.test/")));
    }

    #[test]
    fn an_iri_a_json_ld_1_0_broker_would_read_as_a_compact_iri_has_no_name() {
        // `ex:speed` is an absolute IRI to JSON-LD 1.1, because `ex` is no prefix (its IRI ends in
        // no gen-delim), and `ex` + `speed` to JSON-LD 1.0, which treats any defined term as one.
        let context = ResolvedContext::from_json(r#"{"ex":"https://example.test/a"}"#).unwrap();

        assert_eq!(context.compact(&ExpandedIri::new("ex:speed")), None);
    }

    #[test]
    fn a_defined_term_is_the_name_its_iri_compacts_to() {
        assert_eq!(
            context().compact(&ExpandedIri::new("https://uri.fiware.org/ns/data-models#speed")),
            Some(Term::new("speed"))
        );
    }

    #[test]
    fn an_unknown_iri_stays_an_iri() {
        let unknown = ExpandedIri::new("https://elsewhere.test/Thing");

        assert_eq!(context().compact(&unknown), Some(Term::new("https://elsewhere.test/Thing")));
    }

    #[test]
    fn a_context_that_needs_the_network_fails_here_rather_than_fetching() {
        // Fetching belongs to the resolver, which has the allow list and the timeout.
        let remote = ResolvedContext::from_json(r#""https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld""#);

        assert!(remote.is_err(), "processing must not reach the network from here");
    }

    #[test]
    fn malformed_input_is_reported_rather_than_ignored() {
        assert!(matches!(ResolvedContext::from_json("{not json"), Err(ProcessingError::Json { .. })));
        assert!(ResolvedContext::from_json("42").is_err());
    }

    #[test]
    fn a_context_knows_the_terms_it_defines_itself() {
        let context = ResolvedContext::from_json(r#"{"@vocab": "https://example.test/", "Vehicle": "https://example.test/fleet#Vehicle"}"#).unwrap();

        assert!(context.defines(&Term::new("Vehicle")));
        assert!(!context.defines(&Term::new("Building")), "expanding through the vocabulary is not defining");
        assert_eq!(context.defined_terms().collect::<Vec<_>>(), vec![Term::new("Vehicle")]);
    }
}
