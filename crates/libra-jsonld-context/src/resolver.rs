//! Resolves the one context that applies to a request.
//!
//! The composition order is the security-relevant part. A caller-supplied context is applied
//! first and the core context last, so core definitions win. That is not a preference: Scorpio
//! stores `location` under the core IRI even when the request's own context redefines it, while
//! accepting the caller's definition for a term the core context does not know.
//!
//! If the order were reversed, a caller could redefine `location`, `observedAt` or any other
//! structural term, and every policy written about those names would be evaluated against a
//! meaning the caller chose.

use crate::{
    channel::{ContextChannel, channel_for},
    core_context,
    core_redefinition::refuse_core_redefinition,
    error::ContextError,
    link_header::{self, ParamName},
    loader::AllowListLoader,
    scoped::refuse_scoped,
};
use iri_rs::{Iri, IriBuf, IriRefBuf, iri};
use jsonld::{
    Context,
    context_processing::{Error as ProcessingFailure, Options as ProcessingOptions, Process},
    syntax::{TryFromJson, context::Context as SyntaxContext},
};
use jstrict::{Parse, Value};
use libra_config::jsonld::JsonLd;
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use std::fs;
use url::Url;

/// The link relation that marks a context link (JSON-LD 1.1 section 6.1, NGSI-LD clause 6.3.5).
pub static CONTEXT_RELATION: Iri<&str> = iri!("http://www.w3.org/ns/json-ld#context");

/// What a request says about its context.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestContext<'a> {
    /// The `Content-Type` header, which decides which channel is legal.
    pub content_type: Option<&'a str>,
    /// The `@context` entry of the request body, if it has one.
    pub body_context: Option<&'a Value>,
    /// Every `Link` header on the request, in order.
    ///
    /// All of them, not the first: RFC 8288 allows several link-values in one header, and a
    /// request may repeat the header, so a context link can arrive beside `next` and `prev`.
    /// Reading only the first is how an implementation resolves against the wrong context on a
    /// perfectly legal request.
    pub link_headers: &'a [&'a str],
}

/// Resolves request contexts, fetching only what the configuration allows.
pub struct ContextResolver {
    loader: AllowListLoader,
    /// The core context, parsed once and processed last in every resolution.
    core: SyntaxContext,
    /// The core context on its own, to tell a caller's term apart from a redefinition of a core one.
    core_terms: ResolvedContext,
}

impl ContextResolver {
    /// Builds a resolver from the `[jsonld]` configuration.
    ///
    /// The core context is processed here rather than on the request path: a failure at startup
    /// stops the process, where a failure mid-request would have nowhere to go.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the HTTP client cannot be built, if the embedded core context
    /// is not usable, or if a context named in `preloaded-contexts` cannot be read or processed.
    pub fn new(config: &JsonLd) -> Result<Self, ContextError> {
        // Cloned because the loader keeps its settings for its lifetime and the configuration is borrowed.
        let mut loader = AllowListLoader::new(config.clone())?;

        // Preloaded, so the core context is available even with fetching switched off, and so a
        // user context that references it by URL resolves without a network call.
        let core_url = config.core_context.clone().unwrap_or_else(core_context::url); // the loader owns what it preloads, the configuration is borrowed
        loader.preload(core_url, core_context::DOCUMENT)?;

        // Read before the first request rather than on it: a preloaded context exists because the
        // deployment cannot fetch one, so an unreadable file has no fallback.
        for (url, path) in &config.preloaded_contexts {
            // The error and the loader each own their url; the configuration is only borrowed.
            let document = fs::read_to_string(path).map_err(|source| ContextError::PreloadUnreadable {
                url: Box::new(url.clone()),
                path: path.clone(),
                source,
            })?;
            loader.preload(url.clone(), &document)?;
        }

        let core_value = core_context_value()?;
        let malformed = |reason: String| ContextError::Malformed {
            url: Box::new(core_context::url()),
            reason,
        };
        let core = SyntaxContext::try_from_json(&core_value).map_err(|error| malformed(error.to_string()))?;
        let core_terms = ResolvedContext::from_value(&core_value).map_err(|error| malformed(error.to_string()))?;

        Ok(Self { loader, core, core_terms })
    }

    /// Resolves the context for one request.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the request mixes context channels, names a context that may
    /// not be fetched, or supplies one that cannot be processed. Every one of those fails the
    /// request: a name that cannot be resolved is a name no authorization decision can be made
    /// about.
    pub async fn resolve(&self, request: &RequestContext<'_>) -> Result<ResolvedContext, ContextError> {
        let context_links = context_links(request.link_headers)?;
        let channel = channel_for(request.content_type, request.body_context, &context_links)?;

        if let (ContextChannel::Body, Some(body_context)) = (channel, request.body_context) {
            refuse_scoped(body_context).map_err(|reason| ContextError::MalformedBodyContext { reason: reason.to_owned() })?;
        }

        let caller = match (channel, request.body_context) {
            (ContextChannel::Body, Some(body_context)) => Some(self.process(body_context).await?),
            (ContextChannel::LinkHeader, _) => {
                let links = context_links.iter().map(|url| Value::String(url.as_str().into())).collect();
                Some(self.process(&Value::Array(links)).await?)
            }
            // No context means the core context alone (NGSI-LD clause 6.3.5), for Libra and the
            // broker alike. A deployment default applied here only would expand the request
            // differently from the broker, which cannot be told of it: a `Link` header beside an
            // `application/ld+json` body is refused by clause 6.3.5.
            (ContextChannel::Body, None) | (ContextChannel::None, _) => None,
        };

        if let Some(caller) = &caller {
            refuse_core_redefinition(&self.core_terms, caller)?;
        }

        // The caller's context first, the core context last. Later definitions win in JSON-LD, so
        // this is what makes the core context authoritative over anything the caller sends.
        self.with_core_last(caller.as_ref()).await
    }

    /// Makes a context available without fetching it.
    ///
    /// The deployment case is an air-gapped or offline install, where the contexts a policy and its
    /// clients share are shipped as files rather than reachable over the network. Preloading is
    /// also what the core context itself uses, so a preloaded document is resolved through exactly
    /// the same path as a fetched one.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the document is not a valid context.
    pub fn preload(&mut self, url: Url, document: &str) -> Result<(), ContextError> {
        self.loader.preload(url, document)
    }

    /// Resolves a context declared up front rather than by a request.
    ///
    /// A policy file names the contexts its terms are written against, and those terms have to
    /// resolve the way a request's terms resolve or the two could never be compared. Composition
    /// is therefore identical to [`ContextResolver::resolve`]: the declared contexts first, the
    /// core context last. It is one function calling the same processing rather than two that
    /// happen to agree.
    ///
    /// An empty list is the core context alone, which is what the specification prescribes for a
    /// request that supplies nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if a declared context may not be fetched or cannot be processed.
    pub async fn resolve_declared(&self, contexts: &[IriBuf]) -> Result<ResolvedContext, ContextError> {
        let declared = if contexts.is_empty() {
            None
        } else {
            let urls = contexts.iter().map(|url| Value::String(url.as_str().into())).collect();
            Some(self.process(&Value::Array(urls)).await?)
        };

        self.with_core_last(declared.as_ref()).await
    }

    /// The core context, processed over `before`, or alone when there is nothing before it.
    ///
    /// JSON-LD 1.1 context processing takes an array one entry at a time, each over the result of
    /// the last, so this is the composition `[before, core]` without the core document copied into
    /// an array on every request.
    async fn with_core_last(&self, before: Option<&ResolvedContext>) -> Result<ResolvedContext, ContextError> {
        let initial = Context::default();
        let active = before.map_or(&initial, ResolvedContext::as_json_ld);

        let processed = self
            .core
            .process_with(&mut (), active, &self.loader, None::<IriBuf>, ProcessingOptions::default())
            .await
            .map_err(context_error_from)?;

        Ok(ResolvedContext::from_processed(processed.into_processed()))
    }

    /// A caller's or a policy file's context, processed on its own.
    async fn process(&self, value: &Value) -> Result<ResolvedContext, ContextError> {
        let syntax = SyntaxContext::try_from_json(value).map_err(|error| ContextError::MalformedBodyContext { reason: error.to_string() })?;

        let processed = syntax
            .process_with(&mut (), &Context::default(), &self.loader, None::<IriBuf>, ProcessingOptions::default())
            .await
            .map_err(context_error_from)?;

        Ok(ResolvedContext::from_processed(processed.into_processed()))
    }
}

/// The targets of a request's context links, refusing every shape two readers could take apart
/// differently.
///
/// JSON-LD 1.1 API section 9.4.1 makes a second context link an error (`multiple context link
/// headers`), and NGSI-LD clause 6.3.5 writes the link with `type="application/ld+json"`. Orion-LD
/// ignores a context link without the type and Stellio reads only the first one, so honouring either
/// shape here would resolve a request against a context the broker does not use. An `anchor` makes
/// the link about another resource than the request.
fn context_links(headers: &[&str]) -> Result<Vec<IriRefBuf>, ContextError> {
    let mut targets = Vec::new();

    for header in headers {
        let links = link_header::parse(header).map_err(|error| ContextError::MalformedLinkHeader { reason: error.reason })?;

        for link in links.into_iter().filter(|link| link.has_relation(&CONTEXT_RELATION)) {
            if link.param(&ParamName::Anchor).is_some() {
                return Err(ContextError::UnusableContextLink {
                    reason: "a context link may not carry an anchor",
                });
            }
            if !link
                .param(&ParamName::Type)
                .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/ld+json"))
            {
                return Err(ContextError::UnusableContextLink {
                    reason: "a context link must declare type=\"application/ld+json\"",
                });
            }
            targets.push(link.target);
        }
    }

    if targets.len() > 1 {
        return Err(ContextError::UnusableContextLink {
            reason: "a request may carry only one context link",
        });
    }

    Ok(targets)
}

/// Recovers the reason a context failed to process.
///
/// The loader's own error type travels inside the processing error, so a refusal keeps its
/// identity (not on the allow list, timed out, too large) instead of being flattened into
/// "processing failed". The operator needs to know which of those happened.
///
/// Every variant is named. The processor is pinned to an exact version, so a release that adds a
/// way to fail stops this from compiling and gets read, rather than being filed under "malformed"
/// by a catch-all nobody reconsidered.
fn context_error_from(error: ProcessingFailure<ContextError>) -> ContextError {
    match error {
        ProcessingFailure::ContextLoadingFailed(failure) => failure.source,
        ProcessingFailure::InvalidContextNullification
        | ProcessingFailure::LoadingDocumentFailed
        | ProcessingFailure::ProcessingModeConflict
        | ProcessingFailure::InvalidContextEntry
        | ProcessingFailure::InvalidImportValue
        | ProcessingFailure::InvalidRemoteContext
        | ProcessingFailure::InvalidBaseIri
        | ProcessingFailure::InvalidVocabMapping
        | ProcessingFailure::CyclicIriMapping
        | ProcessingFailure::InvalidTermDefinition
        | ProcessingFailure::KeywordRedefinition
        | ProcessingFailure::InvalidProtectedValue
        | ProcessingFailure::InvalidTypeMapping
        | ProcessingFailure::InvalidReverseProperty
        | ProcessingFailure::InvalidIriMapping
        | ProcessingFailure::InvalidKeywordAlias
        | ProcessingFailure::InvalidContainerMapping
        | ProcessingFailure::InvalidScopedContext
        | ProcessingFailure::ProtectedTermRedefinition
        | ProcessingFailure::ContextExtractionFailed(_)
        | ProcessingFailure::RecursiveContextInclusion
        | ProcessingFailure::ContextOverflow
        | ProcessingFailure::ForbiddenVocab => ContextError::MalformedBodyContext { reason: error.to_string() },
    }
}

/// The `@context` value of the embedded core context document.
fn core_context_value() -> Result<Value, ContextError> {
    let (json, _) = Value::parse_str(core_context::DOCUMENT).map_err(|error| ContextError::Malformed {
        url: Box::new(core_context::url()),
        reason: error.to_string(),
    })?;

    let Value::Object(object) = &json else {
        return Err(ContextError::Malformed {
            url: Box::new(core_context::url()),
            reason: "not a JSON object".to_owned(),
        });
    };

    object.get_unique("@context").ok().flatten().cloned().ok_or_else(|| ContextError::Malformed {
        url: Box::new(core_context::url()),
        reason: "no unique @context entry".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_jsonld_term_expansion::name::{ExpandedIri, Term};
    use pretty_assertions::assert_eq;
    use std::{collections::BTreeMap, path::PathBuf};
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{method, path},
    };

    const LD_JSON: Option<&str> = Some("application/ld+json");
    const JSON: Option<&str> = Some("application/json");

    fn url(text: &str) -> Url {
        Url::parse(text).expect("the test address is a URL")
    }

    fn resolver(config: &JsonLd) -> ContextResolver {
        ContextResolver::new(config).expect("the resolver should build")
    }

    fn body_context(source: &str) -> Value {
        let (value, _) = Value::parse_str(source).expect("test context should parse");
        value
    }

    fn context_link(url: &str) -> String {
        format!("<{url}>; rel=\"{CONTEXT_RELATION}\"; type=\"application/ld+json\"")
    }

    #[tokio::test]
    async fn a_request_with_no_context_gets_the_core_context() {
        let resolved = resolver(&JsonLd::default()).resolve(&RequestContext::default()).await.unwrap();

        assert_eq!(
            resolved.expand(&Term::new("Property")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/Property")
        );
        assert_eq!(
            resolved.expand(&Term::new("Widget")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/default-context/Widget"),
            "an undefined term must fall back to the default context, as the broker does"
        );
    }

    #[tokio::test]
    async fn a_body_context_changes_what_a_term_means() {
        // The caller aliases `Vehicle` to an IRI no policy names, which a string comparison misses.
        let context = body_context(r#"{"Vehicle": "https://example.test/probe#Vehicle"}"#);
        let request = RequestContext {
            content_type: LD_JSON,
            body_context: Some(&context),
            link_headers: &[],
        };

        let resolved = resolver(&JsonLd::default()).resolve(&request).await.unwrap();

        assert_eq!(
            resolved.expand(&Term::new("Vehicle")).unwrap(),
            ExpandedIri::new("https://example.test/probe#Vehicle")
        );
    }

    #[tokio::test]
    async fn redefining_a_core_term_is_refused() {
        // Libra composes the core context last and would read `location` as the core term; a broker
        // with a positional rule would store it under the caller's IRI.
        let context = body_context(r#"{"location": "https://example.test/probe#location", "Sensor": "https://example.test/probe#Sensor"}"#);
        let request = RequestContext {
            content_type: LD_JSON,
            body_context: Some(&context),
            link_headers: &[],
        };

        let refused = resolver(&JsonLd::default()).resolve(&request).await;

        assert!(matches!(refused, Err(ContextError::RedefinesCoreTerm { term }) if term == Term::new("location")));
    }

    #[tokio::test]
    async fn restating_a_core_term_with_its_own_iri_is_accepted_and_new_terms_are_the_callers() {
        let context = body_context(r#"{"location": "https://uri.etsi.org/ngsi-ld/location", "Sensor": "https://example.test/probe#Sensor"}"#);
        let request = RequestContext {
            content_type: LD_JSON,
            body_context: Some(&context),
            link_headers: &[],
        };

        let resolved = resolver(&JsonLd::default()).resolve(&request).await.unwrap();

        assert_eq!(
            resolved.expand(&Term::new("location")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/location")
        );
        assert_eq!(
            resolved.expand(&Term::new("Sensor")).unwrap(),
            ExpandedIri::new("https://example.test/probe#Sensor")
        );
    }

    #[tokio::test]
    async fn restating_a_core_term_in_the_core_namespace_over_http_is_accepted() {
        // The Smart Data Models context maps `location` this way.
        let context = body_context(r#"{"location": "http://uri.etsi.org/ngsi-ld/location"}"#);
        let request = RequestContext {
            content_type: LD_JSON,
            body_context: Some(&context),
            link_headers: &[],
        };

        let resolved = resolver(&JsonLd::default()).resolve(&request).await.unwrap();

        assert_eq!(
            resolved.expand(&Term::new("location")).unwrap().as_str(),
            "https://uri.etsi.org/ngsi-ld/location"
        );
    }

    #[tokio::test]
    async fn the_smart_data_models_definition_of_coordinates_is_accepted_and_the_core_one_applies() {
        // The Smart Data Models context writes `coordinates` this way and never defines `geojson`.
        let context = body_context(r#"{"coordinates": {"@container": "@list", "@id": "geojson:coordinates"}}"#);
        let request = RequestContext {
            content_type: LD_JSON,
            body_context: Some(&context),
            link_headers: &[],
        };

        let resolved = resolver(&JsonLd::default()).resolve(&request).await.unwrap();

        assert_eq!(
            resolved.expand(&Term::new("coordinates")).unwrap().as_str(),
            "https://uri.etsi.org/ngsi-ld/coordinates"
        );
    }

    #[tokio::test]
    async fn a_type_scoped_context_in_a_body_is_refused() {
        let context = body_context(r#"{"Vehicle": {"@id": "https://example.test/Vehicle", "@context": {"speed": "https://example.test/secret"}}}"#);
        let request = RequestContext {
            content_type: LD_JSON,
            body_context: Some(&context),
            link_headers: &[],
        };

        assert!(matches!(
            resolver(&JsonLd::default()).resolve(&request).await,
            Err(ContextError::MalformedBodyContext { .. })
        ));
    }

    #[tokio::test]
    async fn a_preloaded_context_with_a_scoped_definition_is_refused_at_startup() {
        let mut resolver = resolver(&JsonLd::default());

        let refused = resolver.preload(
            url("https://example.test/scoped.jsonld"),
            r#"{"@context": {"Vehicle": {"@id": "https://example.test/Vehicle", "@context": {}}}}"#,
        );

        assert!(matches!(refused, Err(ContextError::Malformed { .. })));
    }

    async fn with_links(links: &[&str]) -> Result<ResolvedContext, ContextError> {
        let mut resolver = resolver(&JsonLd {
            allow_remote: false,
            ..JsonLd::default()
        });
        resolver
            .preload(
                url("https://example.test/a.jsonld"),
                r#"{"@context": {"Vehicle": "https://example.test/Vehicle"}}"#,
            )
            .unwrap();

        resolver
            .resolve(&RequestContext {
                content_type: None,
                link_headers: links,
                body_context: None,
            })
            .await
    }

    #[tokio::test]
    async fn a_single_typed_context_link_is_used() {
        let resolved = with_links(&["<https://example.test/a.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json\""])
            .await
            .unwrap();

        assert_eq!(
            resolved.expand(&Term::new("Vehicle")).unwrap(),
            ExpandedIri::new("https://example.test/Vehicle")
        );
    }

    #[tokio::test]
    async fn two_context_links_are_refused_in_one_header_or_two() {
        let link = "<https://example.test/a.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json\"";
        let folded = format!("{link}, {link}");

        assert!(matches!(with_links(&[&folded]).await, Err(ContextError::UnusableContextLink { .. })));
        assert!(matches!(with_links(&[link, link]).await, Err(ContextError::UnusableContextLink { .. })));
    }

    #[tokio::test]
    async fn a_context_link_without_the_json_ld_type_is_refused() {
        let untyped = "<https://example.test/a.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"";
        let other = "<https://example.test/a.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/json\"";

        assert!(matches!(with_links(&[untyped]).await, Err(ContextError::UnusableContextLink { .. })));
        assert!(matches!(with_links(&[other]).await, Err(ContextError::UnusableContextLink { .. })));
    }

    #[tokio::test]
    async fn a_context_link_with_an_anchor_is_refused() {
        let anchored =
            "<https://example.test/a.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json\"; anchor=\"https://elsewhere.test/\"";

        assert!(matches!(with_links(&[anchored]).await, Err(ContextError::UnusableContextLink { .. })));
    }

    #[tokio::test]
    async fn a_link_header_context_is_fetched_and_applied() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"@context": {"WeatherObserved": "https://smartdatamodels.org/dataModel.Weather/WeatherObserved"}}"#),
            )
            .mount(&server)
            .await;

        let context_url = format!("{}/ctx.jsonld", server.uri());
        let link = context_link(&context_url);
        let config = JsonLd {
            allowed_contexts: vec![url(&server.uri())],
            ..JsonLd::default()
        };
        let request = RequestContext {
            content_type: JSON,
            body_context: None,
            link_headers: &[&link],
        };

        let resolved = resolver(&config).resolve(&request).await.unwrap();

        assert_eq!(
            resolved.expand(&Term::new("WeatherObserved")).unwrap(),
            ExpandedIri::new("https://smartdatamodels.org/dataModel.Weather/WeatherObserved")
        );
    }

    #[tokio::test]
    async fn a_context_that_may_not_be_fetched_fails_the_request() {
        // The failure that must not degrade into "match nothing": if this returned the core
        // context instead of an error, a caller could disable every policy about their own terms
        // by naming a context Libra will not fetch.
        let link = context_link("https://not-allowed.test/ctx.jsonld");
        let request = RequestContext {
            content_type: JSON,
            body_context: None,
            link_headers: &[&link],
        };

        let error = resolver(&JsonLd::default()).resolve(&request).await.expect_err("must fail closed");

        // The loader's own refusal reaches the caller intact, rather than being flattened into a
        // generic processing failure: the operator needs to see that it was the allow list.
        assert!(matches!(error, ContextError::NotAllowed { .. }), "got {error:?}");
        assert!(error.to_string().contains("not-allowed.test"));
    }

    #[tokio::test]
    async fn mixing_the_two_channels_is_refused() {
        let context = body_context(r#"{"Thing": "https://example.test/Thing"}"#);
        let link = context_link("https://example.test/ctx.jsonld");

        let request = RequestContext {
            content_type: LD_JSON,
            body_context: Some(&context),
            link_headers: &[&link],
        };
        assert!(matches!(
            resolver(&JsonLd::default()).resolve(&request).await,
            Err(ContextError::LinkHeaderNotAllowed)
        ));

        let request = RequestContext {
            content_type: JSON,
            body_context: Some(&context),
            link_headers: &[],
        };
        assert!(matches!(
            resolver(&JsonLd::default()).resolve(&request).await,
            Err(ContextError::BodyContextNotAllowed)
        ));
    }

    #[tokio::test]
    async fn a_link_without_the_context_relation_is_not_a_context() {
        // A `Link` header is used for other things too. Treating an unrelated link as a context
        // would fetch whatever it points at.
        let link = "<https://example.test/other>; rel=\"describedby\"".to_owned();
        let request = RequestContext {
            content_type: JSON,
            body_context: None,
            link_headers: &[&link],
        };

        let resolved = resolver(&JsonLd::default()).resolve(&request).await.unwrap();

        assert_eq!(
            resolved.expand(&Term::new("Property")).unwrap(),
            ExpandedIri::new("https://uri.etsi.org/ngsi-ld/Property")
        );
    }

    #[tokio::test]
    async fn a_context_preloaded_from_disk_resolves_with_fetching_switched_off() {
        // What makes an air-gapped deployment possible. A preloaded document is consulted before
        // the allow list and before the network, so it needs neither.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("fleet.jsonld");
        fs::write(&path, r#"{"@context":{"Vehicle":"https://uri.fiware.org/ns/data-models#Vehicle"}}"#).expect("writable");

        let config = JsonLd {
            allow_remote: false,
            preloaded_contexts: BTreeMap::from([(url("https://example.test/fleet.jsonld"), path)]),
            ..JsonLd::default()
        };
        let resolver = ContextResolver::new(&config).expect("the resolver should build");

        let context = resolver
            .resolve(&RequestContext {
                content_type: None,
                link_headers: &["<https://example.test/fleet.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json\""],
                body_context: None,
            })
            .await
            .expect("a preloaded context should resolve without fetching");

        assert_eq!(
            context.expand(&Term::new("Vehicle")).map(|iri| iri.as_str().to_owned()),
            Some("https://uri.fiware.org/ns/data-models#Vehicle".to_owned())
        );
    }

    #[tokio::test]
    async fn a_preloaded_context_that_is_not_there_stops_the_process() {
        // Fatal at startup rather than deferred: the deployment that preloads is the one that
        // cannot fetch, so there is no fallback to discover this on a request.
        let config = JsonLd {
            allow_remote: false,
            preloaded_contexts: BTreeMap::from([(url("https://example.test/fleet.jsonld"), PathBuf::from("/nonexistent/fleet.jsonld"))]),
            ..JsonLd::default()
        };

        assert!(matches!(ContextResolver::new(&config), Err(ContextError::PreloadUnreadable { .. })));
    }
}
