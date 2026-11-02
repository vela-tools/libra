//! What can go wrong while resolving a context, and why every one of these is fatal to the request.

use iri_rs::IriBuf;
use libra_jsonld_term_expansion::name::Term;
use std::{io::Error as IoError, path::PathBuf};
use url::Url;

/// A context could not be resolved.
///
/// The addresses are boxed so that the error stays small: every `Result` that carries one, up
/// through the policy store, would otherwise be large enough for clippy to object.
///
/// Every variant fails the request closed. There is deliberately no "carry on without a context"
/// path: with no context, a term has no meaning, so a policy naming that term cannot be evaluated.
/// Degrading to "match nothing" would turn a fetch failure, or a hostile context URL, into an
/// authorization bypass: the caller would simply have to make resolution fail to get past the
/// rules written about them.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// The context URL is not on the configured allow list.
    #[error("context '{url}' is not on the allow list")]
    NotAllowed { url: Box<Url> },

    /// The context URL carries a query, so it does not name one document.
    ///
    /// A context is cached and allow-listed by its URL, and a query makes one address stand for as
    /// many documents as the query values a caller can invent.
    #[error("context '{url}' carries a query, and a context URL names exactly one document")]
    QueryNotAllowed { url: Box<Url> },

    /// The context URL's path is one Libra and the broker's decoder could read differently.
    ///
    /// Some decoders split a path on a decoded `%2F` or climb out through a decoded dot segment.
    /// Libra reads the path once and the broker reads it once, and a path carrying either makes the
    /// two readings need not agree, so it is refused rather than guessed at.
    #[error("context '{url}' has a path that could be read two ways: {reason}")]
    AmbiguousPath {
        /// The URL.
        url: Box<Url>,
        /// What makes the path ambiguous.
        reason: &'static str,
    },

    /// Remote fetching is switched off entirely and this context is not already known.
    #[error("context '{url}' is not preloaded and remote fetching is disabled")]
    RemoteFetchDisabled { url: Box<Url> },

    /// The context is named by an IRI that is not a URL, so there is nowhere to fetch it from and
    /// nothing on the allow list can match it.
    #[error("context '{iri}' is not a URL")]
    NotAUrl { iri: IriBuf },

    /// The HTTP client that fetches contexts could not be built.
    #[error("the HTTP client for fetching contexts could not be built: {reason}")]
    Client { reason: String },

    /// The fetch did not finish inside the configured timeout.
    #[error("fetching context '{url}' timed out")]
    Timeout { url: Box<Url> },

    /// The fetch failed.
    #[error("failed to fetch context '{url}': {reason}")]
    Fetch { url: Box<Url>, reason: String },

    /// A context named in `[jsonld] preloaded-contexts` could not be read from disk.
    ///
    /// Fatal at startup rather than deferred: a deployment that preloads a context is usually one
    /// that cannot fetch it, so a missing file means every policy written against that context
    /// fails later, one request at a time.
    #[error("preloaded context '{url}' could not be read from '{}'", .path.display())]
    PreloadUnreadable {
        /// The URL the document was to be preloaded under.
        url: Box<Url>,
        /// Where it was to be read from.
        path: PathBuf,
        /// What went wrong. Carried as the source error rather than a rendered string: three
        /// owned strings in one variant is enough to make every `Result` in the loader large
        /// enough for clippy to object, and the chain prints the same text.
        #[source]
        source: IoError,
    },

    /// The document fetched was not a usable context.
    #[error("context '{url}' is not a valid JSON-LD context: {reason}")]
    Malformed { url: Box<Url>, reason: String },

    /// The `@context` in the request body was not a usable context.
    #[error("the @context in the request body is not valid: {reason}")]
    MalformedBodyContext { reason: String },

    /// An `application/ld+json` request carried a context `Link` header.
    ///
    /// The two channels are mutually exclusive, and the broker rejects this outright. Libra
    /// rejects it too rather than picking one, because picking one means guessing which context
    /// the broker would have used.
    #[error("a context Link header is not allowed with content type application/ld+json")]
    LinkHeaderNotAllowed,

    /// A `Link` header could not be parsed.
    ///
    /// Refused rather than ignored: a header Libra cannot read may still be one the broker can,
    /// and then the two would resolve the request against different contexts.
    #[error("malformed Link header: {reason}")]
    MalformedLinkHeader { reason: String },

    /// An `application/json` request carried an `@context` in its body.
    #[error("an @context entry in the body is not allowed with content type application/json")]
    BodyContextNotAllowed,

    /// The caller's context defines a term the core context defines, with another IRI.
    ///
    /// Libra composes the core context last, so its definition wins here. A broker that applies
    /// the caller's context positionally would not agree, and would store under the caller's IRI a
    /// name Libra judged as the core one.
    #[error("the request context redefines the core term '{term}'")]
    RedefinesCoreTerm {
        /// The redefined term.
        term: Term,
    },

    /// A context `Link` header is one Libra and the broker could read differently: a second
    /// context link, one carrying an `anchor`, or one not declaring `type="application/ld+json"`.
    #[error("a context Link header is not usable: {reason}")]
    UnusableContextLink {
        /// Why.
        reason: &'static str,
    },

    /// The request supplied no context that could be used, and no default was configured.
    #[error("no usable @context for this request")]
    Unresolvable,
}

/// Why a fetch inside the single-flight window came back with nothing.
///
/// Small and clonable, because the cache hands the refusal back wrapped in an `Arc` and shared
/// between every concurrent caller that missed together. [`ContextError`] is neither: it carries an
/// [`IoError`], which clones nothing. The conversion at the boundary below is hand-written rather
/// than derived because the variants it maps to hold two named fields each, and a derive would
/// match on tuples instead.
#[derive(Clone, Debug)]
pub enum FetchRefusal {
    /// Remote fetching is switched off entirely and this context is not already known.
    RemoteFetchDisabled {
        /// The URL.
        url: Box<Url>,
    },

    /// The context URL is not on the configured allow list.
    NotAllowed {
        /// The URL.
        url: Box<Url>,
    },

    /// The fetch did not finish inside the configured timeout.
    Timeout {
        /// The URL.
        url: Box<Url>,
    },

    /// The fetch failed.
    Fetch {
        /// The URL.
        url: Box<Url>,
        /// What went wrong.
        reason: String,
    },

    /// The document fetched was not a usable context.
    Malformed {
        /// The URL.
        url: Box<Url>,
        /// Why.
        reason: String,
    },
}

impl From<FetchRefusal> for ContextError {
    fn from(refusal: FetchRefusal) -> Self {
        match refusal {
            FetchRefusal::RemoteFetchDisabled { url } => Self::RemoteFetchDisabled { url },
            FetchRefusal::NotAllowed { url } => Self::NotAllowed { url },
            FetchRefusal::Timeout { url } => Self::Timeout { url },
            FetchRefusal::Fetch { url, reason } => Self::Fetch { url, reason },
            FetchRefusal::Malformed { url, reason } => Self::Malformed { url, reason },
        }
    }
}

impl ContextError {
    /// The context URL this failure concerns, when it concerns one.
    #[must_use]
    pub fn url(&self) -> Option<&Url> {
        match self {
            ContextError::NotAllowed { url }
            | ContextError::RemoteFetchDisabled { url }
            | ContextError::QueryNotAllowed { url }
            | ContextError::AmbiguousPath { url, .. }
            | ContextError::Timeout { url }
            | ContextError::Fetch { url, .. }
            | ContextError::Malformed { url, .. }
            | ContextError::PreloadUnreadable { url, .. } => Some(url.as_ref()),
            ContextError::NotAUrl { .. }
            | ContextError::Client { .. }
            | ContextError::MalformedBodyContext { .. }
            | ContextError::MalformedLinkHeader { .. }
            | ContextError::LinkHeaderNotAllowed
            | ContextError::BodyContextNotAllowed
            | ContextError::RedefinesCoreTerm { .. }
            | ContextError::UnusableContextLink { .. }
            | ContextError::Unresolvable => None,
        }
    }
}
