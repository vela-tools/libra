//! Fetches remote contexts, under every restriction that makes doing so safe.
//!
//! A context URL arrives in a request, which means an attacker chooses it. Fetching it turns the
//! proxy into an HTTP client pointed wherever the caller likes, from inside the network the proxy
//! is defending. Six things keep that from being a server-side request forgery primitive:
//!
//! - an allow list, checked before any connection is opened;
//! - no redirect following, so an allow-listed URL cannot hand the request to somewhere else;
//! - a timeout, so a slow host cannot pin request-handling resources;
//! - a size limit, so a large body cannot exhaust memory;
//! - a single-flight window, so concurrent misses on one URL share one fetch instead of each
//!   opening its own;
//! - a cache weighed in bytes, so a bounded number of documents is a bounded amount of memory.
//!
//! Everything the loader refuses fails the request closed.

use crate::{
    error::{ContextError, FetchRefusal},
    scoped::refuse_scoped_document,
};
use iri_rs::{Iri, IriBuf};
use jsonld::{Loader, RemoteDocument, loader::LoadError};
use jstrict::Value;
use libra_config::jsonld::JsonLd;
use libra_fetched_body::{FetchedBodyError, read};
use libra_json_body::strict;
use mediatype::MediaTypeBuf;
use moka::future::Cache;
use percent_encoding::percent_decode_str;
use reqwest::{Client, redirect::Policy};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use tracing::{debug, warn};
use url::Url;

/// A `User-Agent` that identifies the product and nothing else.
const USER_AGENT: &str = concat!("libra/", env!("CARGO_PKG_VERSION"));

/// Why a context that grew past the configured size was refused.
const OVER_THE_LIMIT: &str = "context exceeds the configured size limit";

/// A fetched context document, and the size the cache's byte weigher sees.
///
/// The weight is the length of the body as it arrived, so bounding the cache bounds the parsed
/// trees by the same number and no document is re-serialised to measure it.
#[derive(Clone, Debug)]
struct CachedContext {
    document: Value,
    bytes: u32,
}

/// Loads contexts, refusing anything the configuration does not allow.
pub struct AllowListLoader {
    config: JsonLd,
    client: Client,
    cache: Cache<Url, CachedContext>,
    preloaded: Vec<(Url, Value)>,
}

impl AllowListLoader {
    /// Builds a loader from the `[jsonld]` configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Client`] if the HTTP client cannot be built.
    pub fn new(config: JsonLd) -> Result<Self, ContextError> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            // A redirect is a second URL, and it was not the one the allow list approved. Rather
            // than re-checking each hop, refuse to follow: a context that redirects is a context
            // the operator can allow-list at its final address.
            .redirect(Policy::none())
            .timeout(Duration::from_secs(config.fetch_timeout_seconds))
            .build()
            .map_err(|error| ContextError::Client { reason: error.to_string() })?;

        let cache = Cache::builder()
            .max_capacity(config.cache_max_bytes as u64)
            .weigher(|_, context: &CachedContext| context.bytes)
            .time_to_live(Duration::from_secs(config.cache_ttl_seconds))
            .build();

        Ok(Self {
            config,
            client,
            cache,
            preloaded: Vec::new(),
        })
    }

    /// Adds a context that is always available and never fetched.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Malformed`] if `document` is not JSON the strict parse accepts, or
    /// carries a scoped context.
    pub fn preload(&mut self, url: Url, document: &str) -> Result<(), ContextError> {
        let json = strict::parse(document.as_bytes()).map_err(|error| malformed(&url, error.to_string()))?;
        refuse_scoped_document(&json).map_err(|reason| malformed(&url, reason))?;

        self.preloaded.push((url, json));
        Ok(())
    }

    fn preloaded_document(&self, url: &Url) -> Option<Value> {
        self.preloaded
            .iter()
            .find(|(preloaded, _)| preloaded == url)
            // The preloaded copy stays in place for the next request; the caller takes its own.
            .map(|(_, document)| document.clone())
    }

    /// Fetches a context that is not already in memory, applying every restriction.
    ///
    /// Every refusal here is a [`FetchRefusal`] rather than a [`ContextError`]: the single-flight
    /// window may hand one refusal to several concurrent callers, and [`ContextError`] is not
    /// built to be cloned.
    async fn fetch_uncached(&self, address: &Url) -> Result<CachedContext, FetchRefusal> {
        if !self.config.allow_remote {
            return Err(FetchRefusal::RemoteFetchDisabled {
                url: Box::new(address.clone()),
            }); // the refusal owns the address
        }

        if !self.config.allows_fetching(address) {
            // Logged at warn: a request naming a context nobody allow-listed is either a
            // misconfiguration or someone probing what the proxy will fetch.
            warn!(url = %address, "refused to fetch a context that is not on the allow list");
            return Err(FetchRefusal::NotAllowed {
                url: Box::new(address.clone()),
            }); // the refusal owns the address
        }

        let deadline = Duration::from_secs(self.config.fetch_timeout_seconds);
        let response = timeout(deadline, self.client.get(address.as_str()).send())
            .await
            .map_err(|_| timed_out(address))?
            .map_err(|error| fetch_failed(address, error.to_string()))?;

        if !response.status().is_success() {
            return Err(fetch_failed(address, format!("HTTP {}", response.status().as_u16())));
        }

        // Trust the declared length only to refuse early; the real limit is applied to what
        // actually arrives, because a hostile server can lie about it or omit it.
        if response.content_length().is_some_and(|length| length > self.config.max_context_bytes as u64) {
            return Err(fetch_failed(address, OVER_THE_LIMIT));
        }

        // Read under the limit as it arrives: buffering the whole body and measuring it afterwards
        // lets a chunked response from an allow-listed host spend the full timeout at full
        // bandwidth in memory before being refused.
        let body = timeout(deadline, read(response, self.config.max_context_bytes))
            .await
            .map_err(|_| timed_out(address))?
            .map_err(|error| match error {
                FetchedBodyError::TooLarge { .. } => fetch_failed(address, OVER_THE_LIMIT),
                FetchedBodyError::Unreadable(error) => fetch_failed(address, error.to_string()),
            })?;

        // The strict parse: a context document nested past the limit or repeating a term is one
        // the broker's processor may read differently from this one.
        let json = strict::parse(&body).map_err(|error| malformed(address, error.to_string()))?;
        refuse_scoped_document(&json).map_err(|reason| malformed(address, reason))?;

        let bytes = u32::try_from(body.len()).map_err(|_| fetch_failed(address, OVER_THE_LIMIT))?;

        Ok(CachedContext { document: json, bytes })
    }

    /// Resolves a context address to its document, through the cache.
    ///
    /// A miss fetches once even when several requests miss together: `try_get_with` is the
    /// single-flight window, and only the winner of it opens a connection. An error is not cached,
    /// so a context whose fetch failed is retried by the next request rather than pinned as
    /// unavailable for the cache's lifetime.
    async fn fetch(&self, address: &Url) -> Result<Value, ContextError> {
        let cached = self
            .cache
            .try_get_with(address.clone(), self.fetch_uncached(address))
            .await
            // Shared refusals arrive in an `Arc`; one is unwrapped, the rest are cloned, which is
            // what `FetchRefusal` is small and clonable for.
            .map_err(|refusal| match Arc::try_unwrap(refusal) {
                Ok(owned) => ContextError::from(owned),
                Err(shared) => ContextError::from(FetchRefusal::clone(&shared)),
            })?;

        debug!(url = %address, "context document resolved");

        Ok(cached.document)
    }
}

/// A context that could not be fetched.
fn fetch_failed(address: &Url, reason: impl Into<String>) -> FetchRefusal {
    FetchRefusal::Fetch {
        url: Box::new(address.clone()),
        reason: reason.into(),
    }
}

/// A context that did not answer in time.
fn timed_out(address: &Url) -> FetchRefusal {
    FetchRefusal::Timeout {
        url: Box::new(address.clone()),
    }
}

/// A context that arrived and is not a usable document.
fn malformed(address: &Url, reason: impl Into<String>) -> FetchRefusal {
    FetchRefusal::Malformed {
        url: Box::new(address.clone()),
        reason: reason.into(),
    }
}

/// The media type a context document is labelled with.
fn ld_json() -> Option<MediaTypeBuf> {
    "application/ld+json".parse().ok()
}

/// Why a context URL's path is one two readers could disagree about, when it is.
///
/// `Url` preserves an encoded `%2F` in the path it reports and normalises only literal dot
/// segments, so an encoded separator or an encoded dot segment arrives exactly as the caller wrote
/// it. A broker that decodes before splitting reads a different path from the one Libra authorised
/// against, so either is refused rather than guessed at.
fn ambiguous_path(address: &Url) -> Option<&'static str> {
    let path = address.path();

    if path.to_ascii_lowercase().contains("%2f") {
        return Some("the path carries an encoded path separator");
    }

    let decoded = percent_decode_str(path).decode_utf8_lossy();
    decoded
        .split('/')
        .find(|segment| matches!(*segment, "." | ".."))
        .map(|_| "the path carries a dot segment that only decoding reveals")
}

impl Loader for AllowListLoader {
    /// The concrete refusal, not a boxed one. The processor carries it through unchanged, so the
    /// caller learns whether a context was refused, timed out, or came back malformed, rather
    /// than only that processing failed.
    type Error = ContextError;

    async fn load(&self, url: Iri<&str>) -> Result<RemoteDocument<IriBuf>, LoadError<Self::Error>> {
        let Ok(address) = Url::parse(url.as_str()) else {
            let iri = IriBuf::from(url);
            return Err(LoadError::new(IriBuf::from(url), ContextError::NotAUrl { iri }));
        };

        // The fragment never selects a different document, so it is dropped before the address is
        // matched, fetched or cached: one document, one cache entry.
        let mut address = address;
        address.set_fragment(None);

        if address.query().is_some() {
            return Err(LoadError::new(IriBuf::from(url), ContextError::QueryNotAllowed { url: Box::new(address) }));
        }

        if let Some(reason) = ambiguous_path(&address) {
            return Err(LoadError::new(
                IriBuf::from(url),
                ContextError::AmbiguousPath {
                    url: Box::new(address),
                    reason,
                },
            ));
        }

        let document = match self.preloaded_document(&address) {
            Some(preloaded) => preloaded,
            None => self.fetch(&address).await.map_err(|error| LoadError::new(IriBuf::from(url), error))?,
        };

        Ok(RemoteDocument::new(Some(IriBuf::from(url)), ld_json(), document))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::{sync::Arc, time::Instant};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinSet,
        time::sleep,
    };
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{method, path},
    };

    const CONTEXT: &str = r#"{"@context": {"Vehicle": "https://example.test/Vehicle"}}"#;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("the test address is a URL")
    }

    fn config_allowing(prefix: &str) -> JsonLd {
        JsonLd {
            allow_remote: true,
            allowed_contexts: vec![url(prefix)],
            fetch_timeout_seconds: 2,
            ..JsonLd::default()
        }
    }

    /// The loader's refusal now travels as itself rather than as a boxed error, so recovering it
    /// is a field access instead of a downcast.
    fn cause_of(error: &LoadError<ContextError>) -> &ContextError {
        &error.source
    }

    /// Boxed because a [`Url`] makes the refusal large enough that returning it by value from a
    /// helper trips the large-error lint; the loader itself returns it as the trait requires.
    async fn load(loader: &AllowListLoader, url: &str) -> Result<RemoteDocument<IriBuf>, Box<LoadError<ContextError>>> {
        let iri = IriBuf::new(url.to_owned()).expect("test URL should be an IRI");
        loader.load(iri.as_ref()).await.map_err(Box::new)
    }

    #[tokio::test]
    async fn fetches_an_allow_listed_context() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT))
            .expect(1)
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();

        assert!(load(&loader, &format!("{}/ctx.jsonld", server.uri())).await.is_ok());
    }

    #[tokio::test]
    async fn refuses_a_context_that_is_not_allow_listed() {
        let server = MockServer::start().await;
        // No mock is mounted, and none is needed: the refusal must happen before any connection.
        let loader = AllowListLoader::new(config_allowing("https://allowed.test/")).unwrap();

        let error = load(&loader, &format!("{}/ctx.jsonld", server.uri())).await.expect_err("must refuse");

        assert!(matches!(cause_of(&error), ContextError::NotAllowed { .. }));
        assert_eq!(
            server.received_requests().await.map(|requests| requests.len()),
            Some(0),
            "an allow-list refusal must not open a connection"
        );
    }

    #[tokio::test]
    async fn refuses_everything_when_remote_fetching_is_off() {
        let server = MockServer::start().await;
        let config = JsonLd {
            allow_remote: false,
            allowed_contexts: vec![url(&server.uri())],
            ..JsonLd::default()
        };
        let loader = AllowListLoader::new(config).unwrap();

        let error = load(&loader, &format!("{}/ctx.jsonld", server.uri())).await.expect_err("must refuse");

        assert!(matches!(cause_of(&error), ContextError::RemoteFetchDisabled { .. }));
        assert_eq!(server.received_requests().await.map(|requests| requests.len()), Some(0));
    }

    #[tokio::test]
    async fn does_not_follow_a_redirect_out_of_the_allow_list() {
        // The dangerous shape: an allow-listed URL that redirects somewhere internal. Following it
        // would turn the proxy into a request forgery primitive against its own network.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "http://169.254.169.254/latest/meta-data/"))
            .expect(1)
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();

        let error = load(&loader, &format!("{}/ctx.jsonld", server.uri()))
            .await
            .expect_err("a redirect must not be followed");

        assert!(matches!(cause_of(&error), ContextError::Fetch { .. }));
    }

    #[tokio::test]
    async fn refuses_a_context_larger_than_the_limit() {
        let server = MockServer::start().await;
        let oversized = format!(r#"{{"@context": {{"pad": "{}"}}}}"#, "x".repeat(4096));
        Mock::given(method("GET"))
            .and(path("/big.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(oversized))
            .mount(&server)
            .await;

        let config = JsonLd {
            max_context_bytes: 1024,
            ..config_allowing(&server.uri())
        };
        let loader = AllowListLoader::new(config).unwrap();

        let error = load(&loader, &format!("{}/big.jsonld", server.uri()))
            .await
            .expect_err("must refuse an oversized context");

        assert!(matches!(cause_of(&error), ContextError::Fetch { .. }));
    }

    #[tokio::test]
    async fn an_oversized_chunked_context_is_refused_without_waiting_for_it_to_finish() {
        // No Content-Length, so only the running total can catch it. The server sends more than
        // the limit and then stalls: a loader that buffers first would sit out the whole timeout.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            let chunk = "x".repeat(2000);
            let response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{chunk}\r\n", chunk.len());
            socket.write_all(response.as_bytes()).await.unwrap();
            sleep(Duration::from_secs(30)).await;
        });

        let base = format!("http://{address}");
        let config = JsonLd {
            max_context_bytes: 1024,
            fetch_timeout_seconds: 20,
            ..config_allowing(&base)
        };
        let loader = AllowListLoader::new(config).unwrap();

        let started = Instant::now();
        let error = load(&loader, &format!("{base}/big.jsonld"))
            .await
            .expect_err("must refuse an oversized context");

        assert!(matches!(cause_of(&error), ContextError::Fetch { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "it must not wait out the timeout");
    }

    #[tokio::test]
    async fn a_slow_host_cannot_hold_the_request_open() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT).set_delay(Duration::from_secs(3)))
            .mount(&server)
            .await;

        let config = JsonLd {
            fetch_timeout_seconds: 1,
            ..config_allowing(&server.uri())
        };
        let loader = AllowListLoader::new(config).unwrap();

        let error = load(&loader, &format!("{}/slow.jsonld", server.uri())).await.expect_err("must time out");

        assert!(
            matches!(cause_of(&error), ContextError::Timeout { .. } | ContextError::Fetch { .. }),
            "a slow context must fail the request rather than wait indefinitely"
        );
    }

    #[tokio::test]
    async fn a_fetched_context_is_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT))
            .expect(1)
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();
        let url = format!("{}/ctx.jsonld", server.uri());

        for _ in 0..5 {
            assert!(load(&loader, &url).await.is_ok());
        }
        // `expect(1)` on the mock is the assertion: five loads, one fetch.
    }

    #[tokio::test]
    async fn a_preloaded_context_is_never_fetched() {
        let server = MockServer::start().await;
        let mut loader = AllowListLoader::new(JsonLd {
            allow_remote: false,
            ..JsonLd::default()
        })
        .unwrap();
        let url = url(&format!("{}/core.jsonld", server.uri()));
        loader.preload(url.clone(), CONTEXT).unwrap(); // the loader owns its entries; the test loads the same address below

        assert!(
            load(&loader, url.as_str()).await.is_ok(),
            "a preloaded context works even with fetching switched off"
        );
        assert_eq!(server.received_requests().await.map(|requests| requests.len()), Some(0));
    }

    #[tokio::test]
    async fn an_iri_that_is_not_a_url_is_refused_before_anything_is_fetched() {
        // A legal IRI whose host the URL standard rejects: its last label reads as a number, and
        // 256 is not an octet.
        let loader = AllowListLoader::new(config_allowing("http://1.2.3.4/")).unwrap();

        let error = load(&loader, "http://1.2.3.256/ctx.jsonld").await.expect_err("must refuse");

        assert!(matches!(cause_of(&error), ContextError::NotAUrl { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn a_non_json_body_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/html"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>not a context</html>"))
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();

        let error = load(&loader, &format!("{}/html", server.uri())).await.expect_err("must refuse");

        assert!(matches!(cause_of(&error), ContextError::Malformed { .. }));
    }

    #[tokio::test]
    async fn a_fragment_is_stripped_before_matching_fetching_and_caching() {
        // The fragment never selects a different document, so the second load must be served by the
        // cache entry the first one filled rather than fetch a "different" address.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT))
            .expect(1)
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();
        let base = format!("{}/ctx.jsonld", server.uri());

        assert!(load(&loader, &format!("{base}#one")).await.is_ok());
        assert!(load(&loader, &format!("{base}#two")).await.is_ok());
    }

    #[tokio::test]
    async fn a_query_on_a_context_url_is_refused() {
        // A query makes one address stand for as many documents as a caller can invent, which the
        // cache and the allow list cannot tell apart. Refused before anything is fetched.
        let server = MockServer::start().await;
        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();

        let error = load(&loader, &format!("{}/ctx.jsonld?version=2", server.uri()))
            .await
            .expect_err("must refuse a query");

        assert!(matches!(cause_of(&error), ContextError::QueryNotAllowed { .. }), "{error:?}");
        assert_eq!(server.received_requests().await.map(|requests| requests.len()), Some(0));
    }

    #[tokio::test]
    async fn an_encoded_path_separator_in_a_context_url_is_refused() {
        // `..%2f` climbs out of a path for a decoder that splits after decoding. Whether the broker
        // behind the proxy splits before or after is exactly the kind of thing that must not be
        // guessed at, so the address is refused before any connection.
        let server = MockServer::start().await;
        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();

        let error = load(&loader, &format!("{}/a/..%2fb.jsonld", server.uri()))
            .await
            .expect_err("must refuse an encoded separator");

        assert!(matches!(cause_of(&error), ContextError::AmbiguousPath { .. }), "{error:?}");
        assert_eq!(server.received_requests().await.map(|requests| requests.len()), Some(0));
    }

    #[tokio::test]
    async fn an_encoded_dot_segment_is_resolved_before_anything_is_checked() {
        // The URL standard decodes the unreserved `%2E` and then removes the dot segments it forms,
        // so every conformant reader, Libra's parser and the host that answers, sees `/b.jsonld`.
        // The path is unambiguous once resolved, and the fetch happens at the resolved address.
        // The refusal covers the encoded separator, which the standard preserves.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/b.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT))
            .expect(1)
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();

        let document = load(&loader, &format!("{}/a/%2e%2e/b.jsonld", server.uri()))
            .await
            .expect("the resolved path is fetched");
        let _ = document;
        assert_eq!(server.received_requests().await.map(|requests| requests.len()), Some(1));
    }

    #[tokio::test]
    async fn an_exact_allow_list_entry_allows_no_suffix_path() {
        let server = MockServer::start().await;
        let loader = AllowListLoader::new(JsonLd {
            allowed_contexts: vec![url(&format!("{}/ctx.jsonld", server.uri()))],
            ..JsonLd::default()
        })
        .unwrap();

        let error = load(&loader, &format!("{}/ctx.jsonld.evil", server.uri()))
            .await
            .expect_err("must refuse a suffix of an exact entry");

        assert!(matches!(cause_of(&error), ContextError::NotAllowed { .. }), "{error:?}");
        assert_eq!(server.received_requests().await.map(|requests| requests.len()), Some(0));
    }

    #[tokio::test]
    async fn concurrent_misses_on_one_url_fetch_once() {
        // The single-flight window: five requests missing together must share one fetch, not open
        // five connections for one document.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT).set_delay(Duration::from_millis(300)))
            .expect(1)
            .mount(&server)
            .await;

        let loader = Arc::new(AllowListLoader::new(config_allowing(&server.uri())).unwrap());
        let address = format!("{}/ctx.jsonld", server.uri());

        let mut loads = JoinSet::new();
        for _ in 0..5 {
            let loader = Arc::clone(&loader);
            let address = address.clone();
            loads.spawn(async move { load(&loader, &address).await.is_ok() });
        }

        let mut answered = 0;
        while let Some(loaded) = loads.join_next().await {
            assert!(loaded.expect("the task should not panic"), "every concurrent load must succeed");
            answered += 1;
        }

        assert_eq!(answered, 5);
    }

    #[tokio::test]
    async fn a_cache_bounded_in_bytes_refetches_an_evicted_context() {
        // The bound holds exactly one context. Two addresses alternating under it must evict each
        // other and refetch: eviction in the cache is amortized rather than synchronous, so the
        // assertion is that the network is revisited, not on which load it happens.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT))
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(JsonLd {
            cache_max_bytes: CONTEXT.len(),
            ..config_allowing(&server.uri())
        })
        .unwrap();

        let addresses = [format!("{}/one.jsonld", server.uri()), format!("{}/two.jsonld", server.uri())];
        for round in 0..200 {
            for address in &addresses {
                assert!(load(&loader, address).await.is_ok(), "round {round} against {address} must load");
            }
        }

        let fetched = server.received_requests().await.map(|requests| requests.len()).unwrap_or_default();
        assert!(fetched > 2, "the byte bound must evict and refetch, not hold both: {fetched} fetches");
    }

    #[tokio::test]
    async fn a_fetched_error_is_not_cached() {
        // A fetch that failed must not pin the context as unavailable: the next request tries the
        // network again, and this time the answer is a document.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/ctx.jsonld"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONTEXT))
            .expect(1)
            .mount(&server)
            .await;

        let loader = AllowListLoader::new(config_allowing(&server.uri())).unwrap();
        let address = format!("{}/ctx.jsonld", server.uri());

        let error = load(&loader, &address).await.expect_err("the first fetch fails");
        assert!(matches!(cause_of(&error), ContextError::Fetch { .. }), "{error:?}");

        assert!(load(&loader, &address).await.is_ok(), "the retried fetch must not be refused from a cache");
    }
}
