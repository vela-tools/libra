//! JWKS fetching, caching and key lookup for token validation.
//!
//! Libra verifies token signatures against the public keys the identity provider publishes at its
//! JWKS endpoint. That endpoint is remote, so the key set is cached, refreshed on a schedule, and
//! refreshed on demand when a token arrives carrying a key id the cache has not seen, which is
//! what happens for a few seconds after the provider rotates its signing key.
//!
//! Two properties matter more than freshness:
//!
//! *Fail-static.* A failed fetch never disturbs the cached key set. If the provider is down, the
//! keys Libra already holds keep verifying the tokens they were minted for, and a key id nobody
//! has ever published is still rejected. An outage at the identity provider must not become an
//! outage at the proxy, and it must not become an open door either.
//!
//! *Bounded.* The on-demand refresh is rate limited, because the trigger for it (an unrecognised
//! key id) is chosen by whoever sends the request. Without a cooldown, a stream of tokens
//! carrying random key ids turns every one of them into an outbound HTTP request to the identity
//! provider, with Libra as the amplifier. The response is size capped for the same reason: it is
//! read into memory on every refresh.
//!
//! A request that arrives while a fetch is already running waits for that fetch, but only for a
//! short bound of its own. That covers a key rotation, where many valid tokens carry the new key id
//! at once and one fetch serves them all, without letting a hung provider hold requests for as long
//! as the fetch takes to time out.

use crate::{
    document::JwksDocument,
    error::KeyStoreError,
    key_id::KeyId,
    refresh_claim::{Claim, RefreshGate},
};
use arc_swap::ArcSwap;
use jsonwebtoken::DecodingKey;
use libra_fetched_body::{FetchedBodyError, read};
use reqwest::{Client, redirect::Policy};
use serde_json::from_slice;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{spawn, task::JoinHandle, time::interval};
use tracing::{debug, error, info};
use url::Url;

mod document;
pub mod error;
pub mod key_id;
pub mod key_use;
mod refresh_claim;

/// Largest JWKS document Libra will read.
///
/// A real key set is a few hundred bytes per key. The cap exists because the body is buffered in
/// full on every refresh, so an endpoint that answers with an unbounded stream (a compromised
/// provider, or anything that can answer in its place) would otherwise choose how much memory
/// Libra allocates.
const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// How long the whole fetch may take before it is abandoned.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Shortest interval between two fetch attempts triggered by an unknown key id.
///
/// Long enough that a burst of unrecognised key ids costs one request, short enough that a genuine
/// key rotation is picked up in seconds rather than waiting for the scheduled refresh.
const DEFAULT_REFRESH_COOLDOWN: Duration = Duration::from_secs(5);

/// Longest a request waits for a fetch somebody else already started.
///
/// A healthy identity provider answers in milliseconds, so this is generous for the case it exists
/// for: many tokens carrying a newly rotated key id, all served by one fetch. It is far below
/// [`FETCH_TIMEOUT`] on purpose. Against a provider that hangs, the request is answered as an
/// unknown key id after this long and not after the fetch gives up.
const IN_FLIGHT_WAIT: Duration = Duration::from_secs(2);

/// The cached JWKS and everything needed to replace it.
struct KeyStoreInner {
    /// The current key set, indexed by key id.
    ///
    /// Swapped as a whole. Inserting the new keys into a shared map and then pruning the ones that had
    /// gone would leave a window in which a revoked key and its replacement were both live, and a token
    /// signed with a key the provider had just withdrawn would still verify during it.
    keys: ArcSwap<HashMap<KeyId, DecodingKey>>,

    /// Where the key set is published.
    jwks_url: Arc<Url>,

    /// The client used for every fetch, so connections are reused across refreshes.
    http_client: Client,

    /// Decides who fetches and who waits, and holds the cooldown.
    ///
    /// Never held across a fetch, so a hung provider does not queue every unknown key id, and the
    /// scheduled refresh, behind it. The check ("may I refresh?") and the claim ("I am refreshing
    /// now") are one indivisible step, which is what stops a burst of unknown key ids all fetching.
    gate: Arc<RefreshGate>,
}

/// A cached, periodically refreshed set of JWKS signing keys.
///
/// Cheap to clone: every clone shares one cache and one cooldown.
#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<KeyStoreInner>,
}

impl KeyStore {
    /// Builds a keystore and performs the first fetch.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyStoreError`] if the first fetch fails. Starting without keys is refused on
    /// purpose: a proxy that comes up with an empty key set rejects every request it is given, and
    /// failing at startup says why once instead of once per request.
    pub async fn new(jwks_url: Url) -> Result<Self, KeyStoreError> {
        Self::with_refresh_cooldown(jwks_url, DEFAULT_REFRESH_COOLDOWN).await
    }

    /// Builds a keystore with an explicit on-demand refresh cooldown.
    ///
    /// # Errors
    ///
    /// As [`KeyStore::new`].
    pub async fn with_refresh_cooldown(jwks_url: Url, refresh_cooldown: Duration) -> Result<Self, KeyStoreError> {
        // No redirects: the address in the configuration is the one the operator chose to trust. A
        // redirect hands the key set to a host nobody configured.
        let jwks_url = Arc::new(jwks_url);
        let http_client = match Client::builder().timeout(FETCH_TIMEOUT).redirect(Policy::none()).build() {
            Ok(client) => client,
            Err(source) => return Err(KeyStoreError::Client { url: jwks_url, source }),
        };

        let store = Self {
            inner: Arc::new(KeyStoreInner {
                keys: ArcSwap::from_pointee(HashMap::new()),
                jwks_url,
                http_client,
                gate: Arc::new(RefreshGate::new(refresh_cooldown)),
            }),
        };

        // Through `refresh`, so the cooldown is armed from the moment the store exists and after every
        // scheduled refresh, not only after an on-demand one.
        store.refresh().await?;

        Ok(store)
    }

    /// Fetches the key set and replaces the cache with it.
    ///
    /// Not subject to the on-demand cooldown, and it starts that cooldown when it ends. If a fetch
    /// is already running this waits for it, for a bounded time, instead of starting a second one,
    /// and returns `Ok` whatever that fetch's outcome: the fetch that owns the work reports it.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyStoreError`] if the endpoint could not be read or held no usable key. The
    /// cached key set is left exactly as it was.
    pub async fn refresh(&self) -> Result<(), KeyStoreError> {
        match self.inner.gate.claim_scheduled() {
            Claim::Fetch(guard) => {
                let outcome = self.fetch_and_replace().await;

                // Released whether or not the fetch succeeded, which starts the cooldown either
                // way. A failing endpoint must not be a way to bypass it, which is precisely the
                // case a flood of unknown key ids creates.
                drop(guard);

                outcome
            }
            Claim::Join(waiter) => {
                // Another fetch is already doing this refresh's work and reports its own outcome,
                // so there is nothing for this call to add or to fail with.
                debug!("a JWKS fetch is already running, waiting for it instead of starting another");
                waiter.until_finished(IN_FLIGHT_WAIT).await;

                Ok(())
            }
        }
    }

    /// The cached key with this id, if there is one.
    ///
    /// Matching is exact. There is no "try every key" fallback: trying keys until one verifies
    /// means a token that names a key it was not signed with can still be accepted, which removes
    /// the only cheap way to bind a token to one specific key.
    #[must_use]
    pub fn get(&self, kid: &KeyId) -> Option<DecodingKey> {
        self.inner.keys.load().get(kid).cloned()
    }

    /// Whether any key is cached, for a readiness probe.
    #[must_use]
    pub fn has_keys(&self) -> bool {
        !self.inner.keys.load().is_empty()
    }

    /// The cached key with this id, refreshing once if it is not cached and the cooldown allows.
    ///
    /// A failed refresh is logged, not returned: the answer to "is this key known?" is still the
    /// cached key set, so a provider outage leaves already-known key ids working and unknown ones
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::UnknownKeyId`] if no cached key carries the id, whether because
    /// the refresh failed, because the cooldown suppressed it, or because the id is simply not one
    /// the identity provider publishes.
    pub async fn get_or_refresh(&self, kid: KeyId) -> Result<DecodingKey, KeyStoreError> {
        if let Some(key) = self.get(&kid) {
            return Ok(key);
        }

        match self.inner.gate.claim_on_demand() {
            Some(Claim::Fetch(guard)) => {
                debug!(kid = %kid, "key id is not cached, refreshing the JWKS");

                if let Err(error) = self.fetch_and_replace().await {
                    error!(%error, "JWKS refresh failed, keeping the cached key set");
                }

                drop(guard);
            }
            Some(Claim::Join(waiter)) => {
                // The concurrent requests behind one unknown key id wait for the one fetch in
                // flight and then re-read the cache, rather than each starting a fetch of their
                // own. The wait is bounded, so a provider that hangs costs each of them
                // `IN_FLIGHT_WAIT` and no more.
                debug!(kid = %kid, "key id is not cached, waiting for the JWKS fetch already running");
                waiter.until_finished(IN_FLIGHT_WAIT).await;
            }
            None => debug!(kid = %kid, "key id is not cached and the refresh cooldown has not elapsed"),
        }

        match self.get(&kid) {
            Some(key) => Ok(key),
            None => Err(KeyStoreError::UnknownKeyId { kid }),
        }
    }

    /// Spawns a task that refreshes the key set every `period`.
    ///
    /// The task runs until it is aborted. A failed refresh is logged and the next tick tries
    /// again, because the cached key set is still serving requests in the meantime.
    #[must_use]
    pub fn start_refresh_task(self, period: Duration) -> JoinHandle<()> {
        spawn(async move {
            let mut ticker = interval(period);

            // The first tick of a tokio interval completes immediately, and the key set was just
            // fetched by the constructor.
            ticker.tick().await;

            loop {
                ticker.tick().await;

                if let Err(error) = self.refresh().await {
                    error!(%error, "scheduled JWKS refresh failed, keeping the cached key set");
                }
            }
        })
    }

    /// Fetches, reads and installs a new key set, or leaves the cache untouched.
    async fn fetch_and_replace(&self) -> Result<(), KeyStoreError> {
        let document = self.fetch().await?;
        let keys = document.usable_keys(&self.inner.jwks_url)?;

        info!(count = keys.len(), url = %self.inner.jwks_url, "loaded JWKS signing keys");

        // One store. Every reader sees either the whole previous key set or the whole new one.
        self.inner.keys.store(Arc::new(keys));

        Ok(())
    }

    /// Reads the JWKS document, refusing a body over [`MAX_JWKS_BYTES`].
    async fn fetch(&self) -> Result<JwksDocument, KeyStoreError> {
        let url = &self.inner.jwks_url;

        debug!(url = %url, "fetching the JWKS");

        let response = self
            .inner
            .http_client
            .get(url.as_str())
            .send()
            .await
            .map_err(|source| KeyStoreError::Fetch { url: Arc::clone(url), source })?;

        let status = response.status();
        if !status.is_success() {
            return Err(KeyStoreError::Status {
                url: Arc::clone(url),
                status: status.as_u16(),
            });
        }

        // The declared `Content-Length` is not consulted: what is enforced is what arrives.
        let body = read(response, MAX_JWKS_BYTES).await.map_err(|error| match error {
            FetchedBodyError::TooLarge { limit } => KeyStoreError::TooLarge { url: Arc::clone(url), limit },
            FetchedBodyError::Unreadable(source) => KeyStoreError::Fetch { url: Arc::clone(url), source },
        })?;

        from_slice(&body).map_err(|source| KeyStoreError::Parse { url: Arc::clone(url), source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_log_capture::captured;
    use pretty_assertions::assert_eq;
    use std::time::Instant;
    use tokio::time::sleep;
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{method, path},
    };

    /// A modulus and exponent that base64-decode, which is all `from_rsa_components` checks.
    const MODULUS: &str = "vYM0rC14e5a-vM_1gX-5jQ";
    const EXPONENT: &str = "AQAB";

    fn jwks_with(kids: &[&str]) -> String {
        let entries: Vec<String> = kids
            .iter()
            .map(|kid| format!(r#"{{ "kid": "{kid}", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "{MODULUS}", "e": "{EXPONENT}" }}"#))
            .collect();

        format!(r#"{{ "keys": [{}] }}"#, entries.join(","))
    }

    /// Serves `bodies` in order, then repeats the last one for every further request.
    async fn serve(bodies: &[(u16, String)]) -> MockServer {
        // Cloned because the delayed server owns its steps and the caller keeps its bodies.
        let steps: Vec<(u16, String, Duration)> = bodies.iter().map(|(status, body)| (*status, body.clone(), Duration::ZERO)).collect();

        serve_delayed(&steps).await
    }

    /// As [`serve`], with each answer held back for its own delay.
    async fn serve_delayed(steps: &[(u16, String, Duration)]) -> MockServer {
        let server = MockServer::start().await;

        let Some((last_status, last_body, last_delay)) = steps.last() else {
            return server;
        };

        for (status, body, delay) in &steps[..steps.len() - 1] {
            Mock::given(method("GET"))
                .and(path("/certs"))
                .respond_with(ResponseTemplate::new(*status).set_body_string(body.as_str()).set_delay(*delay))
                .up_to_n_times(1)
                .mount(&server)
                .await;
        }

        Mock::given(method("GET"))
            .and(path("/certs"))
            .respond_with(ResponseTemplate::new(*last_status).set_body_string(last_body.as_str()).set_delay(*last_delay))
            .mount(&server)
            .await;

        server
    }

    fn certs_url(server: &MockServer) -> Url {
        Url::parse(&format!("{}/certs", server.uri())).expect("the mock server address is a URL")
    }

    async fn request_count(server: &MockServer) -> usize {
        server.received_requests().await.expect("wiremock records requests").len()
    }

    #[tokio::test]
    async fn a_successful_fetch_loads_every_signing_key_in_the_document() {
        let server = serve(&[(200, jwks_with(&["key1", "key2"]))]).await;

        let store = KeyStore::new(certs_url(&server)).await.unwrap();

        assert!(store.has_keys());
        assert!(store.get(&"key1".parse::<KeyId>().unwrap()).is_some());
        assert!(store.get(&"key2".parse::<KeyId>().unwrap()).is_some());
    }

    #[tokio::test]
    async fn a_failed_fetch_leaves_the_previously_cached_keys_intact() {
        // Fail-static. An outage at the identity provider must not invalidate the keys Libra
        // already holds, or every token in flight is rejected until the provider comes back.
        let server = serve(&[(200, jwks_with(&["key1"])), (500, String::new())]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        let outcome = store.refresh().await;

        assert!(matches!(outcome, Err(KeyStoreError::Status { status: 500, .. })));
        assert!(
            store.get(&"key1".parse::<KeyId>().unwrap()).is_some(),
            "a failed refresh must not empty the cache"
        );
        assert!(store.has_keys());

        // And the outage is not an opening either: an id nobody published is still refused.
        assert!(matches!(
            store.get_or_refresh("never-published".parse::<KeyId>().unwrap()).await,
            Err(KeyStoreError::UnknownKeyId { .. })
        ));
    }

    #[tokio::test]
    async fn a_body_over_the_size_cap_is_refused_and_leaves_the_cache_intact() {
        // The body is buffered in full on every refresh, so without a cap the endpoint chooses how
        // much memory Libra allocates.
        let oversized = format!(r#"{{ "padding": "{}", "keys": [] }}"#, "p".repeat(MAX_JWKS_BYTES + 1));
        let server = serve(&[(200, jwks_with(&["key1"])), (200, oversized)]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        let outcome = store.refresh().await;

        assert!(matches!(outcome, Err(KeyStoreError::TooLarge { limit: MAX_JWKS_BYTES, .. })), "got {outcome:?}");
        assert!(store.get(&"key1".parse::<KeyId>().unwrap()).is_some());
    }

    #[tokio::test]
    async fn an_oversized_body_on_the_first_fetch_stops_startup() {
        let oversized = format!(r#"{{ "padding": "{}", "keys": [] }}"#, "p".repeat(MAX_JWKS_BYTES + 1));
        let server = serve(&[(200, oversized)]).await;

        assert!(matches!(KeyStore::new(certs_url(&server)).await, Err(KeyStoreError::TooLarge { .. })));
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed_to_another_key_set() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/certs"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", format!("{}/elsewhere", server.uri())))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200).set_body_string(jwks_with(&["attacker"])))
            .mount(&server)
            .await;

        let outcome = KeyStore::new(certs_url(&server)).await;

        assert!(outcome.is_err(), "a redirect must stop startup rather than deliver another host's keys");
        let requested: Vec<String> = server
            .received_requests()
            .await
            .expect("wiremock records requests")
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(requested, ["/certs"], "the redirect target must never be requested");
    }

    #[tokio::test]
    async fn an_unknown_key_id_is_rejected_rather_than_matched_against_some_other_key() {
        // Strict `kid` matching. Trying every cached key until one verifies would accept a token
        // that names a key it was not signed with.
        let server = serve(&[(200, jwks_with(&["key1"]))]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        assert!(store.get(&"key1".parse::<KeyId>().unwrap()).is_some());
        assert!(store.get(&"key2".parse::<KeyId>().unwrap()).is_none());
        assert!(
            matches!(store.get_or_refresh("key2".parse::<KeyId>().unwrap()).await, Err(KeyStoreError::UnknownKeyId { kid }) if kid == "key2".parse::<KeyId>().unwrap())
        );
    }

    #[tokio::test]
    async fn an_unknown_key_id_triggers_one_refresh_once_the_cooldown_has_elapsed() {
        let server = serve(&[(200, jwks_with(&["key1"])), (200, jwks_with(&["key1", "key2"]))]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        assert!(
            store.get_or_refresh("key2".parse::<KeyId>().unwrap()).await.is_ok(),
            "a rotated-in key must be picked up on demand"
        );
        assert_eq!(request_count(&server).await, 2);
    }

    #[tokio::test]
    async fn the_cooldown_is_armed_by_the_constructor_so_it_limits_refreshes_from_the_first_request() {
        // The constructor and a scheduled refresh arm the cooldown as well as `get_or_refresh`; otherwise
        // a burst of tokens carrying random key ids turns into one outbound request each, with Libra as
        // the amplifier.
        let server = serve(&[(200, jwks_with(&["key1"]))]).await;
        let store = KeyStore::new(certs_url(&server)).await.unwrap();

        for attempt in 0..5 {
            assert!(store.get_or_refresh(format!("random-{attempt}").parse::<KeyId>().unwrap()).await.is_err());
        }

        assert_eq!(request_count(&server).await, 1, "only the constructor's fetch should have been made");
    }

    #[tokio::test]
    async fn a_scheduled_refresh_rearms_the_cooldown() {
        // `refresh` is what the background task calls, and it too has to record the attempt.
        let server = serve(&[(200, jwks_with(&["key1"]))]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::from_secs(30)).await.unwrap();

        store.refresh().await.unwrap();
        assert_eq!(request_count(&server).await, 2);

        assert!(store.get_or_refresh("unknown".parse::<KeyId>().unwrap()).await.is_err());
        assert_eq!(request_count(&server).await, 2, "the scheduled refresh should have rearmed the cooldown");
    }

    #[tokio::test]
    async fn concurrent_requests_for_an_unknown_key_id_cost_one_refresh_between_them() {
        // The cooldown is read and written under one lock; otherwise every concurrent request would pass
        // the check before any of them recorded the attempt, and all of them would fetch.
        let cooldown = Duration::from_millis(50);
        let server = serve(&[(200, jwks_with(&["key1"]))]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), cooldown).await.unwrap();

        sleep(cooldown * 2).await;

        let mut waiting = Vec::new();
        for _ in 0..8 {
            // Each spawned task owns a handle onto the shared store.
            let store = store.clone();
            waiting.push(spawn(async move { store.get_or_refresh("unknown".parse::<KeyId>().unwrap()).await.is_err() }));
        }

        for handle in waiting {
            assert!(handle.await.unwrap(), "an unknown key id must stay unknown");
        }

        assert_eq!(request_count(&server).await, 2, "the constructor's fetch plus one coalesced refresh");
    }

    #[tokio::test]
    async fn a_refresh_replaces_the_key_set_rather_than_merging_into_it() {
        // Upserting the new keys and then pruning would leave a window in which a withdrawn key and its
        // replacement were both live.
        let server = serve(&[(200, jwks_with(&["retired", "current"])), (200, jwks_with(&["current"]))]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        assert!(store.get(&"retired".parse::<KeyId>().unwrap()).is_some());

        store.refresh().await.unwrap();

        assert!(
            store.get(&"retired".parse::<KeyId>().unwrap()).is_none(),
            "a key the provider withdrew must stop verifying"
        );
        assert!(store.get(&"current".parse::<KeyId>().unwrap()).is_some());
    }

    #[tokio::test]
    async fn a_key_published_for_encryption_is_not_used_to_verify_signatures() {
        let document = format!(
            r#"{{ "keys": [
                {{ "kid": "enc-key", "kty": "RSA", "use": "enc", "n": "{MODULUS}", "e": "{EXPONENT}" }},
                {{ "kid": "sig-key", "kty": "RSA", "use": "sig", "n": "{MODULUS}", "e": "{EXPONENT}" }}
            ] }}"#
        );
        let server = serve(&[(200, document)]).await;
        let store = KeyStore::new(certs_url(&server)).await.unwrap();

        assert!(
            store.get(&"enc-key".parse::<KeyId>().unwrap()).is_none(),
            "its publisher excluded it from signature use"
        );
        assert!(store.get(&"sig-key".parse::<KeyId>().unwrap()).is_some());
    }

    #[tokio::test]
    async fn one_unreadable_entry_is_skipped_while_the_keys_beside_it_still_load() {
        let document = format!(
            r#"{{ "keys": [
                {{ "kid": "broken", "kty": "RSA", "use": "sig", "n": "not base64!!", "e": "{EXPONENT}" }},
                {{ "kid": "no-components", "kty": "EC", "use": "sig", "crv": "P-256", "x": "abc", "y": "def" }},
                {{ "kty": "RSA", "use": "sig", "n": "{MODULUS}", "e": "{EXPONENT}" }},
                {{ "kid": "good", "kty": "RSA", "use": "sig", "n": "{MODULUS}", "e": "{EXPONENT}" }}
            ] }}"#
        );
        let server = serve(&[(200, document)]).await;
        let store = KeyStore::new(certs_url(&server)).await.unwrap();

        assert!(
            store.get(&"good".parse::<KeyId>().unwrap()).is_some(),
            "a cosmetic provider bug must not be a total outage"
        );
        assert!(store.get(&"broken".parse::<KeyId>().unwrap()).is_none());
        assert!(store.get(&"no-components".parse::<KeyId>().unwrap()).is_none());
    }

    #[tokio::test]
    async fn an_entry_whose_key_id_could_forge_a_log_line_is_skipped_without_being_logged() {
        let document = format!(
            r#"{{ "keys": [
                {{ "kid": "forged\nlevel=ERROR", "kty": "RSA", "use": "sig", "n": "{MODULUS}", "e": "{EXPONENT}" }},
                {{ "kid": "good", "kty": "RSA", "use": "sig", "n": "{MODULUS}", "e": "{EXPONENT}" }}
            ] }}"#
        );
        let server = serve(&[(200, document)]).await;

        let (store, records) = captured(KeyStore::new(certs_url(&server))).await;

        assert!(store.unwrap().get(&"good".parse::<KeyId>().unwrap()).is_some());
        for record in &records {
            assert!(!record.mentions("forged"), "{record:?}");
        }
    }

    #[tokio::test]
    async fn a_document_with_nothing_usable_in_it_is_an_error_rather_than_an_empty_cache() {
        let server = serve(&[(200, r#"{ "keys": [] }"#.to_owned())]).await;

        assert!(matches!(KeyStore::new(certs_url(&server)).await, Err(KeyStoreError::NoUsableKey { .. })));
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_jwks_document_is_an_error() {
        let server = serve(&[(200, "not json at all".to_owned())]).await;

        assert!(matches!(KeyStore::new(certs_url(&server)).await, Err(KeyStoreError::Parse { .. })));
    }

    #[tokio::test]
    async fn a_failing_endpoint_stops_startup_rather_than_starting_with_no_keys() {
        let server = serve(&[(500, String::new())]).await;

        assert!(matches!(
            KeyStore::new(certs_url(&server)).await,
            Err(KeyStoreError::Status { status: 500, .. })
        ));
    }

    /// Long enough to outlast every bound in these tests, short enough to finish with the server.
    const HUNG: Duration = Duration::from_secs(6);

    /// How far past a bound a test lets an answer drift before calling it unbounded.
    const MARGIN: Duration = Duration::from_millis(1500);

    #[tokio::test]
    async fn a_hung_identity_provider_does_not_hold_a_waiter_past_the_bound() {
        // The lock is not held across the fetch; otherwise, while the provider hung, a request with an
        // unknown key id would wait out the fetch, up to its ten second timeout.
        let server = serve_delayed(&[(200, jwks_with(&["key1"]), Duration::ZERO), (200, jwks_with(&["key1"]), HUNG)]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        let scheduled = {
            // The spawned refresh owns a handle onto the shared store.
            let store = store.clone();
            spawn(async move { store.refresh().await })
        };
        sleep(Duration::from_millis(200)).await;

        let started = Instant::now();
        let outcome = store.get_or_refresh("unknown".parse::<KeyId>().unwrap()).await;
        let waited = started.elapsed();

        assert!(matches!(outcome, Err(KeyStoreError::UnknownKeyId { .. })));
        assert!(waited >= IN_FLIGHT_WAIT, "it should have waited for the fetch in flight, waited {waited:?}");
        assert!(waited < IN_FLIGHT_WAIT + MARGIN, "it must not wait out the fetch, waited {waited:?}");
        assert_eq!(request_count(&server).await, 2, "the waiter must not start a fetch of its own");

        scheduled.abort();
    }

    #[tokio::test]
    async fn a_known_key_id_is_answered_at_once_while_a_refresh_hangs() {
        let server = serve_delayed(&[(200, jwks_with(&["key1"]), Duration::ZERO), (200, jwks_with(&["key1"]), HUNG)]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        let scheduled = {
            // The spawned refresh owns a handle onto the shared store.
            let store = store.clone();
            spawn(async move { store.refresh().await })
        };
        sleep(Duration::from_millis(200)).await;

        let started = Instant::now();
        assert!(store.get_or_refresh("key1".parse::<KeyId>().unwrap()).await.is_ok());
        assert!(started.elapsed() < Duration::from_millis(500), "a cached key never touches the refresh");

        scheduled.abort();
    }

    #[tokio::test]
    async fn a_rotation_serves_many_concurrent_waiters_from_one_fetch() {
        let cooldown = Duration::from_millis(50);
        let server = serve_delayed(&[
            (200, jwks_with(&["key1"]), Duration::ZERO),
            (200, jwks_with(&["key1", "key2"]), Duration::from_millis(300)),
        ])
        .await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), cooldown).await.unwrap();

        sleep(cooldown * 2).await;

        let mut waiting = Vec::new();
        for _ in 0..16 {
            // Each spawned task owns a handle onto the shared store.
            let store = store.clone();
            waiting.push(spawn(async move { store.get_or_refresh("key2".parse::<KeyId>().unwrap()).await.is_ok() }));
        }

        for handle in waiting {
            assert!(handle.await.unwrap(), "every request carrying the rotated-in key id must be served");
        }

        assert_eq!(request_count(&server).await, 2, "the constructor's fetch plus exactly one for all sixteen");
    }

    #[tokio::test]
    async fn a_flood_of_unknown_key_ids_costs_one_fetch_per_cooldown() {
        let cooldown = Duration::from_millis(400);
        let server = serve_delayed(&[
            (200, jwks_with(&["key1"]), Duration::ZERO),
            (200, jwks_with(&["key1"]), Duration::from_millis(100)),
        ])
        .await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), cooldown).await.unwrap();

        sleep(cooldown + Duration::from_millis(50)).await;
        flood(&store, 20).await;
        assert_eq!(request_count(&server).await, 2, "the first wave costs one fetch");

        flood(&store, 20).await;
        assert_eq!(request_count(&server).await, 2, "a second wave inside the cooldown costs none");

        sleep(cooldown + Duration::from_millis(50)).await;
        flood(&store, 20).await;
        assert_eq!(request_count(&server).await, 3, "and one more once the cooldown has passed");
    }

    /// `count` concurrent requests, each carrying a key id nobody publishes.
    async fn flood(store: &KeyStore, count: usize) {
        let mut waiting = Vec::new();
        for attempt in 0..count {
            // Each spawned task owns a handle onto the shared store.
            let store = store.clone();
            waiting.push(spawn(async move {
                store.get_or_refresh(format!("random-{attempt}").parse::<KeyId>().unwrap()).await.is_err()
            }));
        }

        for handle in waiting {
            assert!(handle.await.unwrap(), "an unknown key id must stay unknown");
        }
    }

    #[tokio::test]
    async fn a_failed_fetch_still_starts_the_cooldown() {
        // A failing endpoint must not be a way past the cooldown, which is exactly what a flood of
        // unknown key ids against a provider that is down would otherwise be.
        let cooldown = Duration::from_millis(100);
        let server = serve(&[(200, jwks_with(&["key1"])), (500, String::new())]).await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), cooldown).await.unwrap();

        sleep(cooldown + Duration::from_millis(50)).await;
        assert!(store.get_or_refresh("unknown-1".parse::<KeyId>().unwrap()).await.is_err());
        assert_eq!(request_count(&server).await, 2, "the first unknown key id fetched, and the fetch failed");

        assert!(store.get_or_refresh("unknown-2".parse::<KeyId>().unwrap()).await.is_err());
        assert_eq!(request_count(&server).await, 2, "the failure started the cooldown, so no second fetch");
        assert!(store.get(&"key1".parse::<KeyId>().unwrap()).is_some(), "and the cache is untouched");
    }

    #[tokio::test]
    async fn a_cancelled_fetch_does_not_wedge_later_refreshes() {
        // A request dropped mid-fetch, for instance because its client went away, drops the claim
        // with it. The gate must come free, or no key set would ever be fetched again.
        let server = serve_delayed(&[
            (200, jwks_with(&["key1"]), Duration::ZERO),
            (200, jwks_with(&["key1"]), HUNG),
            (200, jwks_with(&["key1", "key2"]), Duration::ZERO),
        ])
        .await;
        let store = KeyStore::with_refresh_cooldown(certs_url(&server), Duration::ZERO).await.unwrap();

        let cancelled = {
            // The spawned refresh owns a handle onto the shared store.
            let store = store.clone();
            spawn(async move { store.refresh().await })
        };
        sleep(Duration::from_millis(200)).await;
        cancelled.abort();
        sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        store.refresh().await.unwrap();

        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "the next refresh must not wait on the cancelled one"
        );
        assert!(store.get(&"key2".parse::<KeyId>().unwrap()).is_some());
    }
}
