//! Liveness and readiness.
//!
//! The two answer different questions and are wired to different things. Liveness says the process
//! is running and should not be restarted. Readiness says the process can serve a request, which
//! for an authentication proxy means it can reach the broker and, when it accepts JWTs, holds the
//! keys to verify them: without either, every request would fail, and a load balancer should stop
//! sending them.

use axum::{Router, extract::State, http::StatusCode, routing::get};
use libra_identity_jwks::KeyStore;
use reqwest::Client;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use tracing::{debug, warn};
use url::Url;

/// How long a readiness check waits on the broker.
///
/// Short on purpose: readiness is polled, and a probe that outlives its own interval stacks up.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a broker answer is reused.
///
/// The route is unauthenticated and unthrottled by design, so without this every request to it
/// would become a request to the broker with a five second timeout: an anonymous flood of probes
/// would be a flood against the broker. Short enough that an orchestrator still sees a broker
/// outage within a couple of probe intervals.
const BROKER_ANSWER_TTL: Duration = Duration::from_secs(2);

/// What the probes need in order to answer.
#[derive(Clone)]
pub struct HealthState {
    /// The JWT signing keys, absent when the deployment accepts no JWT.
    keystore: Option<KeyStore>,
    broker: Url,
    client: Client,
    // Held across the broker request, so a burst of probes waits for one check and then shares its
    // answer rather than each making its own.
    broker_answer: Arc<Mutex<Option<(Instant, StatusCode)>>>,
    answer_ttl: Duration,
}

impl HealthState {
    /// Builds the probe state.
    ///
    /// # Errors
    ///
    /// Returns the client-construction error if an HTTP client cannot be built, which is a startup
    /// failure rather than something to discover on the first probe.
    pub fn new(keystore: Option<KeyStore>, broker: Url) -> Result<Self, reqwest::Error> {
        let client = Client::builder().timeout(PROBE_TIMEOUT).build()?;

        Ok(Self {
            keystore,
            broker,
            client,
            broker_answer: Arc::new(Mutex::new(None)),
            answer_ttl: BROKER_ANSWER_TTL,
        })
    }
}

/// The probe routes.
///
/// Deliberately unauthenticated: a probe that needed a token would need an identity provider to be
/// reachable in order to report that the identity provider is not reachable. Nothing here reveals
/// anything about the deployment beyond whether it is working.
pub fn router(state: HealthState) -> Router {
    Router::new()
        .route("/ngsi-ld/auth/health", get(live))
        .route("/ngsi-ld/auth/ready", get(ready))
        .with_state(state)
}

/// Whether the process is running.
///
/// Always yes. If this can be answered at all, it is true, and a liveness probe that consults a
/// dependency is a liveness probe that restarts a healthy process when the dependency blinks.
async fn live() -> StatusCode {
    StatusCode::OK
}

/// Whether the process can serve a request.
async fn ready(State(state): State<HealthState>) -> StatusCode {
    if state.keystore.as_ref().is_some_and(|keystore| !keystore.has_keys()) {
        warn!("not ready: no signing keys are loaded, so every token would be refused");

        return StatusCode::SERVICE_UNAVAILABLE;
    }

    let mut cached = state.broker_answer.lock().await;
    if let Some((checked, answer)) = *cached
        && checked.elapsed() < state.answer_ttl
    {
        return answer;
    }

    let answer = probe_broker(&state).await;
    *cached = Some((Instant::now(), answer));

    answer
}

/// Asks the broker whether it is answering.
async fn probe_broker(state: &HealthState) -> StatusCode {
    // `/types` is the cheapest NGSI-LD read that proves the broker is answering. A 404 counts:
    // an empty broker has no types and says so, which is a broker that is working.
    let probe = format!("{}/ngsi-ld/v1/types", state.broker.as_str().trim_end_matches('/'));

    match state.client.get(&probe).send().await {
        Ok(response) if response.status().is_success() || response.status() == StatusCode::NOT_FOUND => {
            debug!(status = %response.status(), "ready");

            StatusCode::OK
        }
        Ok(response) => {
            warn!(status = %response.status(), "not ready: the broker answered with an error");

            StatusCode::SERVICE_UNAVAILABLE
        }
        Err(error) => {
            warn!(error = %error, "not ready: the broker could not be reached");

            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use pretty_assertions::assert_eq;
    use std::future::Future;
    use tokio::time::sleep;
    use tower::ServiceExt;
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{method, path},
    };

    fn url(text: &str) -> Url {
        Url::parse(text).expect("the test address is a URL")
    }

    async fn keystore(server: &MockServer) -> KeyStore {
        Mock::given(method("GET"))
            .and(path("/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": "test",
                    "kty": "RSA",
                    "use": "sig",
                    "n": "sXchqZ1nJ9JLGrqLHR7t3d1PbY0kEZLTvhjxs1kA3fWzhXbrPd2SGe1bDHRCkGuA2j5jw5vLTvGDPFVRAYr8jw1oOfLb9xTk5vJoxKVKF8y6PtRcvKtGSPRCw8PFRi6Vk2b7cQVwqZ5s3jZzWs1t6tE7oB0iZeqbf0eWuT-Kk9E",
                    "e": "AQAB"
                }]
            })))
            .mount(server)
            .await;

        KeyStore::new(url(&format!("{}/certs", server.uri()))).await.expect("the keystore should load")
    }

    async fn probe(state: HealthState, uri: &str) -> StatusCode {
        router(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap_or_else(|_| Request::new(Body::empty())))
            .await
            .map_or(StatusCode::INTERNAL_SERVER_ERROR, |response| response.status())
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_anything() {
        // A liveness probe that consulted the broker would have the orchestrator restart Libra
        // every time the broker restarted, which is the opposite of what it is for.
        let server = MockServer::start().await;
        let state = HealthState::new(Some(keystore(&server).await), url("http://127.0.0.1:1")).expect("the state should build");

        assert_eq!(probe(state, "/ngsi-ld/auth/health").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_needs_a_reachable_broker() {
        let server = MockServer::start().await;
        let keystore = keystore(&server).await;

        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/types"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let reachable = HealthState::new(Some(keystore.clone()), url(&server.uri())).expect("the state should build"); // each state owns a handle to the shared key store
        let unreachable = HealthState::new(Some(keystore), url("http://127.0.0.1:1")).expect("the state should build");

        assert_eq!(probe(reachable, "/ngsi-ld/auth/ready").await, StatusCode::OK);
        assert_eq!(probe(unreachable, "/ngsi-ld/auth/ready").await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_burst_of_probes_makes_one_request_to_the_broker() {
        let server = MockServer::start().await;
        let keystore = keystore(&server).await;

        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/types"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;

        let state = HealthState::new(Some(keystore), url(&server.uri())).expect("the state should build");
        let probes = (0..20).map(|_| probe(state.clone(), "/ngsi-ld/auth/ready")); // each concurrent probe owns a handle to the one shared state, which is what the test is about

        for status in futures_join(probes).await {
            assert_eq!(status, StatusCode::OK);
        }
        // `expect(1)` is verified when the server drops.
    }

    /// Runs the futures to completion together.
    async fn futures_join(probes: impl Iterator<Item = impl Future<Output = StatusCode> + Send + 'static>) -> Vec<StatusCode> {
        let handles: Vec<_> = probes.map(tokio::spawn).collect();
        let mut statuses = Vec::new();
        for handle in handles {
            statuses.push(handle.await.expect("a probe task"));
        }

        statuses
    }

    #[tokio::test]
    async fn the_broker_is_asked_again_once_the_answer_is_stale() {
        let server = MockServer::start().await;
        let keystore = keystore(&server).await;

        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/types"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(2)
            .mount(&server)
            .await;

        let mut state = HealthState::new(Some(keystore), url(&server.uri())).expect("the state should build");
        state.answer_ttl = Duration::from_millis(20);

        assert_eq!(probe(state.clone(), "/ngsi-ld/auth/ready").await, StatusCode::OK); // both probes must hit the same shared answer cache
        sleep(Duration::from_millis(60)).await;
        assert_eq!(probe(state, "/ngsi-ld/auth/ready").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_empty_broker_is_still_a_working_broker() {
        // A broker with no data answers `/types` with a 404. Reading that as not-ready would keep
        // a fresh deployment out of rotation until somebody wrote an entity to it.
        let server = MockServer::start().await;
        let keystore = keystore(&server).await;

        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/types"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let state = HealthState::new(Some(keystore), url(&server.uri())).expect("the state should build");

        assert_eq!(probe(state, "/ngsi-ld/auth/ready").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_broker_that_answers_with_an_error_is_not_ready() {
        let server = MockServer::start().await;
        let keystore = keystore(&server).await;

        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/types"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let state = HealthState::new(Some(keystore), url(&server.uri())).expect("the state should build");

        assert_eq!(probe(state, "/ngsi-ld/auth/ready").await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn without_jwt_authentication_readiness_depends_on_the_broker_alone() {
        // A deployment that accepts API keys only holds no signing keys, and must not be kept out of
        // rotation for lacking them.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/types"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let reachable = HealthState::new(None, url(&server.uri())).expect("the state should build");
        let unreachable = HealthState::new(None, url("http://127.0.0.1:1")).expect("the state should build");

        assert_eq!(probe(reachable, "/ngsi-ld/auth/ready").await, StatusCode::OK);
        assert_eq!(probe(unreachable, "/ngsi-ld/auth/ready").await, StatusCode::SERVICE_UNAVAILABLE);
    }
}
