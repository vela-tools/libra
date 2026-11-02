//! The client that fetches one entity from the broker.

use crate::error::PreflightError;
use http::{
    HeaderMap,
    header::{ACCEPT, LINK},
};
use jstrict::Value;
use libra_fetched_body::{FetchedBodyError, read};
use libra_json_body::strict::parse;
use libra_ngsi_ld_operation::{
    path::API_PREFIX,
    resource::{Resource, ResourceId},
};
use libra_ngsi_ld_representation::accept::MediaType;
use libra_tenant::TENANT_HEADER;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, redirect::Policy};
use std::time::Duration;
use url::Url;

/// How long a pre-flight may take before the request it guards is refused.
///
/// Short on purpose: the caller is waiting on it, and a pre-flight that hangs must become a
/// refusal quickly rather than holding a connection open for as long as the broker likes.
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(5);

/// Characters that must not survive into a path segment.
///
/// An entity identifier reaches this crate already decoded, by `libra-ngsi-ld-operation`, so it
/// has to be encoded again before it goes back into a URL. A `/` or a `?` left raw would move the
/// pre-flight to a different resource than the one the request addressed, and it is that
/// resource's type or scope the request would then be judged by. `url`'s own segment encoder is
/// not used because it drops a `.` or `..` segment rather than encoding it, which addresses the
/// collection instead of the entity.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%')
    .add(b'\\')
    .add(b'^')
    .add(b'|');

/// Which representation of an entity the pre-flight reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityEndpoint {
    /// `GET /entities/{id}` (NGSI-LD clause 5.7.1).
    Current,
    /// `GET /temporal/entities/{id}` (NGSI-LD clause 5.7.3).
    ///
    /// A temporal request is pre-flighted against the resource it addresses, so an entity whose
    /// history outlives its current representation is still found.
    Temporal,
}

impl EntityEndpoint {
    /// The endpoint that answers for the entity a request addresses.
    #[must_use]
    pub const fn for_resource(resource: &Resource) -> Self {
        if resource.is_temporal() { Self::Temporal } else { Self::Current }
    }

    /// The collection the entity is read from, and the query that bounds the answer.
    ///
    /// The read carries no `local=true` (NGSI-LD clause 6.3.18), because the request it vouches for
    /// carries none: a distributing broker forwards a write to every registered source whose
    /// registration matches (clause 4.3.6), so a pre-flight answered from the broker's own store
    /// alone would call an entity absent, or of an allowed type, that a source holds under a
    /// forbidden one, and the write would reach it. Asking as widely as the write reaches costs a
    /// fan-out per pre-flight, and is the only answer that describes what the write will change. It
    /// also ties the pre-flight to every registered source: Scorpio forwards a retrieval by
    /// identifier to each source registered in the tenant that can retrieve, whatever type it
    /// registers, so one unreachable source fails the pre-flight, and the request is refused rather
    /// than judged on a partial answer.
    /// `lastN=1` bounds a temporal answer to one instance per attribute, since only the entity's
    /// system members are being read.
    const fn address(self) -> ResourceAddress {
        match self {
            Self::Current => ResourceAddress {
                collection: "/entities",
                query: None,
            },
            Self::Temporal => ResourceAddress {
                collection: "/temporal/entities",
                query: Some("lastN=1"),
            },
        }
    }
}

/// Where under the API root a pre-flighted resource is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourceAddress {
    /// The collection path the identifier is appended to.
    collection: &'static str,
    /// The query string the read carries, if any.
    query: Option<&'static str>,
}

/// `GET /csourceRegistrations/{id}` (NGSI-LD clause 5.9.3).
const REGISTRATION_ADDRESS: ResourceAddress = ResourceAddress {
    collection: "/csourceRegistrations",
    query: None,
};

/// Fetches entities from the broker so a layer can judge a by-id request against them.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// One client, held for the life of the layer, rather than one per request.
    client: Client,
    broker_url: Url,
    max_body_bytes: usize,
}

impl Preflight {
    /// Builds the pre-flight client.
    ///
    /// # Errors
    ///
    /// Returns [`PreflightError::Client`] if the HTTP client cannot be built. Reported at
    /// construction rather than on the first request, so a deployment that cannot pre-flight finds
    /// out at startup.
    pub fn new(broker_url: Url, max_body_bytes: usize) -> Result<Preflight, PreflightError> {
        // No redirect is followed: the pre-flight reads the entity at the address the request
        // names, and a broker answer that points elsewhere is a refusal, not a second address to
        // judge the request by.
        let client = Client::builder()
            .timeout(PREFLIGHT_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .map_err(|error| PreflightError::Client { reason: error.to_string() })?;

        Ok(Preflight {
            client,
            broker_url,
            max_body_bytes,
        })
    }

    /// Fetches one entity, whole.
    ///
    /// The pre-flight states its own `Accept` rather than inheriting the broker's default, because
    /// the answer is read as a normalized entity: `type` and `scope` members of the document, not
    /// of a `GeoJSON` `properties` container. A broker configured to default to
    /// `application/geo+json` would send something else, and the reading would be wrong rather
    /// than absent.
    ///
    /// `headers` are the ones the request arrived with. Two of them are carried across, and each
    /// one changes the answer:
    ///
    /// * `NGSILD-Tenant` decides which data set the entity is looked up in. Without it the
    ///   pre-flight would read the default tenant and judge the request against another entity.
    /// * `Link` carries the request's `@context`, so the names in the answer are compacted the way
    ///   the request's own names are written, which is what makes the two comparable.
    ///
    /// Nothing else is forwarded. `Authorization` is not: the caller's credential stops at Libra,
    /// and the authentication layer has removed it before any pre-flight runs; it is left out here
    /// as well, so no wiring order can put it back. The identity headers Libra adds are not either, because
    /// they are added below the enforcement layers and are the proxy's statement about the caller
    /// rather than part of the question being asked.
    ///
    /// # Errors
    ///
    /// Returns a [`PreflightError`] if the URL cannot be built, the broker cannot be reached,
    /// answers with anything but success, sends more than the configured limit, or sends something
    /// that is not a JSON document, is nested past the strict parse's limit or repeats a member.
    pub async fn entity(&self, id: &ResourceId, endpoint: EntityEndpoint, headers: &HeaderMap) -> Result<Value, PreflightError> {
        self.fetch(self.url_for(endpoint.address(), id)?, headers).await
    }

    /// Fetches one context source registration, whole (NGSI-LD clause 5.9.3).
    ///
    /// An update or a delete of a registration names it by identifier alone, so what it registers
    /// and in which scope is read from the broker first, exactly as it is for an entity. The same
    /// headers are carried across, for the same reasons as [`Preflight::entity`].
    ///
    /// # Errors
    ///
    /// As [`Preflight::entity`].
    pub async fn registration(&self, id: &ResourceId, headers: &HeaderMap) -> Result<Value, PreflightError> {
        self.fetch(self.url_for(REGISTRATION_ADDRESS, id)?, headers).await
    }

    /// Reads one JSON document from the broker.
    async fn fetch(&self, url: Url, headers: &HeaderMap) -> Result<Value, PreflightError> {
        let mut pending = self.client.get(url).header(ACCEPT, MediaType::JsonLd.as_str());

        for name in [TENANT_HEADER, LINK] {
            if let Some(value) = headers.get(&name) {
                pending = pending.header(name, value);
            }
        }

        let response = pending
            .send()
            .await
            .map_err(|error| PreflightError::Unreachable { reason: error.to_string() })?;

        let status = response.status();
        if !status.is_success() {
            return Err(PreflightError::Status { status });
        }

        let limit = u64::try_from(self.max_body_bytes).unwrap_or(u64::MAX);
        if response.content_length().is_some_and(|length| length > limit) {
            return Err(PreflightError::TooLarge);
        }

        // Read under the cap, chunk by chunk: a broker that understates `Content-Length`, or sends
        // none at all, must not be able to choose how much memory Libra allocates.
        let bytes = read(response, self.max_body_bytes).await.map_err(|error| match error {
            FetchedBodyError::TooLarge { .. } => PreflightError::TooLarge,
            FetchedBodyError::Unreadable(error) => PreflightError::Unreadable { reason: error.to_string() },
        })?;

        // The strict parse, because a document repeating `type` or `scope` would be judged by one
        // occurrence while the broker acts on whichever it resolves to.
        Ok(parse(&bytes)?)
    }

    /// The URL the resource `id` names under `address` is fetched from.
    fn url_for(&self, address: ResourceAddress, id: &ResourceId) -> Result<Url, PreflightError> {
        let encoded = utf8_percent_encode(id.as_str(), PATH_SEGMENT);
        let broker = self.broker_url.as_str().trim_end_matches('/');
        let collection = address.collection;

        let url = match address.query {
            None => format!("{broker}{API_PREFIX}{collection}/{encoded}"),
            Some(query) => format!("{broker}{API_PREFIX}{collection}/{encoded}?{query}"),
        };

        Ok(Url::parse(&url)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::PreflightError,
        preflight::{EntityEndpoint, Preflight, REGISTRATION_ADDRESS},
    };
    use http::{
        HeaderMap,
        HeaderValue,
        StatusCode,
        header::{ACCEPT, AUTHORIZATION},
    };
    use jstrict::{Value, json};
    use libra_json_body::{error::BodyError, nesting::MAX_DEPTH};
    use libra_ngsi_ld_operation::resource::{Resource, ResourceId};
    use pretty_assertions::assert_eq;
    use url::Url;
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{header, method, path, query_param_is_missing},
    };

    fn preflight() -> Preflight {
        Preflight::new(Url::parse("http://broker.test:1026/").expect("a URL"), 1024).expect("the client should build")
    }

    fn url_for(id: &str, endpoint: EntityEndpoint) -> String {
        preflight()
            .url_for(endpoint.address(), &ResourceId::new(id))
            .expect("the URL should build")
            .into()
    }

    #[test]
    fn an_entity_is_fetched_whole_rather_than_through_an_attribute_selector() {
        // `?attrs=scope` asks for an attribute named `scope`. A scope is a system member, so a
        // broker that honours the selector answers with an entity that has none, which would
        // be read as "this entity has no scope".
        assert_eq!(
            url_for("urn:ngsi-ld:Vehicle:1", EntityEndpoint::Current),
            "http://broker.test:1026/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1"
        );
    }

    #[test]
    fn a_temporal_request_is_pre_flighted_against_the_temporal_endpoint() {
        assert_eq!(
            url_for("urn:ngsi-ld:Vehicle:1", EntityEndpoint::Temporal),
            "http://broker.test:1026/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1?lastN=1"
        );
    }

    #[test]
    fn an_identifier_cannot_move_the_pre_flight_to_another_resource() {
        // The identifier arrives decoded, so a raw separator in it would address something else
        // entirely, and the answer from that something else is what the request would then be
        // judged against.
        assert_eq!(
            url_for("urn:x/../../subscriptions", EntityEndpoint::Current),
            "http://broker.test:1026/ngsi-ld/v1/entities/urn:x%2F..%2F..%2Fsubscriptions"
        );
        assert_eq!(
            url_for("urn:x?attrs=none", EntityEndpoint::Current),
            "http://broker.test:1026/ngsi-ld/v1/entities/urn:x%3Fattrs=none"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_broker_url_does_not_double_up() {
        let trimmed = Preflight::new(Url::parse("http://broker.test:1026").expect("a URL"), 1024).expect("the client should build");
        let id = ResourceId::new("urn:e:1");

        assert_eq!(
            trimmed.url_for(EntityEndpoint::Current.address(), &id).expect("the URL should build"),
            preflight().url_for(EntityEndpoint::Current.address(), &id).expect("the URL should build")
        );
    }

    #[test]
    fn a_registration_is_read_from_the_registrations_collection_with_its_identifier_encoded() {
        assert_eq!(
            String::from(
                preflight()
                    .url_for(REGISTRATION_ADDRESS, &ResourceId::new("urn:ngsi-ld:ContextSourceRegistration:1/x"))
                    .expect("the URL should build")
            ),
            "http://broker.test:1026/ngsi-ld/v1/csourceRegistrations/urn:ngsi-ld:ContextSourceRegistration:1%2Fx"
        );
    }

    #[tokio::test]
    async fn a_registration_is_fetched_without_the_callers_credential() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/csourceRegistrations/urn:r:1"))
            .and(header(ACCEPT, "application/ld+json"))
            .respond_with(json_ld(r#"{"id":"urn:r:1","type":"ContextSourceRegistration"}"#))
            .mount(&server)
            .await;

        let preflight = Preflight::new(Url::parse(&server.uri()).expect("a URL"), 1024).expect("the client should build");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));

        assert_eq!(
            preflight.registration(&ResourceId::new("urn:r:1"), &headers).await.ok(),
            Some(json!({ "id": "urn:r:1", "type": "ContextSourceRegistration" }))
        );
        assert!(!carried_a_credential(&server).await);
    }

    /// Whether any request the broker received carried an `Authorization` header.
    async fn carried_a_credential(server: &MockServer) -> bool {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .any(|request| request.headers.contains_key(AUTHORIZATION))
    }

    #[test]
    fn a_temporal_resource_is_read_from_the_temporal_endpoint() {
        let id = ResourceId::new("urn:e:1");

        assert_eq!(
            EntityEndpoint::for_resource(&Resource::TemporalEntity {
                id: ResourceId::new("urn:e:1")
            }),
            EntityEndpoint::Temporal
        );
        assert_eq!(EntityEndpoint::for_resource(&Resource::Entity { id }), EntityEndpoint::Current);
    }

    async fn broker_answering(template: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/entities/urn:e:1"))
            .and(query_param_is_missing("local"))
            .and(header(ACCEPT, "application/ld+json"))
            .respond_with(template)
            .mount(&server)
            .await;

        server
    }

    fn json_ld(body: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_raw(body.to_owned(), "application/ld+json")
    }

    async fn fetch(server: &MockServer, limit: usize) -> Result<Value, PreflightError> {
        let preflight = Preflight::new(Url::parse(&server.uri()).expect("a URL"), limit).expect("the client should build");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));

        preflight.entity(&ResourceId::new("urn:e:1"), EntityEndpoint::Current, &headers).await
    }

    #[tokio::test]
    async fn the_entity_is_asked_for_as_widely_as_the_write_reaches_as_json_ld_and_without_the_callers_credential() {
        let server = broker_answering(json_ld(r#"{"id":"urn:e:1","type":"T"}"#)).await;

        assert_eq!(fetch(&server, 1024).await.ok(), Some(json!({ "id": "urn:e:1", "type": "T" })));
        assert!(!carried_a_credential(&server).await);
    }

    #[tokio::test]
    async fn a_non_success_answer_is_an_error_rather_than_an_empty_entity() {
        let server = broker_answering(ResponseTemplate::new(404)).await;

        assert!(matches!(fetch(&server, 1024).await, Err(PreflightError::Status { status }) if status == StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn an_answer_over_the_limit_is_an_error() {
        let server = broker_answering(json_ld(&format!(r#"{{"id":"urn:e:1","padding":"{}"}}"#, "x".repeat(64)))).await;

        assert!(matches!(fetch(&server, 16).await, Err(PreflightError::TooLarge)));
    }

    #[tokio::test]
    async fn a_redirecting_broker_is_an_error_and_the_redirect_is_not_followed() {
        let elsewhere = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(json_ld(r#"{"id":"urn:e:1","type":"Allowed"}"#))
            .mount(&elsewhere)
            .await;
        let server = broker_answering(ResponseTemplate::new(307).insert_header("location", format!("{}/entity", elsewhere.uri()))).await;

        assert!(matches!(fetch(&server, 1024).await, Err(PreflightError::Status { status }) if status == StatusCode::TEMPORARY_REDIRECT));
        assert_eq!(elsewhere.received_requests().await.map(|requests| requests.len()), Some(0));
    }

    #[tokio::test]
    async fn an_answer_that_is_not_json_is_an_error() {
        let server = broker_answering(ResponseTemplate::new(200).set_body_string("<html>")).await;

        assert!(matches!(fetch(&server, 1024).await, Err(PreflightError::NotJson { .. })));
    }

    #[tokio::test]
    async fn an_answer_nested_past_the_limit_is_an_error() {
        let server = broker_answering(json_ld(&format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1)))).await;

        assert_eq!(
            fetch(&server, 1024).await,
            Err(PreflightError::NotJson {
                source: BodyError::TooDeep { limit: MAX_DEPTH }
            })
        );
    }

    #[tokio::test]
    async fn an_answer_repeating_a_member_is_an_error_rather_than_one_reading_of_it() {
        let server = broker_answering(json_ld(r#"{"id":"urn:e:1","type":"Allowed","type":"Forbidden"}"#)).await;

        assert_eq!(
            fetch(&server, 1024).await,
            Err(PreflightError::NotJson {
                source: BodyError::RepeatedMember { member: "type".to_owned() }
            })
        );
    }
}
