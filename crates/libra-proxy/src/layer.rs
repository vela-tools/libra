//! The layer that forwards a request to the broker and streams the answer back.

use crate::{
    client::{self, UpstreamClient},
    error::ProxyError,
    forwarded,
    hop_by_hop::{self, Direction},
    query::forwardable,
    response_headers::conceal_broker,
    settings::ProxySettings,
    upstream_base::UpstreamBase,
};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    response::{IntoResponse, Response},
};
use http::{Extensions, HeaderValue, Uri, header::HOST, uri::PathAndQuery};
use libra_forwarding::{inbound_scheme::InboundScheme, trusted_proxies::TrustedProxies};
use libra_problem_details::problem::Problem;
use std::{
    borrow::Cow,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use tracing::{debug, warn};

/// Layer that forwards to the upstream broker.
///
/// The service it produces is **terminal**: a proxy is the end of the stack, so the inner service
/// it is layered over is dropped rather than called. Put this innermost, or use
/// [`ProxyLayer::service`] with `Router::fallback_service`, which says the same thing without
/// looking like a wrapper.
///
/// One layer holds one client, and every service cloned out of it shares that client's connection
/// pool.
#[derive(Clone)]
pub struct ProxyLayer {
    service: ProxyService,
}

impl ProxyLayer {
    /// Builds the layer, validating the settings once.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::InvalidUpstream`] if the upstream is not an absolute `http` or
    /// `https` URL, and [`ProxyError::Tls`] if the TLS client cannot be built. Both are startup failures:
    /// a proxy that cannot reach anything should say so before it starts accepting requests.
    pub fn new(settings: ProxySettings) -> Result<Self, ProxyError> {
        let upstream = UpstreamBase::try_from(&settings.upstream)?;
        let client = client::build(&settings)?;
        let scheme = settings.inbound_scheme;
        let trusted = settings.trusted_proxies.clone(); // the service owns a handle to the shared list, the settings are borrowed for the rest of the build
        let via = settings.via_pseudonym.into_header_value();

        Ok(Self {
            service: ProxyService {
                client,
                upstream,
                via,
                scheme,
                trusted,
            },
        })
    }

    /// The proxy as a standalone service, for use as a router fallback.
    #[must_use]
    pub fn service(&self) -> ProxyService {
        // The layer keeps its service to hand out again; the pooled client and upstream are shared handles.
        self.service.clone()
    }
}

impl<S> Layer<S> for ProxyLayer {
    type Service = ProxyService;

    fn layer(&self, _inner: S) -> Self::Service {
        // `Layer::layer` borrows the layer, which keeps producing services; the clone shares the pool.
        self.service.clone()
    }
}

/// The service produced by [`ProxyLayer`].
#[derive(Clone)]
pub struct ProxyService {
    client: UpstreamClient,
    upstream: UpstreamBase,
    via: HeaderValue,
    scheme: InboundScheme,
    trusted: TrustedProxies,
}

impl Service<Request> for ProxyService {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    /// Always ready.
    ///
    /// There is no inner service to drive: readiness belongs to the pooled client, which acquires
    /// or opens a connection inside the future returned by `call` on the clone made there.
    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // Cloned because the future is `'static`; every field is a shared handle or a small value.
        let proxy = self.clone();

        Box::pin(async move { Ok(proxy.forward(request).await) })
    }
}

impl ProxyService {
    /// Forwards one request and returns the broker's answer.
    ///
    /// Never fails: a broker that cannot be reached becomes a [`Problem::BadGateway`] response. A
    /// broker that is merely slow is not this service's problem: the timeout belongs to a layer
    /// above, which can then distinguish a timeout from a refusal.
    async fn forward(self, request: Request) -> Response {
        let (mut parts, body) = request.into_parts();

        let target = match self.target_uri(&parts.uri) {
            Ok(target) => target,
            Err(problem) => return problem.into_response(),
        };

        let version = parts.version;
        // The caller's `Host` names Libra, not the broker. Removing it lets the client write the
        // right one from the target URI; forwarding it would ask the broker to answer as Libra,
        // which for a virtual-hosted broker means answering for the wrong site entirely.
        let host = parts.headers.remove(HOST);
        let peer = peer_address(&parts.extensions);

        hop_by_hop::strip(&mut parts.headers, Direction::Request);
        forwarded::add_forwarded(&mut parts.headers, peer, &self.trusted, self.scheme, host);
        forwarded::add_via(&mut parts.headers, version, &self.via);

        parts.uri = target;

        debug!(target = %parts.uri, "forwarding to the broker");

        match self.client.request(Request::from_parts(parts, body)).await {
            Ok(response) => {
                let (mut parts, incoming) = response.into_parts();

                // Framing headers describe the broker's connection, not the one the answer travels
                // back on. Passing `Transfer-Encoding: chunked` through would describe a body the
                // server below is about to frame for itself.
                hop_by_hop::strip(&mut parts.headers, Direction::Response);
                conceal_broker(&mut parts.headers, &self.upstream);
                forwarded::add_via(&mut parts.headers, parts.version, &self.via);

                // The body is wrapped, not read. Nothing here awaits the last byte, so a large
                // response is relayed as it arrives instead of being held in memory twice.
                Response::from_parts(parts, Body::new(incoming))
            }
            Err(error) => {
                warn!(error = %error, upstream = %self.upstream, "the broker could not be reached");

                // The detail stays generic on purpose: the underlying message names the host and
                // port that failed, which is the operator's topology rather than the caller's
                // business.
                Problem::BadGateway("the upstream broker could not be reached".to_owned()).into_response()
            }
        }
    }

    /// The upstream URL for one request.
    fn target_uri(&self, uri: &Uri) -> Result<Uri, Problem> {
        // The path and query are taken exactly as they arrived, still percent-encoded, and the
        // query gets exactly two repairs. Operation classification splits a path on literal `/`
        // and decodes each segment only afterwards, so it reads `/entities%2Ffoo/bar` as two
        // segments, and anything that decoded and re-encoded here could move a separator: Libra
        // would then have enforced the rules for one resource while the broker served another. In
        // the query, servlet containers and Netty-family decoders split on a literal `;` before
        // percent-decoding, and form decoding reads a literal `+` as a space, so either byte could
        // make the broker read a request other than the one Libra parsed. Encoding exactly those
        // two bytes, and never an existing escape, makes the bytes the broker decodes equal the
        // values Libra parsed.
        let path_and_query = uri.path_and_query().map_or_else(|| uri.path(), PathAndQuery::as_str);

        let forwardable = match path_and_query.split_once('?') {
            Some((path, query)) => Cow::Owned(format!("{path}?{}", forwardable(query))),
            None => Cow::Borrowed(path_and_query),
        };

        self.upstream
            .target(&forwardable)
            .map_err(|_| Problem::BadRequest("the request target cannot be forwarded".to_owned()))
    }
}

/// The address Libra observed the request coming from.
///
/// `None` unless the server was built with `into_make_service_with_connect_info::<SocketAddr>()`.
/// Absent is reported as absent rather than guessed at: `X-Forwarded-For` is a record of what each
/// hop saw, and an invented entry is worse than a missing one.
fn peer_address(extensions: &Extensions) -> Option<IpAddr> {
    extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        Method,
        StatusCode,
        header::{ACCEPT, AUTHORIZATION, CONNECTION, VIA},
    };
    use http_body_util::BodyExt;
    use libra_via_pseudonym::ViaPseudonym;
    use pretty_assertions::assert_eq;
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        time::timeout,
    };
    use tower::ServiceExt;
    use url::Url;
    use wiremock::{
        Mock,
        MockServer,
        Request as RecordedRequest,
        ResponseTemplate,
        matchers::{any, method, path},
    };

    /// The name the proxy under test gives itself in `Via`.
    fn pseudonym() -> ViaPseudonym {
        ViaPseudonym::new("gateway-a".to_owned()).expect("a pseudonym")
    }

    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 40_000);

    fn url(text: &str) -> Url {
        Url::parse(text).expect("the test address is a URL")
    }

    fn proxy(upstream: &str) -> ProxyService {
        ProxyLayer::new(ProxySettings {
            connect_timeout: Duration::from_millis(500),
            ..ProxySettings::new(url(upstream), pseudonym())
        })
        .expect("the layer should build")
        .service()
    }

    fn request(target: &str) -> Request {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(target)
            .header(HOST, "libra.test")
            .body(Body::empty())
            .expect("a valid request");

        request.extensions_mut().insert(ConnectInfo(PEER));

        request
    }

    async fn recorded(server: &MockServer) -> RecordedRequest {
        server
            .received_requests()
            .await
            .expect("request recording is on")
            .into_iter()
            .next()
            .expect("the broker should have seen a request")
    }

    async fn broker() -> MockServer {
        let server = MockServer::start().await;

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;

        server
    }

    #[tokio::test]
    async fn an_end_to_end_header_reaches_the_broker() {
        let server = broker().await;
        let mut forwarded = request("/ngsi-ld/v1/entities");
        forwarded.headers_mut().insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        forwarded.headers_mut().insert(ACCEPT, HeaderValue::from_static("application/ld+json"));

        let response = proxy(&server.uri()).oneshot(forwarded).await.expect("the proxy answers");

        assert_eq!(response.status(), StatusCode::OK);

        let seen = recorded(&server).await;
        assert_eq!(seen.headers.get(AUTHORIZATION).unwrap(), "Bearer token");
        assert_eq!(seen.headers.get(ACCEPT).unwrap(), "application/ld+json");
    }

    #[tokio::test]
    async fn hop_by_hop_headers_do_not_reach_the_broker() {
        // Copying every header except `Host` would tell the broker about a connection it has never seen
        // and a framing it is not going to receive.
        let server = broker().await;
        let mut forwarded = request("/ngsi-ld/v1/entities");
        forwarded.headers_mut().insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        forwarded.headers_mut().insert("keep-alive", HeaderValue::from_static("timeout=5"));
        forwarded.headers_mut().insert("te", HeaderValue::from_static("trailers"));
        forwarded.headers_mut().insert("upgrade", HeaderValue::from_static("websocket"));
        forwarded.headers_mut().insert("proxy-authorization", HeaderValue::from_static("Basic Zm9v"));

        proxy(&server.uri()).oneshot(forwarded).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        for name in ["keep-alive", "te", "upgrade", "proxy-authorization", "proxy-connection"] {
            assert!(seen.headers.get(name).is_none(), "{name} must not reach the broker");
        }
    }

    #[tokio::test]
    async fn a_header_named_in_the_connection_header_does_not_reach_the_broker() {
        // RFC 9110 section 7.6.1: `Connection` lists further field names that belong to this hop.
        let server = broker().await;
        let mut forwarded = request("/ngsi-ld/v1/entities");
        forwarded.headers_mut().insert(CONNECTION, HeaderValue::from_static("X-Custom"));
        forwarded.headers_mut().insert("x-custom", HeaderValue::from_static("secret"));

        proxy(&server.uri()).oneshot(forwarded).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        assert!(seen.headers.get("x-custom").is_none(), "a header named in Connection must stop here");
    }

    #[tokio::test]
    async fn the_broker_is_told_which_proxy_the_request_came_through() {
        let server = broker().await;

        proxy(&server.uri()).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(
            seen.headers.get(VIA).unwrap(),
            "1.1 gateway-a",
            "RFC 9110 section 7.6.3 requires an intermediary to name itself"
        );
    }

    #[tokio::test]
    async fn the_answer_also_names_the_proxy_it_came_through() {
        let server = broker().await;

        let response = proxy(&server.uri()).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");

        assert_eq!(response.headers().get(VIA).unwrap(), "1.1 gateway-a");
    }

    #[tokio::test]
    async fn an_existing_via_chain_is_appended_to() {
        let server = broker().await;
        let mut forwarded = request("/ngsi-ld/v1/entities");
        forwarded.headers_mut().insert(VIA, HeaderValue::from_static("1.1 edge"));

        proxy(&server.uri()).oneshot(forwarded).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.headers.get(VIA).unwrap(), "1.1 edge, 1.1 gateway-a");
    }

    #[tokio::test]
    async fn the_observed_peer_reaches_the_broker_as_x_forwarded_for() {
        let server = broker().await;

        proxy(&server.uri()).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.headers.get("x-forwarded-for").unwrap(), "198.51.100.2");
        assert_eq!(seen.headers.get("x-forwarded-proto").unwrap(), "http");
        assert_eq!(seen.headers.get("x-forwarded-host").unwrap(), "libra.test");
    }

    fn proxy_trusting(upstream: &str, networks: &[&str]) -> ProxyService {
        ProxyLayer::new(ProxySettings {
            connect_timeout: Duration::from_millis(500),
            trusted_proxies: TrustedProxies::new(networks.iter().map(|network| network.parse().expect("a network")).collect()),
            ..ProxySettings::new(url(upstream), pseudonym())
        })
        .expect("the layer should build")
        .service()
    }

    /// A request carrying every forwarding header a caller could write to claim an origin.
    fn claiming_request() -> Request {
        let mut claiming = request("/ngsi-ld/v1/entities");
        let headers = claiming.headers_mut();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
        headers.insert("forwarded", HeaderValue::from_static("for=203.0.113.7;host=evil.example"));
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));
        claiming
    }

    #[tokio::test]
    async fn the_forwarding_claims_of_an_untrusted_caller_do_not_reach_the_broker() {
        // The peer is not in any trusted network, so what it wrote about its own origin is a claim
        // nobody vouches for. A broker that builds `Link` or `Location` from `X-Forwarded-Host`
        // would otherwise build them from the caller's words.
        let server = broker().await;

        proxy(&server.uri()).oneshot(claiming_request()).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.headers.get("x-forwarded-for").unwrap(), "198.51.100.2");
        assert_eq!(seen.headers.get("x-forwarded-proto").unwrap(), "http");
        assert_eq!(seen.headers.get("x-forwarded-host").unwrap(), "libra.test");
        assert!(seen.headers.get("forwarded").is_none());
        assert!(seen.headers.get("x-real-ip").is_none());
    }

    #[tokio::test]
    async fn the_forwarding_claims_of_a_trusted_proxy_reach_the_broker() {
        let server = broker().await;

        proxy_trusting(&server.uri(), &["198.51.100.0/24"])
            .oneshot(claiming_request())
            .await
            .expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(
            seen.headers.get("x-forwarded-for").unwrap(),
            "203.0.113.7, 198.51.100.2",
            "the chain keeps the hops before Libra and adds the one Libra observed"
        );
        assert_eq!(seen.headers.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(seen.headers.get("x-forwarded-host").unwrap(), "evil.example");
        assert_eq!(seen.headers.get("forwarded").unwrap(), "for=203.0.113.7;host=evil.example");
        assert_eq!(seen.headers.get("x-real-ip").unwrap(), "203.0.113.7");
    }

    #[tokio::test]
    async fn the_host_header_names_the_broker_rather_than_libra() {
        let server = broker().await;
        let authority = server.uri().trim_start_matches("http://").to_owned();

        proxy(&server.uri()).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(
            seen.headers.get(HOST).unwrap(),
            authority.as_str(),
            "a virtual-hosted broker would otherwise answer for the wrong site"
        );
    }

    #[tokio::test]
    async fn the_raw_path_reaches_the_broker_untouched_and_untouched_escapes_survive() {
        // Operation classification splits the raw path on `/` before decoding, so it reads
        // `entities%2Ffoo` as one segment. A proxy that decoded and re-encoded could hand the broker two,
        // and Libra would have authorized the wrong one. In the query, `%20` is already
        // unambiguous, and re-encoding its `%` would change the value.
        let server = broker().await;
        let target = "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/https%3A%2F%2Fexample.test%23speed?type=Veh%20icle";

        proxy(&server.uri()).oneshot(request(target)).await.expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(
            seen.url.path(),
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/https%3A%2F%2Fexample.test%23speed"
        );
        assert_eq!(seen.url.query(), Some("type=Veh%20icle"));
    }

    #[tokio::test]
    async fn a_semicolon_in_a_query_value_is_forwarded_percent_encoded() {
        // A literal `;` is a parameter separator for servlet containers and Netty-family decoders
        // before it is ever decoded, so it could carry a second `type` past Libra's duplicate
        // check. Encoded, it is one value to every reader.
        let server = broker().await;

        proxy(&server.uri())
            .oneshot(request("/ngsi-ld/v1/entities?q=a;type=Vehicle"))
            .await
            .expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.url.query(), Some("q=a%3Btype=Vehicle"));
    }

    #[tokio::test]
    async fn a_literal_plus_in_a_query_value_is_forwarded_percent_encoded() {
        // Form decoding reads a literal `+` as a space, which moves a timezone offset by a whole
        // zone. Encoded, it decodes to the `+` the caller wrote; the colons are unambiguous and stay.
        let server = broker().await;

        proxy(&server.uri())
            .oneshot(request("/ngsi-ld/v1/entities?timeAt=2026-01-01T00:00:00+01:00"))
            .await
            .expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.url.query(), Some("timeAt=2026-01-01T00:00:00%2B01:00"));
    }

    #[tokio::test]
    async fn pre_encoded_escapes_pass_through_byte_identical() {
        // `%2B` and a newly encoded `+` decode identically, and the `%` of an existing escape must
        // not become a literal percent sign by being encoded again.
        let server = broker().await;

        proxy(&server.uri())
            .oneshot(request("/ngsi-ld/v1/entities?q=%2B%3B"))
            .await
            .expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.url.query(), Some("q=%2B%3B"));
    }

    #[tokio::test]
    async fn a_semicolon_in_the_path_is_forwarded_untouched() {
        // The repair belongs to the query alone: a path is segmented before it is decoded, so the
        // broker cannot mistake a path semicolon for a query separator.
        let server = broker().await;

        proxy(&server.uri())
            .oneshot(request("/ngsi-ld/v1/entitiesurn;ngsi-ld;q=1"))
            .await
            .expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.url.path(), "/ngsi-ld/v1/entitiesurn;ngsi-ld;q=1");
    }

    #[tokio::test]
    async fn an_upstream_path_prefix_is_kept_in_front_of_the_request_path() {
        let server = broker().await;

        proxy(&format!("{}/broker/", server.uri()))
            .oneshot(request("/ngsi-ld/v1/entities"))
            .await
            .expect("the proxy answers");

        let seen = recorded(&server).await;
        assert_eq!(seen.url.path(), "/broker/ngsi-ld/v1/entities");
    }

    #[tokio::test]
    async fn the_status_and_response_headers_pass_through() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/entities"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw("{}", "application/problem+json")
                    .insert_header("ngsild-tenant", "acme"),
            )
            .mount(&server)
            .await;

        let response = proxy(&server.uri()).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/problem+json");
        assert_eq!(response.headers().get("ngsild-tenant").unwrap(), "acme");
    }

    #[tokio::test]
    async fn the_answer_does_not_carry_the_brokers_address_or_product() {
        let server = MockServer::start().await;
        let created = format!("{}/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:A", server.uri());
        Mock::given(method("GET"))
            .and(path("/ngsi-ld/v1/entities"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("location", created.as_str())
                    .insert_header("server", "Quarkus")
                    .insert_header("set-cookie", "session=abc"),
            )
            .mount(&server)
            .await;

        let response = proxy(&server.uri()).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");

        assert_eq!(response.headers().get("location").unwrap(), "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:A");
        assert!(!response.headers().contains_key("server"));
        assert!(!response.headers().contains_key("set-cookie"));
    }

    #[tokio::test]
    async fn a_broker_that_cannot_be_reached_is_a_bad_gateway() {
        // Not a 504: nothing timed out. A layer above owns the timeout, and it can only tell the
        // two apart if this one does not answer for both.
        let response = proxy("http://127.0.0.1:1")
            .oneshot(request("/ngsi-ld/v1/entities"))
            .await
            .expect("the proxy answers");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_large_body_arrives_intact() {
        let payload = "x".repeat(8 * 1024 * 1024);
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(payload.as_str()))
            .mount(&server)
            .await;

        let response = proxy(&server.uri()).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");
        let body = response.into_body().collect().await.expect("the body").to_bytes();

        assert_eq!(body.len(), payload.len());
        assert_eq!(body.as_ref(), payload.as_bytes());
    }

    const FIRST_PIECE: &[u8] = b"{\"piece\":\"first\"}";
    const SECOND_PIECE: &[u8] = b"{\"piece\":\"second\"}";

    #[tokio::test]
    async fn a_response_body_is_streamed_rather_than_buffered() {
        // The upstream writes one chunk and then stops until the test says otherwise. A proxy that
        // collected the body before answering could not produce that chunk, so the read below
        // would time out, which is the whole assertion.
        let (open, gate) = oneshot::channel();
        let upstream = trickling_upstream(gate).await;

        let response = proxy(&upstream).oneshot(request("/ngsi-ld/v1/entities")).await.expect("the proxy answers");
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let first = timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("the first chunk must arrive before the rest of the body is written")
            .expect("a frame")
            .expect("a readable frame")
            .into_data()
            .expect("a data frame");

        assert_eq!(first.as_ref(), FIRST_PIECE);

        open.send(()).expect("the upstream is still waiting");

        let rest = body.collect().await.expect("the rest of the body").to_bytes();
        assert_eq!(rest.as_ref(), SECOND_PIECE);
    }

    /// An upstream that answers in two chunks, the second only once `gate` fires.
    async fn trickling_upstream(gate: oneshot::Receiver<()>) -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("a local port");
        let address = listener.local_addr().expect("the bound address");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a connection");

            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.expect("the request head") == 0 {
                    return;
                }
                head.push(byte[0]);
            }

            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n")
                .await
                .expect("the response head");
            write_chunk(&mut stream, FIRST_PIECE).await;

            let _held = gate.await;

            write_chunk(&mut stream, SECOND_PIECE).await;
            stream.write_all(b"0\r\n\r\n").await.expect("the terminating chunk");
            stream.flush().await.expect("a flush");
        });

        format!("http://{address}")
    }

    async fn write_chunk(stream: &mut TcpStream, chunk: &[u8]) {
        let length = chunk.len();
        stream.write_all(format!("{length:x}\r\n").as_bytes()).await.expect("a chunk header");
        stream.write_all(chunk).await.expect("a chunk");
        stream.write_all(b"\r\n").await.expect("a chunk terminator");
        stream.flush().await.expect("a flush");
    }
}
