//! A request's body, `Content-Type` and `Link` headers, through the layer that reads the body once
//! and resolves the one JSON-LD context the request is judged under.
//!
//! A request either reaches the layers below with its context and its parsed body beside it, and
//! with its bytes unchanged, or it is refused there. Remote contexts are not fetched.
#![no_main]

use axum::{
    body::{Body, Bytes, to_bytes},
    extract::Request,
    response::{IntoResponse, Response},
};
use http::{
    HeaderValue,
    Method,
    StatusCode,
    Uri,
    header::{CONTENT_TYPE, LINK},
};
use jstrict::Value;
use libfuzzer_sys::fuzz_target;
use libra_fuzz::{context_resolver, runtime};
use libra_json_body::request_body::RequestBody;
use libra_jsonld_context_layer::{ContextLayer, RequestContextExtension};
use libra_jsonld_term_expansion::name::Term;
use std::convert::Infallible;
use tower::{Layer, ServiceExt, service_fn};

/// The bound the layer reads a body up to.
const MAX_BODY_BYTES: usize = 1_048_576;

/// What the layers below answer with, which no refusal ever carries.
const PASSED: StatusCode = StatusCode::ACCEPTED;

/// The parts of a request the layer reads, framed as a header block: the `Content-Type` value on
/// the first line (an empty line for none), one `Link` value on each further line, a blank line,
/// then the body. A header value cannot hold a line break, so the framing loses nothing.
struct Submission<'a> {
    content_type: Option<&'a [u8]>,
    links: Vec<&'a [u8]>,
    body: &'a [u8],
}

impl<'a> Submission<'a> {
    fn read(data: &'a [u8]) -> Submission<'a> {
        let (head, body) = match data.windows(2).position(|pair| pair == b"\n\n") {
            Some(end) => {
                let (head, rest) = data.split_at(end);
                (head, rest.strip_prefix(b"\n\n").unwrap_or(rest))
            }
            None => (data, &[][..]),
        };

        let mut lines = head.split(|byte| *byte == b'\n');
        let content_type = lines.next().filter(|line| !line.is_empty());

        Submission {
            content_type,
            links: lines.collect(),
            body,
        }
    }
}

/// Stands in for the layers below and checks what they would be handed.
async fn below(request: Request, sent: Bytes) -> Result<Response, Infallible> {
    // Cloned out of the extensions so the request can give up its body below.
    let context = request.extensions().get::<RequestContextExtension>().cloned();
    let body = request.extensions().get::<RequestBody>().cloned();
    assert!(context.is_some() && body.is_some(), "a request passed without its context or its parsed body");

    if let (Some(context), Some(RequestBody::Json(Value::Object(object)))) = (context, body) {
        for entry in &object {
            let _ = context.context().expand(&Term::new(entry.key.as_str()));
        }
    }

    let forwarded = to_bytes(request.into_body(), MAX_BODY_BYTES).await;
    assert_eq!(forwarded.ok(), Some(sent), "the body changed on its way through");

    Ok(PASSED.into_response())
}

fuzz_target!(|data: &[u8]| {
    let submission = Submission::read(data);

    let mut request = Request::new(Body::from(submission.body.to_vec()));
    *request.method_mut() = Method::POST;
    *request.uri_mut() = Uri::from_static("/ngsi-ld/v1/entities");

    if let Some(content_type) = submission.content_type {
        let Ok(value) = HeaderValue::from_bytes(content_type) else {
            return;
        };
        request.headers_mut().insert(CONTENT_TYPE, value);
    }
    for link in &submission.links {
        let Ok(value) = HeaderValue::from_bytes(link) else {
            return;
        };
        request.headers_mut().append(LINK, value);
    }

    let sent = Bytes::copy_from_slice(submission.body);
    // A `Bytes` clone shares the buffer: each call of the service checks against the same bytes.
    let service = ContextLayer::new(context_resolver::offline(), MAX_BODY_BYTES).layer(service_fn(move |request| below(request, sent.clone())));

    let response = runtime::shared().block_on(service.oneshot(request));
    let Ok(response) = response;
    assert!(response.status() == PASSED || response.status().is_client_error(), "{}", response.status());
});
