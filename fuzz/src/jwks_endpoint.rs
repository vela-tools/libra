//! A key set endpoint on the loopback interface, serving whatever document it was last given.
//!
//! The key store reads its keys only over HTTP, so a target reaches the JWKS reader and the token
//! validator through it rather than through anything the production crates expose for testing.

use crate::runtime;
use axum::{Router, body::Bytes, extract::State, routing::get};
use std::sync::{Arc, PoisonError, RwLock};
use tokio::net::TcpListener;
use url::Url;

/// A running endpoint at `/certs`.
pub struct JwksEndpoint {
    document: Arc<RwLock<Bytes>>,
    url: Url,
}

impl JwksEndpoint {
    /// Starts an endpoint on the shared runtime, serving `document` until told otherwise.
    ///
    /// # Panics
    ///
    /// Panics if no loopback port can be bound, which leaves the target nothing to run against.
    #[must_use]
    pub fn start(document: &[u8]) -> JwksEndpoint {
        let document = Arc::new(RwLock::new(Bytes::copy_from_slice(document)));
        // The router holds one handle to the document and the endpoint the other.
        let router = Router::new().route("/certs", get(answer)).with_state(Arc::clone(&document));

        let runtime = runtime::shared();
        let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).expect("a loopback port is free");
        let address = listener.local_addr().expect("a bound listener has an address");
        runtime.spawn(async move { axum::serve(listener, router).await });

        let url = Url::parse(&format!("http://{address}/certs")).expect("a loopback address is a URL");

        JwksEndpoint { document, url }
    }

    /// Serves `document` from the next request on.
    pub fn serve(&self, document: &[u8]) {
        *self.document.write().unwrap_or_else(PoisonError::into_inner) = Bytes::copy_from_slice(document);
    }

    /// Where the document is served.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }
}

/// Answers with the current document. Cloning `Bytes` shares the buffer rather than copying it.
async fn answer(State(document): State<Arc<RwLock<Bytes>>>) -> Bytes {
    document.read().unwrap_or_else(PoisonError::into_inner).clone()
}
