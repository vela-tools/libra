//! Reading the body of a response Libra fetched for itself, under a byte cap.
//!
//! Libra fetches documents on its own account: an entity from the broker before judging a write
//! to it, a key set from an identity provider, a JSON-LD context from an allow-listed host. Each
//! answer is held in memory whole before it is parsed, so each is read in chunks and abandoned the
//! moment it passes its cap. The declared `Content-Length` is not what is enforced: it is a claim
//! by the same party that supplies the body, and a chunked response carries none at all, so the
//! only number worth enforcing is what has actually arrived.

use reqwest::Response;
use thiserror::Error;

/// A fetched body could not be read whole.
#[derive(Debug, Error)]
pub enum FetchedBodyError {
    /// The body passed the cap; the rest of it was not read.
    #[error("the response body is larger than {limit} bytes")]
    TooLarge {
        /// The cap, in bytes.
        limit: usize,
    },
    /// The connection failed while the body was being read.
    #[error("the response body could not be read: {0}")]
    Unreadable(#[source] reqwest::Error),
}

/// Reads the body of `response`, refusing it once more than `limit` bytes have arrived.
///
/// # Errors
///
/// Returns [`FetchedBodyError::TooLarge`] as soon as the body passes `limit`, and
/// [`FetchedBodyError::Unreadable`] if the transfer fails.
pub async fn read(mut response: Response, limit: usize) -> Result<Vec<u8>, FetchedBodyError> {
    let mut body = Vec::new();

    while let Some(chunk) = response.chunk().await.map_err(FetchedBodyError::Unreadable)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(FetchedBodyError::TooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use crate::{FetchedBodyError, read};
    use pretty_assertions::assert_eq;
    use reqwest::{Client, Response};
    use std::iter::repeat_n;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

    async fn answering(body: &'static [u8]) -> (MockServer, Response) {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        let response = Client::new().get(server.uri()).send().await.unwrap();

        (server, response)
    }

    #[tokio::test]
    async fn a_body_within_the_cap_is_read_whole() {
        let (_server, response) = answering(b"{\"id\":\"urn:ngsi-ld:Vehicle:A\"}").await;

        assert_eq!(read(response, 1024).await.unwrap(), b"{\"id\":\"urn:ngsi-ld:Vehicle:A\"}");
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_cap_is_read() {
        let (_server, response) = answering(b"0123456789").await;

        assert_eq!(read(response, 10).await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn a_body_one_byte_past_the_cap_is_refused() {
        let (_server, response) = answering(b"0123456789").await;

        assert!(matches!(read(response, 9).await, Err(FetchedBodyError::TooLarge { limit: 9 })));
    }

    /// Answers one request with a chunked body that declares no length: `chunks` chunks of 1 KiB.
    async fn chunked(chunks: usize) -> Response {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _read = stream.read(&mut request).await.unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n").await.unwrap();
            let chunk = format!("400\r\n{}\r\n", "x".repeat(1024));
            let body = repeat_n(chunk.as_bytes(), chunks).chain([b"0\r\n\r\n".as_slice()]);
            for part in body {
                // A reader that stopped at the cap has closed the connection; the rest is not sent.
                if stream.write_all(part).await.is_err() {
                    return;
                }
            }
        });

        Client::new().get(format!("http://{address}/")).send().await.unwrap()
    }

    #[tokio::test]
    async fn a_chunked_body_that_declares_no_length_is_refused_once_it_passes_the_cap() {
        let response = chunked(64).await;

        assert_eq!(response.content_length(), None);
        assert!(matches!(read(response, 4096).await, Err(FetchedBodyError::TooLarge { limit: 4096 })));
    }

    #[tokio::test]
    async fn a_chunked_body_within_the_cap_is_read_whole() {
        assert_eq!(read(chunked(2).await, 4096).await.unwrap().len(), 2048);
    }
}
