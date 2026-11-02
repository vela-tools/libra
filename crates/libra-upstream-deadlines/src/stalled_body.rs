//! A request or response body that sends one chunk and then hangs, for tests.

use axum::body::Bytes;
use http_body::{Body as HttpBody, Frame};
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

/// One chunk, then nothing, ever: the shape of a peer that started sending and stopped without
/// closing the connection.
#[derive(Debug, Default)]
pub struct OneChunkThenSilence {
    sent: bool,
}

impl HttpBody for OneChunkThenSilence {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.sent {
            return Poll::Pending;
        }
        self.sent = true;

        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"one")))))
    }
}
