//! Bounding the whole upstream answer, not only its headers.
//!
//! The upstream timeout resolves when the response future does, which is when the broker's status
//! line and headers arrive. A body the broker then streams slowly, or stops sending without closing
//! the connection, would hold that connection for as long as the broker likes. The same deadline
//! therefore carries on into the body, and whatever has not arrived by then is cut off. The status
//! has already gone out at that point, so the caller sees a truncated response rather than a 504.

use axum::{Error as AxumError, body::Body};
use http_body::{Body as HttpBody, Frame, SizeHint};
use libra_problem_details::problem::Problem;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep, sleep_until};
use tracing::warn;

/// Wraps a body so that it fails once `deadline` passes before it has ended.
///
/// A body that is already complete is returned as it is: there is nothing left to wait for.
pub fn bound(body: Body, deadline: Instant) -> Body {
    if body.is_end_stream() {
        return body;
    }

    Body::new(Bounded {
        inner: body,
        deadline: Box::pin(sleep_until(deadline)),
    })
}

/// A body that gives up at a fixed instant.
struct Bounded {
    inner: Body,
    deadline: Pin<Box<Sleep>>,
}

impl HttpBody for Bounded {
    type Data = <Body as HttpBody>::Data;
    type Error = AxumError;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // The body first, so a frame that is ready as the deadline passes is still delivered.
        if let Poll::Ready(frame) = Pin::new(&mut self.inner).poll_frame(context) {
            return Poll::Ready(frame);
        }

        if self.deadline.as_mut().poll(context).is_ready() {
            warn!("the upstream did not finish its response body in time; the rest has been cut off");

            return Poll::Ready(Some(Err(AxumError::new(Problem::GatewayTimeout(
                "the upstream did not finish its response in time".to_owned(),
            )))));
        }

        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stalled_body::OneChunkThenSilence;
    use http_body_util::BodyExt;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn a_body_still_arriving_at_the_deadline_is_cut_off() {
        let body = bound(Body::new(OneChunkThenSilence::default()), Instant::now() + Duration::from_secs(5));

        let error = body.collect().await.expect_err("the body never ends, so the deadline has to end it");

        assert!(error.to_string().contains("did not finish its response in time"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_ends_in_time_is_delivered_whole() {
        let body = bound(Body::from("[1,2,3]"), Instant::now() + Duration::from_secs(5));

        let collected = body.collect().await.expect("the body ended in time").to_bytes();

        assert_eq!(collected.as_ref(), b"[1,2,3]");
    }
}
