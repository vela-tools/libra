//! Pre-flighting every entity a batch names, within hard bounds.
//!
//! A batch request is one request to Libra and one pre-flight per entity it names, so the number of
//! entities is the amplification factor. A 2 MiB body holds tens of thousands of identifiers, and
//! pre-flighting them one after another held the request open until the upstream timeout cut it
//! off, in every layer that pre-flights. The bounds here keep one request's cost to the broker
//! fixed: identifiers are de-duplicated, a batch naming more than [`MAX_BATCH_ENTITIES`] distinct
//! entities is refused before any pre-flight is sent, and no more than [`IN_FLIGHT`] pre-flights
//! run at once.

use crate::{
    error::PreflightError,
    preflight::{EntityEndpoint, Preflight},
};
use futures::{StreamExt, stream::FuturesOrdered};
use http::HeaderMap;
use jstrict::Value;
use libra_ngsi_ld_operation::resource::ResourceId;
use std::collections::HashSet;
use thiserror::Error;

/// The most distinct entities one batch request may name.
pub const MAX_BATCH_ENTITIES: usize = 1000;

/// The most pre-flights one request has in flight at once.
pub const IN_FLIGHT: usize = 8;

/// A batch naming more distinct entities than Libra pre-flights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the batch names {count} distinct entities, more than the {MAX_BATCH_ENTITIES} one request may name")]
pub struct BatchTooLarge {
    /// How many distinct entities it names.
    pub count: usize,
}

/// The distinct identifiers of a batch, in the order they were first named.
///
/// # Errors
///
/// Returns [`BatchTooLarge`] when there are more than [`MAX_BATCH_ENTITIES`] of them.
pub fn distinct(identifiers: impl IntoIterator<Item = ResourceId>) -> Result<Vec<ResourceId>, BatchTooLarge> {
    let mut seen = HashSet::new();
    let distinct: Vec<ResourceId> = identifiers
        .into_iter()
        // The set keeps its own copy of each identifier; the list keeps the order they came in.
        .filter(|identifier| seen.insert(identifier.clone()))
        .collect();

    if distinct.len() > MAX_BATCH_ENTITIES {
        return Err(BatchTooLarge { count: distinct.len() });
    }

    Ok(distinct)
}

impl Preflight {
    /// Pre-flights every entity in `identifiers` and hands each answer to `judge`, in order.
    ///
    /// At most [`IN_FLIGHT`] pre-flights run at once. The first refusal `judge` returns ends the
    /// walk and cancels the pre-flights still running: one entity the request may not touch refuses
    /// the request, so nothing after it needs asking.
    ///
    /// # Errors
    ///
    /// Returns the first error `judge` returns.
    pub async fn each_entity<E>(
        &self,
        identifiers: &[ResourceId],
        endpoint: EntityEndpoint,
        headers: &HeaderMap,
        mut judge: impl FnMut(&ResourceId, Result<Value, PreflightError>) -> Result<(), E>,
    ) -> Result<(), E> {
        // Kept as a window over the identifiers rather than `stream::iter(..).map(..).buffered(..)`:
        // the closure that combinator needs borrows with a lifetime the compiler cannot prove
        // general enough once the caller's future is required to be `Send`, as every layer's is.
        let mut waiting = identifiers.iter();
        let mut running = FuturesOrdered::new();
        for identifier in waiting.by_ref().take(IN_FLIGHT) {
            running.push_back(self.answer(identifier, endpoint, headers));
        }

        while let Some((identifier, answer)) = running.next().await {
            if let Some(next) = waiting.next() {
                running.push_back(self.answer(next, endpoint, headers));
            }
            judge(identifier, answer)?;
        }

        Ok(())
    }

    /// One pre-flight of [`Preflight::each_entity`], paired with the identifier it asked about.
    async fn answer<'i>(&self, identifier: &'i ResourceId, endpoint: EntityEndpoint, headers: &HeaderMap) -> (&'i ResourceId, Result<Value, PreflightError>) {
        (identifier, self.entity(identifier, endpoint, headers).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::{
        iter::repeat_n,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread::sleep,
        time::Duration,
    };
    use url::Url;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

    fn ids(names: &[&str]) -> Vec<ResourceId> {
        names.iter().map(|name| ResourceId::new(*name)).collect()
    }

    #[test]
    fn repeated_identifiers_are_kept_once_in_the_order_first_named() {
        assert_eq!(distinct(ids(&["urn:b", "urn:a", "urn:b", "urn:a"])), Ok(ids(&["urn:b", "urn:a"])));
    }

    #[test]
    fn a_batch_of_exactly_the_limit_is_accepted() {
        let names: Vec<ResourceId> = (0..MAX_BATCH_ENTITIES).map(|n| ResourceId::new(format!("urn:e:{n}"))).collect();

        assert_eq!(distinct(names).map(|names| names.len()), Ok(MAX_BATCH_ENTITIES));
    }

    #[test]
    fn a_batch_past_the_limit_is_refused() {
        let names: Vec<ResourceId> = (0..=MAX_BATCH_ENTITIES).map(|n| ResourceId::new(format!("urn:e:{n}"))).collect();

        assert_eq!(distinct(names), Err(BatchTooLarge { count: MAX_BATCH_ENTITIES + 1 }));
    }

    #[test]
    fn repeats_do_not_count_towards_the_limit() {
        let names = repeat_n(ResourceId::new("urn:e:1"), MAX_BATCH_ENTITIES * 2);

        assert_eq!(distinct(names).map(|names| names.len()), Ok(1));
    }

    /// Answers every pre-flight after a pause, counting how many were open at once.
    struct Counting {
        open: Arc<AtomicUsize>,
        most: Arc<AtomicUsize>,
    }

    impl Respond for Counting {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let now = self.open.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(now, Ordering::SeqCst);
            sleep(Duration::from_millis(20));
            self.open.fetch_sub(1, Ordering::SeqCst);

            ResponseTemplate::new(200).set_body_raw(r#"{"id":"urn:e","type":"T"}"#, "application/ld+json")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_more_than_the_bound_are_in_flight_and_every_answer_is_judged() {
        let server = MockServer::start().await;
        let most = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .respond_with(Counting {
                open: Arc::new(AtomicUsize::new(0)),
                most: Arc::clone(&most),
            })
            .mount(&server)
            .await;
        let preflight = Preflight::new(Url::parse(&server.uri()).unwrap(), 1024).unwrap();
        let names: Vec<ResourceId> = (0..40).map(|n| ResourceId::new(format!("urn:e:{n}"))).collect();

        let mut judged = Vec::new();
        let outcome: Result<(), PreflightError> = preflight
            .each_entity(&names, EntityEndpoint::Current, &HeaderMap::new(), |identifier, answer| {
                judged.push(identifier.clone());
                answer.map(|_| ())
            })
            .await;

        assert_eq!(outcome, Ok(()));
        assert_eq!(judged, names, "every entity is judged, in the order named");
        assert!(most.load(Ordering::SeqCst) <= IN_FLIGHT, "{} were in flight", most.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_first_refusal_ends_the_walk() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let preflight = Preflight::new(Url::parse(&server.uri()).unwrap(), 1024).unwrap();

        let mut judged = 0;
        let outcome = preflight
            .each_entity(&ids(&["urn:a", "urn:b", "urn:c"]), EntityEndpoint::Current, &HeaderMap::new(), |_, answer| {
                judged += 1;
                answer.map(|_| ())
            })
            .await;

        assert!(matches!(outcome, Err(PreflightError::Status { .. })));
        assert_eq!(judged, 1);
    }
}
