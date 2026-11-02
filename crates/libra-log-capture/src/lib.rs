//! What a piece of code writes to the log, captured so a test can assert on it.
//!
//! A log line is a disclosure: a field written there reaches whoever reads the deployment's logs,
//! a wider audience than the caller, and one that keeps what it reads. A test that holds code to
//! what it may log runs that code under [`captured`] and inspects every event and every span it
//! emitted, including the fields a span is given after it opens.
//!
//! The subscriber is attached to the future rather than to the thread, so no guard is held across
//! an await and the future under test stays `Send`. Nothing is filtered: every level is captured,
//! so a value that would reach the log only with debug logging switched on is still seen.
//!
//! A callsite caches whether anything is interested in it the first time it is reached. Reached
//! first by a test running outside any capture, with no subscriber in the process, it is cached as
//! of no interest, and a capture running at that moment on another thread misses the event. So the
//! first capture installs a process-wide subscriber that discards everything, and every callsite
//! is registered as one somebody listens to.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    future::Future,
    mem::take,
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
};
use tracing::{
    Event,
    Level,
    Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
    subscriber::set_global_default,
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
    registry,
};

/// Whether a record is a log event or a span that events nest in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A log event.
    Event,
    /// A span, which every event emitted inside it is written with.
    Span,
}

/// One event or span, with each field flattened to the text a formatter writes for it.
#[derive(Debug, Clone)]
pub struct Emitted {
    /// Event or span.
    pub kind: Kind,
    /// The level it was emitted at.
    pub level: Level,
    /// The span's name, or the name of the event's callsite.
    pub name: &'static str,
    fields: BTreeMap<&'static str, String>,
}

impl Emitted {
    /// The event's message, empty for a span or an event without one.
    #[must_use]
    pub fn message(&self) -> &str {
        self.field("message").unwrap_or_default()
    }

    /// The text of one field, absent when the record does not carry it.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// Whether any field of the record, the message included, contains `text`.
    #[must_use]
    pub fn mentions(&self, text: &str) -> bool {
        self.fields.values().any(|value| value.contains(text))
    }
}

/// Set once the process-wide subscriber is in place.
static LISTENED_TO: OnceLock<()> = OnceLock::new();

/// Runs `future` with a subscriber that captures everything it emits, and returns its output with
/// the records in the order they were emitted.
pub async fn captured<F: Future>(future: F) -> (F::Output, Vec<Emitted>) {
    LISTENED_TO.get_or_init(|| {
        if set_global_default(registry()).is_err() {
            // A test that installed its own global subscriber already gives every callsite an
            // interested subscriber, which is all this one is for.
        }
    });
    let capture = Capture::default();
    // A handle to the shared buffer: the subscriber owns one, this function reads the other.
    let output = future.with_subscriber(registry().with(capture.clone())).await;

    (output, capture.records())
}

/// Flattens the fields of one event or span into text.
#[derive(Default)]
struct Fields(BTreeMap<&'static str, String>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name(), value.to_owned());
    }
}

/// What has been captured so far.
#[derive(Default)]
struct Captured {
    records: Vec<Emitted>,
    /// Where each open span sits in `records`, so a field recorded on it later lands there.
    spans: HashMap<Id, usize>,
}

/// The capturing subscriber layer, shared between the subscriber and the test that reads it.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Captured>>);

impl Capture {
    /// Locks the buffer, recovering from poisoning: a test that panicked while holding it has
    /// already failed, and the records it left are still the ones emitted.
    fn lock(&self) -> MutexGuard<'_, Captured> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn records(&self) -> Vec<Emitted> {
        take(&mut self.lock().records)
    }
}

impl<S: Subscriber> Layer<S> for Capture {
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, _context: Context<'_, S>) {
        let mut fields = Fields::default();
        attributes.record(&mut fields);

        let mut captured = self.lock();
        let index = captured.records.len();
        captured.records.push(Emitted {
            kind: Kind::Span,
            level: *attributes.metadata().level(),
            name: attributes.metadata().name(),
            fields: fields.0,
        });
        // The id is the subscriber's handle to the span; the map keeps its own copy.
        captured.spans.insert(id.clone(), index);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, _context: Context<'_, S>) {
        let mut fields = Fields::default();
        values.record(&mut fields);

        let mut captured = self.lock();
        if let Some(index) = captured.spans.get(id).copied()
            && let Some(span) = captured.records.get_mut(index)
        {
            span.fields.extend(fields.0);
        }
    }

    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);

        self.lock().records.push(Emitted {
            kind: Kind::Event,
            level: *event.metadata().level(),
            name: event.metadata().name(),
            fields: fields.0,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{Kind, captured};
    use pretty_assertions::assert_eq;
    use tracing::{Level, debug, field::Empty, info_span, warn};

    #[tokio::test]
    async fn an_event_is_captured_with_its_level_message_and_fields() {
        let ((), records) = captured(async { warn!(policy = "fleet-read", "access denied") }).await;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, Kind::Event);
        assert_eq!(records[0].level, Level::WARN);
        assert_eq!(records[0].message(), "access denied");
        assert_eq!(records[0].field("policy"), Some("fleet-read"));
    }

    #[tokio::test]
    async fn a_debug_event_is_captured_although_no_deployment_logs_at_that_level_by_default() {
        let ((), records) = captured(async { debug!("validating a token") }).await;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, Level::DEBUG);
    }

    #[tokio::test]
    async fn a_span_is_captured_with_the_fields_it_opened_with_and_those_recorded_later() {
        let ((), records) = captured(async {
            let span = info_span!("request", path = "/entities", status = Empty);
            span.record("status", 200);
        })
        .await;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, Kind::Span);
        assert_eq!(records[0].name, "request");
        assert_eq!(records[0].field("path"), Some("/entities"));
        assert_eq!(records[0].field("status"), Some("200"));
    }

    #[tokio::test]
    async fn a_displayed_value_is_matched_as_the_text_a_formatter_writes() {
        let name = String::from("alice");
        let ((), records) = captured(async { warn!(caller = %name, "access denied") }).await;

        assert!(records[0].mentions("alice"));
        assert!(!records[0].mentions("bob"));
    }

    #[tokio::test]
    async fn the_output_of_the_future_is_returned() {
        let (output, records) = captured(async { 7 }).await;

        assert_eq!(output, 7);
        assert!(records.is_empty());
    }
}
