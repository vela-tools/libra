//! Entities, put into the broker directly.
//!
//! Seeding goes around the proxy on purpose. A test about reading is about what the policy allows
//! to be read, and it should not first have to satisfy a policy about writing, nor should a
//! failure to write be reported as a failure to read.

use crate::{stack::Endpoints, tenant_creation};
use reqwest::blocking::Client;
use serde_json::Value;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Distinguishes two identifiers minted in the same clock tick, which the suite does whenever two
/// tests seed at once and the platform's clock is coarser than a nanosecond.
static MINTED: AtomicU64 = AtomicU64::new(0);

/// An entity identifier nothing else in the suite will use.
///
/// The broker outlives a single run, so a fixed identifier would make the second run fail on the
/// first run's leftovers.
///
/// # Panics
///
/// Panics if the system clock is before the Unix epoch, which no machine a suite runs on is.
#[must_use]
pub fn unique_id(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock should be after the epoch")
        .as_nanos();
    let sequence = MINTED.fetch_add(1, Ordering::Relaxed);

    format!("urn:ngsi-ld:{kind}:{nanos}-{sequence}")
}

/// Creates an entity in the broker, in the named tenant or in none.
///
/// # Panics
///
/// Panics unless the broker accepts it, because every assertion that follows would otherwise be
/// about an entity that is not there.
pub fn create(stack: &Endpoints, tenant: Option<&str>, entity: &Value) {
    let mut request = Client::new()
        .post(stack.broker_endpoint("/ngsi-ld/v1/entities"))
        .header("Content-Type", "application/ld+json")
        .body(entity.to_string());

    if let Some(tenant) = tenant {
        request = request.header("NGSILD-Tenant", tenant);
    }

    let response = tenant_creation::write_into(tenant, || request.send().expect("the broker should answer"));
    let status = response.status();

    assert!(
        status.is_success(),
        "the broker refused the seed entity: {status} {}",
        response.text().unwrap_or_default()
    );
}
