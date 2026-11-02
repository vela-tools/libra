//! The first write into each tenant, made one at a time.
//!
//! Scorpio creates a tenant on the first write into it, and of two first writes into a new tenant
//! at once, one fails with 409 `AlreadyExists`, for an entity and a registration alike. The suite
//! runs its tests in parallel and many share a tenant, so a first run against a fresh broker would
//! fail at random. Every seed goes through [`write_into`], which lets the first write into a tenant
//! run alone and every later one run freely.

use std::{
    collections::BTreeSet,
    sync::{Mutex, PoisonError},
};

/// The tenants a seed has written into. The lock is held across the first write into a tenant, not
/// only across the lookup, because the write itself is what must not run twice at once.
static CREATED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// The tenant a broker writes into when a request names none.
const DEFAULT_TENANT: &str = "";

/// Runs `write` into `tenant`, alone if it is the first write into that tenant.
///
/// A panic in another test's first write leaves the set as it was, so the lock is taken back from a
/// poisoned state rather than failing every test that comes after it.
pub fn write_into<T>(tenant: Option<&str>, write: impl FnOnce() -> T) -> T {
    let tenant = tenant.unwrap_or(DEFAULT_TENANT);
    let mut created = CREATED.lock().unwrap_or_else(PoisonError::into_inner);
    if created.contains(tenant) {
        drop(created);
        return write();
    }

    let written = write();
    created.insert(tenant.to_owned());
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Barrier,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    #[test]
    fn a_write_into_a_new_tenant_waits_for_the_first_one_to_finish() {
        let first_started = Barrier::new(2);
        let first_finished = AtomicBool::new(false);

        thread::scope(|scope| {
            scope.spawn(|| {
                write_into(Some("waits-for-the-first"), || {
                    first_started.wait();
                    thread::sleep(Duration::from_millis(50));
                    first_finished.store(true, Ordering::SeqCst);
                });
            });

            first_started.wait();
            write_into(Some("waits-for-the-first"), || {
                assert!(first_finished.load(Ordering::SeqCst), "the second write ran while the first was in flight");
            });
        });
    }

    #[test]
    fn writes_after_the_first_do_not_wait_for_each_other() {
        write_into(Some("later-writes-overlap"), || ());
        let both_started = Barrier::new(2);

        thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    write_into(Some("later-writes-overlap"), || {
                        // Two writes that each wait for the other can only both return if they overlap.
                        both_started.wait();
                    });
                });
            }
        });
    }

    #[test]
    fn a_write_returns_what_the_closure_returns() {
        assert_eq!(write_into(Some("returns-its-value"), || 7), 7);
        assert_eq!(write_into(None, || 9), 9);
    }
}
