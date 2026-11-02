//! Where the broker under test is, and whether there is one.
//!
//! The suite needs a context broker. It is named by environment variable so an ordinary
//! `cargo test` does not need one. The identity provider is the suite's own (see
//! [`crate::identity`]), so nothing else needs to be running.
//!
//! A broker that is named but unreachable is a failure, not a skip. The skip exists so a developer
//! without Docker can still run the rest of the workspace, not so a broken service can produce a
//! green run.

use std::env;
use url::Url;

/// The services the suite runs against.
pub struct Endpoints {
    /// The NGSI-LD context broker the proxy fronts.
    pub broker: Url,
}

impl Endpoints {
    /// Reads the broker from the environment, or reports that there is no stack.
    ///
    /// # Panics
    ///
    /// Panics when the variable is set and is not a URL. Skipping on it would turn the suite green
    /// while it ran nothing.
    #[must_use]
    pub fn from_environment() -> Option<Self> {
        named("LIBRA_INTEGRATION_BROKER").map(|broker| Self { broker })
    }

    /// An address on the broker, from an absolute path with its query, such as
    /// `/ngsi-ld/v1/entities?type=Vehicle`.
    ///
    /// # Panics
    ///
    /// Panics if `path_and_query` does not make a URL, which is a mistake in the test.
    #[must_use]
    pub fn broker_endpoint(&self, path_and_query: &str) -> Url {
        self.broker.join(path_and_query).expect("a path on the broker should make a URL")
    }
}

/// A non-empty environment variable that is a URL, or nothing.
///
/// # Panics
///
/// Panics if the variable is set and is not a URL.
fn named(variable: &str) -> Option<Url> {
    env::var(variable)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| Url::parse(&value).unwrap_or_else(|error| panic!("{variable} must be a URL: {error}")))
}

/// Binds the test to a running stack, or skips it.
///
/// Expands to the [`Endpoints`], so a test body reads as though the stack were always there:
///
/// ```ignore
/// let stack = require_stack!();
/// ```
#[macro_export]
macro_rules! require_stack {
    () => {
        match $crate::stack::Endpoints::from_environment() {
            Some(endpoints) => endpoints,
            None => {
                eprintln!("skipping: set LIBRA_INTEGRATION_BROKER to run the integration suite");
                return;
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_endpoints_are_addressed_by_absolute_path() {
        let stack = Endpoints {
            broker: Url::parse("http://broker.test:9090").expect("the test address is a URL"),
        };

        assert_eq!(
            stack.broker_endpoint("/ngsi-ld/v1/entities?type=Vehicle").as_str(),
            "http://broker.test:9090/ngsi-ld/v1/entities?type=Vehicle"
        );
    }
}
