//! `[cors]`: cross-origin resource sharing.

use crate::allow_list::AllowList;
use http::{HeaderName, HeaderValue, Method};
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    de::{Error as DeError, Visitor},
};
use std::fmt::{Formatter, Result as FmtResult};

/// Tristate CORS switch: off, on with the configured values, or on with permissive defaults.
///
/// Off by default: a policy that mirrors every origin and header is a decision for the operator
/// to make, not one for an authentication proxy to make on their behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CorsEnabled {
    /// CORS is disabled.
    #[default]
    False,
    /// CORS is enabled with the values configured below.
    True,
    /// CORS is enabled with permissive defaults.
    Permissive,
}

impl<'de> Deserialize<'de> for CorsEnabled {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CorsEnabledVisitor;

        impl Visitor<'_> for CorsEnabledVisitor {
            type Value = CorsEnabled;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("a boolean or the string 'permissive'")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(if value { CorsEnabled::True } else { CorsEnabled::False })
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                match value.to_lowercase().as_str() {
                    "permissive" => Ok(CorsEnabled::Permissive),
                    "true" => Ok(CorsEnabled::True),
                    "false" => Ok(CorsEnabled::False),
                    other => Err(DeError::unknown_variant(other, &["permissive", "true", "false"])),
                }
            }
        }

        deserializer.deserialize_any(CorsEnabledVisitor)
    }
}

/// CORS configuration.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Cors {
    /// Whether CORS is enabled, and in which mode.
    pub enabled: CorsEnabled,
    /// Allowed origins. `["*"]` allows any origin; name them explicitly in production.
    pub allow_origins: AllowList<HeaderValue>,
    /// Allowed HTTP methods.
    pub allow_methods: AllowList<Method>,
    /// Allowed request headers.
    pub allow_headers: AllowList<HeaderName>,
    /// Headers exposed to the browser.
    pub expose_headers: AllowList<HeaderName>,
    /// Allow credentials. Cannot be combined with an origin of `*`.
    pub allow_credentials: bool,
    /// Preflight cache lifetime in seconds.
    pub max_age_seconds: u64,
}

impl Default for Cors {
    fn default() -> Self {
        Self {
            enabled: CorsEnabled::False,
            allow_origins: AllowList::Any,
            allow_methods: AllowList::Only(vec![Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS]),
            allow_headers: AllowList::Any,
            expose_headers: AllowList::Only(Vec::new()),
            allow_credentials: false,
            max_age_seconds: 3600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn deserializes_from_bool_and_string() {
        assert_eq!(serde_json::from_str::<CorsEnabled>("true").unwrap(), CorsEnabled::True);
        assert_eq!(serde_json::from_str::<CorsEnabled>("false").unwrap(), CorsEnabled::False);
        assert_eq!(serde_json::from_str::<CorsEnabled>("\"permissive\"").unwrap(), CorsEnabled::Permissive);
        assert_eq!(serde_json::from_str::<CorsEnabled>("\"PERMISSIVE\"").unwrap(), CorsEnabled::Permissive);
    }

    #[test]
    fn rejects_an_unknown_string() {
        assert!(serde_json::from_str::<CorsEnabled>("\"maybe\"").is_err());
    }
}
