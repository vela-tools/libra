//! `[jsonld]`: how request contexts are resolved and fetched.
//!
//! Every policy-relevant name in NGSI-LD is a term, and a term has no meaning without a context.
//! These settings decide which contexts Libra is willing to trust and how long it will wait for
//! one. They are security settings, not performance tuning: a proxy that resolves a context
//! differently from its broker is a proxy that can be talked past.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
use url::Url;
use url_macro::url;

/// Context resolution and fetching.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct JsonLd {
    /// Fetch contexts that are not already known.
    ///
    /// With this off, only the built-in core context and any preloaded contexts can be used, and
    /// a request naming anything else fails. That is the strictest posture and the right one for
    /// a deployment whose contexts are known in advance.
    pub allow_remote: bool,

    /// URL addresses Libra is willing to fetch a context from.
    ///
    /// An entry that ends in `/` matches everything under it, at that path boundary and no other:
    /// `https://smartdatamodels.org/` allows everything under `https://smartdatamodels.org/` and
    /// nothing under the lookalike host `https://smartdatamodels.org.example.test/`. An entry that
    /// ends anywhere else is an exact address and allows exactly that one document, with no suffix.
    /// An empty list with `allow_remote` on allows nothing: the effect is fail-closed either way,
    /// and never a silent fetch of a context the operator did not name.
    ///
    /// The default names the ETSI core context and the Smart Data Models, the contexts an NGSI-LD
    /// deployment most often meets. Setting the list replaces it rather than adding to it.
    pub allowed_contexts: Vec<Url>,
    /// Contexts read from disk at startup, keyed by the URL that names them.
    ///
    /// A preloaded context is used in place of fetching, so it needs no allow-list entry and works
    /// with `allow-remote = false`. This is what makes a deployment with no outbound network
    /// possible: without it, `allow-remote = false` leaves only the built-in core context, and
    /// every policy written against a data model fails to load.
    pub preloaded_contexts: BTreeMap<Url, PathBuf>,

    /// How long to wait for a context fetch before failing the request.
    pub fetch_timeout_seconds: u64,

    /// Largest context document Libra will read, in bytes.
    ///
    /// A context is fetched because a request asked for it, so its size is attacker-influenced.
    /// Reading an unbounded body on the request path is a denial-of-service vector against the
    /// proxy, and through it against everything behind the proxy.
    pub max_context_bytes: usize,

    /// How much memory the fetched-context cache may hold, in bytes.
    ///
    /// The bound is on fetched body bytes, so an entry count cannot turn a large context into an
    /// unbounded cache: whatever a document costs to hold is at least roughly what it cost on the
    /// wire, and the cache holds no more than this many of those bytes.
    pub cache_max_bytes: usize,

    /// How long a fetched context stays usable before it is fetched again.
    pub cache_ttl_seconds: u64,

    /// Override for the core context URL.
    ///
    /// The core context is compiled in, so this exists for deployments pinned to a different
    /// specification version, or serving it from an internal mirror. Changing it changes what
    /// every unqualified term means, so it is not a routine setting.
    pub core_context: Option<Url>,
}

impl Default for JsonLd {
    fn default() -> Self {
        Self {
            allow_remote: true,
            allowed_contexts: vec![
                url!("https://uri.etsi.org/ngsi-ld/"),
                url!("https://smartdatamodels.org/"),
                url!("https://raw.githubusercontent.com/smart-data-models/"),
            ],
            preloaded_contexts: BTreeMap::new(),
            fetch_timeout_seconds: 5,
            max_context_bytes: 1_048_576,
            cache_max_bytes: 67_108_864,
            cache_ttl_seconds: 3600,
            core_context: None,
        }
    }
}

impl JsonLd {
    /// Whether `url` is one Libra may fetch.
    ///
    /// Fetching is refused unless remote fetching is on and the URL matches one of the configured
    /// prefixes. A caller that gets `false` must fail the request rather than continue without the
    /// context: continuing would mean comparing names whose meaning is unknown.
    #[must_use]
    pub fn allows_fetching(&self, url: &Url) -> bool {
        self.allow_remote && self.allowed_contexts.iter().any(|allowed| prefix_matches(allowed, url))
    }
}

/// Matches a configured allow-list entry against a URL.
///
/// Both are compared in their serialised form, in which a bare host already ends in `/`, so
/// `https://smartdatamodels.org` and `https://smartdatamodels.org/` are the same directory entry.
/// An entry that does not end in `/` is an exact address: `https://example.test/v1/context.jsonld`
/// allows that document and no suffix of it, so `.../context.jsonld.evil` matches nothing.
///
/// A plain `starts_with` would be a hostname-confusion bug: the entry
/// `https://smartdatamodels.org/` would then also match
/// `https://smartdatamodels.org.example.test/context.jsonld`, which is an attacker-controlled host
/// that merely begins with the trusted one. Requiring the entry to end at its own boundary, or to
/// be the whole URL, removes that.
fn prefix_matches(allowed: &Url, url: &Url) -> bool {
    let (allowed, url) = (allowed.as_str(), url.as_str());

    if url == allowed {
        return true;
    }

    allowed.ends_with('/') && url.starts_with(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("the test address is a URL")
    }

    #[test]
    fn nothing_is_fetchable_without_an_allow_list() {
        let config = JsonLd {
            allowed_contexts: Vec::new(),
            ..JsonLd::default()
        };

        assert!(!config.allows_fetching(&url("https://smartdatamodels.org/context.jsonld")));
    }

    #[test]
    fn every_context_trusted_by_default_is_named_in_full() {
        // A prefix is matched at a path boundary, so `https://smartdatamodels.org/` cannot be
        // satisfied by `https://smartdatamodels.org.example.test/`. That only holds if the entry is
        // a real origin; a bare scheme would allow everything.
        let config = JsonLd::default();

        assert_eq!(config.allowed_contexts.len(), 3);
        for allowed in &config.allowed_contexts {
            assert_eq!(allowed.scheme(), "https", "{allowed} must be https");
            assert!(allowed.host().is_some(), "{allowed} must name a host, or it allows every host");
            assert!(allowed.as_str().ends_with('/'), "{allowed} must be a directory, not a document");
        }
    }

    #[test]
    fn the_default_trusts_the_core_context_and_the_smart_data_models() {
        let config = JsonLd::default();

        assert!(config.allows_fetching(&url("https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context-v1.9.jsonld")));
        assert!(config.allows_fetching(&url("https://smartdatamodels.org/context.jsonld")));
        assert!(config.allows_fetching(&url(
            "https://raw.githubusercontent.com/smart-data-models/dataModel.Transportation/master/context.jsonld"
        )));
        assert!(!config.allows_fetching(&url("https://raw.githubusercontent.com/someone-else/context.jsonld")));
    }

    #[test]
    fn a_prefix_allows_everything_beneath_it() {
        let config = JsonLd {
            allowed_contexts: vec![url("https://smartdatamodels.org")],
            ..JsonLd::default()
        };

        assert!(config.allows_fetching(&url("https://smartdatamodels.org/context.jsonld")));
        assert!(config.allows_fetching(&url("https://smartdatamodels.org/dataModel.Weather/context.jsonld")));
        assert!(config.allows_fetching(&url("https://smartdatamodels.org")));
    }

    #[test]
    fn a_lookalike_host_does_not_match_a_trusted_prefix() {
        let config = JsonLd {
            allowed_contexts: vec![url("https://smartdatamodels.org")],
            ..JsonLd::default()
        };

        assert!(!config.allows_fetching(&url("https://smartdatamodels.org.example.test/context.jsonld")));
        assert!(!config.allows_fetching(&url("https://smartdatamodels.org.evil/context.jsonld")));
    }

    #[test]
    fn a_full_url_allows_exactly_one_document() {
        let config = JsonLd {
            allowed_contexts: vec![url("https://example.test/v1/context.jsonld")],
            ..JsonLd::default()
        };

        assert!(config.allows_fetching(&url("https://example.test/v1/context.jsonld")));
        assert!(!config.allows_fetching(&url("https://example.test/v1/context.jsonld.evil")));
        assert!(!config.allows_fetching(&url("https://example.test/v1/other.jsonld")));
    }

    #[test]
    fn an_exact_entry_matches_no_path_suffix() {
        // An entry that is not a directory must stay a single document. A suffix match would let
        // `.../context.jsonld.evil` ride in under the trust the exact entry earned.
        let config = JsonLd {
            allowed_contexts: vec![url("https://example.test/ctx.jsonld")],
            ..JsonLd::default()
        };

        assert!(config.allows_fetching(&url("https://example.test/ctx.jsonld")));
        assert!(!config.allows_fetching(&url("https://example.test/ctx.jsonld.evil")));
        assert!(!config.allows_fetching(&url("https://example.test/dir/ctx.jsonld")));
    }

    #[test]
    fn a_byte_bound_replaces_the_entry_count_under_its_kebab_case_name() {
        // The cache is bounded in bytes, not in entries. The old key must stop loading, so a
        // deployment still carrying it stops at startup instead of quietly keeping the entry count.
        let renamed = toml::from_str::<JsonLd>(
            "allow-remote = true\nfetch-timeout-seconds = 5\nmax-context-bytes = 1024\ncache-max-bytes = 2048\ncache-ttl-seconds = 60",
        )
        .expect("the new key should load");
        assert_eq!(renamed.cache_max_bytes, 2048);

        assert!(
            toml::from_str::<JsonLd>("allow-remote = true\nfetch-timeout-seconds = 5\nmax-context-bytes = 1024\ncache-capacity = 16\ncache-ttl-seconds = 60")
                .is_err(),
            "the retired key must not load"
        );
    }

    #[test]
    fn turning_remote_fetching_off_overrides_the_allow_list() {
        let config = JsonLd {
            allow_remote: false,
            allowed_contexts: vec![url("https://smartdatamodels.org")],
            ..JsonLd::default()
        };

        assert!(!config.allows_fetching(&url("https://smartdatamodels.org/context.jsonld")));
    }

    #[test]
    fn the_default_context_setting_is_refused() {
        assert!(toml::from_str::<JsonLd>("default-context = \"https://example.test/ctx.jsonld\"").is_err());
    }
}
