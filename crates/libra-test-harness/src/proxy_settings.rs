//! The configuration one proxy instance runs with, and the file it is rendered into.

use crate::{identity, stack::Endpoints};
use libra_config::{audience::Audience, issuer::Issuer};
use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};
use url::Url;

/// The configuration one proxy instance runs with.
///
/// Every field is a line of the generated `libra.toml`. Construct it with [`ProxySettings::new`]
/// and override what the test is about:
///
/// ```ignore
/// let settings = ProxySettings {
///     tenant_policy: "require-header",
///     ..ProxySettings::new(&stack, POLICIES)
/// };
/// ```
pub struct ProxySettings {
    /// The whole policy file, written into the instance's policy directory.
    pub policies: String,
    /// What the proxy forwards to. The broker unless a test substitutes an origin of its own.
    pub upstream: Url,
    /// `[multitenancy] policy`.
    pub tenant_policy: &'static str,
    /// `[authz] default-effect`.
    pub default_effect: &'static str,
    /// `[representation] unsatisfiable-accept`. `"forward"` (the default) lets the broker answer an
    /// `Accept` naming nothing Libra produces; `"refuse"` answers 406 at the gateway.
    pub unsatisfiable_accept: &'static str,
    /// `[representation] contradictory-options`. `"forward"` (the default) lets the broker resolve
    /// `options`/`format` that name no single shape; `"refuse"` answers 400 at the gateway.
    pub contradictory_options: &'static str,
    /// `[jwt]`. `None` writes no section, so no JWT is accepted.
    pub jwt: Option<JwtSettings>,
    /// `[jsonld] allowed-contexts`.
    pub allowed_contexts: Vec<Url>,
    /// `[jsonld] allow-remote`.
    pub allow_remote: bool,
    /// Contexts written to disk and named in `[jsonld] preloaded-contexts`, as URL and document.
    pub preloaded_contexts: Vec<(Url, String)>,
    /// `[management-api] metrics-access`: `"privileged"` (the default) or `"authenticated"`.
    pub metrics_access: &'static str,
    /// Whole TOML tables for sections the settings above do not render, appended as written.
    ///
    /// Empty by default. A binary that reads such a section is handed it here, and a binary that does
    /// not stops at startup when it is given one, which is the property the sections exist to have.
    pub extra_sections: String,
    /// `[key-store] path`. `None` turns the key store off, so no API key is accepted.
    pub key_store: Option<PathBuf>,
}

/// The `[jwt]` section one proxy instance runs with.
pub struct JwtSettings {
    /// Where the proxy fetches its signing keys.
    pub jwks_url: Url,
    /// `jwks-cache-duration`, in seconds: how long a fetched key set is trusted before the
    /// scheduled refresh replaces it. Left at the real default except by a test about rotation,
    /// which sets it low so a rotated key set is picked up within the test's lifetime.
    pub jwks_cache_duration: u64,
    /// The issuer a token must name.
    pub issuer: Issuer,
    /// The audience a token must name.
    pub audience: Audience,
}

impl JwtSettings {
    /// Accepts the tokens the suite's own issuer signs.
    #[must_use]
    pub fn suite() -> Self {
        Self {
            jwks_url: identity::jwks_url(),
            jwks_cache_duration: 3600,
            issuer: identity::issuer(),
            audience: identity::audience(),
        }
    }

    /// Renders the section. The suite serves its keys over plain http on the loopback interface,
    /// which the proxy only accepts when told so by name.
    fn to_toml(&self) -> String {
        format!(
            "[jwt]\njwks-url = \"{}\"\njwks-transport = \"insecure-http\"\njwks-cache-duration = {}\nissuer = \"{}\"\naudience = \"{}\"\n",
            self.jwks_url, self.jwks_cache_duration, self.issuer, self.audience
        )
    }
}

impl ProxySettings {
    /// The settings every test starts from: this stack's broker, tokens from the suite's issuer
    /// accepted, and nothing allowed that no policy allows.
    #[must_use]
    pub fn new(stack: &Endpoints, policies: &str) -> Self {
        Self {
            policies: policies.to_owned(),
            upstream: stack.broker.clone(), // the settings own their address, the endpoints are borrowed
            tenant_policy: "allow-public",
            default_effect: "deny",
            unsatisfiable_accept: "forward",
            contradictory_options: "forward",
            jwt: Some(JwtSettings::suite()),
            allowed_contexts: Vec::new(),
            allow_remote: true,
            preloaded_contexts: Vec::new(),
            metrics_access: "privileged",
            extra_sections: String::new(),
            key_store: None,
        }
    }

    /// Renders the settings as the configuration file the proxy reads.
    pub(crate) fn to_toml(&self, directory: &Path, port: u16) -> String {
        let policies_dir = directory.join("policies");
        // Optional sections are built whole and placed between complete sections: a key written at
        // the end of the file lands in whichever section happens to be last.
        let mut optional = String::new();
        if let Some(jwt) = &self.jwt {
            let _ = writeln!(optional, "{}", jwt.to_toml());
        }
        // The key store is on unless turned off, and its default file is outside the test's
        // directory.
        match &self.key_store {
            Some(path) => {
                let _ = writeln!(optional, "[key-store]\npath = \"{}\"\n", path.display());
            }
            None => {
                let _ = writeln!(optional, "[key-store]\nenabled = false\n");
            }
        }

        format!(
            r#"
[libra]
host = "127.0.0.1"
port = {port}

[broker]
url = "{upstream}"

{optional}
[authz]
policies-dir = "{policies_dir}"
default-effect = "{default_effect}"

[representation]
unsatisfiable-accept = "{unsatisfiable_accept}"
contradictory-options = "{contradictory_options}"

[jsonld]
allow-remote = {allow_remote}
allowed-contexts = [{allowed_contexts}]

[jsonld.preloaded-contexts]
{preloaded_contexts}

[multitenancy]
policy = "{tenant_policy}"

[proxy]
via-pseudonym = "libra-test"

[management-api]
admin-users = ["admin"]
admin-principals = ["operator"]
admin-roles = ["libra-admin"]
metrics-access = "{metrics_access}"

[logging.console]
enabled = true
level = "warn"
format = "compact"
ansi = false

{extra_sections}
"#,
            upstream = self.upstream,
            policies_dir = policies_dir.display(),
            default_effect = self.default_effect,
            unsatisfiable_accept = self.unsatisfiable_accept,
            contradictory_options = self.contradictory_options,
            tenant_policy = self.tenant_policy,
            extra_sections = self.extra_sections,
            metrics_access = self.metrics_access,
            allow_remote = self.allow_remote,
            preloaded_contexts = self
                .preloaded_contexts
                .iter()
                .map(|(url, _)| format!("\"{url}\" = \"{}\"", preloaded_path(directory, url).display()))
                .collect::<Vec<_>>()
                .join("\n"),
            allowed_contexts = self
                .allowed_contexts
                .iter()
                .map(|context| format!("\"{context}\""))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// Where a preloaded context's document is written, named after the URL that claims it.
pub(crate) fn preloaded_path(directory: &Path, url: &Url) -> PathBuf {
    let name: String = url
        .as_str()
        .chars()
        .map(|character| if character.is_ascii_alphanumeric() { character } else { '-' })
        .collect();

    directory.join(format!("{name}.jsonld"))
}
