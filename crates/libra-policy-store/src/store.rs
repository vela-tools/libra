//! Reading policy files, compiling them, and holding the result.
//!
//! Loading is where every check that can be made once is made. A term is expanded here, not on the
//! request path; a duration is parsed here; a key that is no restriction is refused here. What
//! reaches evaluation is a set of policies that are known to be about something.

use crate::{
    error::PolicyStoreError,
    snapshot::{PolicySnapshot, Source},
};
use arc_swap::ArcSwap;
use libra_config::authz::{Authz, DefaultEffect};
use libra_jsonld_context::resolver::ContextResolver;
use libra_policy_model::{
    effect::Effect,
    policy::{CompiledPolicy, Policy, PolicyFile, PolicyId},
};
use std::{
    collections::BTreeMap,
    fmt::{Debug, Formatter, Result as FmtResult},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{fs, sync::Mutex};
use tracing::{info, warn};

/// Holds the policy set and swaps it atomically on reload.
///
/// Reads take no lock: a request evaluates against whichever snapshot was current when it started,
/// and a reload that lands mid-request cannot show it half a policy set.
pub struct PolicyStore {
    snapshot: ArcSwap<PolicySnapshot>,
    directory: PathBuf,
    default_effect: Effect,
    /// Held by a reload from the moment it reads the directory until its snapshot is stored.
    reloading: Mutex<()>,
}

impl Debug for PolicyStore {
    /// Deliberately shallow. A policy set printed into a log line would bury whatever the line was
    /// about, and the count and the directory are what is actually diagnostic.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter
            .debug_struct("PolicyStore")
            .field("directory", &self.directory)
            .field("policies", &self.snapshot.load().len())
            .field("default_effect", &self.default_effect)
            .finish_non_exhaustive()
    }
}

impl PolicyStore {
    /// Loads every policy file in `directory`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyStoreError`] if the directory is unreadable, a file does not parse (which
    /// includes a key that is no restriction), a declared context cannot be resolved, a term cannot
    /// be expanded, two policies share an identifier, or a policy can never apply.
    pub async fn load(directory: &Path, default_effect: Effect, resolver: &ContextResolver) -> Result<Self, PolicyStoreError> {
        let (policies, sources) = read_directory(directory, resolver).await?;

        info!(total = policies.len(), default_effect = ?default_effect, "policy set loaded");

        Ok(Self {
            snapshot: ArcSwap::from_pointee(PolicySnapshot::with_sources(policies, sources, default_effect)),
            directory: directory.to_path_buf(),
            default_effect,
            reloading: Mutex::new(()),
        })
    }

    /// Loads from the `[authz]` configuration section.
    ///
    /// # Errors
    ///
    /// As [`PolicyStore::load`].
    pub async fn from_config(config: &Authz, resolver: &ContextResolver) -> Result<Self, PolicyStoreError> {
        Self::load(&config.policies_dir, effect_of(config.default_effect), resolver).await
    }

    /// The current policy set.
    #[must_use]
    pub fn snapshot(&self) -> Arc<PolicySnapshot> {
        self.snapshot.load_full()
    }

    /// The directory the policy set was loaded from.
    ///
    /// The management API writes files here and then asks for a reload, rather than mutating a
    /// loaded set: a write that goes back through loading is a write that has been through every
    /// check a startup load makes.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Re-reads the directory and replaces the policy set.
    ///
    /// The new set is fully built and fully checked before it replaces the old one, so a reload
    /// that fails leaves the running set exactly as it was. A half-applied reload would mean
    /// running with a policy set nobody wrote.
    ///
    /// Reloads run one at a time, each reading the directory only after the one before it has
    /// stored its set. Two reloads that overlapped could finish in the other order, and the set read
    /// first would then replace the set read later: a deny added between the two reads would be
    /// gone without an error.
    ///
    /// # Errors
    ///
    /// As [`PolicyStore::load`].
    pub async fn reload(&self, resolver: &ContextResolver) -> Result<usize, PolicyStoreError> {
        let _reloading = self.reloading.lock().await;
        let (policies, sources) = read_directory(&self.directory, resolver).await?;
        let count = policies.len();

        self.snapshot
            .store(Arc::new(PolicySnapshot::with_sources(policies, sources, self.default_effect)));
        info!(total = count, "policy set reloaded");

        Ok(count)
    }
}

/// The policy model's effect, from the configuration's own enum.
///
/// The conversion lives here because this crate owns the policy concept; `libra-config` declares
/// its own enum so that it stays a leaf.
#[must_use]
pub const fn effect_of(configured: DefaultEffect) -> Effect {
    match configured {
        DefaultEffect::Allow => Effect::Allow,
        DefaultEffect::Deny => Effect::Deny,
    }
}

/// The compiled policies of a directory, and the file each one was read from.
type LoadedPolicies = (Vec<CompiledPolicy>, BTreeMap<PolicyId, Source>);

/// Reads and compiles every policy file in a directory.
async fn read_directory(directory: &Path, resolver: &ContextResolver) -> Result<LoadedPolicies, PolicyStoreError> {
    if !fs::metadata(directory).await.is_ok_and(|metadata| metadata.is_dir()) {
        return Err(PolicyStoreError::NotADirectory { path: directory.to_path_buf() });
    }

    let mut files = Vec::new();
    let mut entries = fs::read_dir(directory).await.map_err(|source| PolicyStoreError::Unreadable {
        path: directory.to_path_buf(),
        source,
    })?;

    while let Some(entry) = entries.next_entry().await.map_err(|source| PolicyStoreError::Unreadable {
        path: directory.to_path_buf(),
        source,
    })? {
        let path = entry.path();

        if
        // Case-insensitive: `Deny.TOML` is a policy file, and skipping it silently would drop a deny.
        path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("toml")) {
            files.push(path);
        } else {
            // An editor backup, `deny.toml.bak`, or a subdirectory of policies is not loaded, and
            // an operator who expected it to be is told.
            warn!(file = %path.display(), "skipped: only files ending in .toml directly in the policy directory are loaded");
        }
    }

    // The filesystem returns entries in whatever order it likes. Sorting makes the duplicate-id
    // diagnostic name the same two files every time, and makes a load reproducible.
    files.sort();

    let mut compiled = Vec::new();
    let mut sources: BTreeMap<PolicyId, Source> = BTreeMap::new();

    for path in files {
        let in_file = read_file(&path, resolver).await?;
        let siblings = in_file.len();

        for policy in in_file {
            // Returning, so the first file's entry is taken rather than copied.
            if let Some(first) = sources.remove(&policy.id) {
                return Err(PolicyStoreError::DuplicateId {
                    id: policy.id,
                    first: first.path,
                    second: path,
                });
            }
            // The compiled policy and the source map each own their copy of the id and the path.
            sources.insert(policy.id.clone(), Source { path: path.clone(), siblings });
            compiled.push(policy);
        }
    }

    Ok((compiled, sources))
}

/// Reads, checks and compiles one policy file.
async fn read_file(path: &Path, resolver: &ContextResolver) -> Result<Vec<CompiledPolicy>, PolicyStoreError> {
    let source = fs::read_to_string(path).await.map_err(|source| PolicyStoreError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;

    let file: PolicyFile = toml::from_str(&source).map_err(|source| PolicyStoreError::Malformed {
        path: path.to_path_buf(),
        source,
    })?;

    // Resolved once per file. Every policy in it is written against the same declared context, so
    // resolving per policy would only be a chance for two of them to disagree.
    let context = resolver.resolve_declared(&file.context).await.map_err(|source| PolicyStoreError::Context {
        path: path.to_path_buf(),
        source,
    })?;

    let mut compiled = Vec::with_capacity(file.policy.len());

    for policy in &file.policy {
        check(policy, path)?;

        compiled.push(policy.compile(&context).map_err(|source| PolicyStoreError::Compile {
            path: path.to_path_buf(),
            source,
        })?);
    }

    info!(file = %path.display(), count = compiled.len(), "loaded policies");

    Ok(compiled)
}

/// The checks that do not need a context.
fn check(policy: &Policy, path: &Path) -> Result<(), PolicyStoreError> {
    if !policy.is_satisfiable() {
        return Err(PolicyStoreError::Unsatisfiable {
            id: policy.id.clone(), // the error outlives the borrowed policy
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_config::jsonld::JsonLd;
    use libra_log_capture::captured;
    use libra_policy_model::{aggregation::AggregationRestriction, duration::IsoDuration};
    use pretty_assertions::assert_eq;
    use std::{fs, time::Duration};
    use tempfile::TempDir;
    use tokio::{join, time::sleep};
    use url::Url;
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{method, path},
    };

    /// A resolver that will not reach the network, so a test's context is the core context alone.
    fn resolver() -> ContextResolver {
        ContextResolver::new(&JsonLd {
            allow_remote: false,
            allowed_contexts: Vec::new(),
            ..JsonLd::default()
        })
        .expect("the resolver should build")
    }

    fn directory(files: &[(&str, &str)]) -> TempDir {
        let directory = TempDir::new().expect("a temporary directory");

        for (name, contents) in files {
            fs::write(directory.path().join(name), contents).expect("the file should be written");
        }

        directory
    }

    const READ_VEHICLES: &str = r#"
        [[policy]]
        id = "fleet-read"
        priority = 100

        [policy.condition]
        roles = ["fleet-operator"]
        operations = ["read"]

        [policy.access]
        effect = "allow"
    "#;

    const SCOPED: &str = r#"
        [[policy]]
        id = "madrid-only"
        priority = 50

        [policy.access]
        effect = "allow"

        [policy.access.scope]
        allowed = ["/Madrid/#"]
    "#;

    const HOURLY: &str = r#"
        [[policy]]
        id = "hourly"
        priority = 50

        [policy.access]
        effect = "allow"

        [policy.access.aggregation]
        allowed-methods = ["avg"]
        min-period-duration = "PT1H"
    "#;

    async fn load(files: &[(&str, &str)]) -> Result<PolicyStore, PolicyStoreError> {
        let directory = directory(files);
        let store = PolicyStore::load(directory.path(), Effect::Deny, &resolver()).await;

        // The directory has to outlive the load, and only the load reads it.
        drop(directory);
        store
    }

    #[tokio::test]
    async fn a_directory_of_policies_loads() {
        let store = load(&[("fleet.toml", READ_VEHICLES)]).await.expect("the policies should load");

        assert_eq!(store.snapshot().len(), 1);
        assert!(store.snapshot().get(&PolicyId::new("fleet-read").unwrap()).is_some());
    }

    #[tokio::test]
    async fn a_policy_file_with_an_uppercase_extension_is_still_a_policy_file() {
        // A `Deny.TOML` holding a deny is loaded, not skipped without a word.
        let store = load(&[("Fleet.TOML", READ_VEHICLES)]).await.expect("the policies should load");

        assert!(store.snapshot().get(&PolicyId::new("fleet-read").unwrap()).is_some());
    }

    #[tokio::test]
    async fn a_policy_with_an_aggregation_restriction_loads_with_it() {
        let store = load(&[("hourly.toml", HOURLY)]).await.expect("the policy should load");
        let snapshot = store.snapshot();
        let hourly = snapshot
            .get(&PolicyId::new("hourly").unwrap())
            .and_then(|policy| policy.access.aggregation.as_deref());

        assert_eq!(
            hourly.and_then(AggregationRestriction::min_period_duration).map(IsoDuration::as_secs),
            Some(3600)
        );
    }

    #[tokio::test]
    async fn a_key_that_is_no_restriction_is_refused_and_names_the_file_and_the_key() {
        // A misspelling and a restriction nothing enforces look the same to the loader. Loading
        // either and ignoring it would read the policy as an unrestricted allow.
        for (written, file) in [("policy.access.scopes", "scopes.toml"), ("policy.access.ceiling", "ceiling.toml")] {
            let refused = load(&[(file, &SCOPED.replace("policy.access.scope", written))]).await;

            match refused {
                Err(PolicyStoreError::Malformed { path, source }) => {
                    assert!(path.ends_with(file), "{}", path.display());
                    assert!(source.to_string().contains(written.trim_start_matches("policy.access.")), "{source}");
                }
                other => panic!("an unknown restriction key must be refused, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_deny_carrying_a_restriction_fails_to_load() {
        // A deny refuses outright, so a restriction on one reads as a partial deny nothing enforces.
        let deny = r#"
            [[policy]]
            id = "no-madrid"
            priority = 900

            [policy.access]
            effect = "deny"

            [policy.access.scope]
            allowed = ["/Madrid/#"]
        "#;

        let refused = load(&[("deny.toml", deny)]).await;

        assert!(
            matches!(&refused, Err(PolicyStoreError::Compile { path, .. }) if path.ends_with("deny.toml")),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_deny_with_queries_fails_to_load() {
        let deny = r#"
            [[policy]]
            id = "no-vehicle-query"
            priority = 900

            [policy.condition]
            queries = ["?type=Vehicle"]

            [policy.access]
            effect = "deny"
        "#;

        assert!(matches!(load(&[("deny.toml", deny)]).await, Err(PolicyStoreError::Compile { .. })));
    }

    #[tokio::test]
    async fn an_aggregation_restriction_that_restricts_nothing_names_the_file() {
        let empty = HOURLY.replace("allowed-methods = [\"avg\"]", "").replace("min-period-duration = \"PT1H\"", "");
        let refused = load(&[("empty.toml", &empty)]).await;

        assert!(
            matches!(&refused, Err(PolicyStoreError::Malformed { path, .. }) if path.ends_with("empty.toml")),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn two_policies_with_one_identifier_are_refused() {
        // Which one applies would otherwise depend on the order the directory was read in.
        let refused = load(&[("a.toml", READ_VEHICLES), ("b.toml", READ_VEHICLES)]).await;

        assert!(
            matches!(refused, Err(PolicyStoreError::DuplicateId { .. })),
            "a repeated identifier must be refused, got {refused:?}"
        );
    }

    #[tokio::test]
    async fn a_policy_that_can_never_apply_is_refused() {
        // An empty list is not a wildcard. Written this way the policy reads as though it narrows
        // to some role, and narrows to none.
        let never = r#"
            [[policy]]
            id = "never"
            priority = 10

            [policy.condition]
            roles = []

            [policy.access]
            effect = "allow"
        "#;

        assert!(matches!(load(&[("never.toml", never)]).await, Err(PolicyStoreError::Unsatisfiable { .. })));
    }

    #[tokio::test]
    async fn a_term_the_declared_context_does_not_define_is_refused() {
        // The policy names a type nothing can resolve. Loading it would put a policy in force that
        // could never match anything, while reading as though it governed vehicles.
        let unknown = r#"
            [[policy]]
            id = "mystery"
            priority = 10

            [policy.condition]
            entity-types = ["NotInAnyContext__"]

            [policy.access]
            effect = "allow"
        "#;

        // The core context supplies a vocabulary, so an unknown term does expand, which is the
        // broker's own behaviour. A term that is a keyword cannot, and that is the real failure.
        let keyword = unknown.replace("NotInAnyContext__", "@type");

        assert!(matches!(load(&[("keyword.toml", &keyword)]).await, Err(PolicyStoreError::Compile { .. })));
    }

    #[tokio::test]
    async fn a_malformed_file_names_itself() {
        let refused = load(&[("broken.toml", "[[policy]]\nid = \"x\"")]).await;

        match refused {
            Err(PolicyStoreError::Malformed { path, .. }) => assert!(path.ends_with("broken.toml")),
            other => panic!("expected a parse failure naming the file, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_missing_directory_is_refused_rather_than_treated_as_empty() {
        // An empty policy set with a deny default is safe; a *missing* one usually means a volume
        // did not mount, and starting anyway hides that until the first request.
        let refused = PolicyStore::load(Path::new("/nonexistent/libra/policies"), Effect::Deny, &resolver()).await;

        assert!(matches!(refused, Err(PolicyStoreError::NotADirectory { .. })));
    }

    #[tokio::test]
    async fn a_failed_reload_leaves_the_running_policy_set_in_place() {
        let directory = directory(&[("fleet.toml", READ_VEHICLES)]);
        let store = PolicyStore::load(directory.path(), Effect::Deny, &resolver())
            .await
            .expect("the policies should load");

        fs::write(directory.path().join("broken.toml"), "[[policy]]\nid = \"x\"").expect("the file should be written");

        assert!(store.reload(&resolver()).await.is_err());
        assert_eq!(
            store.snapshot().len(),
            1,
            "a reload that failed must not leave the process with a policy set nobody wrote"
        );
        assert!(store.snapshot().get(&PolicyId::new("fleet-read").unwrap()).is_some());
    }

    #[tokio::test]
    async fn a_successful_reload_replaces_the_set() {
        let directory = directory(&[("fleet.toml", READ_VEHICLES)]);
        let store = PolicyStore::load(directory.path(), Effect::Deny, &resolver())
            .await
            .expect("the policies should load");

        fs::write(directory.path().join("scoped.toml"), SCOPED).expect("the file should be written");

        assert_eq!(store.reload(&resolver()).await.expect("the reload should succeed"), 2);
        assert_eq!(store.snapshot().len(), 2);
    }

    /// The minimum period of the `hourly` policy in a snapshot, in seconds.
    fn minimum(snapshot: &PolicySnapshot) -> Option<u64> {
        snapshot
            .get(&PolicyId::new("hourly").unwrap())
            .and_then(|policy| policy.access.aggregation.as_deref())
            .and_then(AggregationRestriction::min_period_duration)
            .map(IsoDuration::as_secs)
    }

    #[tokio::test]
    async fn a_reload_replaces_a_restriction_and_leaves_earlier_snapshots_alone() {
        let directory = directory(&[("hourly.toml", HOURLY)]);
        let store = PolicyStore::load(directory.path(), Effect::Deny, &resolver())
            .await
            .expect("the policies should load");
        let before = store.snapshot();

        fs::write(directory.path().join("hourly.toml"), HOURLY.replace("PT1H", "PT2H")).expect("the file should be written");
        store.reload(&resolver()).await.expect("the reload should succeed");

        assert_eq!(
            minimum(&before),
            Some(3600),
            "a request that began before the reload keeps the set it began with"
        );
        assert_eq!(minimum(&store.snapshot()), Some(7200));
    }

    #[tokio::test]
    async fn a_failed_reload_keeps_the_previous_restriction() {
        let directory = directory(&[("hourly.toml", HOURLY)]);
        let store = PolicyStore::load(directory.path(), Effect::Deny, &resolver())
            .await
            .expect("the policies should load");

        fs::write(directory.path().join("hourly.toml"), HOURLY.replace("min-period-duration", "min-period")).expect("the file should be written");

        assert!(store.reload(&resolver()).await.is_err());
        assert_eq!(minimum(&store.snapshot()), Some(3600));
    }

    #[tokio::test]
    async fn a_reload_that_started_first_cannot_replace_the_set_a_later_reload_read() {
        // The first reload reads a file whose context answers after 400 ms; the second starts
        // 100 ms in, after the file was replaced. Run side by side, the second would store first
        // and the first would then overwrite it with the set it read before the change.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow.jsonld"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"@context": {}}"#)
                    .set_delay(Duration::from_millis(400)),
            )
            .mount(&server)
            .await;
        let slow = ContextResolver::new(&JsonLd {
            allow_remote: true,
            allowed_contexts: vec![Url::parse(&server.uri()).unwrap()],
            ..JsonLd::default()
        })
        .unwrap();

        let directory = directory(&[("fleet.toml", READ_VEHICLES)]);
        let store = PolicyStore::load(directory.path(), Effect::Deny, &resolver())
            .await
            .expect("the policies should load");
        let older = format!("context = [\"{}/slow.jsonld\"]\n{}", server.uri(), SCOPED);
        fs::write(directory.path().join("older.toml"), older).expect("the file should be written");

        let (first, second) = join!(store.reload(&slow), async {
            sleep(Duration::from_millis(100)).await;
            fs::remove_file(directory.path().join("older.toml")).expect("the file should be removed");
            fs::write(directory.path().join("newer.toml"), HOURLY).expect("the file should be written");
            store.reload(&resolver()).await
        });

        assert!(first.is_ok() && second.is_ok(), "{first:?} {second:?}");
        assert!(
            store.snapshot().get(&PolicyId::new("hourly").unwrap()).is_some(),
            "the set read last is the one in force"
        );
        assert!(store.snapshot().get(&PolicyId::new("madrid-only").unwrap()).is_none());
    }

    #[tokio::test]
    async fn a_file_that_is_not_loaded_is_named_in_a_warning() {
        let directory = directory(&[("fleet.toml", READ_VEHICLES), ("deny.toml.bak", SCOPED)]);
        fs::create_dir(directory.path().join("nested")).expect("the directory should be created");

        let (store, records) = captured(PolicyStore::load(directory.path(), Effect::Deny, &resolver())).await;

        assert_eq!(store.expect("the policies should load").snapshot().len(), 1);
        for skipped in ["deny.toml.bak", "nested"] {
            assert!(
                records
                    .iter()
                    .any(|record| record.level == tracing::Level::WARN && record.field("file").is_some_and(|file| file.ends_with(skipped))),
                "{skipped} must be named in a warning"
            );
        }
    }

    #[tokio::test]
    async fn the_configured_default_effect_reaches_the_snapshot() {
        assert_eq!(effect_of(DefaultEffect::Deny), Effect::Deny);
        assert_eq!(effect_of(DefaultEffect::Allow), Effect::Allow);
    }
}
