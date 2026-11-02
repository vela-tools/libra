//! API keys, end to end: issued by the binary's own commands against the store a serving proxy
//! reads, presented by a caller, and seen by the broker.
//!
//! The upstream is an origin of the test's own, so each test can see what the broker would be told
//! about a key holder.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings, stack::Endpoints};
use reqwest::StatusCode;
use std::path::Path;
use tempfile::TempDir;

/// Whatever the origin is asked for, it answers with this.
const ANSWER: &str = r#"{"answered":true}"#;

/// Allows reads to the `fleet` group, and nothing to anyone else.
const FLEET_READS: &str = r#"
[[policy]]
id = "fleet-read"
priority = 100

[policy.condition]
groups = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

/// The read every test makes.
const QUERY: &str = "/ngsi-ld/v1/entities?type=Vehicle";

/// The settings of a proxy forwarding to `origin` and reading the key store at `store`.
fn settings(stack: &Endpoints, origin: &Origin, store: &Path) -> ProxySettings {
    ProxySettings {
        upstream: origin.address(),
        key_store: Some(store.to_path_buf()),
        ..ProxySettings::new(stack, FLEET_READS)
    }
}

/// Runs a command against the proxy's configuration and returns what it printed, failing the test
/// if it did not succeed.
fn command(proxy: &Proxy, arguments: &[&str]) -> String {
    let output = proxy.command(arguments);
    assert!(
        output.status.success(),
        "libra {arguments:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("the command prints text")
}

/// Creates a principal with these extra arguments and issues it a key, returning the key and its id.
fn issue(proxy: &Proxy, name: &str, membership: &[&str]) -> (String, String) {
    let mut create = vec!["principal", "create", name];
    create.extend_from_slice(membership);
    command(proxy, &create);

    let printed = command(proxy, &["key", "create", "--principal", name, "--expires-in", "1d"]);
    let field = |label: &str| {
        printed
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .map(str::trim)
            .expect("the key creation report has the field")
            .to_owned()
    };

    (field("key:"), field("id:"))
}

fn read(proxy: &Proxy, key: &str) -> StatusCode {
    proxy.get(QUERY).bearer_auth(key).send().expect("the proxy should answer").status()
}

#[test]
fn a_key_reads_as_its_principal_and_the_broker_is_told_who_that_is() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let proxy = Proxy::start(&settings(&stack, &origin, &store.path().join("keys.db")));

    let (key, _) = issue(&proxy, "ingest", &["--group", "fleet", "--role", "writer"]);

    assert_eq!(read(&proxy, &key), StatusCode::OK);

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    // The principal's URN, never its name as a username: the broker must not mistake it for an
    // account the identity provider vouches for.
    assert!(
        forwarded
            .header("x-auth-subject")
            .is_some_and(|subject| subject.starts_with("urn:libra:principal:")),
        "{:?}",
        forwarded.header("x-auth-subject")
    );
    assert_eq!(forwarded.header("x-auth-username"), None);
    assert_eq!(forwarded.header("x-auth-groups"), Some("fleet"));
    assert_eq!(forwarded.header("x-auth-roles"), Some("writer"));
    assert_eq!(forwarded.header("x-auth-machine"), Some("true"));
    assert_eq!(forwarded.header("x-auth-email"), None);
    // A key is a long-lived secret, and the broker learns who asked from the headers above.
    assert_eq!(forwarded.header("authorization"), None, "the key stops at Libra");
}

#[test]
fn a_deployment_with_api_keys_alone_accepts_a_key_and_refuses_a_jwt() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let proxy = Proxy::start(&ProxySettings {
        jwt: None,
        ..settings(&stack, &origin, &store.path().join("keys.db"))
    });

    let (key, _) = issue(&proxy, "ingest", &["--group", "fleet"]);

    assert_eq!(read(&proxy, &key), StatusCode::OK);
    assert_eq!(
        read(&proxy, &token("writer")),
        StatusCode::UNAUTHORIZED,
        "with no [jwt] nothing recognizes a JWT, however well it is signed"
    );
}

#[test]
fn a_revoked_key_is_refused_from_the_next_request_without_a_restart() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let proxy = Proxy::start(&settings(&stack, &origin, &store.path().join("keys.db")));
    let (key, id) = issue(&proxy, "ingest", &["--group", "fleet"]);
    assert_eq!(read(&proxy, &key), StatusCode::OK);

    command(&proxy, &["key", "revoke", &id]);

    assert_eq!(read(&proxy, &key), StatusCode::UNAUTHORIZED);
}

#[test]
fn a_key_that_was_altered_or_never_issued_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let proxy = Proxy::start(&settings(&stack, &origin, &store.path().join("keys.db")));
    let (key, id) = issue(&proxy, "ingest", &["--group", "fleet"]);

    // One character of the secret changed: refused by its checksum.
    let mut mistyped = key.clone();
    let last = mistyped.pop().expect("a key is not empty");
    mistyped.push(if last == '2' { '3' } else { '2' });
    assert_eq!(read(&proxy, &mistyped), StatusCode::UNAUTHORIZED);

    // A well-formed id nothing was issued under, with a valid secret.
    let other_id = format!("{}{}", &id[..25], if id.ends_with('0') { '1' } else { '0' });
    assert_eq!(read(&proxy, &key.replacen(&id, &other_id, 1)), StatusCode::UNAUTHORIZED);

    assert_eq!(read(&proxy, "libra_not-a-key"), StatusCode::UNAUTHORIZED);
    assert!(origin.last_request().is_none(), "nothing refused reaches the broker");
}

#[test]
fn a_principal_the_policy_does_not_name_is_authenticated_but_not_authorized() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let proxy = Proxy::start(&settings(&stack, &origin, &store.path().join("keys.db")));

    let (key, _) = issue(&proxy, "outsider", &["--group", "visitors"]);

    assert_eq!(read(&proxy, &key), StatusCode::FORBIDDEN);
}

/// Allows tenant `accounts` to the account `ingest`, and tenant `principals` to the principal
/// `ingest`: the same name, in each of the two namespaces.
const BY_NAME: &str = r#"
[[policy]]
id = "account-ingest"
priority = 100

[policy.condition]
users = ["ingest"]
tenants = ["accounts"]
operations = ["read"]

[policy.access]
effect = "allow"

[[policy]]
id = "principal-ingest"
priority = 100

[policy.condition]
principals = ["ingest"]
tenants = ["principals"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

#[test]
fn a_policy_naming_a_user_does_not_admit_a_principal_of_that_name() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let proxy = Proxy::start(&ProxySettings {
        upstream: origin.address(),
        key_store: Some(store.path().join("keys.db")),
        ..ProxySettings::new(&stack, BY_NAME)
    });
    let (key, _) = issue(&proxy, "ingest", &[]);

    let read_on = |tenant: &str| {
        proxy
            .get(QUERY)
            .header("NGSILD-Tenant", tenant)
            .bearer_auth(&key)
            .send()
            .expect("the proxy should answer")
            .status()
    };

    assert_eq!(read_on("accounts"), StatusCode::FORBIDDEN);
    assert_eq!(read_on("principals"), StatusCode::OK);
}

#[test]
fn a_second_instance_on_the_same_key_store_refuses_to_start() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let path = store.path().join("keys.db");
    let _first = Proxy::start(&settings(&stack, &origin, &path));

    let refusal = Proxy::start_expecting_failure(&settings(&stack, &origin, &path));

    assert!(refusal.contains("holds the key store's lease"), "{refusal}");
}

#[test]
fn a_principal_named_as_an_administrator_or_holding_an_admin_role_passes_the_management_gate() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let store = TempDir::new().expect("a temporary directory");
    let proxy = Proxy::start(&settings(&stack, &origin, &store.path().join("keys.db")));

    // The harness configures `admin-principals = ["operator"]` and `admin-roles = ["libra-admin"]`.
    let (operator, _) = issue(&proxy, "operator", &[]);
    let (by_role, _) = issue(&proxy, "monitor", &["--role", "libra-admin"]);
    let (ingest, _) = issue(&proxy, "ingest", &["--group", "fleet"]);

    let info = |key: &str| {
        proxy
            .get("/ngsi-ld/auth/info")
            .bearer_auth(key)
            .send()
            .expect("the proxy should answer")
            .status()
    };

    assert_eq!(info(&operator), StatusCode::OK);
    assert_eq!(info(&by_role), StatusCode::OK);
    assert_eq!(info(&ingest), StatusCode::FORBIDDEN);
}
