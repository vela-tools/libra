//! What happens when a file asks for something this binary does not read.
//!
//! A policy carrying a key that is no restriction, or a configuration with a section nothing
//! claims, stops the process. A proxy that loaded either and ignored it would answer requests the
//! policy never allowed, or run without a cache the operator believes is on.

use libra_test_harness::{proxy::Proxy, proxy_settings::ProxySettings};

/// A policy carrying a restriction under a misspelled key.
const MISSPELLED: &str = r#"
[[policy]]
id = "madrid-only"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scopes]
allowed = ["/Madrid/#"]
"#;

/// A policy that loads, so a test about a section is not also a test about a policy.
const PLAIN: &str = r#"
[[policy]]
id = "readers"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

#[test]
fn a_misspelled_restriction_stops_the_process() {
    let stack = require_stack!();
    let reported = Proxy::start_expecting_failure(&ProxySettings::new(&stack, MISSPELLED));

    assert!(reported.contains("scopes"), "the refusal should name what was written: {reported}");
}

#[test]
fn a_configuration_section_nothing_reads_stops_the_process() {
    let stack = require_stack!();
    let settings = ProxySettings {
        extra_sections: "[cache]\nenabled = true\n".to_owned(),
        ..ProxySettings::new(&stack, PLAIN)
    };
    let reported = Proxy::start_expecting_failure(&settings);

    assert!(reported.contains("cache"), "the refusal should name the section: {reported}");
}

#[test]
fn a_rate_limit_section_stops_the_process() {
    // Nothing in this build limits request rates. A file that configures a limit and is served
    // without one would leave the operator believing a flood is shed when it is not.
    let stack = require_stack!();
    let settings = ProxySettings {
        extra_sections: "[governor]\nenabled = true\n".to_owned(),
        ..ProxySettings::new(&stack, PLAIN)
    };
    let reported = Proxy::start_expecting_failure(&settings);

    assert!(reported.contains("governor"), "the refusal should name the section: {reported}");
}

#[test]
fn a_misspelled_configuration_section_stops_the_process() {
    let stack = require_stack!();
    let settings = ProxySettings {
        extra_sections: "[managment-api]\nadmin-users = [\"ops\"]\n".to_owned(),
        ..ProxySettings::new(&stack, PLAIN)
    };
    let reported = Proxy::start_expecting_failure(&settings);

    assert!(reported.contains("managment-api"), "the refusal should name what was written: {reported}");
}

#[test]
fn a_policy_whose_terms_have_no_meaning_stops_the_process() {
    let stack = require_stack!();
    // Nothing can load this: the policy
    // declares a context, nothing may fetch it, and a policy whose terms cannot be compiled to IRIs
    // cannot be said to allow or refuse anything. Loading it would put a policy in force that its
    // author believes governs vehicles and which in fact governs nothing.
    let policies = r#"
context = ["https://elsewhere.test/context.jsonld"]

[[policy]]
id = "unresolvable"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"
"#;

    let reported = Proxy::start_expecting_failure(&ProxySettings::new(&stack, policies));

    assert!(!reported.trim().is_empty(), "the process should say why it refused to start");
}
