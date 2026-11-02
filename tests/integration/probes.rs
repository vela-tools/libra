//! Health, readiness and metrics, on the running proxy.

use libra_test_harness::{identity::token, origin::address, proxy::Proxy, proxy_settings::ProxySettings};
use reqwest::StatusCode;

#[test]
fn health_is_served_without_a_token() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ""));

    let response = proxy.get("/ngsi-ld/auth/health").send().expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK, "a liveness probe cannot be asked to authenticate");
}

#[test]
fn readiness_passes_when_the_broker_and_the_keys_are_reachable() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ""));

    let response = proxy.get("/ngsi-ld/auth/ready").send().expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the stack is up, so readiness should report ready: {}",
        response.text().unwrap_or_default()
    );
}

#[test]
fn readiness_fails_when_the_broker_is_unreachable() {
    let stack = require_stack!();
    // A port nothing serves. Liveness stays green because the process is fine; readiness is the
    // probe that is supposed to notice, and a gateway that reports ready without a broker behind
    // it takes traffic it can only answer with 502.
    let settings = ProxySettings {
        upstream: address("http://127.0.0.1:1"),
        ..ProxySettings::new(&stack, "")
    };
    let proxy = Proxy::start(&settings);

    assert_eq!(
        proxy.get("/ngsi-ld/auth/health").send().expect("the proxy should answer").status(),
        StatusCode::OK
    );
    assert_eq!(
        proxy.get("/ngsi-ld/auth/ready").send().expect("the proxy should answer").status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn metrics_are_refused_without_a_privileged_caller() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ""));

    let anonymous = proxy.get("/ngsi-ld/auth/metrics").send().expect("the proxy should answer");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED, "metrics name every route and every tenant in use");

    let ordinary = proxy
        .get("/ngsi-ld/auth/metrics")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert_eq!(ordinary.status(), StatusCode::FORBIDDEN, "authenticating is not the same as being privileged");
}

#[test]
fn metrics_are_served_to_a_privileged_caller() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ""));

    // The exporter has nothing to say until something has been measured, and the probes are
    // excluded from measurement on purpose, so a proxied request has to happen first.
    proxy.get("/ngsi-ld/v1/entities?type=Vehicle").send().expect("the proxy should answer");

    let response = proxy
        .get("/ngsi-ld/auth/metrics")
        .bearer_auth(token("admin"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.text().unwrap_or_default().contains("# TYPE"),
        "the metrics endpoint should answer in the Prometheus exposition format"
    );
}

#[test]
fn metrics_can_be_opened_to_any_authenticated_caller() {
    let stack = require_stack!();
    // The other half of the switch: a deployment that scrapes with an ordinary service account.
    // Worth pinning, because the failure mode of a privilege flag is that it does nothing.
    let settings = ProxySettings {
        metrics_access: "authenticated",
        ..ProxySettings::new(&stack, "")
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/auth/metrics")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn build_info_is_served_to_a_privileged_caller_and_nobody_else() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ""));

    // Which commit a gateway is running decides which known vulnerabilities apply to it, so this is
    // the one management gate that starts closed.
    let anonymous = proxy.get("/ngsi-ld/auth/info").send().expect("the proxy should answer");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let ordinary = proxy
        .get("/ngsi-ld/auth/info")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert_eq!(ordinary.status(), StatusCode::FORBIDDEN);

    let privileged = proxy
        .get("/ngsi-ld/auth/info")
        .bearer_auth(token("admin"))
        .send()
        .expect("the proxy should answer");
    assert_eq!(privileged.status(), StatusCode::OK);
    assert!(privileged.text().unwrap_or_default().contains("\"name\":\"libra\""));
}
