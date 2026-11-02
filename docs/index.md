# Libra documentation

> **Beta.** Libra has not been independently audited. Do not put it in front of production data yet. [Known limitations](security/known-limitations.md) lists what this release does not defend.

Libra is an authentication and authorization proxy in front of an NGSI-LD context broker. It authenticates the caller, decides against a policy set, narrows the request to what the policy allows, forwards it to the broker, and filters the response on its way back. Libra stores no context data. The pages run in the order you are likely to need them: stand up the proxy, authenticate callers, write policies that govern them, read how enforcement works, verify it, and look up the rest.

## Run it

| Page | Covers |
| --- | --- |
| [Getting started](getting-started.md) | From nothing to an authenticated, policy-governed request, with API keys and with JWTs |
| [Deployment](deployment.md) | The container image, verification, probes, trusted proxies, one instance, shutdown, upgrades |
| [Operations](operations.md) | The routes outside the NGSI-LD path, their gates, the metrics series, what to alert on, the audit record, changing the policy set, logging, and correlating one request |
| [Troubleshooting](troubleshooting.md) | Startup refusals, what each status code means, reading the logs, and why a change did not take effect |

## Authenticate callers

| Page | Covers |
| --- | --- |
| [Authentication](authentication/index.md) | The two credential kinds, the identity each produces, and the map of pages |
| [API keys](authentication/api-keys.md) | Machine identities Libra issues itself: principals, issuance, rotation, revocation, the key store |
| [JWT access tokens](authentication/jwt.md) | The `[jwt]` section, what a token must pass, what Libra reads, the key set |
| [Keycloak](authentication/keycloak.md) | Realm setup, mappers for top-level groups and roles, the audience, `at+jwt` |

## Write policies

| Page | Covers |
| --- | --- |
| [Writing policies](policies/index.md) | Policy files, the context declaration, conditions, precedence, and the map of restrictions |
| [Attribute restriction](policies/attribute-restriction.md) | Which attributes a caller may see and name, and the filters that would leak them |
| [Entity type restriction](policies/entity-type-restriction.md) | Which entity types a caller may see and write |
| [Scope restriction](policies/scope-restriction.md) | Which hierarchical scopes apply: any-scope reads and all-scope writes |
| [Time restriction](policies/time-restriction.md) | Which slice of the data's history, for temporal and current-state reads |
| [Aggregation restriction](policies/aggregation-restriction.md) | Trends instead of raw readings: methods, minimum period, and the grid |
| [Linked entity retrieval](policies/linked-entity-retrieval.md) | What a join asks for, and how a restriction judges a join answer |
| [Context source registrations](policies/context-source-registrations.md) | How each restriction judges a registration, and what a reader is shown |
| [Policy cookbook](policies/cookbook.md) | Policy sets to copy from: administrators, tenant-scoped principals, public reads, suspensions, trends, office hours, subscriptions, progressive hardening |

## Examples

| Page | Covers |
| --- | --- |
| [Examples](examples/index.md) | The conventions the example pages share, and the map of scenarios |
| [Smart-city fleet](examples/smart-city-fleet.md) | Hiding `location` from a dispatch room, end to end through config, policies, keys and requests |
| [Multi-tenant dataspace](examples/multi-tenant-dataspace.md) | Two tenants on one broker, `NGSILD-Tenant`, the `tenants` condition, and what an unnamed tenant gets |
| [Read-only dashboard](examples/read-only-dashboard.md) | Hourly averages for a week and nothing else, with aggregation and time restrictions together |
| [Federation](examples/federation.md) | A context source registration pointing at a second Libra, and a filter refused at the far hop |
| [API key onboarding](examples/api-key-onboarding.md) | The runbook around keys: issue, verify, rotate, revoke, remove, and the key store lease |

## How it works

| Page | Covers |
| --- | --- |
| [The request path](request-path.md) | Layer order, where each decision is made once, and what the order protects |
| [Architecture](architecture.md) | The composition root, which concern owns a Tower layer, and how a build extends the proxy |
| [Editions](editions.md) | What the FOSS edition holds permanently, what Pro covers, and which way the line moves |

## Trust and verify

| Page | Covers |
| --- | --- |
| [Threat model](security/threat-model.md) | Trust boundaries, the attacker model, and the fail-closed guarantees |
| [Known limitations](security/known-limitations.md) | What this release does not defend, and the behaviours it accepts |
| [Testing](testing.md) | The workspace tests, the end-to-end suite against a broker, and the broker parity harness |

## Reference

| Page | Covers |
| --- | --- |
| [Command-line reference](reference/cli.md) | Every subcommand and flag of the `libra` binary, generated from the definitions themselves |
| [Configuration reference](reference/configuration.md) | Every section, every key, every default, and the environment overrides |
| [Error catalog](reference/errors.md) | Every problem type Libra answers with, what produces it, what to do, and the startup failures |
| [Broker parity](reference/jsonld-broker-parity.md) | Observed broker behaviour for `@context` handling, and the rules Libra mirrors |
| [Multi-scope semantics](reference/multi-scope-semantics.md) | What several scopes on one entity mean for a scope restriction, and the reading Libra implements |
| [Glossary](reference/glossary.md) | The one word Libra uses for each concept of its policy language |

Editions: this repository is the FOSS edition, complete on its own and licensed under the EUPL-1.2. [Editions](editions.md) says what Pro adds around it and states the permanence guarantee. Reporting a vulnerability: [SECURITY.md](../SECURITY.md).
