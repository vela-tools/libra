# Editions

Libra is open core. This repository is the FOSS edition, licensed under the EUPL-1.2. Libra Pro is a separate, proprietary binary built on top of it through the extension points [Architecture](architecture.md) describes. This page says where the line between the two runs and which way it can move.

## The rule

The FOSS edition is complete on its own. It authenticates, decides and enforces without a licence key, an account, or a call-home check. Pro adds operational capabilities around the same proxy.

The line only moves towards FOSS. Everything released in the FOSS edition stays there permanently. A feature released here is never moved to Pro later, and never withdrawn to create an upgrade path. A Pro feature can be released to FOSS at any time.

## What the FOSS edition holds, permanently

- Every restriction kind and its enforcement: entity type, attribute, scope, time and aggregation, on reads, writes, joins, subscriptions and context source registrations.
- Authentication with API keys Libra issues and stores itself, managed from the command line, and generic JWT verification against a configured issuer and key set.
- The full audit record: one structured line per request, allowed or refused, with an optional fingerprint of the presented credential.
- Self-protection: the upstream timeout, the response deadline, stalled-body detection, payload limits, the in-flight request ceiling, and hard bounds on paths that amplify one request into several.
- The probes, build info and Prometheus metrics.

## What Pro covers

Pro is in development. Its scope is what follows, and [velacontext.com](https://velacontext.com) has its status.

- **Policy management.** An HTTP API to inspect, add, change and remove policies while Libra runs. A policy accepted through it goes through the same parsing, context compilation and capability check as one loaded at startup, and a change that fails any of them leaves the running set untouched. Hot reload applies an edited policy directory without a restart, on a signal or through the API.
- **Key management.** An HTTP API for principals and keys, with last-used tracking and expiry notices, beside the command line the FOSS edition has.
- **Several replicas.** Libra running as more than one instance behind a load balancer. The key store moves to a PostgreSQL database every replica shares, so a key issued or revoked on one replica holds on every replica from its next request, and a policy change reaches every replica.
- **Resilience.** Keeping Libra serving when the broker is slow, failing or unavailable.
- **Rate limiting.** Limits by what Libra knows after authentication: per principal, per tenant, per operation and per entity type. Limiting per client address is left to the gateway or ingress in front of Libra.
- **NGSI-LD response cache.** A cache of entity reads, temporal reads and the type and attribute indices, placed below authorization so that an answer is only ever served to a request that reached the same decision. A write through Libra invalidates what it touched, by entity and by type. Subscriptions, context source registrations and batch queries are never cached.
- **Request deduplication.** Concurrent identical reads from callers with the same identity and decision share one broker request.
- **Identity provider integration.** OpenID Connect discovery, provider-specific claim mapping such as Keycloak roles, token introspection, token exchange, several issuers at once, and data space trust.
- **Federation.** What only a distributed deployment needs: an end-user identity carried across a federation, trust between chained Libra instances, outbound credentials held by Libra for registered context sources, and entity maps bound to the caller that created them.

A security defect is never a Pro feature. When a distributed deployment or a Pro feature exposes a flaw in the FOSS edition, the fix lands in the FOSS edition.
