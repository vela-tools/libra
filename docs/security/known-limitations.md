# Known limitations

Libra is an open beta and has not been independently audited. This page lists what this release does not defend, and the behaviours it accepts on purpose. An unstated gap is harder to plan around than a known one, so each entry says what a deployment does about it. [The threat model](threat-model.md) states what Libra does defend, and against whom.

## Not defended

These are outside what Libra protects. A deployment covers each of them some other way, or accepts the risk knowingly.

> [!CAUTION]
> **Notifications do not pass through Libra.** An NGSI-LD subscription makes the broker push to an endpoint of the subscriber's choosing, directly. Libra governs the request that creates the subscription. A restricted caller cannot read, change or delete an existing subscription, and a subscription it creates is narrowed to its restriction. But a subscription created outside those rules, by a caller without restrictions or before the policy set narrowed, pushes whatever it matches straight to its endpoint, and no restriction follows it. Subscriptions are also shared by every caller of a tenant and record nothing of who created them, so an unrestricted allow naming `subscriptions` is administrative. Govern who may hold one, or keep subscriptions off the broker Libra fronts. [An integrator that manages subscriptions](../policies/cookbook.md#an-integrator-that-manages-subscriptions) shows a policy for it.

> [!CAUTION]
> **Flooding faster than the ceiling drains is somebody else's layer.** This edition ships a ceiling on how many requests are in flight at once (`[limits] max-in-flight-requests`, 256 by default), and no rate limiter. The ceiling bounds how much a flood can hold at once. Each in-flight request pins memory and, once forwarded, a broker connection, and the rest are answered 503. The ceiling does not bound how many requests arrive. A flood that keeps the ceiling full is answered with refusals rather than exhaustion. Keeping honest traffic served through that is the job of whatever stands in front of Libra, such as an edge proxy, an ingress or a firewall. Libra bounds what a single request can cost: the payload it may carry, the time it may take, and the extra broker calls a pre-flight or a linked retrieval may make.

> [!CAUTION]
> **Answers about distributed operations name the sources involved.** When the broker forwards an operation to context sources registered with it (NGSI-LD clause 5.12), its answer can say which source failed. A 207 Multi-Status body lists a `registrationId` beside each entity or attribute that was not changed (clauses 5.2.17 and 5.2.19). The problem details of a 502, 504 or 508 from an exclusive or redirect registration may name the source in their text. The `NGSILD-Warning` header on a distributed retrieval names the source as its warn-agent (clause 6.3.17). Libra passes all of these to the caller as the broker wrote them, the same as every other broker error body. A caller who may write entities but not read registrations can learn a registration's id, and sometimes a source's address, from a failed write. What it cannot learn is what a registration carries for its source: `contextSourceInfo` is withheld from every caller who may not write registrations. A deployment that treats its source topology as confidential keeps distributed operations off the tenants untrusted callers write to, or registers its sources under host aliases that say nothing.

> [!CAUTION]
> **The broker's own behaviour.** Libra mirrors the context rules the broker follows, and brokers disagree with each other on the details. Where they diverge, Libra refuses rather than guessing. The parity harness still has to be run against the broker a deployment fronts, with its version pinned. "The specification says so" does not predict what the thing behind the proxy will do.

> [!CAUTION]
> **Data at rest, and anything inside the broker.** Libra decides who may make a request. It does not encrypt, audit, or govern what the broker does with what it stores.

> [!CAUTION]
> **A compromised identity provider.** Libra trusts the signing keys it is pointed at. Whoever controls them controls every identity.

> [!CAUTION]
> **A withdrawn signing key works until the next key refresh.** Libra fetches the key set every `jwks-cache-duration` seconds (3600 by default, at most 86400), and fetches early only for a key id it has not seen. A key the identity provider withdraws, after a leak for instance, keeps verifying tokens for up to that long. An operator who withdraws a key in response to a compromise restarts Libra, which fetches the key set before it serves. A deployment that cannot afford the window lowers `jwks-cache-duration`.

> [!CAUTION]
> **Denial of service by an allowed caller.** A caller who is allowed to run expensive queries can run them. An aggregation restriction narrows what trends reveal. It does not limit what they cost the broker.

> [!CAUTION]
> **Availability.** The supported deployment is one instance, and its failover is external. This edition ships no replication and no shared state between instances. [One instance](../deployment.md#one-instance) describes the deployment.

## Accepted behaviours

These are behaviours of this release, not open defects. Each follows from the NGSI-LD specification or from a default chosen so that common identity providers work.

> [!WARNING]
> **An identifier in use is visible across types.** A create of an allowed type whose identifier is already held by an entity of another type is answered with the `409 Conflict` NGSI-LD requires. A restricted caller learns that the identifier is in use, and nothing about the entity holding it. Indistinguishable absence in [the threat model](threat-model.md#what-is-defended-and-by-what) covers the rest of that guarantee.

> [!WARNING]
> **The type and attribute index is not narrowed by scope.** A caller restricted by scope alone reads the full `/types` and `/attributes` index, because the index carries no scope dimension to filter by (ETSI GS CIM 009 v1.9.1 clause 5.7.5). Type names and counts outside what the restriction allows are visible there. Hiding entity types takes an [entity type restriction](../policies/entity-type-restriction.md).

> [!WARNING]
> **ID tokens are accepted by default.** `[jwt] token-type` defaults to `"any"`, because many identity providers do not mark access tokens with `typ` `at+jwt` by default, and some (Microsoft Entra ID, Okta) cannot. Under that default, an ID token signed for the configured audience is accepted as an access token. Set `token-type = "at-jwt"` whenever the provider emits that type. [What a token must pass](../authentication/jwt.md#what-a-token-must-pass) lists every check.

## Reporting

Weaknesses that are not yet fixed are tracked as private advisories and published once fixed, so they are not on this page. A gap that is not listed here and lets a caller past a policy is a vulnerability. Report it as [SECURITY.md](../../SECURITY.md) describes, not through a public issue.
