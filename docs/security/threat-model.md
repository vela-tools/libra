# Threat model

Libra is the only thing between a caller and the data behind it, so a defect in it is usually a bypass for everything it protects. This page says what Libra defends, against whom, and what it does not.

## The shape of the deployment

```
client ──▶ Libra ──▶ context broker
              │
              └──▶ identity provider (JWKS), when JWTs are accepted
```

The broker has no authentication of its own. It trusts what arrives, so the identity headers Libra injects are the caller, as far as everything downstream is concerned.

Two trust boundaries follow:

1. **Client to Libra.** Everything the client controls is hostile input: the credential, the tenant header, every other header, the path, the query string, the body, and the JSON-LD context that decides what the names in all of them mean.
2. **Libra to broker.** Everything Libra sends is trusted absolutely. A header a caller could smuggle through is a header they wrote themselves.

A third boundary sits at the filesystem. Whoever can write the key store or the policy directory decides who gets in. Protect both like credentials. They mark where this model ends and the operator's responsibility begins.

The broker must not be reachable except through Libra. Nothing in this document survives a network where the broker is reachable directly.

## Who the attacker is

| Attacker | Holds | Wants |
| --- | --- | --- |
| Anonymous caller | Nothing | Any data at all; a way past authentication |
| Authenticated caller | A valid key or token | Another tenant's data; attributes their policy hides; a slice of history their policy does not allow; another caller's response |
| Realm participant | The ability to have roles or groups created | A name that satisfies a policy written about somebody else |
| Another tenant's caller | A valid credential for their own tenant | To read or write across the tenant line |
| Network position between Libra and the broker | Traffic | To inject identity headers directly |

The last one is out of scope. It is defended by keeping the broker off a reachable network, not by Libra.

## What is defended, and by what

**Authentication.** A JWT is checked against the signing keys of the configured issuer, with rotation and a clock-skew tolerance. `exp` is required and checked, and `nbf` is checked when present. The issuer and the audience are *required* claims. A token omitting one is refused rather than passing a check that had nothing to compare. A token issued for another client of the same provider does not pass. An API key is checked against a digest. The key itself is nowhere in Libra. A mistyped key is refused before any lookup, comparison is constant time, every key carries an expiry, and a revocation takes effect on the next request. The caller's credential stops at Libra. The `Authorization` header is removed once the caller is authenticated, and a request carrying more than one is refused.

**Tenant isolation.** The tenant is an input to the authorization decision. Libra does not treat it as a routing detail. An empty `NGSILD-Tenant` is refused. A repeated one is refused rather than resolved, because whichever value the proxy picked, something downstream could pick the other. A `Connection: NGSILD-Tenant` header is legal HTTP. It is also a way to have the tenant dropped after Libra authorized against it, so it is guarded specifically. The tenant Libra decided on is the tenant the broker is told.

**Identity spoofing.** Every header Libra injects is stripped from every inbound request first. A sweep does this, reading the same list of names the injector writes and matching however the name is spelled: underscores for hyphens, any letter case, repeated values. A name present in one direction and not the other would be a spoofing hole, which is why there is one list and not two.

**Term substitution.** This is the class of attack the whole JSON-LD layer exists to prevent. An entity type is a term, and a caller who supplies a context decides what it means. A policy matching strings is defeated by an inline `@context`, a `Link` header context, or by sending the expanded IRI. So policies compile to IRIs when they load, requests expand once per request, and comparison is IRI against IRI, whichever form the caller spelled. [Broker parity](../reference/jsonld-broker-parity.md) records a live broker storing an entity under a caller-chosen IRI.

**Caller confusion.** An account and a principal are different callers even when they share a name. A policy naming accounts never matches a principal, and the reverse holds too. So a principal created with an account's name gains nothing the account had. Downstream, a principal is identified by an assigned identifier that is never reused, so a principal re-created under a removed name is recorded as a different one.

**Management privilege.** The routes Libra serves itself, build info and metrics, sit behind a privilege gate. Its lists of privileged users, principals, clients, groups and roles all default to empty: no name is privileged until the operator writes one. This build mounts no route that mints or revokes credentials. Keys are managed at the filesystem boundary named above.

**Disclosure through query filters.** An attribute you cannot see can still be read through which entities come back, so a request that filters on a restricted attribute is refused. Every channel that filters counts: `q`, including the operator-free existence form `q=location` that a parser recognizing a name only before an operator would miss; `geoproperty`, and a geospatial query naming none, since `location` is the default; `orderBy` over a hidden attribute, whose order discloses the values it ranked; and the same selectors written in a `POST /entityOperations/query` body.

**Disclosure through the response shape.** The filter is applied to the answer in whichever representation it arrives. Under `application/geo+json` an entity is a GeoJSON Feature, and the geoproperty appears twice, inside `properties` and projected to a top-level `geometry`. Removing it from one and not the other hides the name and publishes the value. An answer that cannot be filtered, because it is not parseable or not the shape the restriction was judged in, is withheld rather than forwarded.

**Indistinguishable absence.** An entity a type or scope restriction withholds, or a registration any restriction hides, is answered with the same 404 an absent identifier gets. A refusal about a stored entity names only the identifier the caller sent, never its type or scope. A different answer would let a restricted caller map which identifiers exist and what they are. One residual is accepted. A create of an allowed type whose identifier is already held by an entity of another type is answered with the conflict the NGSI-LD specification requires. That tells the caller the identifier is in use, and nothing else. A second residual is that a caller restricted by scope alone reads the full `/types` and `/attributes` aggregate index. The index carries no scope dimension to filter by (ETSI GS CIM 009 v1.9.1 clause 5.7.5), so type names and counts outside what the restriction allows are visible there.

**Nothing answers from memory.** This edition ships no response cache and no request coalescing. Every request is authenticated, decided and enforced in full, every time. A build that adds either must place it below authorization, so a hit is an authorized one and a share carries the identity and decision that shaped it. [The request path](../request-path.md) reserves that position.

## Fail-closed guarantees

These are security properties. A defect in any of them is a vulnerability, not a bug:

- An unresolvable, non-allow-listed, or timed-out `@context` fails the request. It never degrades to "match nothing", which would turn a fetch failure into a bypass.
- A policy whose terms cannot be expanded to IRIs is a load error, not a skipped policy.
- A policy key or a configuration section nothing reads is a startup error, naming it. A gateway that silently ignored a restriction would allow what the policy meant to withhold.
- A response that cannot be filtered is withheld, not forwarded.
- A request naming a resource Libra cannot classify is refused.
- A request that mixes the two context channels, or carries two credentials, or two tenants, is refused rather than resolved.
- Evaluation denies on a tie, with a deterministic order, so a decision never depends on the order a directory was read in.
- Startup is all-or-nothing: keys, contexts, policies, configuration sections, and the key store lease are all settled before the first request, and a second instance on the same key store does not start.

## What is not defended

The gaps this release leaves open, and the behaviours it accepts, are on their own page: [known limitations](known-limitations.md). Read it before putting Libra in front of data that matters.

## Reporting

Private vulnerability reporting and the supported-versions table are in [SECURITY.md](../../SECURITY.md).
