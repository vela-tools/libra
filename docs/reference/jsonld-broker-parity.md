# Broker parity

Libra has to resolve a request's `@context` the same way the broker behind it does. Any divergence can be exploited. If the proxy decides `Vehicle` means one IRI and the broker decides it means another, a policy written about vehicles is enforced against something else, or against nothing.

This page records what a broker does, checked rather than assumed. Every block below is a real request and its real response, taken against Scorpio 6.0.1 (`docker.io/scorpiobroker/all-in-one-runner`) on a clean database. An automated harness in this repository, `crates/libra-jsonld-context/tests/broker_parity.rs`, replays three of them against a live broker. The three are what a caller-supplied context does to a term, what an undefined term expands to, and which channel combinations the broker refuses. Replaying them against a live broker means those assumptions cannot rot silently. The core context's precedence and the remote context fetch were observed by hand and are not replayed. Libra refuses a caller context that redefines a core term, so it does not depend on the first. [Testing](../testing.md) shows how to run the harness.

## A caller-supplied context changes what a term means

```http
POST /ngsi-ld/v1/entities
Content-Type: application/ld+json

{
    "id": "urn:ngsi-ld:Probe:1",
    "type": "Vehicle",
    "speed": {
        "type": "Property",
        "value": 42
    },
    "@context": {
        "Vehicle": "https://example.test/probe#Vehicle",
        "speed": "https://example.test/probe#speed"
    }
}
```

`201 Created`. Read back with no context:

```json
{
    "id": "urn:ngsi-ld:Probe:1",
    "type": "https://example.test/probe#Vehicle",
    "https://example.test/probe#speed": {
        "type": "Property",
        "value": 42
    }
}
```

The request says `Vehicle`. The broker stored `https://example.test/probe#Vehicle`. A policy matching the string `Vehicle` would have matched this request. A policy matching the entity type `Vehicle` as the deployment understands it would not.

Querying confirms both halves:

```
GET /ngsi-ld/v1/entities?type=Vehicle                              → []
GET /ngsi-ld/v1/entities?type=https://example.test/probe%23Vehicle → [ the entity ]
```

The expanded IRI is legal in a query parameter. A policy engine that only ever sees terms cannot see the form an attacker would use.

## An undefined term expands against the default context

```http
POST /ngsi-ld/v1/entities
Content-Type: application/json

{
    "id": "urn:ngsi-ld:Probe:2",
    "type": "Widget",
    "weight": {
        "type": "Property",
        "value": 7
    }
}
```

Both of these then return the entity:

```
GET /ngsi-ld/v1/entities?type=Widget
GET /ngsi-ld/v1/entities?type=https://uri.etsi.org/ngsi-ld/default-context/Widget
```

A term no context defines expands against the default context's vocabulary. The term and the resulting IRI are two spellings of one thing.

## The core context wins over the caller's

A caller may define new terms. A caller may not redefine the terms NGSI-LD itself relies on.

```http
POST /ngsi-ld/v1/entities
Content-Type: application/ld+json

{
    "id": "urn:ngsi-ld:Probe:6",
    "type": "Sensor",
    "location": {
        "type": "Property",
        "value": "somewhere"
    },
    "@context": {
        "location": "https://example.test/probe#location",
        "Sensor": "https://example.test/probe#Sensor"
    }
}
```

`201 Created`. Then:

```
GET /entities/urn:ngsi-ld:Probe:6?attrs=https://uri.etsi.org/ngsi-ld/location        → the attribute
GET /entities/urn:ngsi-ld:Probe:6?attrs=https://example.test/probe%23location        → 404 ResourceNotFound
GET /entities?type=https://example.test/probe%23Sensor                               → the entity
```

So `location` was stored under the **core** IRI, and the caller's redefinition of it found nothing. `Sensor`, a term the core context does not define, took the caller's meaning. The core context is applied last, and later definitions win.

This is why Libra composes a request's context as the caller's context first and the core context last. Reversed, a caller could redefine `location`, `observedAt`, `value`, or any other structural term, and every policy written about those names would be evaluated against a meaning the caller picked.

One spelling is not a redefinition. A context that writes a core term in the core namespace over `http`, as the Smart Data Models context does with `http://uri.etsi.org/ngsi-ld/location`, names the core term. Refusing it would refuse every request that sends the most widely used data-model context. Libra reads every IRI under `http://uri.etsi.org/ngsi-ld/` as the same IRI under `https://`, wherever it meets one: in a policy, in a request, and in a response member named by its full IRI. An attribute restriction on `location` holds for both spellings. A broker that applied the caller's definition positionally would store the `http` spelling. A query Libra narrows to the `https` IRI would then miss what it stored. That can leave something out of an answer, but it never puts anything in.

A term no decision reads is not guarded. The members of a `geoQ` (NGSI-LD clause 5.2.13), `geometry`, `coordinates`, `georel` and `geoproperty`, are core terms. Libra takes them from a query body or a subscription by their JSON key and never expands them, so a caller's definition of one changes nothing Libra decides. The Smart Data Models context defines `coordinates` as `geojson:coordinates` without defining the `geojson` prefix. JSON-LD reads that as an IRI of its own. Refusing it would refuse every request that sends that context, for a term no policy is judged against.

## The context channel is decided by the content type, and the rules are strict

An `application/json` request supplies its context with an RFC 8288 `Link` header:

```http
POST /ngsi-ld/v1/entities
Content-Type: application/json
Link: <https://raw.githubusercontent.com/smart-data-models/dataModel.Weather/master/context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"

{
    "id": "urn:ngsi-ld:Probe:3",
    "type": "WeatherObserved",
    "temperature": {
        "type": "Property",
        "value": 21
    }
}
```

`201 Created`. The entity is stored under `https://smartdatamodels.org/dataModel.Weather/WeatherObserved`. A remote context was fetched and applied. This is why Libra fetches contexts only from an allow list, and why it fails the request closed when it cannot.

The two channels are mutually exclusive, and mixing them is refused rather than resolved:

| Request | Response |
| --- | --- |
| `application/json` with `@context` in the body | `400`: `"@context entry in body is not allowed"` |
| `application/ld+json` with a context `Link` header | `400`: `"You can not have a Link to a context is content-type application/ld+json"` |

Both carry `"type": "https://uri.etsi.org/ngsi-ld/errors/BadRequestData"`.

Libra refuses the same two combinations. It does not pick a winner, because picking one means guessing which context the broker would have used, and a guess here is an authorization decision made on the wrong data.

## Brokers disagree with each other, so "the broker" is not one behaviour

Everything above was observed against Scorpio. A survey of the three common brokers found that they diverge on the details. In each case, the divergence is in the parsing that decides which context applies:

**Content-Type.** Orion-LD truncates the header at `;` before comparing, which is correct. Scorpio exact-matches the literal, so a `charset` parameter can produce a 415. Stellio compares the parsed media type including its parameter map. So `application/json; charset=UTF-8` does not equal `application/json`, and the request is handled under the *ld+json* rules instead. An inline `@context` is accepted where the specification says it must be refused. That last one is read from source, not observed at runtime. Treat it as a lead, not a fact.

Libra normalizes the media type before comparing: it splits at `;`, trims, and matches case-insensitively, which is Orion-LD's behaviour and the one the specification implies.

**Link headers.** RFC 8288 allows several link-values to be folded into one comma-separated header, so a context link can arrive alongside `next` and `prev`. Orion-LD validates both `rel` and `type`. Scorpio checks only `rel` and layers every match, so taking the first link-value picks a different context than the broker does. Stellio requires an exact whitespace shape and reads only the first header.

Libra parses every link-value of every `Link` header, respecting quoted commas and semicolons, and selects the context link by `rel`. Where the brokers would each pick differently, Libra refuses instead. Three cases are all answered with 400: a second context link, which JSON-LD 1.1 API section 9.4.1 makes an error; one without `type="application/ld+json"`; and one with an `anchor`.

**Query parameter expansion.** The specification requires query parameters to be expanded against the context, and this is the most duplicated defect across all three brokers. The recurring shape is that retrieve-by-id honours the context while query-by-type does not. The Scorpio version probed here does expand `type`, since both `?type=Widget` and the default-context IRI find the same entity. A proxy that expands faithfully will still disagree with a broker that does not. The disagreement lands on the parameters used for filtering.

**Context precedence is not portable.** The core-context-wins result above is Scorpio's, and it matches Orion-LD's documented positional rule. Scorpio's maintainers have described a position-independent rule elsewhere, and the two only diverge when the core context is not last, which the client controls. Compaction output that one broker fixed as a bug, another defended as correct.

Libra picks no winner in the abstract, so the parity harness has to be run against the broker a deployment fronts, with its version pinned. "The specification says so" is not sufficient to predict what the thing behind the proxy will do.

## Compact-IRI prefixes are a 1.1 concept

JSON-LD 1.1 makes a defined term a compact-IRI prefix only when its IRI ends in a gen-delim (`:`, `/`, `?`, `#`, `@`) or the definition carries `"@prefix": true`. A JSON-LD 1.0 processor treats any defined term as a prefix. With `{"ex": "https://host/Sec"}` in the context, `ex:ret` expands to nothing Libra can compare under 1.1. Under 1.0 it expands to `https://host/Secret`, so a policy written about Secret holds for one reading and not the other.

Libra processes in 1.1 and refuses the term rather than guessing. Expansion answers "no meaning", and the request or the policy naming it fails closed. A 1.1 processor also refuses to define a term of the form `ex:ret` while `ex` is a defined non-prefix term, so the ambiguity cannot be dissolved by redefining it. Authors who want the compact-IRI reading write `"@prefix": true` on the definition, or end the prefix IRI in a gen-delim.

## What this means for Libra

- Every policy-relevant name is an IRI, never a string. Terms are compiled to IRIs when a policy loads, as [Writing policies](../policies/index.md#the-context-declaration-is-not-optional-decoration) describes. Requests are expanded once per request. All comparison is IRI against IRI.
- A request may send the expanded IRI instead of the term. Both forms reach the same comparison.
- A term whose compact-IRI reading depends on the JSON-LD version is refused, not guessed. The 1.1 `@prefix` rule against a 1.0 broker is the kind of disagreement an authorization decision cannot rest on.
- Remote contexts are real and routinely used. Fetching is allow-listed, timed out, and cached. An unresolvable context fails the request rather than matching nothing.
- Context handling differs between brokers in the details. These observations are Scorpio's. The harness is the mechanism for checking another broker, rather than assuming it agrees.
- Where brokers disagree, refuse rather than resolve. A construct whose meaning depends on which broker is behind the proxy cannot be the basis of an authorization decision. A loud 400 is better than two components quietly disagreeing about what a name meant.
