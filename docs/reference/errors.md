# Error catalog

An enforcement point's errors are its user interface. This page lists every problem type Libra answers with, what produces it, and what the caller or the operator should do about it. It then lists the failures that stop Libra before it serves. [Troubleshooting](../troubleshooting.md) works in the opposite direction, from a symptom to its cause.

## The shape of a refusal

Every refusal Libra makes is an RFC 9457 problem document, served as `application/problem+json`:

```json
{
    "type": "https://libra.velacontext.com/problems/AccessDenied",
    "title": "Access Denied",
    "status": 403,
    "detail": "Access Denied: access denied by policy"
}
```

`type` is stable. The same cause always carries the same URI, so a client can branch on it and an operator can search for it. `title` is fixed per type. `detail` depends on who the error is about:

- **A client error** (any 4xx) describes the caller's own request. Its `detail` says what was wrong with the request, and starts with a label naming the type, such as `Access Denied:` or `Resource Not Found:`. A value the caller wrote is quoted and escaped. A control character is reported by its byte offset instead of being copied, so a refusal never carries a raw control character into a log or a response.
- **A server error** (any 5xx) is written for the operator. Its own text can name a broker address, a transport error or a file path, and none of these concern the caller. So the caller gets one fixed sentence per type. The real text goes to the log at warning level, as `answered with a server error whose detail is withheld from the caller`.

Every response carries `x-request-id`, the UUID Libra minted for the request. The audit line of that request carries the same id. Ask a caller for this id when they report a refusal. [Operations](../operations.md#correlation) shows how to get from the id to the log lines.

An error the broker answered with is not a Libra refusal, and Libra does not rewrite it. A broker `409` or `503` reaches the caller with the broker's own status and body. Only the problem types below are Libra's.

## The problem types

| Type | Status | Raised by | Caller's next step |
| --- | --- | --- | --- |
| `Unauthorized` | 401 | Tenant resolution, authentication | Present one valid bearer credential |
| `AccessDenied` | 403 | Authorization, a restriction, the management gate | Ask for a policy that covers the request, or ask for less |
| `ResourceNotFound` | 404 | Operation classification, the type, scope and attribute restrictions | Check the path or the identifier |
| `BadRequest` | 400 | Every layer that reads the request | Fix the request the `detail` names |
| `InvalidTenantHeader` | 400 | Tenant resolution | Send one printable `NGSILD-Tenant` header |
| `NotAcceptable` | 406 | Representation resolution, when configured to refuse | Accept a media type Libra produces |
| `PayloadTooLarge` | 413 | The payload limit, context resolution | Send a smaller body |
| `BadGateway` | 502 | The proxy, context resolution, the enforcement layers | Retry later. The operator reads the log. |
| `GatewayTimeout` | 504 | The upstream timeout, context resolution | Retry later. The operator reads the log. |
| `ServiceUnavailable` | 503 | The in-flight ceiling | Retry with backoff |
| `InternalError` | 500 | Any layer, on a wiring failure | Report it. It is a defect, not a refusal. |
| `MethodNotAllowed` | 405 | Nothing in this build | |
| `TooManyRequests` | 429 | Nothing in this build | |

Every URI is the base `https://libra.velacontext.com/problems/` followed by the name in the first column. `MethodNotAllowed` and `TooManyRequests` are defined for layers that a build adds at the extension point below authorization. The binary this repository builds answers with neither. A method with no NGSI-LD meaning is a `BadRequest` here. Rate limiting is left to an edge proxy, as [known limitations](../security/known-limitations.md) explains.

The rows refer to the layers of [the request path](../request-path.md), outermost first. Where a type is raised tells which checks the request has already passed.

## Unauthorized (401)

No credential the request could be served under. Every 401 carries a `WWW-Authenticate` challenge (RFC 9110 section 15.5.2). The challenge tells the two broad cases apart without naming the failed check (RFC 6750 section 3.1):

| `WWW-Authenticate` | `detail` | Cause |
| --- | --- | --- |
| `Bearer` | `an Authorization header is required` | No `Authorization` header, on a request the `[multitenancy]` setting does not let through anonymously, or on a management route, which never does |
| `Bearer` | `the request carries more than one Authorization header` | Two credentials, of which only one would be judged |
| `Bearer` | `the Authorization header is not printable ASCII` | A header that cannot be read as text |
| `Bearer` | `the Authorization header is not a Bearer token` | Another scheme, such as `Basic` |
| `Bearer` | `the Authorization header carries no token` | `Bearer` and nothing after it |
| `Bearer` | `the NGSILD-Tenant header is required` | `[multitenancy] policy = "require-header"` and no tenant named |
| `Bearer error="invalid_token"` | `the access token was not accepted` | A credential was presented and refused, for any reason |

The last row is uninformative on purpose. Which check failed would help whoever is probing the gateway more than whoever is misconfigured. The log names the reason at warning level (`the credential was not accepted`, and for a token `token validation failed` with the exact check). [Troubleshooting](../troubleshooting.md#every-request-is-refused-with-401) maps each reason to what to check. A credential that is not accepted is never treated as no credential, even where anonymous requests are served.

## AccessDenied (403)

The caller is authenticated. Either the policy set decided against the request, or a restriction of the policy that allowed it refuses what the request asks for. The `detail` says which.

| `detail` | Cause |
| --- | --- |
| `access denied by policy` | A deny matched, or nothing matched and `[authz] default-effect` is `deny` |
| `this resource is not one Libra recognises, so no policy governs it` | A path the broker serves and this build does not classify; refused under any policy set |
| A message naming a type, scope, attribute, window, method or period | A restriction refused the request; the restriction's own page lists its refusals |
| `... under an entity type restriction`, `... under a scope restriction` | A context source subscription, an entity map, or an existing subscription, which a type or scope restriction cannot narrow |
| `caller '<name>' is not a privileged management identity` | A management route refused a caller the `[management-api]` lists do not name |

The decision is logged as `access denied`, with the tenant, the method, the deciding policy (or `(default effect)` when nothing matched) and the credential fingerprint. A restriction's refusal means the policy is working. The caller is allowed the request in some form, and the `detail` says which part of it is outside the restriction. Asking for less is usually the answer, such as a narrower `type`, a filter on an allowed attribute, or an aggregated read on the grid. The restriction pages are [attribute](../policies/attribute-restriction.md), [entity type](../policies/entity-type-restriction.md), [scope](../policies/scope-restriction.md), [time](../policies/time-restriction.md), [aggregation](../policies/aggregation-restriction.md), [linked entity retrieval](../policies/linked-entity-retrieval.md) and [context source registrations](../policies/context-source-registrations.md).

## ResourceNotFound (404)

There are two causes, and the caller cannot tell them apart by design:

- **A path that is not NGSI-LD.** `detail` is `no such resource`, and nothing reached the broker. Libra serves the `/ngsi-ld/v1` resources, its probes and its management routes, and nothing else.
- **An identifier a restriction withholds.** An entity addressed by identifier that a type or scope restriction keeps from the caller, or a registration addressed by identifier that any restriction hides, is answered `'<id>' was not found`. That is also the answer an identifier the broker does not hold gets. A refusal that differed from the broker's own 404 (NGSI-LD clause 5.7.1) would tell the caller which identifiers exist outside what they may see.

A 404 the broker itself answers, for an identifier the caller may see but the broker does not hold, is the broker's problem body, not this type.

## BadRequest (400)

The request arrived, and either Libra cannot give every name in it one meaning or it is not the document the operation takes. Libra refuses it before forwarding, rather than forwarding it on a guess. The `detail` names the parameter, header or body member. The recurring families are:

| Where | Examples |
| --- | --- |
| Request line and headers | a header asking for the request to run as another method (`X-HTTP-Method-Override` and its variants); a method with no NGSI-LD meaning on a known resource; a path that two hops could read differently, such as an encoded `..`; more than one `Content-Type` |
| Query string | a repeated parameter, or one spelled in two cases; a parameter that does not decode; a `q`, `scopeQ`, `type`, `attrs`, `pick`, `omit` or `orderBy` that does not parse; a control character in any of them |
| Context | a malformed `Link` header; a second context link, in one header or two, or one without `type="application/ld+json"` or with an `anchor`; `@context` in an `application/json` body, or a context `Link` on an `application/ld+json` request; a caller context redefining a core term; a name that expands to nothing under the request's context |
| Body | not JSON; a member named twice in one object; nesting deeper than 64 levels; a batch that names more entities than Libra pre-flights; entities without one string `id` where the operation needs them |
| Representation | with `[representation] contradictory-options = "refuse"`, a contradictory `options` and `format`; under any setting, a query string that cannot be read at all |
| Restrictions | a value a restriction must read and cannot, such as an unreadable `scope` or `type` member, a malformed temporal bound, an unknown `timerel`, a window that ends before it begins, an aggregation period in years or months, a projection that removes the member a type or scope restriction judges the answer by |

[Broker parity](jsonld-broker-parity.md) records why each context case is refused rather than resolved. Several are requests a broker would answer, but answering them would make an authorization decision on a meaning Libra could not confirm.

## InvalidTenantHeader (400)

`NGSILD-Tenant` is present, and Libra will not carry it. It appears more than once, or it is not printable ASCII, or it is not a usable tenant name, and that includes the empty value. An empty header is not an absent one: a request that names an empty tenant has not left the tenant out.

## NotAcceptable (406)

This happens only with `[representation] unsatisfiable-accept = "refuse"`. Every media type Libra can produce is unmatched by the request's `Accept`, or given `q=0`. Under the default, `forward`, such a request goes to the broker, and the caller gets the broker's own answer.

## PayloadTooLarge (413)

The request body is larger than `[payload] max-body-size-bytes`. The limit is checked against `Content-Length` before anything is read, and again while a body without one streams in, so an oversized upload costs the proxy nothing beyond the refusal. `detail` names the limit.

## BadGateway (502)

The caller is told `An upstream service failed to give a usable answer`. The log carries the cause:

- **The broker could not be reached.** Connection refused, closed, or failed. Readiness agrees.
- **A context could not be fetched.** The request's or a policy's remote `@context` failed to load from an allowed address.
- **A pre-flight did not produce an answer.** A type or scope restriction fetched the addressed entity to judge it, and the broker answered with something other than the entity or a 404. A failed pre-flight is never taken as permission.
- **An answer could not be filtered.** A successful response under a restriction is withheld rather than forwarded unfiltered if it is compressed, over the body limit, not JSON, or of a shape the filter cannot walk. A registration answer is withheld too if it cannot be stripped of `contextSourceInfo` for a reader who may not see it.

The first two concern the deployment's network. The last two usually mean the broker answered in a shape Libra does not expect. It is worth checking the broker version against the [compatibility statement](../deployment.md#compatibility).

## GatewayTimeout (504)

The caller is told `An upstream service did not answer in time`. The broker did not answer within `[timeout] upstream-timeout-seconds`, its answer stopped arriving within it, or a context fetch exceeded `[jsonld] fetch-timeout-seconds`. A 504 says the connection was made and then was too slow. A 502 says it failed.

## ServiceUnavailable (503)

The caller is told `The service is temporarily unavailable`. The in-flight ceiling, `[limits] max-in-flight-requests`, is full, so the request was refused at once rather than queued. Retry with backoff. A stalled broker is the usual cause, because it holds every slot longer. The readiness probe's 503 is a different response, and it carries no problem body.

## InternalError (500)

The caller is told `An unexpected error occurred`. Every 500 Libra produces is a wiring failure, not a judgement about the request. A layer found something absent that a layer above it always provides, such as the resolved context, the decision or the parsed query. The layer refused the request rather than carry on without it. A request is never forwarded when this happens. The log line names what was missing. In the binary this repository builds, a 500 is a defect. Report it with the request id. In a build that adds layers, it usually means one was placed where it cannot see what it needs.

## Startup failures

Startup is all-or-nothing. A failure is printed to stderr with its cause chain, and the process exits non-zero before it serves anything:

```text
libra: <what failed>
  caused by: <why>
```

| What failed | What the message names | What to fix |
| --- | --- | --- |
| A configuration section or key nothing claims | The section or key | The spelling, which is kebab-case with one accepted form. Or a section left over from another build or an earlier release, such as `[keycloak]`. |
| A configuration value that cannot work | The key | A zero timeout or size, a value past its maximum, an `http` `jwks-url` without `jwks-transport = "insecure-http"`, a `[prometheus] path` outside `/ngsi-ld/auth/` |
| `LIBRA__CONFIG_FILE` naming a missing file | The path | The mount or the variable |
| A missing `[proxy] via-pseudonym` | The key | A name unique to this deployment |
| A policy key nothing claims | The file, the line and the key | The spelling, or a policy written for a build with more restrictions in it |
| A policy term nothing can resolve | The file, the policy and the term | The file's `context` declaration, or `[jsonld]` so the context can be reached |
| A policy that cannot apply | The file and the policy | An empty condition or allow list, a `time-interval` with no days, an absolute `[time]` window that starts after it ends, a relative one longer than a century, a deny carrying a restriction or conditioned on `queries`, a restriction beside `snapshots` or on no resource family it applies to |
| A preloaded context that cannot be read | The file | The path in `[jsonld] preloaded-contexts` |
| The signing keys | The `jwks-url` | Whether the key set is reachable from inside the container and serves the realm that signs the tokens. Redirects are not followed. |
| The key store | The path | A store that cannot be opened or migrated |
| The key store lease | When the holder started | Another instance still running against the same file, or a crashed one whose 30 seconds have not passed |
| No authenticator | Nothing | Configure `[jwt]`, `[key-store]`, or both |

[Troubleshooting](../troubleshooting.md#it-will-not-start) explains each of these at more length, and why none of them is deferred to the first request.
