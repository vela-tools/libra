# The request path

A request passes through about twenty-seven layers on its way to the broker. The order of those layers matters more than which layers there are. The order is the security-relevant part of the design. A cache above authorization would answer a request nobody authenticated, and a filter above a decision would filter against a policy nobody chose. Each layer's position has a reason, and that reason is stated where the stack is assembled, so the whole order can be reviewed in one place.

## The order

Outermost first. A request meets these in this sequence, and a response meets them in reverse. Three wrappers sit around everything. The proxied stack comes after them.

| | Layer | Why it is here and not elsewhere |
| --- | --- | --- |
| 1 | CORS | Answers a preflight without waking anything below it. |
| 2 | Request id, tracing | Discards any `x-request-id` the caller sent and mints one, which the audit record below carries and the response returns, so a caller's report finds its audit line. |
| 3 | Metrics | Outermost measurement, so a timing covers every layer below. The probes and the metrics path itself are excluded, so watching Libra does not become the traffic being watched. |
| 4 | **Audit** | Outermost of the proxied stack, above everything that can refuse, so a 401, a 403 or a 413 is on the record as well as a success. The layers below tell it who the caller was through the slot it inserts. |
| 5 | **Error handling** | Turns any refusal below into an RFC 9457 response, so nothing below has to know how one is rendered. |
| 6 | **In-flight ceiling** | Immediately below the error handler, so a refusal over the ceiling renders as a problem response, and above everything that reads a body or waits on the broker, so it bounds the memory and broker pins a request costs. Proxied traffic only: the management routes are admin-authenticated, and a shared ceiling would lock the operator out during the incident the ceiling exists for. |
| 7 | **Upstream timeout** | Bounds the whole request, so one hung broker cannot pin connections until the proxy stops serving. |
| 8 | **Payload limit** | Before any body is read. |
| 9 | **Identity header stripping** | Before anything can read or write an `X-Auth-*` header. A forged one must not survive to a point where something believes it. The sweep and the propagation read one shared list of names, so the two directions cannot drift. |
| 10 | **Method refusal** | Refuses a method with no NGSI-LD meaning before anything classifies the request by its method. |
| 11 | Security headers | Applied to the response on the way back. |
| 12 | **Tenant resolution** | Decides which tenant, from `NGSILD-Tenant`, and whether the request may be anonymous at all. An empty or repeated header is refused rather than resolved. |
| 13 | **Authentication** | Hands the credential to the one authenticator that recognizes it, and produces the identity the policy engine sees. The `Authorization` header is removed here, so the broker never receives an API key or a token. |
| 14 | **Operation classification** | Classifies the method and path into one NGSI-LD operation, once, into request extensions. Below authentication, so a caller with no acceptable credential learns nothing about which paths exist. A path outside the NGSI-LD API is answered 404. A method or path no two hops would read alike is refused, so nothing unclassifiable travels further. |
| 15 | **Query parsing** | Parses the query string, once, into request extensions. A repeated parameter, one spelled in two cases, or one that does not decode is refused. Every layer below reads this parse, and a layer that narrows the query writes the stored parameters and the request target together, so the next layer reads the query the broker will be sent. |
| 16 | **Context resolution** | Resolves the request's `@context`, once, into request extensions, from the inline member or the `Link` header, never both. The two channels are mutually exclusive by content type, and a request that mixes them is refused rather than resolved. Reading the body here is what makes one parse serve authorization and every enforcement layer below. |
| 17 | **Representation resolution** | Reads the `Accept` (every field line, combined into one list as the broker combines them), the `options` and the `format` the caller sent, once, into request extensions. Everything below that rewrites or filters a response reads the answer rather than parsing the header again. |
| 18 | **Linked entity resolution** | Reads what the request asks for in Linked Entity Retrieval (NGSI-LD 4.5.23), from the query string, a `Query` body or a subscription, once, into request extensions. It sits directly above authorization because authorization is its first reader: a join touches entities of types the request never names. Every enforcement layer below judges a join answer by the same reading. It refuses only a selector it cannot read. |
| 19 | **Authorization** | Evaluates the policy set; produces the decision every layer below reads. |
| 20 | Layers a binary adds | Below authorization, so whatever answers from memory, such as a cache, answers a request that has already been authenticated and authorized. Empty in the binary this repository builds. |
| 21 | **Registration disclosure** | A registration reader who may not also write registrations is not shown what a registration carries for its source, so no caller reads `contextSourceInfo` out of the tenant's topology. |
| 22 | **Aggregation enforcement** | Narrows an aggregated read to the methods, the period and the window grid the decision allows. The temporal layer below it then narrows the window onto that grid. |
| 23 | **Time enforcement** | Intersects the request's temporal window with the restriction's, narrows `timeAt`, `endTimeAt` and `temporalQ`, and on a current-state read under `values-in-window` filters the answer's attribute instances. |
| 24 | **Attribute enforcement** | Narrows `attrs` and the projections of a batch query, and filters the response body, because `attrs` is a hint a broker may ignore and an omit list cannot be written as a selector at all. |
| 25 | **Scope enforcement** | Narrows `scopeQ` to what the decision allows, judges an entity addressed by identifier through a pre-flight, filters the `scope` member down to what is allowed, and holds writes to `scope-on-write`. |
| 26 | **Type enforcement** | Narrows the type selection to what the decision allows, pre-flights entities the request does not name a type for, refuses a create of a forbidden type, and holds writes to `type-on-write`. |
| 27 | **Identity propagation** | The only place an `X-Auth-*` header is written. Every entry is written or removed on every request, so nothing a caller sent survives in one by accident. |
| 28 | Proxy | To the broker. Hop-by-hop headers are stripped in both directions. `NGSILD-Tenant` and the `X-Auth-*` set are protected end to end. The path and the percent-escapes arrive byte for byte, except that a literal `+` or `;` in the query is percent-encoded, so no decoder re-splits what Libra already read. On the way back, `Server`, `X-Powered-By` and `Set-Cookie` are removed, and a `Location`, `Content-Location` or `Link` target that points into the broker is rewritten relative to the root, so the answer never carries the broker's address. |

Rows 21 to 26 each narrow the request under the decision above, in this order. Each also filters the response, including the linked entities of a join answer and the context source registrations of a registration read. An entity or registration a restriction withholds by identifier gets the same 404 that an absent one gets, so a restricted caller cannot learn which identifiers exist.

## What the order is protecting against

**A context is resolved once, and above authorization.** Every name in NGSI-LD, an entity type, an attribute, a term inside a `q` filter, means whatever the request's `@context` says it means. If it is resolved twice, the two resolutions can disagree. A cached context expires between them, a remote context changes, and one layer authorizes against a meaning a later layer does not share. So it is resolved once, put into the request extensions, and read from there by everything below. A layer that finds it absent refuses rather than continuing, because a missing extension means the stack was assembled in the wrong order.

Resolving it means reading the request body, and reading **every** body rather than only an `application/ld+json` one. The two context channels are mutually exclusive. An inline `@context` belongs to `ld+json`, and a context `Link` header belongs to `application/json`. A request that mixes them is refused rather than resolved, because picking a winner means guessing which context the broker would have used. Suppose an `application/json` body carried an `@context` that nobody read. It would be authorized against the core context and forwarded. A broker whose content-type parsing handled that request under the ld+json rules would then store it under a context Libra never saw. The read is bounded by the payload limit above it.

**What a request is, and what its query string says, are resolved once, too.** Authorization weighs the operation and canonicalizes the query. The representation and linked-entity layers read selectors from both, and every enforcement layer branches on the operation and narrows the query. A layer that classified the path or parsed the query string for itself could read one request differently from the layer above it. So each is read once, near the top, and everything below reads the stored value. The query is the one value that layers below change. Each narrowing writes the stored parameters and the request target in one step, so the stored query is always the one the broker is sent, and a layer never judges a query that is not the one forwarded.

**What a request asks for in Linked Entity Retrieval is resolved once, too.** A join is asked for in the query string, in a `POST /entityOperations/query` body, or in a subscription's notification. Authorization and the enforcement layers all need that answer. Authorization weighs a join as touching every type its selectors and joins name. Each enforcement layer judges a join answer linked entity by linked entity on the way back, which needs one shared reading of what was asked. Whether a join can be served at all is decided per restriction. A join whose answer cannot be judged, such as one in `keyValues`, where a withheld linked entity cannot be told from data, is refused.

**Identity header stripping must be above everything that touches those headers.** Libra tells the broker who the caller is with `X-Auth-*` headers, and the broker trusts them. The stripping layer and the propagation layer work from one shared list, `libra_hardening::identity_headers::PROPAGATED_HEADERS`. A name is stripped however it is spelled. Each underscore is read as a hyphen, letter case does not matter, and the name is stripped however many times it repeats. Anything that reads as a propagated name is removed before a request reaches the first layer that could believe it.

**Audit above everything that can refuse.** The audit layer sits at the top of the proxied stack so that a refusal is recorded as faithfully as a success. It records the outcome, the caller when the layers below could determine one, the path without the query string, and a fingerprint of the credential rather than the credential. Nothing below writes to it, and nothing above it is left to record.

**Timed, bounded and counted before anything is read.** The in-flight ceiling, the upstream timeout and the payload limit sit above every layer that reads a body or waits on the broker. So no request can pin memory or a broker connection without end, and no single request can buffer without end or wait without end. The ceiling bounds how many requests are processed at once. It is not a rate limiter, and none ships in this edition. A flood arriving faster than the ceiling drains is for an edge proxy or ingress in front of Libra. [Known limitations](security/known-limitations.md) states what that means for a deployment.

## The routes that are not proxied

The table above is the path to the broker. It is what a request meets when no route matched, and everything Libra serves itself is a route that matches. So the probes, the build info, the metrics endpoint and any management route a binary adds never enter that stack.

The management routes carry the same listener protections as the proxied path, in the same relative order, with the same settings: audit, payload limit, identity header stripping, security headers. They are mounted on their own routes rather than over the whole router. That is what keeps them off the proxied path. What they do not get:

| Layer | Why not |
| --- | --- |
| Upstream timeout (7) | There is no upstream. A 504 saying one did not answer would describe a request that was never made. |
| In-flight ceiling (6) | The management routes are admin-authenticated, and a shared ceiling would lock the operator out during the incident the ceiling exists for. |
| Method refusal (10) | The management routes define their own methods. |
| Tenant, authentication, operation classification, query parsing, context, representation, linked entity resolution, authorization (12 to 19) | This is a different question with a different answer. Each management route carries the management privilege gate, which asks whether the caller is privileged rather than what the policy set allows. |

The probes sit outside even that. `/ngsi-ld/auth/health` and `/ngsi-ld/auth/ready` are mounted bare. A readiness check has to answer when the identity provider does not. A protection that could refuse a probe would let one noisy client sharing its source address give an orchestrator a reason to restart a process that was serving fine.

## A binary adds only at row 20

Nothing else is open to change. A binary that adds layers, such as a cache or a deduplicator, places them at row 20 through the extension point that [architecture](architecture.md) describes. They then sit below authorization and above the enforcement stack, where the decision is available to key on. That placement matters. A cache above authorization would answer a request nobody authenticated.
