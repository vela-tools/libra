# Troubleshooting

Every refusal Libra sends is an RFC 9457 problem document whose `type` field names what happened. The same cause always carries the same type URI, so a client can match on it and an operator can search for it. Client errors quote what was wrong with the request. Server errors answer with a fixed sentence and write the real cause to the log. The detail of a server error names broker addresses and file paths. Those describe the deployment rather than the caller's request, so the detail is withheld on purpose. Finding the cause of a 502 or a 504 means reading the log, and this page names the line to look for in each case.

One audit line is written for every request, allowed or refused, carrying the caller, the tenant, the deciding policy and the status. Between the problem document, the audit line and the log, every refusal below has a place where its cause is written down.

## Start with the probes

`/ngsi-ld/auth/health` answers `200` while the process runs, and answers nothing at all when the process is gone or the port is wrong. It consults nothing else, so run it first. A deployment where this check fails has a process or networking problem. No configuration value is the question.

`/ngsi-ld/auth/ready` answers `503` while the broker cannot be reached or, when a `[jwt]` section is configured, while no signing keys are loaded. The log line names which:

```text
not ready: no signing keys are loaded, so every token would be refused
not ready: the broker answered with an error
not ready: the broker could not be reached
```

A broker that answers the readiness check's request to `/ngsi-ld/v1/types` with `404` counts as working. An empty broker has no types, so a `404` still means it answers. Each answer is reused for two seconds, so a burst of probes produces one broker request. An outage is visible within a couple of probe intervals.

## It will not start

Startup is all-or-nothing. A failure is printed to stderr with its cause chain, and the process exits non-zero:

```text
libra: <what failed>
  caused by: <why>
```

The message names what it stopped on: the key, the section, or the policy file and the line in it. Nothing is half-loaded, and nothing is deferred to the first request. The alternative is a proxy that refuses everything while reporting itself healthy, or one that answers while silently ignoring a rule nobody checked. The recurring causes:

**No configuration file.** `LIBRA__CONFIG_FILE` naming a file that does not exist stops the process rather than falling back to defaults. Without the variable, the first of `/etc/libra.toml` and `config/libra.toml` (relative to the working directory) that exists is used. With no file anywhere, Libra starts on built-in defaults and environment variables, and says so in the log. `[management-api]` is then at its defaults unless an environment variable sets it, which means the gated endpoints refuse everyone until something names who may call them.

**A name nothing reads.** Every section and key is kebab-case with one accepted spelling. `[management_api]` and `[managment-api]` are startup errors. They do not quietly become sections that do nothing. The same refusal covers a key written `admin_users` where `admin-users` belongs. A `[keycloak]` section left from an earlier release stops startup for the same reason. Its settings belong in `[jwt]`.

**A value that parses and cannot work.** A timeout or a size set to zero is refused with its key, because a timeout of zero fails every request: `upstream-timeout-seconds`, `connect-timeout-seconds`, `fetch-timeout-seconds`, `shutdown-grace-seconds`, `header-read-timeout-seconds`, `max-body-size-bytes`, `max-context-bytes`, `max-in-flight-requests` and `jwks-cache-duration` must all be greater than zero. A value past its maximum is refused the same way: `jwks-cache-duration` is at most 86400 and `clock-skew-seconds` at most 300, because past those a withdrawn signing key or an expired token is accepted for longer than any deployment means. A `jwks-url` on plain `http` is refused until `jwks-transport = "insecure-http"` says the choice was deliberate. A `[prometheus] path` outside `/ngsi-ld/auth/` is refused, because it would answer in place of a proxied route, and so is one on a route Libra already serves there, because the router cannot be built twice for one path.

**The signing keys.** With a `[jwt]` section, the key set is fetched before Libra serves, and a failure there stops the process. A proxy without keys would refuse every token while reporting itself ready. Check that `jwks-url` is reachable from inside the container, and that it serves the key set of the realm that signs the tokens. Redirects are not followed.

**A preloaded context.** A file named in `[jsonld] preloaded-contexts` that cannot be read stops the process. The deployment that preloads a context is usually the one that cannot fetch it, so deferring the problem would mean every policy written against that context failing one request at a time.

**The policy set.** The whole directory loads or nothing does. The refusal names the file: a directory that does not exist, a file that cannot be read, TOML that does not parse, a declared context that cannot be resolved, a term that cannot be expanded, a key the policy format does not have (``unknown field `scopes` ``, with the line it is on), two policies sharing one identifier, or a policy that can never apply because its condition list is empty or its window starts after it ends. A policy file written for a build with more restrictions in it stops here. [Deployment](deployment.md) shows the message and why it is deliberate.

**No way to authenticate.** With neither `[jwt]` nor `[key-store]`, no credential could ever be accepted, and Libra refuses to start rather than become a gateway that authenticates nobody.

**The key store lease.** A second instance pointed at a key store whose lease is still live refuses to start. The lease is renewed every ten seconds and is taken over thirty seconds after its holder stops renewing it. So the usual causes are a first instance that is in fact still running, or a crashed one whose takeover interval has not yet passed.

**The `Via` pseudonym.** `[proxy] via-pseudonym` has no default, and Libra refuses to start without one. Give each deployment a name of its own. A broker that federates compares `Via` entries against context source aliases to detect loops. Two deployments answering to one name look like the same hop.

## Every request is refused with 401

A 401 from Libra carries no reason in its body. Which check failed is a detail that helps whoever is probing the gateway more than whoever is misconfigured. So the body stays generic, and the reason goes to the log at warning level. For a credential that was not accepted, the line reads `the credential was not accepted`. For a token, it reads `token validation failed` with the exact cause. Look there first. The `WWW-Authenticate` header tells the two broad cases apart without naming the check. `Bearer` alone means the request carried no bearer token Libra could read (none, another scheme, an empty token, two `Authorization` headers). `Bearer error="invalid_token"` means a token was presented and refused. The management endpoints judge a credential the same way and answer the same 401s.

Some refusals happen before any credential is judged, and those do name themselves in the body: no `Authorization` header at all, two of them on one request, a scheme other than `Bearer`, a bearer token that is empty, or a header that is not printable ASCII. Each is the caller's request to fix.

For a token that was judged, the `token validation failed` line names the failed check in its `error` field:

| The log says | What to check |
| --- | --- |
| `the token has expired` | Clocks between the identity provider and Libra; `clock-skew-seconds` already tolerates 60 |
| `the token is not valid yet` | The same, for a token issued ahead of its own `nbf` |
| `the token was issued by an issuer this deployment does not trust` | `[jwt] issuer` must equal the token's `iss`, with no trailing slash allowance |
| `the token is not addressed to this audience` | The token's `aud` must contain `[jwt] audience`. The check is required by RFC 9068 section 4. |
| `no signing key matches the key id in the token header` | The provider rotated its keys. A refetch happens on an unknown key id at most once per five seconds. A first refusal after a rotation is expected, and a persistent one means `jwks-url` does not serve the keys signing these tokens |
| `the token header carries no key id` | The token names no key, and Libra does not try keys until one verifies. The identity provider must set `kid`. |
| `the token signature does not verify` | The key the token names is in the key set but did not sign this token. Either the token was altered, or another realm or environment publishes a key under the same id. |
| `the token is signed with an algorithm this deployment does not accept` | The token names an algorithm other than `[jwt] algorithm`. The token's own `alg` header is never trusted, so only the configured value decides. |
| `the token is not declared to be an access token` | `token-type = "at-jwt"` is set and the token carries no such `typ` header |
| `the token omits the required '…' claim` | `exp`, `iss` and `aud` are required claims. A token without one is refused, rather than passed through a check that had nothing to compare. |
| `the token is not a well-formed JWT, or its claims cannot be read` | The token does not decode, a claim has the wrong type, or it carries no `sub`, which Libra requires to name the caller |
| `the token carries an unusable name: …` | The token verifies but carries a subject, client id, group or role that is empty, holds a comma or a control character, or is longer than 256 characters. The log names the kind of name and the reason, but never the name itself. Find the offending one in the identity provider's account or group settings. |

Two claims rules produce refusals that look like configuration errors. They are the identity provider's to fix. Groups and roles are read only from the top level of the token. An identity provider that nests them, as Keycloak does under `realm_access` and `resource_access` by default, must be configured to emit them at the top level, because Libra reads them nowhere else. A token carrying a group or role name that Libra cannot use is refused as an unusable name. The name is empty, holds a comma or a control character, or is longer than 256 characters. The token is refused rather than read with that name silently left out. Dropping the name would hand the policy engine a caller holding fewer groups than the identity provider says, and the deny that follows would look like a policy bug.

For API keys, a revoked or expired key answers 401 from its next request onward. The revocation needs no restart. The key store does not make the readiness probe depend on anything. An identity provider being down does not affect API key callers at all.

One tenant case also answers 401. It occurs with `[multitenancy] policy = "require-header"` and a request with no `NGSILD-Tenant` header. An empty or repeated header is a 400 instead, with the type URI `InvalidTenantHeader`.

## Every request is refused with 403

A 403 means the caller was authenticated and the policy set decided against them. The log warns `access denied` with the tenant, the method, the policy that decided and, with `[audit] token-fingerprint-key` set, the `credential` fingerprint. The audit line carries the same policy id and fingerprint, and the caller's name. The log line names no caller, because a name is a personal identifier. Join it to the audit line on the fingerprint and the time. The body says `access denied by policy`.

`access denied` logged with `(default effect)` in place of a policy id means no policy matched and `[authz] default-effect` decided, which is `deny` unless the deployment changed it. That is the most common 403 of a fresh deployment. The policies loaded, but none of them covers this caller, this tenant, this operation or this resource.

When a request you expected to allow is refused, check in this order:

- **The operation.** `POST /entityOperations/query` is a read, whatever its method says. A policy whose condition names `operations = ["read"]` covers batch queries. One written as if the method were the operation does not.
- **The resources.** A condition naming no `resources` covers entity data only: entities, temporal reads and the type and attribute listings. Subscriptions, context source registrations, snapshots and the rest each need their family named. A deny naming no `resources` works the other way and covers every family.
- **Who the caller is.** A condition's `users` names account subjects from tokens, and `principals` names API key principals. A principal and an account that share a name are different callers, and a policy naming one does not cover the other.
- **The tenant.** A condition's `tenants` is matched against the tenant the request resolved to. A request without a tenant header resolves differently under each `[multitenancy]` policy, and an untenanted request is never the same as a request for any tenant.
- **The context.** A policy is compiled against the context its file declares. A policy written against terms of a context its file does not declare loads without complaint and matches nothing, because its `Vehicle` is a different IRI from the caller's. [Writing policies](policies/index.md#the-context-declaration-is-not-optional-decoration) covers the declaration and how a name becomes an IRI.

A 403 whose body says `this resource is not one Libra recognises, so no policy governs it` is a path the broker grew and this build does not know. It is refused even under an allow-everything policy set, because letting an unnamed resource past every rule that names something else is how a new endpoint becomes an unguarded one. It stops being a 403 in a build that knows the resource.

An entity addressed by identifier that a type or scope restriction withholds from the caller answers 404, not 403, and so does a registration a restriction hides. That is the same answer an entity the broker does not hold gets, so a refused caller cannot discover which identifiers exist.

## 400 bad request

A 400 means the request arrived and Libra cannot give every name in it one meaning, so it is refused before authorization rather than forwarded on a guess. The body's `detail` names the cause. The recurring cases: a query parameter that does not parse or expands to nothing the request's context defines; a context `Link` header that is malformed, is not the request's only link, lacks `type="application/ld+json"`, or carries an `anchor`; `@context` in the body of an `application/json` request, or a `Link` header on an `application/ld+json` one, the two channels being mutually exclusive; a caller context giving a core term such as `location` a different IRI (the core namespace written over `http` names the same IRI, and the `geoQ` members `geometry`, `coordinates`, `georel` and `geoproperty` may be given any IRI, because Libra reads them by key); more than one `Content-Type` header; a header asking for the request to be run as another method; a method with no NGSI-LD meaning on a resource Libra knows; a body naming one member twice in one object or nesting more than 64 levels deep; a control character (a NUL, an escape, a tab or a line break, percent-encoded or not) anywhere in `q`, `scopeQ`, `type`, `attrs`, `pick`, `omit` or `orderBy`, or in a scope, which no NGSI-LD name, scope or quoted value admits. The refusal gives the byte offset, not the text, so the character never reaches the log.

These refusals are the fail-closed design working. They are not a malfunction. Several of them are requests a broker would have answered, but the answer would have been an authorization decision made on a meaning Libra could not confirm. [Broker parity](reference/jsonld-broker-parity.md) records why each is refused rather than resolved.

A 406 Not Acceptable is the one other refusal Libra makes on a caller's behalf. It happens only when `[representation] unsatisfiable-accept = "refuse"` is set, and the request's `Accept` matched nothing Libra can produce. The default, `forward`, sends such a request to the broker, and the broker's own answer is the one the caller gets.

## 413 payload too large

The request body is larger than `[payload] max-body-size-bytes` (2097152 by default). The limit is read before the body is buffered anywhere, so an oversized upload costs the proxy nothing but the refusal. Raise it only as far as the largest legitimate write, because the limit is also the bound on what a caller can make Libra read to authorize.

## 502 bad gateway

A 502 means the broker could not be reached, or a remote context the request names could not be fetched. The caller sees `An upstream service failed to give a usable answer`. The log warns `the broker could not be reached` and names the address that failed. Check `[broker] url`, the network between the two containers, and whether the broker is up (for a context, the context host and `[jsonld] allowed-contexts`). The readiness probe answers 503 for the same reason, so it agrees. A 502 is kept apart from a 504 on purpose. The connection failed rather than timed out, and a layer that answered for both would hide which one happened.

Under an attribute restriction, a successful response that cannot be filtered is withheld as a 502 as well. That covers a body that is not JSON, JSON that does not parse, or a body that arrives compressed. Libra strips `Accept-Encoding` on the way out when a filter is in force, so a compressed answer means the broker compressed regardless. A body the filter cannot walk is withheld rather than forwarded unfiltered. Broker error responses pass through untouched. A broker 503 reaches the caller as a 503 with the broker's own problem body.

## 504 gateway timeout

A 504 means Libra waited and the answer did not come. Either the broker exceeded `[timeout] upstream-timeout-seconds` (30 by default), or a context fetch exceeded `[jsonld] fetch-timeout-seconds` (5 by default). The distinction from a 502 matters. A 502 says the connection failed. A 504 says it was established and then too slow. Slow answers on a loaded broker are the broker's queue showing through the proxy, so raise the timeout only after checking what the broker itself is waiting on.

## 503 service unavailable

Two unrelated things answer 503. One is the readiness probe's answer, described above. The caller's 503 is the other, and it means the in-flight ceiling is held. `[limits] max-in-flight-requests` (256 by default) bounds how many requests Libra processes at once, because each pins memory and, once forwarded, a broker connection. A request that arrives while the ceiling is held is refused immediately with a problem document rather than queued. A stalled broker fills the ceiling, and everything behind it gets 503. That is the ceiling doing its job. The alternative is a flood turning into memory exhaustion. The management routes do not share the ceiling, so the endpoints that can change the configuration answer during the incident it exists for. Raising it trades refusals for memory. Switching it off with `enabled = false` removes the bound entirely.

## 404 not found

A path that is not NGSI-LD answers 404 with `no such resource` and is never forwarded. The path is classified after authentication, so a caller without an accepted credential gets the 401 instead. Libra serves the `/ngsi-ld/v1` resources, the two probes and the management endpoints. Anything else ends here rather than at the broker, so a scan of the address space does not become broker traffic. An entity addressed by identifier that a restriction withholds also answers 404, as described under 403 above.

## The management endpoints refuse everyone

`/ngsi-ld/auth/info` and `/ngsi-ld/auth/metrics` are gated by default, and all five `[management-api]` lists default to empty. That means no caller is privileged, and both endpoints refuse everyone. Libra warns about this at startup, so a configuration that loaded differently than the operator expected is visible before the first request. The warning reads `no management caller is privileged; the gated management endpoints will refuse everyone`. Name callers in the lists. Remember that `admin-principals` matches API key principals and `admin-users` matches account subjects from tokens. One never admits the other. Writes to a management route are gated whatever the settings say.

## Reading the logs

Console logging is on by default at `info`, in compact format. File logging is off by default. At `debug`, the log adds a line per step of each request. Examples are `caller authenticated`, `access allowed` and `forwarding to the broker`. No line names the caller. Names go to the audit line, which is `AUDIT_SUCCESS`, `AUDIT_DENIED` or `AUDIT_ERROR`, one per request.

To follow one refusal, start from the `x-request-id` header of its response. The audit line carries the same `request_id`. The audit line's `credential` fingerprint and time lead to the log lines, which do not carry the request id themselves. [Operations](operations.md#the-audit-record) lists every audit field, the sinks and levels, and how the three are joined. Set `[audit] token-fingerprint-key` before you need it, because without it a refused credential that names nobody leaves nothing to join on.

## My change did not take effect

Policy files load once, at startup, and are not watched. An edit takes effect when Libra restarts. Keys and revocations are the exception. They apply immediately, because they are read from the key store per request.

Configuration is read once too. An environment override carries the `LIBRA__` prefix, separates the section from the key with `__`, and writes the `-` inside a name as a single `_`. For example, `LIBRA__MANAGEMENT_API__ADMIN_USERS` sets `[management-api] admin-users`. A variable that does not carry the prefix is silently not a setting. So `LIBRA_BROKER__URL` does nothing, while `LIBRA__BROKER__URL` is the setting. A variable that carries the prefix and names nothing is a startup error, rather than a silent miss.

A corrected remote context document is served from the old copy until the resolved context's cache entry expires, `[jsonld] cache-ttl-seconds` (3600 by default), or until a restart. A corrected signing key set is fetched within `[jwt] jwks-cache-duration` (3600 by default), and sooner if a request presents a key id the cache does not know.
