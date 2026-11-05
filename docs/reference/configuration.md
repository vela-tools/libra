# Configuration reference

Configuration is layered: built-in defaults, then a TOML file, then `LIBRA__*` environment variables. Later layers win. The file is optional. Every key has a default except `[broker] url` and `[proxy] via-pseudonym`, which can be set from the environment alone. `libra config init` prints a file with every key at its default, to start one from.

The file is the one named by `LIBRA__CONFIG_FILE` if that is set. Otherwise it is the first of `/etc/libra.toml`, `config/libra.toml` (relative to the working directory) that exists. If `LIBRA__CONFIG_FILE` names a file that is not there, Libra stops rather than falling back to defaults. A missing file that silently became built-in defaults would start the proxy with a different security posture than the one the operator wrote down.

Every name is kebab-case, sections and keys alike. There is no accepted alternative spelling. **A key or a section Libra does not recognise is a startup error.** It is not a key that quietly does nothing. This prevents a failure in which a section applies under a name nobody reads, and both privilege gates revert to their defaults without a line in the log. A file written for an earlier release that still has `[keycloak]` stops startup for the same reason. Its settings belong in `[jwt]`.

## Environment overrides

Every variable is uppercase, carries the `LIBRA__` prefix, and separates the section from the key with `__`. A single underscore is the `-` inside a name.

```sh
LIBRA__BROKER__URL=http://broker:9090                 # [broker] url
LIBRA__MANAGEMENT_API__ADMIN_PRINCIPALS='["ops"]'     # [management-api] admin-principals
LIBRA__LOGGING__CONSOLE__LEVEL=debug                  # [logging.console] level
```

`LIBRA__CONFIG_FILE` is read before this mapping and is not a key in the file. The double underscore in the prefix also keeps the `LIBRA_PORT`-style variables that a cluster injects for a service named `libra` from reading as settings. None of them is a section and a key.

An override can set a key of an optional section, but it cannot set half of one. `LIBRA__JWT__AUDIENCE` alone, with no `jwks-url` or `issuer` anywhere, is refused for the keys it leaves out.

## Credentials

A deployment accepts API keys (`[key-store]`), JWTs (`[jwt]`), or both. The key store is on by default. `[jwt]` is optional, and absent means no JWT is accepted. With the key store off and no `[jwt]`, nothing could authenticate, and Libra refuses to start.

The credential stops at Libra. Once the caller is authenticated, Libra removes the `Authorization` header. Neither the broker nor the entity pre-flights that Libra sends ever receive it. The broker learns who asked from the `X-Auth-*` headers, so a broker that authenticates callers itself cannot sit behind Libra on the caller's own credential. A request with more than one `Authorization` header is refused.

### `[key-store]`

| Key | Default | Means |
| --- | --- | --- |
| `enabled` | `true` | Keep a key store and accept the API keys in it. Turn it off for a deployment that accepts JWTs only |
| `path` | `"/var/lib/libra/keys.db"` | The SQLite database holding principals and API key verifiers, created if it does not exist |

Whoever can write this file can issue keys, so protect it as you protect the policy directory. The instance that opens the store holds a lease on it, renewed every 10 seconds. A second instance pointed at the same file refuses to start while the lease is live. That second instance takes over 30 seconds after the holder stops renewing the lease. Keys are issued and revoked with `libra principal` and `libra key`, run beside the running proxy with the same configuration file. A revocation applies to the next request.

### `[jwt]`

| Key | Default | Means |
| --- | --- | --- |
| `jwks-url` | required | Where the signing keys come from. Fetched at startup. A failure there stops the process. Redirects are not followed |
| `issuer` | required | The `iss` a token must carry, matched as an exact string |
| `audience` | required | The `aud` a token must contain |
| `jwks-transport` | `"https-only"` | `"https-only"` refuses an `http` address at startup; `"insecure-http"` accepts one. Whoever can alter the response chooses which keys Libra trusts, so use `"insecure-http"` only on a network you control |
| `jwks-cache-duration` | `3600` | Seconds between key refreshes. The value must be greater than zero and at most `86400`, because a signing key the identity provider withdrew keeps verifying until the next refresh. A token naming a key id that is not cached also triggers one fetch, at most once per five seconds. Requests that arrive while a fetch is running wait for it for up to two seconds, and are then answered as an unknown key id |
| `algorithm` | `"RS256"` | The one signature algorithm accepted, as a JOSE `alg` value: `RS256`, `RS384`, `RS512`, `PS256`, `PS384` or `PS512`. The key set is read for RSA keys only, so an elliptic-curve, `EdDSA` or HMAC algorithm is a startup error. The algorithm a token's header names is never trusted |
| `token-type` | `"any"` | `"at-jwt"` accepts only a token whose `typ` header is `at+jwt` or `application/at+jwt`, in any case, as RFC 9068 section 4 requires of a resource server. A token with another `typ`, or with none, is refused with 401. `"any"` accepts a verified token whatever its `typ`. Set `"at-jwt"` whenever your identity provider emits that type. With `"any"`, an ID token the provider signed for the configured audience is accepted as an access token |
| `clock-skew-seconds` | `60` | Tolerance on `exp` and `nbf`, at most `300`, because the tolerance extends the life of every token |

The issuer and the audience are required because RFC 9068 section 4 requires a resource server to check both. Without an audience, a token that the same identity provider issued for any other client would be accepted. `exp`, `iss` and `aud` are required claims. A token that omits one is refused, rather than passing a check that had nothing to compare.

Libra reads the standard claims only: `sub` (required), `client_id`, and `groups` and `roles` at the top level of the token (RFC 9068 sections 2.2 and 2.2.3.1). A JWT caller is an account named by its `sub`. A policy's `users` and `admin-users` name subjects, and the broker receives the subject in `X-Auth-Subject` with no `X-Auth-Username`. A group or role nested elsewhere in the token is not read. An identity provider that nests them, as Keycloak does by default, needs to be configured to emit them at the top level. A token carrying a group or role that a policy name cannot be (empty, containing a comma or a control character, or longer than 256 characters) is refused, rather than read with the name left out.

## `[libra]`

| Key | Default | Means |
| --- | --- | --- |
| `host` | `"0.0.0.0"` | Address to bind |
| `port` | `5667` | Port to bind |
| `trusted-proxies` | `[]` | Networks in CIDR notation of the proxies in front of Libra, whose forwarding headers are believed |
| `shutdown-grace-seconds` | `25` | How long a stopping Libra waits for in-flight requests, counted from the first termination signal |
| `header-read-timeout-seconds` | `10` | How long a client may take to send the start of a request, from connecting or from the end of its previous response |

A forwarding header is a claim by whoever sent it, and `trusted-proxies` names the peers whose claims Libra passes to the broker. A peer outside every listed network is a client talking to Libra directly, and nothing it wrote about itself counts. The default is empty, so no peer is believed.

On the first interrupt or termination signal, Libra stops accepting connections, asks every open connection to finish its current request and close, and waits up to `shutdown-grace-seconds`. It then exits with whatever is still open aborted. A second signal during the wait ends it at once. Keep the grace period below the orchestrator's own. Kubernetes sends SIGKILL after `terminationGracePeriodSeconds`, which is 30 seconds unless set, and a drain that outlasts it ends in a kill. A connection that has sent nothing yet counts as open until `header-read-timeout-seconds` has passed, so keep that value below the grace period as well. Both must be greater than zero.

The header timeout closes a connection that sends no byte within the limit, and a request whose headers have not finished arriving within it. It does not bound a request body, which `[timeout]` and `[payload]` govern. It does not bound an HTTP/2 connection after its first byte.

## `[broker]`

| Key | Default | Means |
| --- | --- | --- |
| `url` | none, required | The NGSI-LD broker every request is forwarded to |

## `[authz]`

| Key | Default | Means |
| --- | --- | --- |
| `policies-dir` | `"/etc/libra/policies"` | Directory of policy files, merged and loaded at startup |
| `default-effect` | `"deny"` | What decides when no policy matches |

## `[aggregation]`

| Key | Default | Means |
| --- | --- | --- |
| `short-period` | `"refuse"` | What to do with an aggregated temporal read that does not fit its policy's minimum period. That covers an `aggrPeriodDuration` that is missing, finer than the minimum or not a whole multiple of it; a `timeAt` or `endTimeAt` off the grid of the minimum, counted from the Unix epoch in UTC; or a window shorter than one minimum period. `refuse` answers 403 naming the minimum. `raise` rewrites the period to the minimum, moves the window out to the enclosing grid points, and forwards. An aggregated read under a minimum period has to name a `between` window, unless the same allow carries a time restriction, whose window is rounded inward to the grid. A minimum period in years or months fails to load |

`raise` is friendlier and quieter. Being quieter is why it is not the default. The caller is served a coarser answer than they asked for, and may not notice.

## `[audit]`

| Key | Default | Means |
| --- | --- | --- |
| `token-fingerprint-key` | none | Hex HMAC key (`openssl rand -hex 32`); every presented credential is recorded in the audit line as its keyed digest, refusals included, and the authorization log lines name the caller by the same digest |

Absent, no fingerprint is computed, and the audit line carries only the subject. The fingerprint correlates requests by credential. This includes refused ones that a subject could not name, such as an expired token after a rotation. It is sixteen hex characters of HMAC-SHA-256 under the configured key. That is enough to tell credentials apart in a deployment's own records, and too little to be worth anything outside them. Rotating the key breaks correlation with the records made before the rotation, by design. The key must decode to at least 128 bits. A shorter one is a startup error.

## `[jsonld]`

Every policy-relevant name is an IRI, and this section decides how a term becomes one.

| Key | Default | Means |
| --- | --- | --- |
| `allow-remote` | `true` | Fetch contexts over the network |
| `allowed-contexts` | `["https://uri.etsi.org/ngsi-ld/", "https://smartdatamodels.org/", "https://raw.githubusercontent.com/smart-data-models/"]` | Addresses Libra may fetch. An entry ending in `/` matches everything under it, at that path boundary. Any other entry is exact and allows that one document only. Setting the list replaces the default. An empty list with fetching on allows nothing |
| `preloaded-contexts` | `{}` | Contexts read from disk at startup, keyed by the URL that names them |
| `fetch-timeout-seconds` | `5` | Per-context fetch timeout |
| `max-context-bytes` | `1048576` | Largest context document accepted |
| `cache-max-bytes` | `67108864` | How much memory the fetched-context cache may hold, in bytes |
| `cache-ttl-seconds` | `3600` | How long a resolved context is reused |
| `core-context` | unset | Replacement for the embedded ETSI core context, for a deployment pinning a specific revision |

A request without a context of its own is read under the core context alone, as NGSI-LD clause 6.3.5 prescribes. There is no deployment default, because the broker could not be told of one. Some contexts are refused, because Libra and the broker could read them differently. The rules are these. A request may carry one context link, which must declare `type="application/ld+json"` and carry no `anchor`. A context, inline or fetched, may not give a term a context of its own (`@context` or `@propagate` inside a term definition) or use `@import`. A body may not carry an `@context` below its top level, or below the entities of a batch. A caller's context may not give a core term such as `location` another IRI. This does not cover the core namespace written over `http`, as the Smart Data Models context writes `location`: that is read as the same IRI. Every request body is read once. One that nests arrays and objects more than 64 levels deep, or names a member twice in one object, is refused.

A prefix is matched at a path boundary. So `https://smartdatamodels.org/` cannot be satisfied by `https://smartdatamodels.org.example.test/`. An entry that does not end in `/` allows only the one document it names, and no suffix of it. A context URL that carries a query is refused, because a query lets one address stand for as many documents as a caller can invent. A fragment is ignored, because it never selects a different document. A path carrying an encoded path separator (`%2F`) is refused, because a decoder that splits after decoding would read a different path from the one Libra authorised. An unresolvable, non-allow-listed, or timed-out context fails the request closed.

Concurrent requests that miss on the same context URL share one fetch, so a burst on one address opens one connection rather than one per request. The cache holds fetched documents up to `cache-max-bytes` of fetched body bytes, and evicts the least recently used ones first. A fetch that failed is never cached, so the next request retries the network.

A preloaded context is consulted before the allow list and before the network, so it needs neither:

```toml
[jsonld]
allow-remote = false

[jsonld.preloaded-contexts]
"https://smartdatamodels.org/context.jsonld" = "/etc/libra/contexts/smart-data-models.jsonld"
```

That is what makes a deployment with no outbound network possible. Without preloading, `allow-remote = false` leaves only the built-in core context, and every policy written against a data model resolves its terms somewhere else. A file named here that cannot be read is a startup error, because a deployment that preloads a context is one that cannot fetch it.

### Contexts in practice

What an operator has to do with this section comes down to one list: every context a request or a policy may name. [Broker parity](jsonld-broker-parity.md) records why each rule below exists. The rest of this section says what the rules mean for running a deployment.

**Make the list.** It holds every context your callers send, in a `Link` header or inline in an `application/ld+json` body, and every context a policy file declares in its `context` line. A context document that names other contexts by URL is resolved through the same rules, so each document it pulls in belongs on the list too. A context missing from it refuses the requests that use it with 400 (`context '<url>' is not on the allow list`), and stops startup when a policy declares it.

**Choose online or offline.** Online, write the list into `allowed-contexts`. Use exact URLs where you can, and a prefix ending in `/` only for a host whose every document you trust, such as a data-model site you publish yourself. Offline, preload each document from disk under `preloaded-contexts`, keyed by the exact URL callers use, and set `allow-remote = false`. A preloaded context needs no allow-list entry. Mixing the two is fine. A preloaded entry is consulted first, so preloading the contexts your policies declare keeps startup independent of the network, even where requests may still fetch.

**One context per request, in one channel.** A request names its context either as one `Link` header, on `application/json`, or as `@context` in an `application/ld+json` body. It never names it both ways. There may be only one context link. It carries `type="application/ld+json"` and no `anchor`. Other links, such as `next`, may sit beside it. A caller that needs several contexts at once publishes one document that composes them and links that document, or sends `ld+json` with an array `@context`. A request with no context at all is read under the core context alone, never under a deployment default, because the broker could not be told of one.

**Know what the cache does.** A resolved context is reused for `cache-ttl-seconds` (3600), so a corrected context document shows its old content until the entry expires or Libra restarts. The broker keeps a cache of its own, so a change has to reach both before it is consistent. `cache-max-bytes` (64 MiB) bounds the fetched documents kept, least recently used first. A failed fetch is never cached and is retried by the next request. A timeout past `fetch-timeout-seconds` answers that request with 504, and any other fetch failure with 502. Concurrent requests for one uncached context share one fetch.

**Pin the core context only on purpose.** `core-context` replaces the ETSI core context Libra embeds. Set it only to match a broker that runs a different revision of the core context, because a core term that means one thing to Libra and another to the broker is a policy matching an IRI the broker never stores.

## `[multitenancy]`

| Key | Default | Means |
| --- | --- | --- |
| `policy` | `"authenticate"` | `require-header`, `authenticate`, or `allow-public` |

This decides only what happens to a request that names **no** tenant. `require-header` refuses it. `authenticate` serves the default tenant to an authenticated caller. `allow-public` serves it to anyone, anonymous callers included. Under `allow-public`, a policy that names no `users`, `principals`, `groups` or `roles` applies to an anonymous caller too, unless it says `callers = "authenticated"`, so it is never the default. A request that names a tenant always authenticates, whatever this says. An empty `NGSILD-Tenant` header is refused outright, and so is a repeated one.

## `[management-api]`

This section decides who may reach the privileged endpoints, which are the metrics endpoint and the build-info endpoint. The same lists decide who is privileged for any route a build adds.

| Key | Default | Means |
| --- | --- | --- |
| `admin-principals` | `[]` | Privileged API key principals, matched against the principal's name |
| `admin-users` | `[]` | Privileged accounts, matched against the account name (a JWT's `sub`) |
| `admin-clients` | `[]` | Privileged OAuth clients, matched against `client_id` |
| `admin-groups` | `[]` | Privileged groups |
| `admin-roles` | `[]` | Privileged roles, each matched by its exact name |
| `metrics-access` | `"privileged"` | Who may read the metrics endpoint: `"privileged"` or `"authenticated"` |
| `info-access` | `"privileged"` | Who may read the build-info endpoint: `"privileged"` or `"authenticated"` |

All five lists default to empty. That means no caller is privileged, and every gated endpoint refuses everyone until you name who may use it. Libra says so in its startup log. Each list is matched against a single name. A principal and an account of the same name are different callers. `admin-principals` never admits an account, and `admin-users` never admits a principal. `admin-users` is not matched against the client, by design: an identity provider holding a client named `admin` would otherwise give management access to every token that client ever issued.

Writes to a management route are always gated. There is no setting that lets an unprivileged caller change the rules they are judged by.

Both default to privileged. With `metrics-access = "authenticated"`, **any caller Libra authenticates** can scrape the metrics. The metrics carry tenant names, request volumes and error rates, so turning it off is a decision to make on purpose. The build-info payload is the exact commit the gateway is running. That commit decides which published advisories apply to it.

## `[payload]`, `[limits]`, `[timeout]`, `[helmet]`

| Section | Key | Default | Means |
| --- | --- | --- | --- |
| `[payload]` | `enabled` | `true` | Apply a body size limit |
| `[payload]` | `max-body-size-bytes` | `2097152` | Largest request body accepted |
| `[limits]` | `enabled` | `true` | Apply an in-flight ceiling |
| `[limits]` | `max-in-flight-requests` | `256` | Largest number of requests processed at the same time |
| `[timeout]` | `upstream-timeout-seconds` | `30` | How long the broker has to answer |
| `[helmet]` | `enabled` | `true` | Security headers |

A response Libra has to filter is fetched uncompressed, whatever these sections say. `Accept-Encoding` is stripped on the way out whenever an attribute, entity type, scope or time restriction has to read the answer, and on a registration read whose answer loses `contextSourceInfo`. A body that cannot be read cannot be filtered, and a body that cannot be filtered is withheld.

`max-in-flight-requests` bounds how much the proxy can hold at once. Every in-flight request pins a buffered body, a parsed context and a parsed response, and, once forwarded, a broker connection. The ceiling bounds all of that. Requests arriving past it are answered 503 rather than queued. Size it against the memory the process may spend, and against how long the broker takes to answer. A slow broker holds each slot longer, so the same ceiling admits less. It bounds the proxied path only. The management routes are admin-authenticated and carry no ceiling, so an operator can still reach the one place that could widen it during the very incident the ceiling exists for.

## `[proxy]`

| Key | Default | Means |
| --- | --- | --- |
| `pool-idle-timeout-seconds` | `60` | Idle connection lifetime |
| `pool-max-idle-per-host` | `32` | Idle connections kept per host |
| `connect-timeout-seconds` | `10` | Connection establishment timeout |
| `tcp-nodelay` | `true` | Disable Nagle's algorithm |
| `via-pseudonym` | none, required | The name written into `Via`, unique to this deployment |
| `inbound-scheme` | `"http"` | The scheme clients use to reach Libra, `"http"` or `"https"`, written into `X-Forwarded-Proto` |

`via-pseudonym` has no default, and Libra refuses to start without it. Brokers that federate compare the entries of `Via` with the aliases of context sources (NGSI-LD clause 5.2.40) to detect loops, so two deployments answering to one name would look like the same hop. It must be a single run of visible ASCII with no comma.

The broker is told the origin of a request in `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`. When the peer is inside `[libra] trusted-proxies`, what it sent is kept. Libra appends the peer to `X-Forwarded-For`. It sets `X-Forwarded-Proto` and `X-Forwarded-Host` only if the proxy sent none. For any other peer, they are replaced with what Libra observed. `X-Forwarded-For` becomes the peer address alone. `X-Forwarded-Proto` becomes `inbound-scheme`. `X-Forwarded-Host` becomes the `Host` of the request, or is removed if it had none. `Forwarded` and `X-Real-IP` are removed for an untrusted peer, and left as sent for a trusted one. Set `inbound-scheme = "https"` when a TLS terminator sits in front of Libra but is not listed in `trusted-proxies`. That makes the broker build `https` links.

## `[cors]`

| Key | Default | Means |
| --- | --- | --- |
| `enabled` | `false` | `false` (off), `true` (the lists below), or `"permissive"` (mirror every origin, header and method, with credentials) |
| `allow-origins` | `["*"]` | Origins, when `true` |
| `allow-methods` | `["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]` | Methods, when `true` |
| `allow-headers` | `["*"]` | Request headers, when `true` |
| `expose-headers` | `[]` | Response headers exposed to the page, for example `Link` and `NGSILD-Results-Count` |
| `allow-credentials` | `false` | Allow credentialed requests |
| `max-age-seconds` | `3600` | Preflight cache lifetime |

An entry that is not a valid origin, method or header name stops startup. So does `allow-credentials = true` together with a `*` in any list. Browsers refuse that combination, so name the entries.

## `[prometheus]`

| Key | Default | Means |
| --- | --- | --- |
| `enabled` | `true` | Collect and expose metrics |
| `path` | `"/ngsi-ld/auth/metrics"` | Where they are served |

`path` must be a route under `/ngsi-ld/auth/`, where Libra keeps its own routes. Any other path is one the broker may serve. A metrics route there would answer in its place, unauthenticated. With metrics enabled, the path must also not be a route Libra already serves there (`health`, `ready`, `info`). A URL, a path, an origin, a method or a header name that does not parse stops startup with the key it was written under.

The health, readiness and build-info routes are excluded from measurement, so a probe every second does not become the traffic the metrics describe.

## `[logging.console]` and `[logging.file]`

| Key | Console default | File default |
| --- | --- | --- |
| `enabled` | `true` | `false` |
| `level` | `"info"` | `"info"` |
| `format` | `"compact"` | `"json"` |
| `ansi` | `true` | (not applicable) |
| `file-line` | `false` | `true` |
| `target` | `true` | `true` |
| `thread-ids` | `false` | `false` |
| `directory` | (not applicable) | `"logs"` |
| `file-prefix` | (not applicable) | `"libra"` |
| `rotation` | (not applicable) | `"daily"` |

Levels are `trace`, `debug`, `info`, `warn`, `error`. Formats are `compact`, `pretty`, `json`. Rotation is `minutely`, `hourly`, `daily`, `never`. File logging needs a writable directory, so a container run with a read-only root filesystem needs a volume mounted there.

## `[representation]`

How strictly the shape of a response is read out of a request. Libra resolves every request's `Accept`, `options` and `format` once, above authorization, so everything that keys, coalesces or rewrites a response describes the same answer. Resolving is not refusing. Both keys default to `forward`, which leaves an unanswerable request going to the broker, as it did before anything read the header.

| Key | Default | Means |
| --- | --- | --- |
| `unsatisfiable-accept` | `"forward"` | `forward` or `refuse`. `refuse` answers 406 when every media type Libra can produce is unmatched or given `q=0` |
| `contradictory-options` | `"forward"` | `forward` or `refuse`. `refuse` answers 400 for `options=keyValues,concise`, a `format` disagreeing with `options`, or a misspelled token. A query string that cannot be read at all is refused with 400 under either setting |

Under `forward`, the request carries the reason it could not be resolved, and the layers below decline to act on it rather than guessing.

## Sections a build adds

The sections above are the ones every build reads. A build that adds behaviour claims its own sections, and a file that has one the running build does not claim is refused at startup, naming the section, so a file written for a build with more in it does not load in this one.
