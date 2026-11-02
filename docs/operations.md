# Operations and observability

Four routes live outside the NGSI-LD path: two probes, the build info and the metrics. This page covers what each answers, who may call it, what the metrics series carry, and what to alert on. It then covers what else a running Libra produces: the audit record, the logs, and how one request is followed across them. When something here answers unexpectedly, [Troubleshooting](troubleshooting.md) names the log line to read.

## The routes

| Route | Answers | Gate |
| --- | --- | --- |
| `/ngsi-ld/auth/health` | `200` while the process runs | none |
| `/ngsi-ld/auth/ready` | `200` when Libra can serve, `503` when it cannot | none |
| `/ngsi-ld/auth/info` | Name, version, build time, target, commit, branch, as JSON | privileged reads |
| `/ngsi-ld/auth/metrics`, or the `[prometheus] path` | Prometheus exposition of the three series below | privileged reads |

The probes are unauthenticated on purpose. A probe that needed a token would need the identity provider to be reachable so that it can report that the identity provider is not. Nothing they answer describes the deployment beyond whether it is working. They also sit outside the `[limits] max-in-flight-requests` ceiling, like every management route, so they answer during the incident the ceiling exists for.

Readiness answers `503` for one of two reasons, and the log names which one. The first is that no signing keys are loaded, with a `[jwt]` section, so every token would be refused. The second is that the broker check failed. That check asks the broker for `/ngsi-ld/v1/types`. It counts success and `404` alike, since an empty broker is a broker that answers. It times out after five seconds and reuses its answer for two seconds, so a burst of probes costs one broker request.

Build info is gated because its payload is the commit the gateway is running. That commit decides which published advisories apply to it. Unlike the probes, there is no routine reason for a caller to want it. Use it after an upgrade, comparing the served `commit` with the commit you meant to deploy. `libra --version` prints the same facts.

## Who may call the gated routes

The same five `[management-api]` lists decide both gated routes: `admin-users`, `admin-principals`, `admin-clients`, `admin-groups` and `admin-roles`, each matched against one kind of name. All five default to empty. That means no caller is privileged, and both routes refuse everyone. Libra warns about this at startup, so a configuration that loaded differently than the operator expected is visible before the first request.

`GET`, `HEAD` and `OPTIONS` are reads and follow `metrics-access` and `info-access`, both `"privileged"` by default. `"authenticated"` opens a route's reads to any caller Libra authenticates. Everything else is treated as a write and is gated whatever the settings say. A method Libra does not recognize falls on the write side. A refused caller is logged as `management endpoint refused` with the method, the path and, with `[audit] token-fingerprint-key` set, the `credential` fingerprint. The caller's name is in the audit line, not the log.

To scrape the metrics, give the scraper a credential of its own. An API key principal named in `admin-principals` is the usual choice. Setting `metrics-access = "authenticated"` opens the endpoint to every caller Libra authenticates. The metrics carry tenant names, request volumes and error rates, so make that choice knowingly.

## The series

Three series, in Prometheus text format:

| Series | Type | Labels |
| --- | --- | --- |
| `axum_http_requests_total` | counter | `endpoint`, `method`, `status` |
| `axum_http_requests_duration_seconds` | histogram | `endpoint`, `method`, `status` |
| `axum_http_requests_pending` | gauge | `endpoint`, `method` |

Every NGSI-LD request is measured under `endpoint="proxied"`, because the proxied path reaches Libra through the fallback and has no route of its own. Labeling it with the request path would give every entity id its own series. The recorder never evicts a series, so an unauthenticated client asking for `/x1`, `/x2` and so on grew memory without bound. A raw path never appears as a label.

`method` is the request method and `status` is the status Libra answered, 401 and 403 included. The refusals the proxy makes on a caller's behalf are countable from the scrape. The two probes, the build info and the metrics endpoint itself are excluded from measurement, so scraping does not add to what it scrapes. No label carries the caller or the tenant. The per-request record with names in it is the audit line. Set `[prometheus] enabled = false` and the endpoint disappears, along with the series.

## What to alert on

| Signal | Watch | Why |
| --- | --- | --- |
| Broker failures | Rising `axum_http_requests_total{status="502"}` and `{status="504"}` | The broker could not be reached or answered too slowly; readiness agrees |
| In-flight ceiling | `axum_http_requests_pending` approaching `[limits] max-in-flight-requests`, and `status="503"` | Requests past the ceiling are refused without being queued, so a 503 means the ceiling is filling up, usually behind a stalled broker |
| Authentication failures | Rising `axum_http_requests_total{status="401"}` | Mass 401s mean expired tokens after a key rotation the deployment did not pick up, an identity provider outage, or clock drift |
| Denials | `axum_http_requests_total{status="403"}` | A step change follows a policy deploy. A sustained unusual rate is worth a look. |
| Latency | The upper buckets of `axum_http_requests_duration_seconds` | Broker latency shows through the proxy. A rising p99 with a steady 502 rate is a broker queue. |
| Probes | Orchestrator checks on `/ngsi-ld/auth/health` and `/ngsi-ld/auth/ready` | Liveness flapping means the process. Readiness flapping means the broker or the key set. The log line names which. |

Watch the metrics endpoint too. A scrape that starts failing means the scraper's credential was revoked or the gate moved. The log says which credential was refused.

## The audit record

Metrics aggregate. The per-request record is the audit line. One is written for every request that reaches the proxied path or a management route, whether allowed or refused. It is written by a layer that sits above everything that can refuse, so a 401, a 403 or a 413 is on the record in the same way as a success. The probes are the one exception. They are mounted outside every protection, auditing included, so an orchestrator polling them does not fill the record.

The line is a log event like any other. It is written to the same sinks under the target `libra_audit` (shown when the sink's `target` setting is on, as it is by default), with a fixed message per outcome so a query can match on it:

| Message | Level | Outcome |
| --- | --- | --- |
| `AUDIT_SUCCESS` | info | The response was not an error |
| `AUDIT_DENIED` | warn | The response was a 401 or a 403 |
| `AUDIT_ERROR` | warn | Any other 4xx or 5xx, or no response at all |

Because the success line is at info, a sink set to `warn` keeps the refusals and drops the record of every request that was served. Keep the sink the audit trail is collected from at `info`.

Each field is written separately, never as one serialized blob. Under the `json` format, every field is its own member of the event's `fields` object, beside `message`. No consumer has to parse JSON out of a string:

| Field | Carries | Absent or `-` when |
| --- | --- | --- |
| `timestamp` | When the record was completed, RFC 3339 with a numeric offset (`2026-01-15T12:00:00.123456789+00:00`) | never |
| `request_id` | The UUID Libra minted for the request, also returned in `x-request-id` | `-` when the request never passed the layer that mints it |
| `subject` | The caller: a token's `sub`, or a principal's `urn:libra:principal:<ulid>` | absent for an anonymous request, and for a credential that was not accepted |
| `credential` | The credential fingerprint, below | absent when no credential was presented or no key is configured |
| `tenant` | The tenant the request named | absent when it named none |
| `policy` | The id of the policy that decided | absent when the default effect decided, or the request was refused before authorization |
| `method` | The HTTP method | never |
| `path` | The request path, without its query string | never |
| `action` | The method reduced to `read`, `write`, `delete` or `other` | never |
| `outcome` | `ALLOWED`, `DENIED` or `ERROR`, as the message says | never |
| `status_code` | The status Libra answered | absent when no response was produced |
| `client_ip` | The peer address of the connection | `-` when the server has no connection information |
| `access` | `credentialed`, or `public` for a request that used the anonymous access `[multitenancy] policy = "allow-public"` allows | never |
| `duration_ms` | How long the request took, in milliseconds | never |

Three of these are easy to misread. `path` never carries the query string. A query on an NGSI-LD request holds entity ids, filter values and geometries. That is the data the caller was authorized for, and it is not a fact about the decision. An audit sink is also usually a lower-trust system than the broker. `action` is read from the method alone. So a `POST /entityOperations/query`, which policies treat as a read, is recorded as a `write`. The deciding `policy` says how it was judged. `client_ip` is the peer address Libra's socket saw. Behind an ingress, it is the ingress, whatever `X-Forwarded-For` says.

### The credential fingerprint

With `[audit] token-fingerprint-key` set, every presented credential is recorded as sixteen hex characters of HMAC-SHA-256 under that key. That is enough to tell credentials apart in the deployment's own records, and too little to be worth anything outside them. The fingerprint is never the credential itself. It is computed before the credential is judged, so a refusal carries it too. This is what makes it useful. A refused credential often names nobody, and then the fingerprint is the only thing that tells one misbehaving client from many presenting the same dead key. It also shows which callers still present a token signed before a rotation.

The same fingerprint is the `credential` field of the `access denied`, `access allowed` and `management endpoint refused` log lines, which name no caller. Rotating the key breaks correlation with the records made before the rotation, by design, and Libra says so at startup. Generate the key with `openssl rand -hex 32`. A key shorter than 128 bits is a startup error.

## Changing the policy set

The policy set is read from `[authz] policies-dir` once, at startup. Every `.toml` file in the directory is loaded and compiled, and any failure anywhere in it stops the process. So a policy directory is not a place for backups or editor droppings, because every `.toml` in it is treated as policy. Anything else in it, such as `deny.toml.bak` or a subdirectory, is not loaded. Each such entry is named in a warning at startup, so that a policy file saved under the wrong name is not mistaken for one in force. Changing the set means editing the files and restarting. Reloading without a restart, and changing policies over HTTP, are Pro features, described under [Editions](editions.md). Startup is all-or-nothing, so a set that does not compile leaves the previous process untouched and the new one down.

## Logging

Two sinks, configured separately in `[logging.console]` and `[logging.file]`. The console writes to standard output, on by default at `info` in the `compact` format. The file sink is off by default. Switched on, it writes `json` to `directory` (`logs`) under `file-prefix` (`libra`), and rotates daily unless `rotation` says `minutely`, `hourly` or `never`. A container with a read-only root filesystem needs a volume where the file sink writes. Each sink has its own level, so the console can stay at `info` while a file collects `debug`. Each sink also has its own format. `compact` and `pretty` suit people, and `json` suits anything that parses the log. Switching both sinks off is a startup error, since it would leave the audit record nowhere to go.

`info` is the level for production. It carries the audit record, every refusal and failure at `warn`, and the startup lines that say what the process loaded. Those lines cover how many policies, which default effect, whether JWTs and API keys are accepted, and which instance holds the key store's lease. `debug` adds a line per step of each request (`caller authenticated`, `access allowed` with the deciding policy, `forwarding to the broker` with the target). These lines sit under a `request` span carrying the method and the path, never the query string. No log line about a request names its caller. A name is a personal identifier. Debug logging is switched on in deployments that never meant to keep one, and the audit record is where a name belongs. `trace` is for following a defect, not for running.

## Correlation

A request is joined across the three places it leaves a trace like this:

- **The caller's side.** Every response carries `x-request-id`, a UUID Libra mints for each request. One the caller sends is discarded first, so the id can be neither forged nor reused across requests. A problem document's body does not repeat it. Ask a caller reporting a refusal for the header.
- **The audit line.** It carries the same `request_id`, so the header finds the record: the caller, the tenant, the deciding policy, the status and the timing.
- **The log lines.** They do not carry the request id. They are joined to the audit line on the `credential` fingerprint and the time, which is why setting `[audit] token-fingerprint-key` is what makes the log readable per request. At `debug` the lines are also written under a `request` span naming the method and the path, which narrows a search but does not single out one request.

A server error's real cause, which the caller's problem document withholds, is a warning in the log written within the request's duration, beside `answered with a server error whose detail is withheld from the caller`.
