# Policy cookbook

Each scenario below gives a policy set to copy from, with its TOML, what it answers, what it refuses and why. [Writing policies](index.md) defines the language these use. The [examples](../examples/index.md) are complete deployments built around some of them.

Every file below declares the Smart Data Models context. Use whichever context your callers send. A policy's names are compiled against the context its file declares, so a policy written against the wrong one matches nothing.

Two rules decide most of what follows. The strongest matching policy decides the request alone. Policies are ranked by priority, then deny before allow, then identifier. Nothing is combined across policies. A request that no policy matches falls to `[authz] default-effect`, which is `deny` unless changed.

## Administrator everywhere

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "administrators"
description = "Administrators may do anything on every resource family"
priority = 1000

[policy.condition]
groups = ["libra-admin"]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts", "snapshots", "info"]

[policy.access]
effect = "allow"
```

**Answers** every NGSI-LD request of a caller in `libra-admin`, in every tenant, read and write. **Refuses** nothing a member of the group asks, except a path this build does not classify, which no policy can allow.

The `resources` list is the part people leave out. Without it the allow covers entity data only (`entities`, `temporal`, `discovery`). The administrator then gets 403 on subscriptions, registrations and the context cache. The priority matters too. This policy carries no restriction, and as the strongest policy its holders match, it decides for them. A restricted allow written later for a group that an administrator also belongs to does not narrow the administrator. Being at the top also means a deny at a lower priority does not reach an administrator. A deny meant to apply to everyone has to sit at the same priority or above, where deny wins the tie.

This policy says nothing about Libra's own routes. The metrics and build-info endpoints are gated by the `[management-api]` lists. If administrators should reach them, name the group there as well (`admin-groups = ["libra-admin"]`).

## A role that writes one thing and reads another

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "telemetry-write"
description = "Telemetry writers create and update devices"
priority = 100

[policy.condition]
roles = ["telemetry-writer"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Device"]

[[policy]]
id = "telemetry-read"
description = "Telemetry writers read vehicles"
priority = 100

[policy.condition]
roles = ["telemetry-writer"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
```

| Request | Answer |
| --- | --- |
| `POST /entities` with `"type": "Device"` | forwarded |
| `PATCH /entities/urn:ngsi-ld:Device:7/attrs` | forwarded: the pre-flight finds a `Device` |
| `GET /entities?type=Vehicle` | forwarded |
| `POST /entities` with `"type": "Vehicle"` | 403: the write policy allows `Device` only |
| `GET /entities?type=Device` | 403: the read policy allows `Vehicle` only |
| `GET /entities/urn:ngsi-ld:Device:7` | 404, the same answer an absent identifier gets |

The two policies never compete. `operations` splits every request between them. The types are a restriction rather than an `entity-types` condition, on purpose. The condition is matched against the `type` the request names in its query. A create names its type in the body, so an allow with `entity-types = ["Device"]` would never cover a create. The restriction reads the body, pre-flights an entity addressed by identifier, and narrows a type selection. That is the behaviour wanted here.

## A tenant-scoped service principal

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "ingest-fleet"
description = "The ingest service writes and reads the fleet tenant, nothing else"
priority = 100

[policy.condition]
principals = ["ingest"]
tenants = ["fleet"]

[policy.access]
effect = "allow"
```

```sh
libra principal create ingest
libra key create --principal ingest --expires-in 90d
```

**Answers** the ingest key's reads and writes of entity data with `NGSILD-Tenant: fleet`. **Refuses** the same key naming any other tenant, or naming none: neither matches, and the default effect decides.

`principals` matches the API key principal by name and nothing else. An account in the identity provider that happens to be called `ingest` is not covered. Naming the principal makes this policy about one caller. When several services share the same rights, give them a group instead.

## Public read of untenanted data

```toml
# /etc/libra.toml
[multitenancy]
policy = "allow-public"
```

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "public-read"
description = "Anyone may read air quality in the default tenant"
priority = 100

[policy.condition]
callers = "anonymous"
tenants = ["*untenanted"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["AirQualityObserved"]
```

**Answers** a read of `AirQualityObserved` that names no tenant and carries no credential. **Refuses** a write, another type, and every request that names a tenant from a caller no other policy covers. A caller who presents a credential is not covered by this policy, so the type restriction it carries does not narrow them. Their requests are decided by the policies written for them.

`*untenanted` matches a request that names no tenant. The broker serves such a request from its default tenant. It does not mean any tenant. A named tenant cannot be made public: a request that names a tenant always authenticates, whatever `[multitenancy]` says. An empty `NGSILD-Tenant` header is refused outright rather than read as no tenant.

`allow-public` lets a request without a credential reach the policy set at all. It changes how every policy is read, not only this one. A policy that names no `users`, `principals`, `groups`, `roles` or `callers` applies to an anonymous caller too. Check the whole set for such policies before switching it on, and add `callers = "authenticated"` to each one that is not meant to be public. Leave `callers` out of the public policy only if it is meant for authenticated callers as well. Keep a restriction on the public policy, as here, so that the public surface is written down. A credential that is presented and refused is still a 401. It never falls back to anonymous.

## Deny one caller everywhere

```toml
[[policy]]
id = "suspend-contractor"
description = "The contractor account is suspended pending review"
priority = 1000

[policy.condition]
users = ["5b0e2a6c-1d7f-4c3e-9a4b-2f8e6d1c0b9a"]

[policy.access]
effect = "deny"
```

**Refuses** every request from that account, on every resource family, in every tenant. **Answers** nothing it did not already answer for anyone else.

A deny whose condition names no `resources` covers every family. That is what makes this a suspension rather than a refusal of entity data only. At priority 1000 it ties with the administrator policy above. Deny wins a tie, so the suspension holds even for an administrator. A deny carries nothing but its effect. It cannot name `queries` or a restriction.

`users` names the token's `sub`. For Keycloak, that is the internal identifier, not the username. For an API key caller, revoking its keys is faster and cleaner than a policy, because it needs no restart. A deny naming `principals` is for the case where the principal must stay but must do nothing.

## Trends only

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "trends-only"
description = "Analysts read hourly averages and sums, never single readings"
priority = 100

[policy.condition]
groups = ["analyst"]
operations = ["read"]
resources = ["temporal", "discovery"]

[policy.access]
effect = "allow"

[policy.access.aggregation]
unaggregated = "disallowed"
allowed-methods = ["avg", "sum"]
min-period-duration = "PT1H"
```

**Answers** an aggregated temporal read for `avg` or `sum` whose window and period sit on the hourly grid, and the type and attribute listings. **Refuses** a current-state read (it falls outside `resources`), an unaggregated temporal read, `min` and `max`, which return readings, and a period or window off the grid.

`allowed-methods` has to be written beside `unaggregated = "disallowed"`. A policy that is meant to allow trends only must say whether it allows `min` and `max`. The grid stops two overlapping windows from being differenced into single readings. [The aggregation restriction](aggregation-restriction.md) explains the grid. The [read-only dashboard](../examples/read-only-dashboard.md) adds a time restriction to the same policy.

## Office hours only

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "operators-office-hours"
description = "Operators may write during the working week, in the city's time zone"
priority = 100

[policy.condition]
groups = ["operator"]
operations = ["write"]

[policy.condition.time-interval]
days = ["mon", "tue", "wed", "thu", "fri"]
start = 08:00:00
end = 18:00:00
timezone = "Europe/Ljubljana"

[policy.access]
effect = "allow"
```

**Answers** an operator's write from Monday to Friday, from 08:00 up to but not including 18:00 Ljubljana time, daylight saving included. **Refuses** the same write at 18:00:00 exactly, at night and at the weekend, where the policy does not match and the default effect decides.

`time-interval` is a condition. It is about when the request is made. It is not the [time restriction](time-restriction.md), which is about which part of the data's history a request may reach. Outside the window this policy does not match, and the default effect decides. Under the default `deny`, nothing more is needed. A deny with an interval refuses a window inside a broader allow. It has to sit at the allow's priority or above. The zone is an IANA name looked up in the database compiled into Libra, so the decision is the same on every host.

## An integrator that manages subscriptions

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "integrator-subscriptions"
description = "The integration platform creates, lists, changes and deletes subscriptions"
priority = 100

[policy.condition]
principals = ["integration-platform"]
tenants = ["fleet"]
resources = ["subscriptions"]

[policy.access]
effect = "allow"
```

**Answers** every subscription request of the integration platform in `fleet`. **Refuses** everything else it asks, including reading the entities themselves, unless another policy allows that.

Treat this allow as administrative, for two reasons. First, subscriptions are shared by every caller of a tenant and record nothing of who created them. Whoever may list, change or delete subscriptions can do so to everyone's. Second, a subscription's notifications go from the broker to the endpoint the subscription names, without passing through Libra. An unrestricted subscription delivers whatever it matches to wherever its creator chose, outside every filter Libra applies to reads.

If the integrator should see only some data, put the restriction on this policy. A subscription created under a restriction is narrowed to it at creation. Existing subscriptions are then closed to the caller entirely, because a listing or an update would reach subscriptions that the restriction never narrowed. A restricted integrator can create subscriptions and nothing more. That is the price of a subscription whose notifications nobody can filter.

## Keycloak groups and roles

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "fleet-readers"
description = "Members of the fleet group with the reader realm role read the fleet"
priority = 100

[policy.condition]
groups = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"

[[policy]]
id = "fleet-writers"
description = "The fleet-writer realm role writes the fleet"
priority = 100

[policy.condition]
roles = ["fleet-writer"]
operations = ["write"]

[policy.access]
effect = "allow"
```

This set works once the realm emits `groups` and `roles` at the top level of its access tokens. [The Keycloak page](../authentication/keycloak.md) sets this up with a Group Membership mapper (full group path off) and a Realm roles mapper. Before that, the tokens still validate and the lists arrive empty. Every request then lands on the default effect, as a 403 that looks like a policy problem.

Names are matched exactly as the token carries them. With full group path on, the claim says `/orgs/fleet`, and `groups = ["fleet"]` matches nothing. A name that is empty, holds a comma or a control character, or is longer than 256 characters refuses the whole token with 401. It is not dropped.

## Progressive hardening

A policy set is easiest to get right in steps. Each step is a restart. The steps below move one fleet deployment from open to deny-by-default without a day on which the operators are locked out.

**Step one: open, and recorded.** Libra runs with `[authz] default-effect = "allow"` and no policies at all. Every authenticated request on every resource family is forwarded, and every one is audited. Anonymous requests are still refused unless `[multitenancy] policy = "allow-public"`. Set `[audit] token-fingerprint-key` now, so that the records of this step can be read by credential later.

**Step two: name who does what.** Still under `default-effect = "allow"`, write the allows that the audit lines show are needed:

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "operators"
description = "Operators run the fleet"
priority = 100

[policy.condition]
groups = ["operator"]

[policy.access]
effect = "allow"

[[policy]]
id = "dispatch"
description = "Dispatchers read the fleet, not where it is"
priority = 100

[policy.condition]
groups = ["dispatch"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
```

A request that one of these policies matches now carries its id in the audit line's `policy` field. A request that none of them matches carries no `policy` field at all. The default effect decided it.

**Step three: narrow.** Add the restrictions and denies that the business needs. Examples are the attribute restriction above, a type restriction on a role, and a deny for a caller who should not be there. Each restart shows up in the audit lines as a change in which policy decides.

**Step four: deny by default.** Before switching, search the audit lines of a representative period. Look for `AUDIT_SUCCESS` on an `/ngsi-ld/v1/` path without a `policy` field. Libra's own routes are audited too and never carry a policy, which is why the path matters. Each line left is a request that the default effect allowed. Each will get a 403 after the switch. Write a policy for it, or accept that it stops. Then set `default-effect = "deny"`, the default, and restart.

Keep step one brief. `default-effect = "allow"` allows every family, including the context cache, registrations and snapshots, to every caller Libra authenticates. That is far more than any deployment means to leave running.
