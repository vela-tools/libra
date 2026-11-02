# Writing policies

A Libra policy says who may do what, to which resources, under which conditions. Policies are TOML files in one directory, read once at startup. Changing the policy set means restarting the process, as [Operations](../operations.md#changing-the-policy-set) describes. Every name in a policy is compiled to an IRI when the policy loads. The request's name is expanded to an IRI in the same way and compared with it, so a policy and a caller that use the same name for different things never match silently.

This page covers the language: what a policy is made of, what it can match on, and how several policies decide. What an allowed request reaches is the job of restrictions. Each restriction has its own page: [attribute](attribute-restriction.md), [entity type](entity-type-restriction.md), [scope](scope-restriction.md), [time](time-restriction.md) and [aggregation](aggregation-restriction.md). Two behaviours cut across them: [linked entity retrieval](linked-entity-retrieval.md) and [context source registrations](context-source-registrations.md). The [cookbook](cookbook.md) shows the language in complete policy sets to copy from.

## A first policy

```toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "fleet-read"
description = "Fleet operators may read vehicles, but not where they are"
priority = 100

[policy.condition]
groups = ["fleet"]
operations = ["read"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
```

Every name is kebab-case. An unrecognised key anywhere in a policy file is a startup error. The error names the file, the line and the key. This includes a restriction under `[policy.access]` that does not exist. Such a key is never silently ignored. The check also catches misspellings, so `[policy.access.scopes]` is refused rather than read as an unrestricted allow:

```
libra: could not parse '/etc/libra/policies/scoped.toml'
  caused by: TOML parse error at line 6, column 16
  |
6 | [policy.access.scopes]
  |                ^^^^^^
unknown field `scopes`, expected one of `effect`, `scope`, `entity-type`, `time`, `attribute`, `aggregation`
```

## The context declaration is not optional decoration

`context` names the JSON-LD contexts that the terms in the file are written against. It is the most important line in a policy file, and the line most often written wrong.

In NGSI-LD, `Vehicle` is not a type. It is a *term*. What it means depends on the `@context` the request carried. Under one context it is `https://uri.fiware.org/ns/data-models#Vehicle`. Under another it is `https://uri.etsi.org/ngsi-ld/default-context/Vehicle`. A caller may also supply a context of their own that makes it mean anything at all. [Broker parity](../reference/jsonld-broker-parity.md) records a live broker that stored an entity under a caller-chosen IRI. The same query found it by IRI but not by term.

A policy is compiled to IRIs when it loads, against the context this line declares. A request is expanded to IRIs when it arrives, against the context the request declares. Both use the same resolution. The declared contexts come first, then the NGSI-LD core context, then a full JSON-LD expansion of each name. The comparison is between IRIs. The consequences are:

- **A policy that declares no context means the core context alone.** The core context sets a vocabulary, so a term it does not define still expands. For `Vehicle` it expands to `https://uri.etsi.org/ngsi-ld/default-context/Vehicle`, which is also where a broker files it when a request sends no context. If your clients send a data-model context and your policy does not declare it, the policy's `Vehicle` and the request's `Vehicle` are different IRIs, and the policy matches nothing. It loads without complaint, because the term resolves. It resolves somewhere else.
- **An absolute IRI can be written instead of a term.** `https://uri.fiware.org/ns/data-models#Vehicle` compiles to itself under any context, so a policy written in IRIs does not depend on its `context` line. It matches a request that names the type by term under a context that expands it to that IRI, or by the same IRI. Anything of the form `scheme://...` is always absolute, even under a context that defines a term named `https`.
- **The core context is applied last, so core terms keep their meaning.** A declared context cannot move `location`, `observedAt` or any other core term to another IRI. The core definition wins, for the policy and for the request alike. A request whose own context redefines a core term is refused with 400. The core namespace written over `http`, as published data-model contexts do for `location`, is read as the same IRI as over `https`. That is not a redefinition, and a rule about `location` covers both spellings.
- **A term with a colon is expanded as JSON-LD expands it.** If the context defines `ex` as a prefix (its IRI ends in `/`, `#` or another gen-delim, or it is marked `@prefix: true`), `ex:Vehicle` expands through it. If nothing defines `ex`, `ex:Vehicle` is an absolute IRI with the scheme `ex` and compiles to itself, so an allow written that way allows nothing, and a deny written that way refuses nothing.
- **A name with no single meaning is a startup error.** That covers a keyword (`id`, `type`, or anything starting with `@`), a name that expands to no valid IRI, and `ex:Vehicle` when the context defines `ex` as an ordinary term rather than a prefix. JSON-LD 1.1 reads that last form as an absolute IRI, and JSON-LD 1.0 reads it through `ex`. A broker could take either reading. A policy whose names have no settled meaning cannot be said to allow or refuse anything, so it is refused rather than guessed at.

Contexts must be reachable. Either list them under `[jsonld] allowed-contexts`, or name them in `[jsonld] preloaded-contexts` so that they are read from disk. The second option is how a deployment with no outbound network resolves them.

## Conditions

Every field is an allow list. An **absent** field matches everything. An **empty** list is a startup error, because it looks like a narrowing and narrows to nothing. A policy matches when every field it names matches.

| Field | Matches |
| --- | --- |
| `users` | the account the caller authenticated as, named by the token's `sub` |
| `principals` | the name of the principal the API key belongs to |
| `groups` | any one of the caller's groups |
| `roles` | any one of the caller's roles |
| `tenants` | the tenant named in `NGSILD-Tenant`; `"*untenanted"` matches a request that named none |
| `operations` | `read` or `write` |
| `resources` | the resource family the request addresses |
| `entity-types` | an allow: every type the request names; a deny: any type the request names, or none |
| `queries` | the exact query, compared through its canonical form |
| `time-interval` | a recurring window during which the request may be made |

An account and a principal are different callers, even when they share a name. `users` never matches a principal, and `principals` never matches a token subject. Roles and groups are compared exactly as the token carries them. They are read only from its top level.

`"*untenanted"` is neither a named tenant nor an empty tenant header. An empty header is refused outright, because a request that names an empty tenant is not the same as a request that names none.

### Resources

`resources` names the NGSI-LD resource families of clause 6 a request addresses:

| Family | Paths |
| --- | --- |
| `entities` | `/entities`, `/entities/{id}`, and the `/entityOperations` batch endpoints |
| `temporal` | `/temporal/entities` and its batch operations |
| `discovery` | `/types` and `/attributes`, with and without a type or attribute named |
| `subscriptions` | `/subscriptions` |
| `registrations` | `/csourceRegistrations` |
| `registration-subscriptions` | `/csourceSubscriptions` |
| `entity-maps` | `/entityMaps` and `/temporal/entityMaps` |
| `contexts` | `/jsonldContexts`, the broker's context cache |
| `snapshots` | `/snapshots` and clone |
| `info` | `/info/*`, the broker's own description of its sources |

An **allow** whose condition names no `resources` covers only `entities`, `temporal` and `discovery`. Subscriptions, registrations, entity maps, the context cache, snapshots and `/info` are reached only by an allow that names them, so a write allow written for entities does not also let its holder register a context source or evict the broker's cached contexts.

A **deny** whose condition names no `resources` covers every family, so a deny written for a caller refuses them everywhere, and no policy that names another family can sidestep it.

A `read` on a family is a GET or a batch query against it. A `write` is a create, update, upsert, merge or delete. A `write` on `registrations` decides where the broker sends other callers' requests, and which of their headers it copies there. Treat it as an administrative allow. See [context source registrations](context-source-registrations.md) for what a reader without it is shown.

### Entity types as a condition

The `type` parameter is read as the NGSI-LD type expression it is. `A|B`, `A;B`, `(A|B)` and `A,B` all name both types. An `allow` with `entity-types` applies only to a request that names at least one type and names nothing outside the list, so `?type=Vehicle,Secret` is not covered by an allow for `Vehicle`.

A `deny` with `entity-types` applies when the request names any listed type. It also applies when the request names no type at all. A read by id, a batch body or a subscription touches types that the query string does not reveal. A deny that stood aside for them could be bypassed by asking differently.

A request for Linked Entity Retrieval (`join`, `joinLevel`, or a `{...}` term in a projection or in `q`, in the query string or in a `POST /entityOperations/query` body) counts as naming no type, even when it carries `type`. The broker also answers with the entities its Relationships point at, whatever their type. So `?type=Vehicle&join=inline` is refused by a deny on `Building`, and it is not covered by an allow for `Vehicle`. To narrow such requests precisely rather than refuse them, use the [entity type restriction](entity-type-restriction.md).

### Recurring intervals

```toml
[policy.condition.time-interval]
days = ["mon", "tue", "wed", "thu", "fri"]
start = 09:00:00
end = 17:00:00
timezone = "Europe/Ljubljana"
```

The window includes `start` and excludes `end`. `end` is the first instant the policy no longer applies, so the window from 09:00:00 to 17:00:00 stops applying at 17:00:00 exactly. An `end` earlier than `start` crosses midnight, so a window that runs to the end of the day ends at `00:00:00`. Ending it at `23:59:59` would leave the last second of every day uncovered. An `end` equal to `start` runs for a whole day from `start`, so `00:00:00` to `00:00:00` covers each listed day entirely. The days name when the window opens, so a window that crosses midnight on Monday runs into Tuesday morning.

`start` and `end` are written as `HH:MM:SS`, optionally with a fraction. `timezone` is an IANA name such as `Europe/Ljubljana` or `UTC`. A fixed offset or a POSIX TZ string is refused, because neither follows the daylight-saving rules of a place. The name is looked up in the time zone database compiled into Libra, not in the host's `/usr/share/zoneinfo`, so a policy makes the same decision on every host. New tzdata reaches Libra with a release. The zone is parsed when the policy loads. A name that nothing recognises stops the process, rather than producing a policy that silently never applies.

## Restrictions

`effect` under `[policy.access]` is `allow` or `deny`. A restriction is a limit that an allow carries. It narrows what the allow covers. A deny refuses the request and carries nothing else. It cannot name `queries` or any restriction.

A policy that carries a restriction and names `resources` must include at least one family that a restriction applies to (`entities`, `temporal`, `discovery`, `subscriptions`, `registrations`). It may not include `snapshots`, which no restriction judges. A policy that names no `resources` covers `entities`, `temporal` and `discovery`, so it qualifies. Each restriction has its own page. The table maps each block to its page:

| Block | Page | In one line |
| --- | --- | --- |
| `[policy.access.attribute]` | [The attribute restriction](attribute-restriction.md) | which attributes the caller may see and name; filters hidden ones out of every answer |
| `[policy.access.entity-type]` | [The entity type restriction](entity-type-restriction.md) | which entity types the caller may see and write |
| `[policy.access.scope]` | [The scope restriction](scope-restriction.md) | which hierarchical scopes; reads match any allowed scope, writes need every one |
| `[policy.access.time]` | [The time restriction](time-restriction.md) | which slice of the data's history; temporal queries narrowed, current-state reads governed by `current-state` |
| `[policy.access.aggregation]` | [The aggregation restriction](aggregation-restriction.md) | trends, not readings: methods, a minimum period and the grid |

Two behaviours cut across all of them. [Linked entity retrieval](linked-entity-retrieval.md) judges a join answer linked entity by linked entity on the way back. [Context source registrations](context-source-registrations.md) are judged by each restriction on the part of the registration that the restriction is about. Subscriptions are narrowed to the restriction at creation, and are closed to a restricted caller afterwards. Entity maps and context source subscriptions are refused to type- and scope-restricted callers, because their notifications reach endpoints Libra never sees.

## Precedence

Policies are evaluated strongest first:

1. **Descending priority.**
2. **Deny before allow** at equal priority. A tie is broken towards refusing.
3. **Ascending identifier** for anything still tied, so the result never depends on the order in which the directory was read.

The strongest matching policy decides the effect and supplies every restriction: scope, entity type, time, attributes and aggregation. Nothing is combined across policies. A restriction means something only beside the other restrictions its own policy states. An attribute allowance written for one scope, joined to another policy's scope, would allow something that neither policy states. A weaker policy that matches the same request has no effect on it, so a rule meant to hide an attribute from a caller must be the strongest policy that caller matches.

If nothing matches, `[authz] default-effect` decides. It is `deny` by default, so a deployment that has written no policy refuses everything.
