# The scope restriction

A scope restriction says which NGSI-LD hierarchical scopes a caller may see and write. Scope patterns use MQTT-style wildcards. `#` covers the remaining levels and may only be last. `+` covers exactly one level. Patterns are compared as patterns. They are never resolved through a JSON-LD context, because a scope is a label the deployment agrees on, not a term with an IRI.

```toml
[policy.access.scope]
allowed = ["/Madrid/Gardens/#", "/Madrid/Parks/#"]
scope-on-write = "required"   # or "optional"; the default is "required"
```

`/Madrid/#` matches `/Madrid/A` and `/Madrid/A/B`. It does not match `/Berlin/A`. `/Madrid/+` matches `/Madrid/A` and not `/Madrid/A/B`.

## One entity, several scopes

An entity can carry several scopes, so the relation between an entity and a caller is many-to-many. Reads and writes take opposite sides of it:

- **A read matches if any one of the entity's scopes is allowed.** This holds for a collection query narrowed with `scopeQ`, for a batch query and for a read by id alike, so a caller cannot list an entity they cannot fetch, or fetch one they cannot list.
- **A write requires every scope the entity carries to be allowed.** A caller who can see an entity through one scope must not be able to alter or delete it for the holders of another. A write payload may name only allowed scopes.

Reads are the lenient side. Writes are the strict side. [Multi-scope semantics](../reference/multi-scope-semantics.md) records why reads use the any rule, what the all rule would cost, and what changes if scopes mean classification labels rather than sharing tags.

## Reads

- **Collection and batch query.** A `scopeQ` that the restriction covers only in part is narrowed to that part. This applies in the query string, in a batch query body and in a subscription alike. A disjunction keeps the sides the restriction reaches. Under `/Madrid/#`, the filter `/Madrid/#|/Berlin/#` is forwarded as `/Madrid/#`. A conjunction is refused as soon as either side lies outside the restriction. An entity in a disallowed scope is not readable for also being in an allowed one. So `/Madrid/#;/Berlin/#` is a `403`. A filter left with nothing is a `403` that names the first scope the restriction does not reach.
- **Read by id.** No NGSI-LD scope filter exists for a read by id, so Libra fetches the entity and checks its scopes itself. An entity that carries no scope is not readable under a scope restriction, just as a `scopeQ`-filtered collection query would not return it. An entity that would be withheld gets the same `404` as an absent identifier.
- **Each entity of a query answer is judged** as a read of it by id would be. An entity with no allowed scope, or with no `scope` member at all, is withheld from the answer. A broker that honours `scopeQ` returns no such entity, so this withholds nothing from it. The check keeps a broker that ignored `scopeQ` from leaking. The linked entities of a join answer are judged the same way.
- **The answer's `scope` member is reduced** to the allowed scopes on every read. The bare string, array, normalized `Property` and temporal instance forms are all handled. In a GeoJSON response, the member is read from `properties`. The reduction applies to an entity's own `scope` member and no deeper.
- **A projection may not remove `scope`.** A `pick` that leaves it out, or an `omit` that lists it, is a `400`. Every entity of the answer would then arrive without the member it is judged by, and would be withheld. `attrs` selects attributes and never removes `scope`.

While a scope restriction is in force, the outbound request carries no `Accept-Encoding`. A compressed body cannot be rewritten, and returning it untouched would be the leak this prevents. A success response that is encoded, over the body limit, not JSON or not parseable is refused.

## Writes

`scope-on-write` decides what a payload that names no scope means. `required`, the default, refuses it. `optional` allows a write that leaves the scope unnamed. A payload that names scopes may name only allowed ones. An update, attribute write or delete of an existing entity requires every scope the entity carries to be allowed. That is judged through a pre-flight of the entity as it exists.

## Worked example

Under a restriction allowing `/Madrid/#`:

| Request | Answer |
| --- | --- |
| `GET /entities?scopeQ=/Madrid/Gardens/%23` | forwarded unchanged: the filter is inside the restriction |
| `GET /entities?scopeQ=/Madrid/Gardens/%23\|/Berlin/%23` | forwarded as `scopeQ=/Madrid/Gardens/%23` |
| `GET /entities?scopeQ=(/Madrid/%23;/Berlin/%23)` | `403`: the conjunction names a disallowed scope |
| `GET /entities/urn:example:Entity:1` where the entity is scoped `/Madrid/A` | answered unchanged |
| the same entity scoped `[/Madrid/A, /Secret/X]` | answered, with `scope` reduced to `/Madrid/A` |
| the same entity scoped `/Secret/X` | `404`, same body as a nonexistent identifier |
| `PATCH` of an entity scoped `[/Madrid/A, /Secret/X]` | `403`: a write needs every scope |

Context source registrations are judged by the scopes they register. See [context source registrations](context-source-registrations.md).
