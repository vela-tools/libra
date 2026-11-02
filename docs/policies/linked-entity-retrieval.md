# Linked entity retrieval under a restriction

Linked Entity Retrieval (NGSI-LD 4.5.23) is the `join` family of parameters. It asks the broker to follow the Relationships of the entities in the answer, and to inline the entities they point at. It is requested in the query string (`join`, `joinLevel`), in linked projection terms (`attrs=relationship{...}`), in linked `q` paths, in a `POST /entityOperations/query` body, and in a subscription's notification parameters.

A join widens what one request answers with, and so it widens what a restriction has to judge. Without a check, a caller allowed only `Vehicle` would get, in one answer, the Buildings those vehicles are parked at. Libra closes this gap by judging a join answer **linked entity by linked entity on the way back**. Each linked entity is judged under the same decision that governs the entities the caller asked for.

This page covers what a restriction does to a join. Each restriction's own meaning is on its own page: [attribute](attribute-restriction.md), [entity type](entity-type-restriction.md), [scope](scope-restriction.md) and [time](time-restriction.md).

## How a join is judged

- **Entity type.** A linked entity is shown when every one of its types is allowed.
- **Scope.** A linked entity is shown when one of its scopes is allowed, with its `scope` member reduced to the allowed ones as for any read.
- **Attribute.** A linked entity's attributes are filtered as any entity's are.

A linked entity that is not shown is removed. The Relationship that points at it stays, so its `object` still names the target, as a read without the join would.

A `{...}` projection term in `attrs`, `pick` or `omit` is served together with a `join`. Its inner names are filtered in the answer. Under an attribute restriction, a linked `q` path is checked in full, relationship by relationship, as [the attribute page](attribute-restriction.md) describes.

## What is served

`join=inline` and `join=flat`, in the normalized and concise representations and in `application/geo+json`, on `/entities`, `/entities/{id}` and `POST /entityOperations/query`, whether `join` is in the query string or the `Query` body.

## What is refused

**With `403`:**

- `join=inline` in `keyValues`. A Relationship's value is replaced by the linked entity there, and a withheld one cannot be told from data.
- A join in `temporalValues` or `aggregatedValues`, or with a representation the request did not settle.
- A `join` value other than `flat`, `inline` or `@none`.
- `joinLevel`, or a `{...}` projection term, without a `join`.
- A `{...}` path in `q` under a type or scope restriction. The linked entities' values decide which entities come back, but they never appear in the answer, so there is no type or scope to judge them by. Under an attribute restriction alone, the path is checked name by name instead.
- Any of the above in a subscription's `notification`. That delivers linked entities straight to an endpoint Libra never sees.
- Any join, or `{...}` path in `q`, on a temporal endpoint under a time restriction.

**With `400`:** a join whose `pick` or `omit` removes `type` under a type restriction, or `scope` under a scope restriction, from any entity of the answer, linked entities included. A linked entity is judged by that member.

**With `502`:** an answer that is not recognisably a join answer, a linked member that holds something other than entities, or nesting deeper than 32 levels. The answer is withheld, not forwarded.

Temporal joins stay refused throughout. NGSI-LD 1.9.1 defines `join` only for `GET /entities` (6.4.3.2), `GET /entities/{id}` (6.5.3.1), the `Query` type (5.2.23) and `NotificationParams` (5.2.14). No clause says how linked entities appear in a temporal answer, so there is no shape to hold to a time window.

A caller that no restriction narrows gets the broker's answer unchanged. Scorpio's `java-latest` image does not implement `join`. It answers a join request as though `join` were absent, with every Relationship and no linked entity. Behind it, the judging above has nothing to judge, but the refusals still apply.
