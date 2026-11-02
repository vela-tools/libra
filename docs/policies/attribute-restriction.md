# The attribute restriction

An attribute restriction says which attributes of an entity a caller may see and name. With it, "you may read vehicles" becomes "you may read vehicles, but not where they are".

```toml
[policy.access.attribute]
action = "omit"        # or "pick"
attributes = ["location", "observedAt"]
```

`pick` allows only the listed attributes. `omit` allows everything else. Both forms name attributes as terms. Like every name in a policy, they are compiled to IRIs against the file's `context` declaration.

There is **no implicit exemption list**. `location`, `createdAt`, `modifiedAt` and the rest are ordinary attributes, and a policy that names one means it. Only `id`, `type` and `@context` are exempt. They say what a document is, rather than holding data in it.

## Both halves are enforced

The request is narrowed where it can be, and the response is filtered regardless. A broker may ignore `attrs`, which is only a hint. "Everything except these" cannot be written as a request selector at all, so trusting the narrowing alone would leave the enforcement to the broker.

A read of `urn:example:Vehicle:1` under an `omit` of `location`:

- The `attrs` parameter, when the caller sent one, keeps the names the policy allows and is forwarded narrowed.
- The response body has `location` removed from every entity, at every level, whatever the broker did with the narrowing.

## Filtering on a forbidden attribute is refused

A request that *filters* on a forbidden attribute is refused with `403`, wherever the filter is written. Filtering by an attribute you cannot see still reveals its values, through which entities come back. Ask `q=location=="Downtown"`, and the set of entities returned is a reading of `location` for every vehicle in the fleet.

Every channel that filters counts:

- `q`, including the operator-free existence form `q=location`, which a parser that only recognises a name beside an operator would miss.
- `geoproperty`, and a geospatial query that names none. `location` is then the default that the query is about.
- `orderBy` naming a forbidden attribute. The order of the answer discloses the values it ranked by.
- The same selectors written in a `POST /entityOperations/query` body. The specification provides that body for queries too long for a URL.

A linked-entity path in `q` (NGSI-LD 4.9), such as `q=isParked{name}=="Downtown"`, is checked in full. The Relationship it follows, every Relationship it follows further, and the attribute the final path starts at must each be allowed. So `q=isParked{Garage,Building:owner{name}}=="x"` needs `isParked`, `owner` and `name`. The `Garage,Building:` prefix names entity types, not attributes, and is not checked. Clause 4.9 requires at least two types in that prefix, so `Building:owner` is a compact IRI naming one attribute.

## A projection is narrowed, not refused

A *filter* asks a question about hidden data, while a *projection* only asks to see less of it. So a projection is narrowed to what the policy allows rather than refused:

- `attrs` and `pick` keep the allowed names, in the query string and in a `Query` body alike.
- A body projection written as an array is narrowed element by element. An element left with no name is dropped.
- A projection left with nothing at all is refused with `403`.
- `omit` is left as written, since it can only remove more.

A narrowed body is re-serialised and forwarded with a `Content-Length` that matches it.

## Every representation is filtered

Under `application/geo+json`, an entity is a GeoJSON Feature. The geoproperty appears twice: inside `properties`, and projected to a top-level `geometry`. Removing it from one place and not the other would hide the name and publish the value. Both go, and the `geometry` is kept only when `location` is allowed.

The same holds for a linked entity in a join answer. Its attributes are filtered as any entity's are. See [linked entity retrieval](linked-entity-retrieval.md) for what a join does under a restriction.

## A write naming a forbidden attribute is refused

A create, update or merge whose payload names a forbidden attribute is refused with `403`. A delete or replace of a whole entity carries no attribute names. It is judged by the entity the broker holds, as any write is.

## Worked example

```toml
[policy.access.attribute]
action = "omit"
attributes = ["location"]
```

| Request | Answer |
| --- | --- |
| `GET /entities?type=Vehicle&attrs=speed` | forwarded as asked; the answer has no `location` in it either way |
| `GET /entities?type=Vehicle&q=location=="Downtown"` | `403`: the filter reads a hidden attribute |
| `GET /entities?type=Vehicle&q=speed>50` | forwarded; entities whose `location` is anywhere come back, without their `location` |
| `POST /entityOperations/query` with a `geoQ` that names no `geoproperty` | `403`: the query is about the default, `location` |
| `PATCH` with a `location` member | `403` |
