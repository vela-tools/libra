# The entity type restriction

An entity type restriction says which entity types a caller may see and write. Like every name in a policy, the types are compiled to IRIs against the file's `context` declaration when the policy loads. A request's types are expanded against the context the request declares, so a caller cannot reach a forbidden type by spelling it through a context of their own.

```toml
[policy.access.entity-type]
allowed = ["Vehicle", "Device"]
type-on-write = "required"    # or "optional"; the default is "required"
```

## Reads

A type selection that the restriction covers only in part is narrowed to that part. This applies to the `type` parameter, to the selectors of a batch query and to a subscription's `entities`.

A disjunction keeps the sides that are allowed. When only `Vehicle` is allowed, `?type=Vehicle,Building` is forwarded as `type=Vehicle`, and `(Vehicle;Building)|Vehicle` is forwarded as `Vehicle`. A conjunction is refused as soon as either side is forbidden. `?type=Vehicle;Building` asks for entities that are both, and an entity of a forbidden type is not readable for also having an allowed one, so with only `Vehicle` allowed that request is a `403`. A selection left with nothing is a `403` that names the first forbidden type.

In a batch body, a selector narrowed to nothing is dropped and the others are kept. The selectors are a disjunction (NGSI-LD 5.2.33). A body whose every selector is dropped is a `403`.

A read by identifier names no type, so it is judged by the entity the broker holds. Libra fetches the entity with a pre-flight request. An entity of a forbidden type gets the same `404` as an absent identifier, so a restricted caller cannot discover which identifiers exist or what they are.

`GET /types/{type}` naming a forbidden type is refused.

## Writes

A create whose payload names a forbidden type is refused before the broker is reached. A batch create, upsert or update is judged entity by entity. An update, merge or delete by identifier is judged by the entity as it exists, through the same pre-flight as a read.

`type-on-write` decides what a payload that names no `type` means. `required`, the default, refuses it. A write whose type nobody can name is a write the restriction cannot judge. `optional` forwards it and judges the payload by what it does carry. A replace (`PUT`) is judged by the entity as it exists, so it never needs `optional`.

## What is unchanged

An `entity-types` *condition* is a different thing from this restriction. It still compares the whole selection. An allow whose condition says `entity-types = ["Vehicle"]` does not cover `?type=Vehicle,Building`, while the restriction narrows it. The condition decides whether the policy matches at all. The restriction decides what an allowed request reaches.

## Worked example

```toml
[policy.access.entity-type]
allowed = ["Vehicle"]
```

| Request | Answer |
| --- | --- |
| `GET /entities?type=Vehicle` | forwarded unchanged |
| `GET /entities?type=Vehicle,Building` | forwarded as `type=Vehicle` |
| `GET /entities?type=Vehicle;Building` | `403`: the conjunction names a forbidden type |
| `GET /entities/urn:example:Building:1` | `404`, same body as a nonexistent identifier, whether or not the broker holds it |
| `POST /entities` with `"type": "Building"` | `403` before the broker is reached |
| `GET /types/Building` | `403` |

Context source registrations are judged by the types they register rather than by the request's `type`. See [context source registrations](context-source-registrations.md).
