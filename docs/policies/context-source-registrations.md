# Context source registrations under a restriction

A context source registration (NGSI-LD 5.2.9, operations 5.9 and 5.10) tells the broker where else context lives: which source, which endpoint, and which entities it holds. It is a document about the tenant's topology, so a restriction judges it by the part of the registration that the restriction is about, and leaves the rest alone. A registration's `endpoint`, `information` and `scope` describe what it is. They are not attributes of an entity.

The `registrations` resource family is reached only by an allow that names it. A `write` on it decides where the broker sends other callers' requests, and which of their headers it copies there. Treat it as an administrative allow. A reader who may not also write it is shown registrations without `contextSourceInfo`, the member that carries the credentials a source expects.

## What each restriction does to a registration

| Restriction | A registration read shows | A registration write must |
| --- | --- | --- |
| [Entity type](entity-type-restriction.md) | only registrations whose registered types are all allowed. A registration with a `RegistrationInfo` that names no `entities` registers its attributes for every type, and is hidden. | register only allowed types; a create naming no `entities` is refused. An update or delete is judged by the registration as it exists, pre-flighted. An update's own `information` is judged too. |
| [Scope](scope-restriction.md) | only registrations with at least one allowed scope, their `scope` reduced to the allowed ones. A registration without `scope` is hidden. | follow `scope-on-write` and name only allowed scopes. An update or delete needs every scope of the existing registration allowed. |
| [Attribute](attribute-restriction.md) | every registration, with forbidden names removed from `propertyNames` and `relationshipNames`. A list left empty is removed. A `RegistrationInfo` left naming no attribute is removed. A registration left with no `RegistrationInfo` is hidden. An `attrs` filter naming a forbidden attribute is refused. | name only allowed properties and relationships. |

A registration read by id that would be hidden gets the same `404` as a registration the broker does not hold. A different answer would tell the caller which registration ids exist outside what they may see.

## What is refused outright

- **Context source subscriptions** (`/csourceSubscriptions`) are refused to type- and scope-restricted callers, because their notifications reach an endpoint Libra never sees.
- **Entity maps** (`/entityMaps`, `/temporal/entityMaps`) are refused under a type or scope restriction for the same reason.
- **An unrestricted holder** of the `registrations` family sees and changes every registration of the tenant, as with subscriptions. No record shows who created a registration, so ownership cannot be enforced. Allow the family with the same care as any administrative allow.

Subscriptions are a separate family. Their rules are in [writing policies](index.md#restrictions).
