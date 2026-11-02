# Multi-tenant dataspace

Two municipalities share one broker. Each holds its own context data under its own tenant, `citya` and `cityb`. Neither city's operators may reach the other's data. A shared audit team reads both, read-only. The broker keeps the tenants apart. Libra decides who may name which tenant, and it refuses a request for a tenant its credential has no rule about.

The moving parts are the `NGSILD-Tenant` header, the `tenants` condition, and `[multitenancy]`. The last is set so that a request without a tenant is not served the default one by accident.

## Configuration

```toml
# /etc/libra.toml
[libra]
host = "0.0.0.0"
port = 5667

[broker]
url = "http://broker:9090"

[proxy]
via-pseudonym = "libra-dataspace"

[key-store]
path = "/var/lib/libra/keys.db"

[authz]
policies-dir = "/etc/libra/policies"
default-effect = "deny"

[multitenancy]
policy = "require-header"

[jsonld]
allowed-contexts = ["https://smartdatamodels.org/context.jsonld"]
```

`require-header` decides only what happens to a request that names no tenant, and it refuses that request. A request that names a tenant always authenticates, whatever the setting says, so there is no anonymous path into a named tenant.

## Policies

```toml
# /etc/libra/policies/dataspace.toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "citya-operate"
description = "City A operators run City A's data"
priority = 100

[policy.condition]
tenants = ["citya"]
groups = ["citya-operator"]

[policy.access]
effect = "allow"

[[policy]]
id = "cityb-operate"
description = "City B operators run City B's data"
priority = 100

[policy.condition]
tenants = ["cityb"]
groups = ["cityb-operator"]

[policy.access]
effect = "allow"

[[policy]]
id = "audit-read"
description = "The audit team reads both tenants, nothing more"
priority = 100

[policy.condition]
tenants = ["citya", "cityb"]
groups = ["auditor"]
operations = ["read"]

[policy.access]
effect = "allow"
```

The operating policies name no `operations`. Each covers read and write for every family an allow covers when `resources` is not named: entities, temporal and discovery. The audit policy names `operations = ["read"]`, so its holders get `403` on any write in either tenant. Every policy names `tenants`, so a request for `cityb` from a City A key matches nothing and falls to the default effect.

Each city's operators hold a group of their own. `tenants` says which tenant a request names. It says nothing about which tenant a caller belongs to. If both operating policies matched one shared group, `operator`, a City A key naming `cityb` would match `cityb-operate`, and each city's operators would run the other's data. The groups keep the cities apart, and the `tenants` condition keeps each group in its own city.

## Keys

```sh
libra principal create citya-ops --group citya-operator
libra principal create cityb-ops --group cityb-operator
libra principal create audit-01 --group auditor
libra key create --principal citya-ops --expires-in 90d
```

Issue the other keys the same way. One key is the same credential in every tenant its policies cover. That is why the audit key works for both tenants, and an operator key works for exactly one.

## The requests

The data is written against the Smart Data Models context, which travels in the `Link` header of every request below. Without it, `Vehicle` is the core context's term, a different IRI, and the answer is an empty list. Set the header once with:

```sh
LINK='Link: <https://smartdatamodels.org/context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"'
```

City A's operator lists its own entities:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK" \
  -H "NGSILD-Tenant: citya"
# 200: City A's vehicles
```

The same key naming the other tenant:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK" \
  -H "NGSILD-Tenant: cityb"
```

```json
{
    "type": "https://libra.velacontext.com/problems/AccessDenied",
    "title": "Access Denied",
    "status": 403,
    "detail": "Access Denied: access denied by policy"
}
```

No policy matches `cityb` for this credential, so the default effect refuses it. The broker never sees the request, so City B's data is not revealed to exist.

The audit key reads either tenant and refuses to write:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK" \
  -H "NGSILD-Tenant: cityb"
# 200: City B's vehicles, read-only

curl -s -X PATCH "localhost:5667/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:cityb-001" \
  -H "Authorization: Bearer libra_..." -H "$LINK" \
  -H "NGSILD-Tenant: cityb" \
  -H "Content-Type: application/json" \
  -d '{"status": {"type": "Property", "value": "maintenance"}}'
# 403: audit-read names operations = ["read"]
```

A request that names no tenant is refused, by design:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 401: require-header refuses a request with no tenant header
```

An empty `NGSILD-Tenant` is refused with `400`, and so is a repeated one. A request that names an empty tenant is not the same as a request that names none. curl writes an empty header as `-H "NGSILD-Tenant;"`. `-H "NGSILD-Tenant:"` removes the header instead, so the request then names no tenant.

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK" \
  -H "NGSILD-Tenant;"
# 400: an empty tenant header is not a tenant
```

An anonymous caller naming a tenant authenticates like anyone:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "NGSILD-Tenant: citya"
# 401: naming a tenant authenticates, and this caller has no credential
```

Writes stay invisible across the boundary, because the header is forwarded. The broker holds per-tenant data, and Libra forwards `NGSILD-Tenant` with the request it accepted, so the broker answers from that tenant only. What the audit key sees in `cityb` is `cityb`'s data as it is, not a copy.

## Untenanted requests elsewhere

Under `authenticate` or `allow-public`, a request with no tenant is served the default tenant instead. A policy can match that case with `tenants = ["*untenanted"]`. That value is not the same as any named tenant. It is also not the same as the empty header, which is refused whatever the setting is. `allow-public` goes further and serves the default tenant to anonymous callers. A policy with no `users`, `principals`, `groups` or `roles` applies to them too, which is why such a policy is never the default. The exact behaviour is in the [configuration reference](../reference/configuration.md).
