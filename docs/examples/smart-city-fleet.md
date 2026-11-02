# Smart-city fleet

A city runs a fleet of connected vehicles that report over NGSI-LD. The dispatch room needs to see every vehicle and its speed. Where each vehicle is right now is a different question. The dispatch floor is shared with contractors, and a live position feed is not theirs to read. The broker holds the positions either way, so the proxy does the job. One group may read vehicles and never see `location`, whatever it asks for and whatever the broker would answer.

This page shows the [attribute restriction](../policies/attribute-restriction.md) doing both of its jobs. It hides an attribute from every answer. It also refuses any request that would read the attribute through a filter.

## What the broker holds

The data model is the Smart Data Models `Vehicle`, resolved through `https://smartdatamodels.org/context.jsonld`. Each vehicle carries a `location` GeoProperty and a `speed` Property:

```json
{
    "id": "urn:ngsi-ld:Vehicle:city-0417",
    "type": "Vehicle",
    "speed": {
        "type": "Property",
        "value": 43
    },
    "location": {
        "type": "GeoProperty",
        "value": {
            "type": "Point",
            "coordinates": [
                15.6405,
                46.5547
            ]
        }
    },
    "@context": "https://smartdatamodels.org/context.jsonld"
}
```

## Configuration

```toml
# /etc/libra.toml
[libra]
host = "0.0.0.0"
port = 5667

[broker]
url = "http://broker:9090"

[proxy]
via-pseudonym = "libra-city-fleet"

[key-store]
path = "/var/lib/libra/keys.db"

[authz]
policies-dir = "/etc/libra/policies"
default-effect = "deny"

[jsonld]
allowed-contexts = ["https://smartdatamodels.org/context.jsonld"]
```

`[multitenancy]` is left at its default, `authenticate`, so an authenticated caller without a tenant header is served the default tenant. The fleet is one tenant, so the requests below carry no tenant header.

The `[jsonld]` entry is exact, so it allows that one document and nothing under it. The policy file declares the same context, and the two lines have to agree. If they disagree, the policy's `location` and the request's `location` compile to different IRIs. The restriction then never applies, and nothing reports this at load time, because each side resolves fine on its own.

## Policies

```toml
# /etc/libra/policies/fleet.toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "dispatcher-read"
description = "Dispatch reads vehicles and their speed, never where they are"
priority = 100

[policy.condition]
groups = ["dispatcher"]
operations = ["read"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]

[[policy]]
id = "supervisor-read"
description = "Supervisors read vehicles whole"
priority = 100

[policy.condition]
groups = ["supervisor"]
operations = ["read"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"
```

There are two allows and no deny, with `default-effect = "deny"` behind them. The strongest matching policy decides alone and supplies every restriction, so a caller who matches only `dispatcher-read` sees vehicles without `location`, and a caller who matches only `supervisor-read` sees them whole.

The tie matters. A caller in both groups matches both policies. The priorities are equal, so the tie is broken by ascending identifier, and `dispatcher-read` wins. The caller sees the fleet without positions. Remember this when you add a wider allow: a restriction has to sit in the strongest policy a caller matches, or it never applies to that caller.

## Keys

```sh
libra principal create dispatch-01 --group dispatcher
libra principal create dispatch-02 --group dispatcher --group supervisor
libra principal create supervisor-01 --group supervisor
libra key create --principal dispatch-01 --expires-in 90d
```

The key is printed once, as `libra_<id>_<secret>`, and Libra keeps only a digest of it. Each command runs beside the running proxy, with the same configuration file. Issue the other keys the same way.

## The requests

Every request below sends the same `Link` header, which carries the context:

```sh
LINK='Link: <https://smartdatamodels.org/context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"'
```

A plain collection read, as dispatch:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
```

The broker answered with the fleet. Libra removed `location` from every entity on the way back. The context comes back in the `Link` header, as it does for any `application/json` answer:

```json
[
    {
        "id": "urn:ngsi-ld:Vehicle:city-0417",
        "type": "Vehicle",
        "speed": {
            "type": "Property",
            "value": 43
        }
    }
]
```

The same request as a supervisor:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 200: the same list, with location present
```

And as `dispatch-02`, which holds both groups and matches both policies:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 200: the list without location; dispatcher-read wins the tie by ascending id
```

A projection asks to see less, so it is narrowed rather than refused.

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle&attrs=speed,location" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# forwarded as attrs=speed; the answer has no location in it either way
```

A filter on the hidden attribute is refused. This is why `omit` alone is not the whole job. The quotes are percent-encoded, because every character outside a URL's legal set has to be. curl sends what it is given. A raw `"`, `<` or `>` in the request line is refused with a `400` before Libra reads the request:

```sh
curl -s 'localhost:5667/ngsi-ld/v1/entities?type=Vehicle&q=location==%22Depot%22' \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 403: the set of entities that answers is a reading of location for every vehicle
```

The geospatial channel counts as a filter whether or not it names the attribute, because `location` is the default geoproperty. This query is refused:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle&geometry=Point&coordinates=%5B15.64,46.55%5D&georel=near;maxDistance==500" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 403: geoproperty is unset, so the query is about location
```

Ordering by a hidden attribute would disclose its values through the order. It is refused the same way:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle&orderBy=location" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 403
```

A write is refused for a different reason. No policy above names `write`, so the default effect refuses every write from dispatch:

```sh
curl -s -X PATCH "localhost:5667/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:city-0417" \
  -H "Authorization: Bearer libra_..." -H "$LINK" \
  -H "Content-Type: application/json" \
  -d '{"speed": {"type": "Property", "value": 51}}'
```

```json
{
    "type": "https://libra.velacontext.com/problems/AccessDenied",
    "title": "Access Denied",
    "status": 403,
    "detail": "Access Denied: access denied by policy"
}
```

A write allow that covered these callers would still refuse a payload that names `location`, with a `403`. Writing what you may not read is how a hidden attribute gets overwritten with chosen values.

Under `application/geo+json`, the hidden attribute appears twice. Both appearances are removed:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Accept: application/geo+json" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 200: location is gone from properties, and the top-level geometry with it
```

## Reading it back

`omit` hides the attribute from every representation. A projection is narrowed. A filter, a geospatial query or an order that names the attribute is refused. To give a caller more, switch to `pick` and list what they may see. `pick` allows only the listed attributes. `id`, `type` and `@context` need no entry, because they say what a document is rather than hold data within it.
