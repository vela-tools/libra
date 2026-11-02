# Read-only dashboard

A wallboard charts the fleet's speed, hour by hour, for the last week. The dashboard's credential should be able to draw exactly that. It should not read current values, take per-vehicle snapshots, or use a method such as `max` that quietly returns a reading as its aggregate. Two restrictions do this together. The [aggregation restriction](../policies/aggregation-restriction.md) allows trends and refuses readings. The [time restriction](../policies/time-restriction.md) limits how far back the trends reach.

## Configuration

```toml
# /etc/libra.toml
[libra]
host = "0.0.0.0"
port = 5667

[broker]
url = "http://broker:9090"

[proxy]
via-pseudonym = "libra-dashboards"

[key-store]
path = "/var/lib/libra/keys.db"

[authz]
policies-dir = "/etc/libra/policies"
default-effect = "deny"

[aggregation]
short-period = "refuse"

[jsonld]
allowed-contexts = ["https://smartdatamodels.org/context.jsonld"]
```

`short-period` is written out for the record, and `refuse` is the default. The other value, `raise`, answers a period below the floor at the minimum instead. The chart then gets a coarser answer than it asked for, and the caller gets less notice of it.

## Policies

```toml
# /etc/libra/policies/dashboard.toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "dashboard-trends"
description = "The wallboard charts hourly averages of the last seven days, and nothing else"
priority = 100

[policy.condition]
groups = ["dashboard-reader"]
operations = ["read"]
resources = ["temporal", "discovery"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "relative"
duration = "PT168H"
direction = "past"

[policy.access.aggregation]
unaggregated = "disallowed"
allowed-methods = ["avg"]
min-period-duration = "PT1H"
```

Naming `resources` narrows the policy to exactly those families. They are aggregated temporal reads, and the `/types` and `/attributes` listings that a chart's type picker uses. `GET /entities`, a read by identifier, and everything else fall outside the policy and to the default effect.

The time restriction is a relative window into the past, so a temporal query's window is narrowed to the last seven days before the broker sees it. The aggregation restriction requires `allowed-methods` to be written out beside `unaggregated = "disallowed"`, because `max` and `min` return readings. A policy that allows only trends has to say so.

## Keys

```sh
libra principal create wallboard --group dashboard-reader
libra key create --principal wallboard --expires-in 90d
```

## The requests

The data is written against the Smart Data Models context. That context travels in the `Link` header of every request below. Without it, `Vehicle` and `speed` are the core context's terms, and the answer is an empty list. Set the header once with:

```sh
LINK='Link: <https://smartdatamodels.org/context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"'
```

The read the chart makes on every refresh:

```sh
curl -s "localhost:5667/ngsi-ld/v1/temporal/entities?type=Vehicle&attrs=speed&timerel=between&timeAt=2026-10-29T10:00:00Z&endTimeAt=2026-10-29T12:00:00Z&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1H" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# forwarded: both boundaries sit on the hour grid, the window spans two periods,
# and the period asked for equals the minimum
```

`aggrMethods` and `aggrPeriodDuration` ask for hourly averages (NGSI-LD clause 6.3.12). The answer holds aggregates, not instances. Each bucket is the value, then the start and end of the period it covers (clause 4.5.19). Scorpio, the broker this example was run against, writes the attribute as an array, with one element per `datasetId`:

```json
[
    {
        "id": "urn:ngsi-ld:Vehicle:city-0417",
        "type": "Vehicle",
        "speed": [
            {
                "type": "Property",
                "avg": [
                    [41.2, "2026-10-29T10:00:00.000000Z", "2026-10-29T11:00:00.000000Z"],
                    [38.7, "2026-10-29T11:00:00.000000Z", "2026-10-29T12:00:00.000000Z"]
                ]
            }
        ]
    }
]
```

Every way the chart could get a reading instead is refused:

```sh
# 403: boundaries off the grid. Two shifted buckets differenced against
# each other are two readings, so the origin is pinned to the period.
curl -s "localhost:5667/ngsi-ld/v1/temporal/entities?type=Vehicle&attrs=speed&timerel=between&timeAt=2026-10-29T10:30:00Z&endTimeAt=2026-10-29T12:30:00Z&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1H" \
  -H "Authorization: Bearer libra_..." -H "$LINK"

# 403: PT30M is finer than the minimum, and not a whole multiple of it
curl -s "localhost:5667/ngsi-ld/v1/temporal/entities?type=Vehicle&attrs=speed&timerel=between&timeAt=2026-10-29T10:00:00Z&endTimeAt=2026-10-29T12:00:00Z&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT30M" \
  -H "Authorization: Bearer libra_..." -H "$LINK"

# 403: max is not in allowed-methods, because a maximum returns a reading
curl -s "localhost:5667/ngsi-ld/v1/temporal/entities?type=Vehicle&attrs=speed&timerel=between&timeAt=2026-10-29T10:00:00Z&endTimeAt=2026-10-29T12:00:00Z&options=aggregatedValues&aggrMethods=max&aggrPeriodDuration=PT1H" \
  -H "Authorization: Bearer libra_..." -H "$LINK"

# 403: no aggregatedValues at all is an unaggregated read, and returns instances
curl -s "localhost:5667/ngsi-ld/v1/temporal/entities?type=Vehicle&attrs=speed&timerel=between&timeAt=2026-10-29T10:00:00Z&endTimeAt=2026-10-29T12:00:00Z" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
```

A read of current state falls outside the policy entirely, because `resources` names only `temporal` and `discovery`:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:city-0417" \
  -H "Authorization: Bearer libra_..."
```

```json
{
    "type": "https://libra.velacontext.com/problems/AccessDenied",
    "title": "Access Denied",
    "status": 403,
    "detail": "Access Denied: access denied by policy"
}
```

A temporal read with no window of its own is not refused. The time restriction closes the open end at the last seven days, the ends are rounded inward onto the hour grid, and the read goes through as a bounded one.

```sh
curl -s "localhost:5667/ngsi-ld/v1/temporal/entities?type=Vehicle&attrs=speed&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1H" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# forwarded with the window narrowed to the last seven days, ends on the hour grid
```

## Reading it back

The grid moves with the minimum. Lengthen `min-period-duration`, and every boundary, span and multiple is judged against the longer period. Add methods to `allowed-methods` only when you mean the chart to see the readings those methods can return. An operator who prefers a coarser answer to a refusal can set `[aggregation] short-period = "raise"`. That answers below-the-floor reads at the minimum period. Set it on purpose, because the caller may not notice the change.
