# The aggregation restriction

The aggregation restriction governs the aggregated reads of NGSI-LD (clause 6.18.3.2). A caller may see trends, but not readings. An aggregated read answers one aggregate per bucket of time. An unaggregated read answers the attribute instances themselves. A policy that allows the first and refuses the second lets a caller chart a fleet's speed without reading any single vehicle's.

```toml
[policy.access.aggregation]
unaggregated = "disallowed"
allowed-methods = ["avg", "sum"]
min-period-duration = "PT1H"
```

All three keys are optional, and each defaults to the permissive side. `unaggregated` is `"allowed"` unless written. `allowed-methods` names a subset of `avg`, `distinctCount`, `max`, `min`, `stddev`, `sum`, `sumsq` and `totalCount`, and when absent names all of them. `min-period-duration` sets no floor unless written.

## Refusing unaggregated reads

`unaggregated = "disallowed"` refuses a read that would return attribute instances rather than aggregates. It also requires `allowed-methods` to be written out beside it. Because `min` and `max` return readings, a policy that means to allow only trends must say whether it allows them.

The setting also confines the caller to the `aggregatedValues` representation. `aggrMethods` is defined only beside that representation (clause 6.18.3.2). A method list beside another representation would be a rule that never applies.

## The minimum period and its grid

`min-period-duration` lays a grid. An aggregated read must satisfy all three of:

- the window boundaries sit on the UTC grid of that period,
- the window spans at least one period,
- the period asked for is a whole multiple of the minimum.

The grid gives the floor its meaning. Partially overlapping windows with a shifted origin let two queries be differenced into single readings. Boundaries pinned to a shared grid remove that possibility. A period written in calendar units has no fixed grid, so it is refused at load. If a [time restriction](time-restriction.md) is also in force, the window is rounded inward onto the same grid. An open window is refused, unless that restriction closes it on the grid.

The `[aggregation] short-period` setting decides what a read below the floor gets. `refuse`, the default, answers it with `403`. `raise` answers it at the minimum period instead. `raise` exists because its answer is still one that the policy allows. `refuse` is the default because it never answers a different question from the one the caller asked.

## Worked example

```toml
[policy.access.aggregation]
unaggregated = "disallowed"
allowed-methods = ["avg"]
min-period-duration = "PT1H"
```

| Request | Answer |
| --- | --- |
| `GET /temporal/entities` with `options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1H`, `timeAt` `10:00` and `endTimeAt` `12:00` | forwarded: boundaries on the hour grid, two whole buckets |
| the same over `10:30` to `12:30` | `403`: the boundaries are off the grid, and shifted buckets are how aggregates become readings |
| the same with `aggrPeriodDuration=PT30M` | `403` under `short-period = "refuse"`; answered as hourly under `short-period = "raise"` |
| the same with `aggrMethods=max` | `403`: `max` is not in `allowed-methods` |
| `GET /entities/urn:example:Vehicle:1` | `403`: a current-state read returns instances, not aggregates |
