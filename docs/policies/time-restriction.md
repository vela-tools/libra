# The time restriction

A time restriction bounds *when* in the life of the data a caller may read. It is a window over the instants that attribute instances are dated with. It says nothing about when a request may be made. That is the `time-interval` condition.

```toml
[policy.access.time]
type = "relative"          # or "absolute"
duration = "PT24H"
direction = "past"         # or "future"
```

An `absolute` window names `start` and `end` instants instead of `duration` and `direction`. Durations are ISO 8601. Years and months are refused, because they have no fixed length. A window written in months is a different window in February. A zero duration is also refused, because it reads as a restriction and allows nothing. A `relative` window longer than one hundred years is refused too.

## Temporal reads

A temporal query's window is narrowed to the restriction's window. The broker is asked for the intersection. A query whose whole range lies outside the window is a `403`. `timeAt`, `endTimeAt` and `temporalQ` are all narrowed.

## Current-state reads

A *current-state* read (`GET /entities`, `GET /entities/{id}`, a batch query) names no window, so the restriction says what one means with `current-state`:

```toml
[policy.access.time]
type = "relative"
duration = "PT24H"
current-state = "values-in-window"   # refuse | request-in-window | allow | values-in-window
```

| `current-state` | A current-state read is |
| --- | --- |
| `refuse` | refused with `403`. The default for a `relative` window. |
| `request-in-window` | allowed while the moment of the request lies inside the window. The default for an `absolute` window. For a `relative` one it is refused at load, because a `relative` window always contains the request. |
| `allow` | allowed; the window bounds temporal reads only. |
| `values-in-window` | answered, with the answer dated down to the window. See below. |

### `values-in-window`

The answer keeps only the attribute instances dated inside the window. An instance is dated by its `observedAt`, or by its `modifiedAt` when it has none. An instance outside the window is removed. An instance with neither date is removed too, and so is an attribute left with no instance. The linked entities of a join answer are filtered the same way.

To date instances that carry no `observedAt`, Libra adds `options=sysAttrs` upstream when the caller did not ask for it. It removes `createdAt` and `modifiedAt` from the answer again, at every level where it added them.

What cannot be dated is refused with `403`:

- `keyValues`, where an attribute is replaced by its value and has no metadata to read a date from.
- `application/geo+json`, whose `geometry` copies a value without its metadata.
- A resource other than `/entities`, `/entities/{id}` and a batch query.
- A `q`, `georel`, `geoQ` or `orderBy` filter, in the query string or a `Query` body. The broker evaluates a filter against current values whatever their age, so which entities come back, and in which order, would disclose values that the answer withholds.

`current-state` does not govern writes. Writes keep the request-time rule of the window's kind. An `absolute` window holds while the request moment is inside it. A `relative` window always holds.

## Worked example

```toml
[policy.access.time]
type = "relative"
duration = "PT24H"
current-state = "values-in-window"
```

| Request | Answer |
| --- | --- |
| `GET /entities/urn:example:Vehicle:1` | answered with the instances of the last 24 hours; older ones removed |
| `GET /entities/urn:example:Vehicle:1?options=keyValues` | `403`: a value without metadata cannot be dated |
| `GET /temporal/entities/urn:example:Vehicle:1?timerel=between&timeAt=...&endTimeAt=...` | the window narrowed to the overlap with the last 24 hours |
| `GET /entities?q=speed>50` | `403`: which entities match is decided against values of any age |
| `GET /entities?orderBy=speed` | `403`: the order ranks by values the answer withholds |
