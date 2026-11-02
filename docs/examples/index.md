# Examples

A policy page explains a rule. An example shows a whole deployment. It covers the configuration file, the policy files, the keys, and the requests sent over the wire with the answers Libra gives. Each page in this section is one complete recipe. Read it as a checklist when you set up something similar.

Every page uses the same conventions. Libra listens on `localhost:5667`. The NGSI-LD paths a caller uses sit under `/ngsi-ld/v1/`, and Libra's own endpoints sit under `/ngsi-ld/auth/`. A caller presents its credential as `Authorization: Bearer libra_...`. The text after `Bearer` is printed once, when the key is issued. After that, Libra keeps only a digest of it. A deployment that names tenants takes `NGSILD-Tenant`.

Every refusal comes back as an RFC 9457 problem document. Its `type` is a stable URI under `https://libra.velacontext.com/problems/`. A client error's `detail` describes the caller's own request. A server error's `detail` is one fixed sentence, and the real cause goes to the log. `401` means no usable credential. `403` means no policy allows the request, or a restriction refuses it. `404` means the identifier is absent or withheld. `502` and `504` mean the broker failed or was slow. `503` means not ready or too much in flight. The [Troubleshooting](../troubleshooting.md) page has the full map.

| Page | Scenario | What it exercises |
| --- | --- | --- |
| [Smart-city fleet](smart-city-fleet.md) | dispatchers see the fleet, never where it is | the [attribute restriction](../policies/attribute-restriction.md), projections against filters, precedence between two allows |
| [Multi-tenant dataspace](multi-tenant-dataspace.md) | two tenants on one broker, auditors across both | `NGSILD-Tenant`, the `tenants` condition, `[multitenancy]` |
| [Read-only dashboard](read-only-dashboard.md) | charts of the last week, never a reading | the [aggregation](../policies/aggregation-restriction.md) and [time](../policies/time-restriction.md) restrictions together |
| [Federation](federation.md) | one broker answering for data held behind another Libra | the `registrations` family, a restriction judging a query at the far hop |
| [API key onboarding](api-key-onboarding.md) | issue, verify, rotate, revoke, remove | `libra principal` and `libra key`, and what the key store is |

The pages assume [Getting started](../getting-started.md) is done. Libra runs from its image in front of a broker, and a policy directory is mounted into it. Each page shows in full what changes between pages. What does not change is described once, here.
