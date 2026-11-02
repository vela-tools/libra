# Federation

City A's broker answers `Vehicle` queries with data it does not hold. City B holds the fleet, behind its own Libra. A context source registration on City A's broker points at City B's Libra. When a query cannot be answered locally, the broker fans out to that source. The caller sees one answer. City B's policies decide what leaves City B. The caller's policies do not decide it, and neither do City A's.

Two deployments are involved, each with its own configuration and policy set. The registration is written at City A. The enforcement that matters happens at City B. Where this page describes what City A's broker does, the behaviour is Scorpio's, observed with the stack Libra is tested against. Another NGSI-LD broker may fan out differently where the specification leaves it room, but City B's enforcement does not depend on which broker asks.

## City A

The proxy in front of City A's broker lets integrators manage registrations and operators read entities:

```toml
# /etc/libra-a.toml
[libra]
host = "0.0.0.0"
port = 5667

[broker]
url = "http://broker-a:9090"

[proxy]
via-pseudonym = "libra-city-a"

[key-store]
path = "/var/lib/libra-a/keys.db"

[authz]
policies-dir = "/etc/libra-a/policies"
default-effect = "deny"

[jsonld]
allowed-contexts = ["https://smartdatamodels.org/context.jsonld"]
```

```toml
# /etc/libra-a/policies/citya.toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "operator-read"
description = "Operators read the city's entities, wherever the broker finds them"
priority = 100

[policy.condition]
groups = ["operator"]
operations = ["read"]

[policy.access]
effect = "allow"

[[policy]]
id = "registrar"
description = "Integrators manage context source registrations"
priority = 100

[policy.condition]
groups = ["integration"]
resources = ["registrations"]

[policy.access]
effect = "allow"

[[policy]]
id = "registration-viewer"
description = "Auditors see registrations, without the credentials they carry"
priority = 100

[policy.condition]
groups = ["auditor"]
operations = ["read"]
resources = ["registrations"]

[policy.access]
effect = "allow"
```

A `write` on `registrations` decides where the broker sends other callers' requests, and which of their headers it copies there. That makes the `registrar` policy an administrative allow, held by a group that does installation work and by no one else.

Create the three principals:

```sh
LIBRA__CONFIG_FILE=/etc/libra-a.toml libra principal create integrator-01 --group integration
LIBRA__CONFIG_FILE=/etc/libra-a.toml libra principal create viewer-01 --group auditor
LIBRA__CONFIG_FILE=/etc/libra-a.toml libra principal create ops-01 --group operator
```

## City B

At this side, City B's Libra treats everything that arrives as an ordinary NGSI-LD read, and judges it by ordinary policies. A request here is not federated in any special way. The caller happens to be another city's broker. The configuration and policy set follow.

```toml
# /etc/libra-b.toml
[libra]
host = "0.0.0.0"
port = 5667

[broker]
url = "http://broker-b:9090"

[proxy]
via-pseudonym = "libra-city-b"

[key-store]
path = "/var/lib/libra-b/keys.db"

[authz]
policies-dir = "/etc/libra-b/policies"
default-effect = "deny"

[jsonld]
allowed-contexts = ["https://smartdatamodels.org/context.jsonld"]
```

```toml
# /etc/libra-b/policies/cityb.toml
context = ["https://smartdatamodels.org/context.jsonld"]

[[policy]]
id = "fleet-reader"
description = "Federated readers may read vehicles, not where they are"
priority = 100

[policy.condition]
groups = ["fleet-reader"]
operations = ["read"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
```

The credential City A's broker presents is an ordinary API key. City B issues it to a principal of its own, with these commands:

```sh
LIBRA__CONFIG_FILE=/etc/libra-b.toml libra principal create site-a --group fleet-reader
LIBRA__CONFIG_FILE=/etc/libra-b.toml libra key create --principal site-a --expires-in 365d
```

City B never puts that key in a policy file. The key travels in the registration's `contextSourceInfo`, the member that carries the credentials a source expects. A reader who may not also write registrations is never shown it.

## The registration

At City A, the integrator creates the registration in `registration.json`. It holds the key City B issued to `site-a` in `contextSourceInfo`:

```json
{
    "id": "urn:ngsi-ld:ContextSourceRegistration:cityb-fleet",
    "type": "ContextSourceRegistration",
    "information": [
        {
            "entities": [
                {
                    "type": "Vehicle"
                }
            ]
        }
    ],
    "endpoint": "https://libra-b.example.com",
    "contextSourceInfo": [
        {
            "key": "Authorization",
            "value": "Bearer libra_..."
        }
    ],
    "@context": "https://smartdatamodels.org/context.jsonld"
}
```

The endpoint is the source's base address. The broker appends `/ngsi-ld/v1/entities` and the rest itself, so an endpoint that ends in `/ngsi-ld/v1` sends every federated query to a path City B's Libra does not know. Scorpio copies each `contextSourceInfo` entry onto its requests to the source as a header, which is how the key reaches City B.

```sh
curl -s -X POST "localhost:5667/ngsi-ld/v1/csourceRegistrations" \
  -H "Authorization: Bearer libra_..." \
  -H "Content-Type: application/ld+json" \
  --data-binary @registration.json
# 201: the broker will answer Vehicle queries from City B's endpoint
```

The auditor may read registrations but not write them. The auditor sees the registration without the member that carries the credential. The listing names a type, because Scorpio answers a registration query that has no filter with `400`. The type is resolved against the Smart Data Models context in the `Link` header:

```sh
LINK='Link: <https://smartdatamodels.org/context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"'

curl -s "localhost:5667/ngsi-ld/v1/csourceRegistrations?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
```

```json
[
    {
        "id": "urn:ngsi-ld:ContextSourceRegistration:cityb-fleet",
        "type": "ContextSourceRegistration",
        "contextSourceAlias": "https://libra-b.example.com",
        "endpoint": "https://libra-b.example.com",
        "information": [
            {
                "entities": [
                    {
                        "type": "Vehicle"
                    }
                ]
            }
        ]
    }
]
```

The answer has no `contextSourceInfo`. That is withholding, not an omission. Scorpio fills in `contextSourceAlias` from the endpoint when the registration names none. Where restrictions exist at City A, each judges the registration on its own part of it, as described in [context source registrations](../policies/context-source-registrations.md).

## The federated requests

An operator reads vehicles at City A.

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 200: City A's own vehicles whole, City B's without location
```

The query leaves City A unchanged. City B's Libra judges it against `fleet-reader`. What comes back has passed City B's attribute restriction before the broker merges the answer. Two restrictions applied, one at each hop. The caller's own policy had no part in the second.

A filter on the hidden attribute cannot get round the far side either. How it fails depends on the broker at City A. Scorpio does not forward the filter. It fetches every `Vehicle` from the source, as `GET /ngsi-ld/v1/entities?type=Vehicle&options=sysAttrs`, and applies `q` to what comes back. By then, City B's attribute restriction has removed `location`, so the filter matches none of City B's vehicles:

```sh
curl -s 'localhost:5667/ngsi-ld/v1/entities?type=Vehicle&q=location==%22Depot%22' \
  -H "Authorization: Bearer libra_..." -H "$LINK"
# 200: City A's own matches only; City B's location never left City B
```

A broker that forwards the filter instead has City B judge it exactly as it would judge a local caller's filter, and refuse it with `403`. Either way, a restriction that refused only direct callers would leak through every federation path. This one does not.

Before it queries, Scorpio also asks the source for `/ngsi-ld/v1/info/sourceIdentity` and `/ngsi-ld/v1/entityMap`. City B's Libra refuses both. The first returns `401`, because Scorpio sends no credential with it. The second returns `403`, because `fleet-reader` names no `resources`. Scorpio then goes on to query the entities. When a query to a source fails, Scorpio writes the source's headers into its own log, the City B key among them, so City A's broker log is as sensitive as the registration.

## Loops

Both Libras stamp `Via` with their own `via-pseudonym`. Brokers that federate compare `Via` entries with the aliases of context sources to detect loops (NGSI-LD clause 5.2.40). Two deployments answering to one name would look like the same hop, so the two pseudonyms here, `libra-city-a` and `libra-city-b`, are distinct, as they must be in any chain.

## Reading it back

The registration family is reached only through an allow that names it. The operator policy above allows neither reading nor writing registrations. To widen what City B serves, edit City B's policies and restart. Nothing City A writes into a registration can enlarge that, because City B judges every request it receives against its own loaded set.
