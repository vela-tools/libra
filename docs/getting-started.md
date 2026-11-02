# Getting started

Libra sits in front of an NGSI-LD context broker. The broker stays as it is. Every request reaches it through Libra, which decides whether the caller may make it.

This page takes you from nothing to an authenticated, policy-governed request. Libra runs from its container image in front of an NGSI-LD broker. The example uses Scorpio, the broker Libra is currently tested against, but Libra is not tied to it: any broker that implements NGSI-LD v1.9.1 can take its place, as [compatibility](deployment.md#compatibility) explains. It uses API keys, which Libra issues itself and which need nothing else running. Accepting JWTs from an identity provider of your own is covered in the last section.

## What you need

- Docker with Compose.
- A directory to hold the Compose file and the policy directory.

Libra ships only as a container image, `ghcr.io/vela-tools/libra`, built for `linux/amd64` and `linux/arm64`. [Deployment](deployment.md) covers verifying it, the paths it uses, and running it outside Compose.

## 1. Write a policy

Create a `policies` directory beside where the stack will live. Libra's image is configured with `default-effect = "deny"`, so with an empty policy directory it starts and refuses everything. This is the intended starting state. A gateway that allowed anything out of the box would stay open until someone remembered to close it.

```toml
# policies/fleet.toml
[[policy]]
id = "fleet-read"
description = "The fleet group may read vehicles, but not their plate numbers"
priority = 100

[policy.condition]
groups = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["https://uri.fiware.org/ns/data-models#Vehicle"]

[policy.access.attribute]
action = "omit"
attributes = ["https://smart-data-models.github.io/data-models/terms.jsonld#/definitions/vehiclePlateIdentifier"]
```

The entity type and the attribute are named by their full IRIs, the ones the Smart Data Models context gives the terms `Vehicle` and `vehiclePlateIdentifier`. A full IRI means the same thing under any context. The allow covers vehicles, and the plate is withheld whichever context the caller sends and however it spells the names: as those terms under that context, or as the IRIs. A term would instead be resolved against the policy file's `context` line, or against the core context when the file declares none. In that case `Vehicle` and `vehiclePlateIdentifier` are different IRIs from the data model's.

Both restrictions sit in one policy, because the policy that decides a request supplies every restriction. Nothing is combined across policies. A second policy allowing `Vehicle` would decide some requests on its own, without the plate omission. [Precedence](policies/index.md#precedence) has the rule.

An allow whose condition names no `resources` covers entity data only: `/entities`, `/temporal` and the `/types` and `/attributes` listings. Subscriptions, context source registrations, registration subscriptions, entity maps, the broker's context cache, snapshots and `/info` are each reached only by a policy that names them. So a write allow written for entities does not also let its holder register a context source or evict the broker's cached contexts:

```toml
[policy.condition]
groups = ["integrators"]
resources = ["subscriptions"]
```

Unlike an allow, a deny that names no `resources` covers every family. A deny written for a caller is not bypassed by a policy that names subscriptions or registrations.

`write` on `registrations` decides where the broker sends other callers' requests and which of their headers it copies there, so treat it as an administrative allow. A reader who may not also write registrations is shown them without `contextSourceInfo`. Under any restriction, existing subscriptions cannot be read, changed or deleted, because the broker returns every subscription of the tenant to whoever may read one. Creating one is narrowed to the restriction.

If your clients send a JSON-LD context of their own, **the policy file has to declare it too**. A policy that declares none means the NGSI-LD core context alone, and its `Vehicle` is then a different IRI from the caller's `Vehicle`. The policy loads without complaint and matches nothing.

## 2. Compose the stack

Scorpio publishes [Docker Compose files](https://github.com/ScorpioBroker/ScorpioBroker/tree/development-quarkus/compose-files) for each way it can be deployed. The simplest runs the all-in-one broker on a PostGIS database. Below is that file with Libra added in front of it. The repository holds it as [`docker-compose.yaml`](../docker-compose.yaml), so you can download it instead of copying it:

```yaml
# docker-compose.yaml
services:
  postgres:
    image: docker.io/postgis/postgis:17-3.5
    platform: linux/amd64
    environment:
      POSTGRES_USER: ngb
      POSTGRES_PASSWORD: ngb
      POSTGRES_DB: ngb
    volumes:
      - broker-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ngb -d ngb"]
      interval: 5s
      timeout: 5s
      retries: 10

  scorpio:
    image: docker.io/scorpiobroker/all-in-one-runner:java-6.0.1
    platform: linux/amd64
    environment:
      DBHOST: postgres
      DBPORT: 5432
      DBNAME: ngb
      DBUSER: ngb
      DBPASS: ngb
    depends_on:
      postgres:
        condition: service_healthy

  libra:
    image: ghcr.io/vela-tools/libra:v1.0.0-beta.1
    ports:
      - "5667:5667"
    environment:
      LIBRA__BROKER__URL: http://scorpio:9090
      LIBRA__PROXY__VIA_PSEUDONYM: libra-site-a
    volumes:
      - ./policies:/etc/libra/policies:ro
      - libra-keys:/var/lib/libra
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    depends_on:
      - scorpio

volumes:
  broker-data:
  libra-keys:
```

Three changes to Scorpio's file matter. Both of its images are pinned to the versions Libra is tested against, and both are published for amd64 only, so each names the platform. An arm64 machine then runs them under emulation instead of refusing to pull them. Neither the broker nor its database publishes a port, so the only way in from outside is Libra on port 5667. A broker with no authentication of its own must not be reachable around the proxy. The database credentials are fixed and reachable only inside the stack. Change them before running it anywhere that matters.

Libra reads its configuration from `LIBRA__<SECTION>__<KEY>` environment variables, which override the built-in defaults. The [configuration reference](reference/configuration.md) lists every key. `LIBRA__BROKER__URL` is the broker every request is forwarded to, here the `scorpio` service by its Compose name. `LIBRA__PROXY__VIA_PSEUDONYM` is the name this deployment gives itself in the `Via` header. Choose one unique to the deployment. Neither value has a default, and the image refuses to start without both.

The key store lives in the `libra-keys` volume. Whoever can write it can issue keys, so give it the same protection as the policy directory. Only one Libra instance may use a key store at a time. The instance that opens it holds a lease on it, and a second instance pointed at the same volume refuses to start.

## 3. Start it

```sh
docker compose up --detach
docker compose logs libra
```

Startup either succeeds completely or stops. Before the first request, the key store is opened and its lease claimed, the core context is processed, and every policy is compiled to IRIs and checked against what this build can enforce. The alternative is finding a problem on a request. At that point the only available answers are to refuse everything or to allow something nobody checked. A policy that does not load stops the container, and its log names the file and the reason.

## 4. Issue a key

Run these inside the running container, so the commands read the same configuration and the same key store as the proxy:

```sh
docker compose exec libra libra principal create ingest --group fleet
docker compose exec libra libra key create --principal ingest --expires-in 90d
```

A principal is a machine identity Libra defines: a name, groups and roles. A key authenticates as its principal, and every key has an expiry. The key is printed once, as `libra_<id>_<secret>`. Libra keeps only a digest of it, so a lost key is revoked and replaced, never recovered. `docker compose exec libra libra key list` shows each key by its id, and `libra key revoke <id>` takes effect on the next request.

## 5. Check it is up

```sh
curl -s localhost:5667/ngsi-ld/auth/health     # liveness: is the process alive
curl -s localhost:5667/ngsi-ld/auth/ready      # readiness: is the broker reachable
```

Readiness fails while the broker is unreachable, and that is the probe doing its job. A gateway that reported ready with no broker behind it would take traffic it can only answer with 502.

## 6. Make a request

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." \
  -H 'Link: <https://smartdatamodels.org/context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"'
```

The `Link` header names the Smart Data Models context, under which `Vehicle` is the IRI the policy allows. A caller that sends no context can name the type by that IRI instead, with its `#` percent-encoded: `?type=https://uri.fiware.org/ns/data-models%23Vehicle`. `?type=Vehicle` with no context would mean the core context's `Vehicle`, a different IRI, and is refused with `403`. A fresh broker holds no vehicles, so the answer is `[]`. With no `NGSILD-Tenant` header the request is for the default tenant. A broker creates any other tenant on its first write, and answers a read for one it does not hold yet with `404`. [Multi-tenant dataspace](examples/multi-tenant-dataspace.md) covers tenants.

A caller no policy allows gets `403` with an RFC 9457 problem document saying so. A caller with no usable credential gets `401`. An entity addressed by identifier that a type or scope restriction keeps from the caller gets `404`, the same answer as for one the broker does not hold. A different answer would tell the caller which identifiers exist outside what they may see. A context source registration a restriction hides gets the same `404`. The response body of an allowed read has been through the attribute restriction the decision carried, so a vehicle's plate number is not in it, whether or not the broker honoured the `attrs` narrowing on the way out. Data written under the Smart Data Models context comes back named by its terms to a caller that links that context, and by full IRIs to one that sends none, because the core context defines neither `Vehicle` nor `vehiclePlateIdentifier`.

The caller's credential stops at Libra. The `Authorization` header is removed once the caller is authenticated, so the broker never receives an API key or a token. A request with more than one `Authorization` header is refused. Instead, the broker is told who asked. `X-Auth-Subject` is `urn:libra:principal:<ulid>`, `X-Auth-Groups` and `X-Auth-Roles` carry what the principal holds, and `X-Auth-Machine` is `true`. `libra principal list` shows each principal's name beside its URN.

## Accepting JWTs as well

An identity provider of your own can authenticate callers too. Set the `[jwt]` section through the `libra` service's environment:

```yaml
    environment:
      LIBRA__PROXY__VIA_PSEUDONYM: libra-site-a
      LIBRA__JWT__JWKS_URL: https://idp.example.com/realms/fiware/protocol/openid-connect/certs
      LIBRA__JWT__ISSUER: https://idp.example.com/realms/fiware
      LIBRA__JWT__AUDIENCE: ngsi-client
```

The issuer and the audience are required. Without an audience check, a token that the same identity provider issued for any other client would be accepted here (RFC 9068 section 4). The signing keys are fetched at startup, and a failure stops the process.

Libra reads only the standard claims: `sub` (a token without one is refused), `client_id`, and `groups` and `roles` at the top level of the token, as RFC 9068 places them. A policy's `users` names subjects. An identity provider that nests roles elsewhere, as Keycloak does under `realm_access` and `resource_access` by default, is configured to emit them at the top level. Libra does not read a role from anywhere else.

A deployment may run with `[key-store]`, `[jwt]`, or both. With neither, nothing could authenticate, and Libra refuses to start.

## Next steps

- [Writing policies](policies/index.md) covers conditions, precedence, and what each restriction can narrow.
- [Policy cookbook](policies/cookbook.md) has policy sets to copy from, one scenario each.
- [Configuration reference](reference/configuration.md) lists every section, key and default, and the environment overrides.
- [Deployment](deployment.md) covers the container image, health probes, and how upgrades work.
- [Threat model](security/threat-model.md) describes what Libra defends against, and against whom.
- [Known limitations](security/known-limitations.md) lists what Libra does not defend. Read it before putting Libra in front of data that matters.

The [Authentication](authentication/index.md) pages cover both credential kinds in full. That covers API keys, JWT identity providers in general, and Keycloak specifically.
