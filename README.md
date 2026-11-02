<p align="center">
  <img src="docs/assets/vela.png" alt="" width="88" height="88">
</p>

<h1 align="center">Libra</h1>

<p align="center">
  <strong>Authentication and authorization in front of an <a href="https://ngsi-ld.org/">NGSI-LD</a> context broker.</strong><br>
  Every request is authenticated, decided against a policy, narrowed to what the policy allows, and forwarded. Every response is filtered before it reaches the caller.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="https://vela-tools.github.io/libra/docs/">Documentation</a> ·
  <a href="#editions">Editions</a> ·
  <a href="#sovereignty">Sovereignty</a> ·
  <a href="#community">Community</a> ·
  <a href="#license">License</a>
</p>

<p align="center">
  <a href="https://github.com/vela-tools/libra/actions/workflows/clippy.yaml"><img alt="clippy" src="https://github.com/vela-tools/libra/actions/workflows/clippy.yaml/badge.svg"></a>
  <a href="https://github.com/vela-tools/libra/actions/workflows/deny.yaml"><img alt="cargo deny" src="https://github.com/vela-tools/libra/actions/workflows/deny.yaml/badge.svg"></a>
  <a href="https://github.com/vela-tools/libra/actions/workflows/test.yaml"><img alt="tests" src="https://github.com/vela-tools/libra/actions/workflows/test.yaml/badge.svg"></a>
  <a href="LICENSE.md"><img alt="license: EUPL-1.2" src="https://img.shields.io/badge/license-EUPL--1.2-blue"></a>
  <img alt="rust 1.98.0+" src="https://img.shields.io/badge/rust-1.98.0%2B-orange">
</p>

<p align="center">
  <sub>Part of <a href="https://github.com/vela-tools">Vela Tools</a> · Based on EU open standards 🇪🇺 · Built in Ljubljana, Slovenia 🇸🇮 by SenLab d.o.o.</sub>
</p>

---

> [!WARNING]
> Libra is in beta and has not been independently audited. Do not put it in front of production data yet. [Known limitations](https://vela-tools.github.io/libra/docs/security/known-limitations) lists what this release does not defend.

## How it works

Libra is a proxy. Point your clients at Libra instead of at the broker, and Libra forwards what they are allowed to do. The broker stays exactly as it is. Libra stores no context data of its own.

A caller authenticates with an API key Libra issues itself, or with a JWT from an identity provider you already run. Libra matches the request against a set of policies written in TOML. A policy can allow or deny an operation, and it can narrow what an allowed operation reaches: which entity types, which attributes, which scopes, which time window. Libra rewrites the request so the broker is asked only for what the policy allows, then filters the response so nothing outside it reaches the caller, whether or not the broker honoured the narrowing.

The caller's credential stops at Libra. The broker never receives an API key or a token; it is told who asked through `X-Auth-*` headers instead.

Libra implements NGSI-LD v1.9.1 (ETSI GS CIM 009 v1.9.1), not the API of any one broker, so it fronts any broker that speaks that version. Scorpio is the broker it is tested against at the moment.

## Quick start

Libra ships as a container image, `ghcr.io/vela-tools/libra`. [`docker-compose.yaml`](docker-compose.yaml) runs it in front of a Scorpio broker:

```yaml
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

The broker publishes no port, so the only way in is Libra on port 5667. Libra reads policies from the `policies` directory beside the file. With no policy, Libra starts and refuses everything. A gateway that allowed anything out of the box would stay open until somebody remembered to close it. A first policy, saved as `policies/fleet.toml`, looks like this:

```toml
[[policy]]
id = "fleet-read"
description = "The fleet group may read vehicles, but not where they are"
priority = 100

[policy.condition]
groups = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
```

Then start the stack, issue a key and make a request:

```sh
docker compose up --detach
docker compose exec libra libra principal create ingest --group fleet
docker compose exec libra libra key create --principal ingest --expires-in 90d

curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..."
```

The response contains the vehicles without their `location`. [Getting started](https://vela-tools.github.io/libra/docs/getting-started) walks through the configuration, the key store, JWTs and the health probes. The [configuration reference](https://vela-tools.github.io/libra/docs/reference/configuration) lists every key.

## Why?

An NGSI-LD broker answers whoever can reach it. Putting a generic API gateway in front of it does not help much: a gateway can allow or refuse a path, but it cannot tell that a query for `Vehicle` should leave out `location`, that a batch update touches a type the caller may not write, or that a JSON-LD context makes two different-looking names the same attribute. Libra understands NGSI-LD requests and responses, so a policy can say what a caller may see, not only which URLs they may call.

## What it does

Libra authenticates callers with API keys it issues and stores itself, with JWTs verified against an identity provider's published keys, or both. Policies decide by group, role, user, operation, tenant and resource, and an allowed decision can carry restrictions on entity type, attribute, scope and time. Policies are compiled against the JSON-LD context they declare, so a policy and a caller that use the same name for different IRIs do not silently match.

Startup either succeeds completely or stops. Every policy is checked against what the running build can enforce before the first request, and an unknown configuration key or policy key is an error rather than a silently ignored rule. Libra fails closed: when it cannot decide, it refuses.

## Documentation

The [documentation](https://vela-tools.github.io/libra/docs/) covers configuring, running and testing Libra. The [glossary](https://vela-tools.github.io/libra/docs/reference/glossary) defines the policy language. More product information is available at [velacontext.com](https://velacontext.com).

## Editions

Libra is open core. This repository contains the FOSS edition, which is complete on its own: it authenticates, decides and enforces without a licence key, account, or call-home check. Pro adds operational capabilities around the same proxy rather than unlocking parts of it.

Everything released in the FOSS edition remains in it permanently. Features released here will not later move to Pro, and they will not be withdrawn to create an upgrade path.

Pro covers policy management over HTTP with hot reload, key management over HTTP, running several replicas on a shared key store, resilience against a slow or failing broker, rate limiting per principal and tenant, an NGSI-LD response cache, request deduplication, identity provider integration, and federation. [Editions](https://vela-tools.github.io/libra/docs/editions) lists what each edition holds. For Pro, see [velacontext.com](https://velacontext.com).

## Sovereignty

Libra keeps your access rules in plain TOML files in your own repository, and it fronts the NGSI-LD context broker you choose. It runs on your own machines under the EUPL-1.2, without an account, licence key, or telemetry.

SenLab's full position on ownership, export, and reversibility is at [velacontext.com/sovereignty](https://velacontext.com/sovereignty).

## Contributing

Libra is not accepting external source-code contributions right now. Bug reports, feature requests, and documentation feedback are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

Never report a security vulnerability through a public issue. Follow the [Libra security policy](https://github.com/vela-tools/libra/security/policy) instead.

## Community

- Issues: [GitHub Issues](../../issues)
- Discussions: [GitHub Discussions](../../discussions)
- Newsletter: [velacontext.com/newsletter](https://velacontext.com/newsletter)
- General contact: info@senlab.io
- Security: [private vulnerability reporting](https://github.com/vela-tools/libra/security/advisories/new), see the [security policy](https://github.com/vela-tools/libra/security/policy)

## License

Libra is licensed under the [European Union Public Licence v. 1.2](LICENSE.md) (EUPL-1.2). The full licence text in all EU languages and additional information are available at [eupl.eu](https://eupl.eu/).

## About

Libra is part of Vela Tools, an open-core infrastructure project for the NGSI-LD ecosystem. SenLab d.o.o. builds it in Ljubljana, Slovenia. Learn more at [velacontext.com](https://velacontext.com).
