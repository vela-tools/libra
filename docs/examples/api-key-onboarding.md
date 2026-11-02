# API key onboarding

A key is the credential a service holds. This page is the runbook for keys. It covers how to issue one, verify it, rotate it on a schedule, revoke it in an incident, and remove a principal that is no longer needed. Run the commands beside the running proxy, with the same configuration file or environment, so every command reaches the same key store.

## Onboard a service

A principal is the identity. A key is what the service holds. A policy matches one of them or the other. Create the principal with the groups its policies will match:

```sh
libra principal create fleet-telemetry --group ingest
```

Issue a key for it:

```sh
libra key create --principal fleet-telemetry --expires-in 90d
# the key is printed once, as libra_<id>_<secret>; Libra keeps only a digest
```

Store the key in the service's secret manager now, because this is the only time it is shown. Libra holds the verifier, not the key, so a lost key cannot be recovered. It can only be revoked and replaced.

Verify with the first real request:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..."
# the answer the policy allows; a wrong key is a 401
```

The broker does not receive the key, because the `Authorization` header stops at Libra. The broker learns who asked from `X-Auth-Subject`, which is `urn:libra:principal:<ulid>`. `X-Auth-Groups` carries `ingest` here, and `X-Auth-Machine` is `true`. The service can do whatever the `ingest` group's policies allow, and nothing else.

Every key has an expiry, and `key create` refuses to issue a key without one. `--expires-in 90d` counts from now, and `--expires-at` takes an RFC 3339 instant.

```sh
libra key create --principal fleet-telemetry --expires-at 2027-01-31T00:00:00Z
```

## Rotate

Rotate on a schedule, not only during an incident. Issue the successor while the old key still works:

```sh
libra key create --principal fleet-telemetry --expires-in 90d
# a second key for the same principal; both live until one is revoked
```

Deploy the new key to the service, and confirm it answers with the new credential. Then take the old one out:

```sh
libra key list
# each key by its id, without its secret

libra key revoke <id>
```

A revocation applies to the next request. There is no grace period, and nothing to wait out. The next request that presents the revoked key gets a `401`.

Rotation needs no policy change. Policies match the principal's groups, and both keys belong to the same principal.

## Revoke a lost key

Revoke a key that may already be in someone else's hands first, and replace it second:

```sh
libra key list
libra key revoke <id>
```

From the next request on:

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_<revoked-id>"
# 401: the credential is no longer usable
```

Once revoked, the old key text has no value. Presenting it again gets the same `401`. A leaked key found in a log or a repository is dead the moment its id is revoked.

## Offboard a service

Removing the principal removes its identity and every key it holds, at once:

```sh
libra principal remove fleet-telemetry
```

Policies that matched its groups stop matching, because nothing authenticates as the principal any more. The group itself remains for the principals that still hold it. A service that kept a copy of its key now holds a dead string.

## The store behind them

Principals and key verifiers live in the SQLite database named by `[key-store] path`. Libra creates it on first use. Whoever can write that file can issue keys, so it gets the same protection as the policy directory. The instance that opens the store holds a lease on it, renewed every 10 seconds, and a second instance pointed at the same file refuses to start while the lease is live. An instance that shuts down cleanly gives up the lease, so its successor starts at once. One that dies without shutting down leaves the lease to go stale, and a new instance can take over 30 seconds after the last renewal. That is why the commands here run beside the running proxy with the same configuration file. Two proxies on one key store file is a startup error, not a silent race.
