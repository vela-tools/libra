# API keys

An API key is a credential Libra issues itself. It authenticates as a principal, which is a machine identity the key store defines. A principal has a name, groups, roles, and keys that expire. No identity provider is involved, which makes this the shortest path to a working caller.

## The principal

```sh
libra principal create ingest --group fleet
```

To give the principal a role as well, run this instead of the command above, because a name can be created only once:

```sh
libra principal create ingest --group fleet --role telemetry-writer
```

A principal's name is what a policy's `principals` condition matches. Its groups and roles feed the same `groups` and `roles` conditions that a token caller's groups and roles feed. Because the conditions are shared, one policy set can govern machines and people with the same rules. A principal and an account of the same name are still different callers. `users` never matches a principal, and `principals` never matches a subject.

The CLI reads the same configuration file as the proxy, so both find the same key store. Run it beside the running proxy.

The broker sees the principal and never the key. `X-Auth-Subject` is the principal's URN `urn:libra:principal:<ulid>`, `X-Auth-Groups` and `X-Auth-Roles` carry what the principal holds, and `X-Auth-Machine` is `true`. No `X-Auth-Username` is sent. A principal is not an account, and the broker must not be able to mistake one for the other. `libra principal list` shows each name beside its URN.

The URN is assigned when the principal is created and never reused. Removing a principal and creating another of the same name gives the new one a new URN. To the broker, and to anything it stored about the old one from `X-Auth-Subject`, the two are different callers. Policies match the name, so the new principal is governed by the same policies the moment it exists.

## Issue a key

```sh
libra key create --principal ingest --expires-in 90d
```

The key is printed once, as `libra_<id>_<secret>`. Libra never stores it. It keeps only a digest of the key. A lost key is revoked and replaced, never recovered, so put it in the secret manager the moment it is printed.

Each of the three parts does one job. `libra_` is the prefix that marks the credential as an API key, and the one a secret scanner matches. The id is a ULID. It is public, names the key in `libra key list` and in the log, and is how the key is looked up. The secret is 32 bytes from the operating system's random source, encoded in Base58Check, whose checksum refuses a mistyped or truncated key before anything is looked up. Neither the id nor the secret can contain `_`, so the three parts split one way only.

What the key store keeps is a verifier, a hash of the id and the secret. Whoever reads the store learns which keys exist and whom they belong to, but not a credential that works. That is also why a lost key cannot be recovered from it. A presented key is checked against its verifier before anything else about it is considered, so the log says a key is revoked or expired only about a caller who holds its secret.

Every key carries an expiry, given as `--expires-in` (such as `90d` or `P30D`, a day counting as 24 hours) or as `--expires-at` (an RFC 3339 time such as `2027-01-31T00:00:00Z`). An expired key answers 401 from its next use, with no restart.

## Use it

```sh
curl -s "localhost:5667/ngsi-ld/v1/entities?type=Vehicle" \
  -H "Authorization: Bearer libra_..." \
  -H "NGSILD-Tenant: fleet"
```

The key format is what Libra recognises as an API key. The same credential never reaches a `[jwt]` check, and a token never reaches the key store.

## Rotate and revoke

Issue the successor key first, deploy it to the caller, then revoke the old one:

```sh
libra key list
libra key revoke <id>
```

Revocation takes effect on the next request. The old key has no grace period in which it still works. No policy or configuration change is involved. Libra reads keys from the key store per request, so keys are the one part of authentication that changes without a restart.

For a key that leaked, revoke first and issue the replacement second, so the leaked credential is dead before a new one exists.

## Remove a principal

```sh
libra principal remove ingest
```

This removes the principal and every key it holds. The groups are untouched. They belong to the policies, not to the principal.

## The key store

`[key-store] path` names the SQLite file holding principals and key verifiers. Whoever can write it can issue keys, so give it the same protection as the policy directory. One Libra instance holds a lease on it at a time. The lease is renewed every ten seconds and is taken over thirty seconds after renewal stops. A second instance pointed at the same file refuses to start. A proxy that stops cleanly releases the lease on its way out, so its replacement starts at once. Only a crashed one leaves the thirty seconds to run.

A serving instance that cannot renew its lease for twenty seconds stops serving, the way a termination signal stops it. The same happens to one whose lease another instance took over. Twenty is one renewal short of the thirty after which a second instance may claim the lease, so two instances never both believe they hold it.

**Backing it up.** The store is SQLite in write-ahead-log mode, so a copy of the database file alone, taken while Libra runs, can miss writes still held in the `-wal` file beside it. Take the backup with SQLite's own backup command, such as `sqlite3 keys.db ".backup keys-backup.db"`, or copy the database together with its `-wal` and `-shm` files while the proxy is stopped. A restored store brings back only the keys it held when the backup was taken. A key revoked since then works again, so revoke it again after a restore.

**A store that will not open.** The file is opened, and its schema brought up to date, before Libra serves. A file that cannot be opened or migrated stops the process with the cause, like any other startup failure. A row Libra did not write, such as one edited by hand into a value its type refuses, is not read. The key it belongs to is answered with 401 and logged as `the key store could not be read`. Libra does this because a value nothing checked is how a hand-edited row would become a caller.

The runbook version of this page, with a transcript of each step, is the [API key onboarding](../examples/api-key-onboarding.md) example.
