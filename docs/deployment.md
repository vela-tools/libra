# Deployment

Libra ships as a container image and nothing else. It is a reverse proxy deployed beside a broker, so the image is the artifact. There is no standalone distribution to install.

## The image

Each release publishes a multi-platform image (`linux/amd64`, `linux/arm64`) to `ghcr.io/vela-tools/libra`, tagged with the version. Version tags plus `latest`. Until the first stable release, `latest` is the newest pre-release. From then on only a stable release moves it. The base is Debian slim with the CA certificates needed to fetch contexts and signing keys over TLS, and Libra runs as an unprivileged system user with no shell.

Every image is signed with cosign and carries a build provenance attestation. An operator can use these to confirm what is running:

```sh
cosign verify ghcr.io/vela-tools/libra:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/vela-tools/libra/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/vela-tools/libra:vX.Y.Z --repo vela-tools/libra
```

| Path | Purpose |
| --- | --- |
| `/etc/libra.toml` | Where Libra looks for a configuration file. The image ships none, so it runs on the built-in defaults until you mount one here. |
| `/etc/libra/policies` | The policy directory. Empty in the image, so Libra starts and refuses every request until you mount policies here. |
| `/var/lib/libra` | The API key store, a volume. Whoever can write it can issue keys. |

The image needs no configuration file. Set what you change with `LIBRA__<SECTION>__<KEY>` environment variables, as the [configuration reference](reference/configuration.md) describes. To use a file instead, start one with `docker run --rm ghcr.io/vela-tools/libra:vX.Y.Z config init > libra.toml`, which prints every key at its default, and mount it at `/etc/libra.toml`. Set `LIBRA__CONFIG_FILE=/etc/libra.toml` as well, so a mount that went wrong stops startup instead of leaving Libra on the defaults.

## Running it

Set two values. Neither has a default, so the image does not start without both. One is the `Via` pseudonym this deployment gives itself. The other is the address of the broker every request is forwarded to.

```sh
docker run --detach --name libra -p 5667:5667 \
  --read-only \
  -e LIBRA__PROXY__VIA_PSEUDONYM=libra-site-a \
  -e LIBRA__BROKER__URL=http://broker:9090 \
  -v "$PWD/policies:/etc/libra/policies:ro" \
  -v libra-keys:/var/lib/libra \
  ghcr.io/vela-tools/libra:vX.Y.Z
```

`--read-only` works as shipped. Nothing writes to the filesystem except the key store volume. Drop every capability and disable privilege escalation. The process needs neither.

Issue keys inside the running container. That way the commands read the same configuration and the same key store as the proxy:

```sh
docker exec libra libra principal create ingest --group fleet
docker exec libra libra key create --principal ingest --expires-in 90d
```

This assumes the container was started with `--name libra`. The key is printed once, and Libra keeps only a digest of it. A second, short-lived container works too, given the same key store volume and the same configuration. The commands open the key store without claiming the proxy's lease. The running proxy accepts a key the moment it is issued.

## Probes

| Path | Answers | Gated |
| --- | --- | --- |
| `/ngsi-ld/auth/health` | Is the process alive | no |
| `/ngsi-ld/auth/ready` | Are the broker and the signing keys reachable | no |
| `/ngsi-ld/auth/info` | Which version and commit this is | yes, by default |
| `/ngsi-ld/auth/metrics` | Prometheus exposition | yes, by default |

Use health as the liveness probe, and readiness as the readiness probe. Readiness answers 503 while the broker is unreachable. That should take an instance out of rotation, not restart it. Both probes are excluded from the metrics, so a probe every second does not become the traffic the metrics describe.

## Behind another proxy

Libra adds itself to `Via`. What it does with `X-Forwarded-*` depends on who the peer is. From a proxy listed in `[libra] trusted-proxies`, the inbound headers are kept, and Libra appends the peer to `X-Forwarded-For`. The broker's log then records every hop. From any other peer, the headers are replaced with what Libra observed. A caller reaching Libra directly cannot put its own `X-Forwarded-Host` or `X-Forwarded-Proto` in front of a broker that builds `Link` or `Location` URLs from them. `Forwarded` and `X-Real-IP` are dropped. The list is empty by default. Behind an ingress that is not listed, the broker is told the ingress's address and the `Host` Libra saw, rather than the ingress's headers.

List only networks that nothing but proxies can send from. The nearest hop not in the list is taken as the client, so a proxy missing from the list is treated as the caller.

## One instance

The FOSS edition supports one running instance. Scale vertically, and put failover in front of that instance. A second instance on the same key store refuses to start, because the store holds a lease for the instance that opened it. Running several replicas, on a key store they share, is a Pro feature, described under [Editions](editions.md).

## Shutdown

Stopping is a drain. On SIGTERM or SIGINT, Libra stops accepting connections and lets in-flight requests finish. It exits after `[libra] shutdown-grace-seconds` (25 by default) at the latest, and anything still open at that point is aborted. In Kubernetes, that value must stay below `terminationGracePeriodSeconds` (30 seconds unless set), with room for the pod's `preStop` hook. Otherwise the kubelet kills the process mid-request before the drain gives up. If a request here can legitimately run longer than 25 seconds, raise the pod's grace period first. A second signal ends the drain immediately. A repeated Ctrl-C does the same in a terminal.

## Compatibility

Libra targets NGSI-LD v1.9.1 (ETSI GS CIM 009 v1.9.1). The resource paths it classifies, the query parameters it reads, and the entity shapes and representations it filters all follow that version. A path a broker serves and this version does not classify is refused with 403 under every policy set rather than forwarded unjudged. So a broker implementing a later version of the specification gains endpoints no caller can reach through Libra until a release classifies them.

Libra is built to the specification, not to a particular broker: it relies on what NGSI-LD v1.9.1 requires of a broker and on nothing a single implementation adds. The broker it is tested against at the moment is Scorpio 6.0.1, on PostgreSQL 17.5 with PostGIS 3.5.2. All of them come from upstream images. `tests/docker-compose.yaml` pins both by image digest, and CI runs the end-to-end suite and the broker parity harness against that stack on every change. These are the versions that this documentation's statements about broker behaviour were checked against.

Any other NGSI-LD broker, and any other version of Scorpio, is untested until the two suites [Testing](testing.md) describes have passed against it. The parity harness matters most. Libra's JSON-LD rules were established by probing a broker. They cover what a caller-supplied context does to a term and which context channels a request may use. A broker that answers differently is one where Libra authorizes a request under a meaning the broker does not share. Fronting another broker means bringing it up, pointing `LIBRA_PARITY_BROKER` and `LIBRA_INTEGRATION_BROKER` at it, and treating every failure as a question about what Libra authorizes.

Pin the broker's version in your deployment the way the test stack pins it, by digest, and upgrade it in a planned way. Run the parity harness against the new version before it serves traffic behind Libra. A broker upgrade that changes one of those rules fails the harness and nothing else.

## Upgrading

Startup is all-or-nothing, so a bad upgrade fails visibly rather than serving with something missing: an unfetchable JWKS, an unresolvable context, a policy naming a term that cannot be expanded, a policy or a configuration section that nothing in the image claims, all stop the process. Roll a canary and watch it come ready before replacing the fleet.

Moving into this image from a build with more in it, or from no gateway at all, is the case worth rehearsing. A policy carrying a key nothing here reads, or a configuration with a section nothing here claims, stops the process. For a policy, the message names the file, the line and the key:

```
libra: could not parse '/etc/libra/policies/limits.toml'
  caused by: TOML parse error at line 6, column 16
  |
6 | [policy.access.scopes]
  |                ^^^^^^
unknown field `scopes`, expected one of `effect`, `scope`, `entity-type`, `time`, `attribute`, `aggregation`
```

That is deliberate. The alternative is a gateway that loads the policy, ignores the block, and answers requests the policy never allowed.
