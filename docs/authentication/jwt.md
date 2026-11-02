# JWT access tokens

With a `[jwt]` section, Libra accepts Bearer credentials shaped as a compact JWS. It judges them as access tokens against the key set the identity provider publishes. Libra validates tokens. It does not obtain them, and the only thing it fetches is the JWKS document.

## The section

```toml
[jwt]
jwks-url = "https://idp.example.com/protocol/openid-connect/certs"
issuer = "https://idp.example.com"
audience = "ngsi-ld"
```

Three keys are required, because without them the checks a resource server owes every token cannot be made (RFC 9068 section 4). The `issuer` is compared with the token's `iss` byte for byte, with no trailing-slash allowance. The `audience` must be contained in the token's `aud`. Without that check, a token the same provider issued for any other client would be accepted here. The key set is fetched before Libra serves, and a failure there stops the process. The remaining keys, their defaults and the environment overrides are in the [configuration reference](../reference/configuration.md).

A deployment may run `[jwt]` beside `[key-store]`, or run `[jwt]` on its own. With neither, Libra refuses to start.

## What a token must pass

In order, per request:

1. **Shape.** Three dot-separated base64url segments, or the credential is refused before any check runs.
2. **Token type.** With `token-type = "at-jwt"` (default `"any"`), the header `typ` must be `at+jwt` or `application/at+jwt`, in any case. This is checked before the key set is consulted, so a token declaring itself something else never costs a fetch. The default is `"any"` because many identity providers do not emit `at+jwt` by default, and some cannot. Keycloak and Auth0 emit it once it is turned on. Microsoft Entra ID always writes `typ` `JWT`, and Okta writes no `typ` at all, so neither can be used with `"at-jwt"`. A strict default would refuse every token they sign. The cost of `"any"` is that an ID token the provider signed for the configured audience is accepted as an access token. Set `"at-jwt"` as soon as your provider can emit the type.
3. **Key id.** The header must carry a `kid` of visible ASCII (no space, no control character), at most 128 bytes. Libra does not try every cached key until one verifies. A token that names a key it was not signed with must not be accepted. The `kid` is read before anything is verified, so anyone can choose it. Holding it to visible ASCII is what lets it be logged without forging a log line. A key set entry whose `kid` breaks the same rule is skipped with a warning, and the keys beside it still load.
4. **Algorithm.** The signature is verified under the one algorithm `algorithm` names, `RS256` by default, written as a JOSE `alg` value. Only the RSA algorithms (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`) are accepted, because only RSA keys are read from the key set. A provider that signs with an elliptic-curve or `EdDSA` key cannot be used. The algorithm in the token's own header is never trusted, so a token signed with the right key by the right issuer under a different algorithm is still refused.
5. **Signature.** The signature is checked under the key the `kid` named.
6. **Time.** `exp` is required and checked, with `clock-skew-seconds` (60 by default) of tolerance. `nbf` is checked as well.
7. **Issuer and audience.** `iss` and `aud` are required claims. A token omitting either is refused instead of passing a check that has nothing to compare against.
8. **Readable claims.** `sub` is required, and every group, role and client id must be a name a policy can hold: not empty, no comma, no control character, at most 256 characters. A token failing this check is refused whole, never read with the offending names quietly dropped.

Every refusal is a 401 whose body carries no reason. The log line names the failed check. [Troubleshooting](../troubleshooting.md) lists the lines and what to check for each.

## What Libra reads

Libra reads only the standard claims, and only at the top level of the payload (RFC 9068 sections 2.2 and 2.2.3.1).

| Claim | Required | Becomes |
| --- | --- | --- |
| `sub` | yes | The account, matched by `users` and `admin-users` and sent as `X-Auth-Subject` |
| `client_id` | no | The client, matched by `admin-clients` |
| `groups` | no | The `groups` condition, and `X-Auth-Groups` |
| `roles` | no | The `roles` condition, and `X-Auth-Roles` |

Anything else in the token is ignored, so a provider that adds claims never starts failing authentication. A claim nested deeper than the top level is not read, and no claim path is configurable. A provider that nests groups or roles must be configured to emit them at the top level instead. Libra infers nothing about the caller. No claim it reads fills a username, an email address, or a statement that the caller is a machine, so a token caller propagates `X-Auth-Subject`, `X-Auth-Groups` and `X-Auth-Roles`, and nothing else.

## The key set

The JWKS document is fetched before Libra serves, then every `jwks-cache-duration` seconds (3600 by default). The properties around that matter more than the schedule:

- **https.** An `http` `jwks-url` is refused at startup unless `jwks-transport = "insecure-http"` says the network is trusted, because whoever can alter the response chooses which keys Libra trusts.
- **No redirects.** The address in the configuration is the one trusted. A redirect would hand the key set to a host nobody configured.
- **Bounded.** An answer over 1 MiB is refused.
- **Fail-static.** A failed refresh keeps the previous key set unchanged, so an outage at the provider does not become an outage at the proxy. A key id nobody has published is still refused.
- **Replaced whole.** Each fetch installs the new key set in one step, so a key the provider withdrew stops verifying the moment its replacement arrives.
- **A withdrawn key verifies until the next refresh.** Only a key id the cache does not know triggers an early fetch, and a withdrawn key is one it knows. A token signed with it keeps verifying for up to `jwks-cache-duration` seconds after the provider removes it. That is the window in which a leaked signing key still works after the provider's rotation. Shorten it by lowering `jwks-cache-duration`, or close it at once by restarting Libra, which fetches the key set before it serves.
- **Rotation on demand.** A token naming an unknown key id triggers one fetch, at most once every five seconds. Requests arriving while a fetch is running wait up to two seconds, then are answered as an unknown key id. A first refusal just after a rotation is expected. A persistent one means the endpoint does not serve the keys that sign these tokens.

With a `[jwt]` section, readiness also answers 503 while no signing keys are loaded, so a deployment whose key set never loaded is visibly not ready.

## A checklist for any provider

- A `jwks-url` over https that serves the keys signing these tokens, and no others.
- An `issuer` byte-equal to the token's `iss`.
- An audience claim on the tokens meant for this deployment, and `audience` set to it.
- Groups and roles emitted at the top level of the payload.
- `exp` on every token, and the algorithm the provider signs with written as `algorithm`.
- Clocks within `clock-skew-seconds`.

For Keycloak, which needs every one of these arranged by hand, see the next page.
