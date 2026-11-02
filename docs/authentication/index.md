# Authentication

Every caller presents one credential in the `Authorization` header, with the `Bearer` scheme. Libra tells the two kinds apart by shape alone. Three dot-separated base64url segments make a JWT access token, judged against the `[jwt]` section. A credential beginning with `libra_` is an API key, judged against the key store. A missing header, two headers on one request, a scheme other than `Bearer`, an empty token, or a credential of no kind Libra knows is refused with 401 before anything else runs.

Each kind is judged by its own authenticator, and each credential is judged by one authenticator only. An authenticator recognises a credential by its shape, before any check runs. If none recognises it, the request gets a 401. If two do, that is a 401 too. Which authenticator judges a credential must follow from the credential itself, not from the order in which a build registered them. A credential the recognising authenticator refuses is never offered to another one. A caller cannot choose its judge by how it shapes what it presents. A malformed key starting with `libra_` is refused as a key and never tried as a token.

Whichever kind admits a caller, the identity it produces has the same shape. It holds a subject, which is a token's `sub` or a principal's `urn:libra:principal:<ulid>`, plus the groups and roles the credential carries. Policies match that identity through conditions. `users` names token subjects, `principals` names API key principals, and `groups` and `roles` name what either kind carries. The management lists in `[management-api]` match the same names.

The credential stops at Libra. Once the caller is authenticated, Libra removes the `Authorization` header and tells the broker who asked through `X-Auth-*` headers instead. [The request path](../request-path.md) shows where each of these runs.

A deployment may run with API keys, with JWTs, or with both. With neither, nothing could ever authenticate, so Libra refuses to start.

| Page | Covers |
| --- | --- |
| [API keys](api-keys.md) | The machine identities Libra issues itself: principals, issuance, rotation, revocation, the key store |
| [JWT access tokens](jwt.md) | Any identity provider that signs standard JWTs: the `[jwt]` section, what Libra validates, what it reads |
| [Keycloak](keycloak.md) | The identity provider most FIWARE deployments already run: realm setup, mappers that put groups and roles at the top level, the audience, `at+jwt` |

Try them in this order. An API key needs nothing beyond Libra itself, so a machine caller works in a minute. A `[jwt]` section exists for callers that already belong to an identity provider, and Keycloak is that provider for most FIWARE installations. It needs configuration on your side. Left at its defaults, Keycloak names no audience of yours, so every token is refused with 401. With the audience mapped, it still nests roles where Libra does not read them, and every request lands on the default effect as a 403 that looks like a policy problem but is not one.
