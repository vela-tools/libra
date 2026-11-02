# Keycloak

A Keycloak realm is the identity provider behind most FIWARE deployments. Libra has no Keycloak-specific code: it judges a realm's tokens with the generic `[jwt]` validator, like any other JWT, and this page configures the realm so its tokens pass. The list to arrange is the same as on the [generic page](jwt.md): the audience, and groups and roles at the top level of the payload. Left at its defaults, a realm emits roles nested under `realm_access` and `resource_access`, no groups, and `account` as the only audience. Without the audience, every token is refused with 401, and the log says `the token is not addressed to this audience`. With the audience mapped and nothing else, the tokens validate and the subject authenticates. The role and group lists arrive empty, though, and every request lands on the default effect as a 403 that looks like a policy problem. Nothing reports the nesting, so only the mappers below change the outcome.

## Realm and client

The realm's issuer is `https://<host>/realms/<realm>`, and it publishes its signing keys at `https://<host>/realms/<realm>/protocol/openid-connect/certs`. Those two strings go into the `[jwt]` section verbatim. The issuer is compared byte for byte, so write it the way the realm answers it, with no trailing slash. Keycloak signs with RS256 unless the realm says otherwise, which is Libra's default algorithm.

```toml
[jwt]
jwks-url = "https://keycloak.example.com/realms/fiware/protocol/openid-connect/certs"
issuer = "https://keycloak.example.com/realms/fiware"
audience = "ngsi-ld"
```

Create one client for the callers that reach Libra through this deployment, for example `ngsi-ld`, and treat it as the audience. The tokens Libra accepts must carry it in `aud`, and `audience` above names it.

## Put the audience in the token

An access token does not name your client as an audience on its own. On the client's Mappers tab, add an **Audience** mapper with *Included Client Audience* set to `ngsi-ld`. Audience mappers write into the access token, which is the token Libra receives. The check matters because without it on Libra's side, a token the same realm issued for any other client would be accepted at Libra (RFC 9068 section 4).

## Groups at the top level

Create the groups in the realm, put users in them, and add a **Group Membership** mapper on the client: *Token claim name* `groups`, *Add to access token* on, and *Full group path* off so the claim carries the group's name (`fleet`, not `/orgs/fleet`). Names compare as written in policies, so whichever you choose, the policy and the claim must say the same thing. The mapper is multivalued by construction.

A service account is a user in the realm, so group membership works the same way for machine callers.

## Roles at the top level

The realm's built-in `roles` client scope carries a *realm roles* mapper whose token claim name defaults to `realm_access.roles`, which is the nesting Libra cannot read. Add a **Realm roles** mapper on your client instead of editing the realm default: *Token claim name* `roles`, *Multivalued* on, *Add to access token* on. Client roles under `resource_access` are nested one level deeper and stay unread. Put the roles that matter into the realm.

The claim names `groups` and `roles` are fixed, not a matter of style. They are the two names Libra reads at the top level, and Libra has no configuration for reading them from anywhere else.

## Who the caller is

`sub` is the user's or service account's internal identifier, not the username, and `preferred_username` is not read. Policies' `users` and the `admin-users` list name that subject, so copy it out of a decoded token when writing them. A service account's token carries `client_id`, which the realm's built-in `service_account` client scope writes, so `admin-clients` matches a machine caller with no mapper. A user's token names the client only as `azp`, which Libra does not read. So `admin-clients` has nothing to match for one until a mapper writes `client_id` into the token. A hardcoded claim mapper with the client's id does this. No token caller is marked as a machine. `X-Auth-Machine` is set for API keys only.

Names reach policies as the realm wrote them. A group or role that is empty, carries a comma or a control character, or is longer than 256 characters refuses the whole token with 401 rather than being read with that name left out, so keep commas out of group and role names.

## Declare the token type

On the client's Advanced tab, under Fine grain OpenID Connect configuration, turn on *Use "at+jwt" as access token header type*. It is off by default. When on, access tokens carry `typ: at+jwt` (RFC 9068). Then set `token-type = "at-jwt"` in `[jwt]` to require it. With the default `"any"`, an ID token the realm signed for the same audience is accepted as an access token. That is the confusion this setting removes.

## What the token should look like

A payload carrying what Libra reads, after the mappers above:

```json
{
    "sub": "9f1cd6e2-4a1e-4b6f-9c2e-8d3f7a5b1c4d",
    "aud": "ngsi-ld",
    "groups": ["fleet", "operators"],
    "roles": ["reader"]
}
```

What a realm emits with the audience mapper alone, with the roles where Libra does not look and no groups:

```json
{
    "sub": "9f1cd6e2-4a1e-4b6f-9c2e-8d3f7a5b1c4d",
    "aud": ["ngsi-ld", "account"],
    "azp": "ngsi-ld",
    "realm_access": {
        "roles": ["fleet-admin"]
    }
}
```

The second token validates and authenticates its subject, but it carries no group or role that Libra reads, so no policy naming one can match it. Decode a token from your realm and compare it. `aud` should contain `ngsi-ld`, and `groups` and `roles` should sit at the top level. The token below comes from the client's service account. The client needs *Service accounts roles* on under Capability config, and the service account user needs the groups and roles its policies match.

```sh
curl -s "https://keycloak.example.com/realms/fiware/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=ngsi-ld" \
  -d "client_secret=..."
```

A 403 from Libra afterwards means the default effect decided, not that authentication failed. The log line `access denied` carries `policy` `(default effect)`. The `AUDIT_DENIED` line beside it names the caller's `subject`. A caller that authenticates but matches no policy brings the mappers back into the picture. [Troubleshooting](../troubleshooting.md) maps every 401 log line to the check it came from.
