# Glossary

Libra uses a single word for each concept of its policy language. The same word appears in type and crate names, identifiers, documentation, error messages, configuration and policy files. A second word for one concept lets two parts of an authorization proxy mean different things by it. The words this glossary retires are refused by a test (`tests/terminology.rs`) in every Rust source of the repository, outside string literals.

## Policies

**Policy.** One authored unit in a policy file. It has an id, a description, a priority, a condition and an access block. Retires "rule" in that sense. Elsewhere "rule" stays an ordinary English word for anything that is not a policy, such as the ld+json rules of NGSI-LD or a parsing rule.

**Condition.** What must be true of a request for a policy to match it. The conditions cover which account or principal the caller is, which groups or roles it has, which tenant, whether it reads or writes, which resources it addresses, which entity types or exact queries it names, and during which recurring time interval. Every field is an allow list. An absent field matches everything, except `resources`. Absent, `resources` means entity data only.

**Resource.** The family of NGSI-LD resources a request addresses, as a condition names it. The families are `entities`, `temporal`, `discovery` (`/types`, `/attributes`), `subscriptions`, `registrations` (`/csourceRegistrations`), `registration-subscriptions` (`/csourceSubscriptions`), `entity-maps`, `contexts` (`/jsonldContexts`), `snapshots` and `info`. An allow whose condition names no resources covers `entities`, `temporal` and `discovery` only. Every other family is reached only by an allow that names it. A deny whose condition names no resources covers every family, so a deny written for a caller refuses them everywhere. A policy carrying a restriction must name at least one family a restriction applies to (`entities`, `temporal`, `discovery`, `subscriptions`, `registrations`), and it may not name `snapshots`.

**Access block.** A policy's effect together with the restrictions it attaches.

**Effect.** `allow` or `deny`. Retires "permit" and "grant" as verbs. A policy allows a request. It does not permit or grant it.

**Allowed**, **disallowed.** The adjectives of the effect vocabulary, as in an allowed attribute or a disallowed scope. Retire "permitted", "granted" and "ungranted".

**Priority.** Which of several matching policies decides. Higher is stronger.

## Evaluation

**Decision.** The outcome of evaluating one request against the policy set. It consists of the effect, the policy that decided, and the restrictions that come with an allow. A request has a single decision. The policy layer makes it once, and every layer below it reads it. Retires "verdict".

**Restriction.** One limit an allow carries. The kinds are scope, entity type, time window, attribute and aggregation. A request the decision allows is still held to every restriction attached to it. Retires "grant" as a noun ("outside the grant" is "outside the restriction") and "constraint".

**Member on write.** A setting of the scope and entity type restrictions (`scope-on-write`, `type-on-write`). It is not a restriction of its own. It says whether an entity written under the restriction must carry the member the restriction judges, or may leave it out. The default is `required`.

## Enforcement

**Enforcement.** Applying a decision's restrictions to the request and to the response it produces. Each restriction kind has its own crate, `libra-enforcement-<restriction>`.

**Narrowing.** Enforcement on the request. It rewrites the request so it asks for no more than the restrictions allow, or refuses it when no rewrite can. Narrowing a temporal query's window is narrowing too. Retires "clamping".

**Filtering.** Enforcement on the response. It removes what the restrictions exclude before the caller sees it. Removing scope values a restriction does not cover is filtering too. Retires "redaction".

**Visibility.** Whether one item of a response, such as an entity or a context source registration, is shown or withheld. It is the per-item outcome of filtering, not the request's decision. Retires "verdict" in that sense.

## Identities

**Assigned.** What an identity provider does with a role or a group. A token carries the roles assigned to its subject. Not "granted", which would read as a policy decision.

**Credential.** Whatever a caller presents to be identified. That is a JWT access token or a Libra API key. It is the general word, and "token" alone means a JWT. A deployment accepts JWTs when it configures `[jwt]`, and API keys when it configures `[key-store]`. It refuses to start with neither.

**Authenticator.** What turns one kind of credential into the caller a policy is about. A credential is judged by the one authenticator that recognizes it. A credential that no authenticator recognizes, or that more than one authenticator recognizes, is refused.

**Account.** A caller that an identity provider authenticated, named by the token's `sub`. Policies name accounts in `users`, and `[management-api]` names them in `admin-users`.

**Principal.** A named machine identity defined in Libra, with the groups and roles policies match it by. API keys belong to principals. A principal has no permissions of its own. Policies name principals in `principals`, never in `users`. A principal and an account of the same name are different callers. Downstream, a principal is identified as `urn:libra:principal:<ulid>`. The id is assigned when the principal is created and is never reused.

**API key.** A credential Libra issues to a principal, written `libra_<id>_<secret>`. Not a token: "token" means a JWT.

**Verifier.** What the key store keeps in place of an API key's secret. It is a hash of the key's id and secret. The key itself is never stored.

**Lease.** The key store's record of which proxy instance is using it. Only one instance holds the lease at a time.

**Standard claims.** The claims Libra reads from a JWT are `sub`, `client_id`, and top-level `groups` and `roles` (RFC 9068 sections 2.2 and 2.2.3.1). Nothing else in a token is read, so a role an identity provider nests elsewhere is not a role here.
