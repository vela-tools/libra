# Multi-scope semantics

An NGSI-LD entity can carry several scopes (ETSI GS CIM 009 v1.9.1), and a scope restriction allows a set of scope patterns, so the relation between an entity and a caller is many-to-many. This page records the two coherent ways to read that relation, which one Libra implements, and what the other would cost.

## The problem

Take an entity scoped `[/Madrid/A, /Secret/X]` and a restriction allowing `/Madrid/#`. A collection query is narrowed with `scopeQ`, which the broker evaluates and which matches an entity if any one of its scopes matches. Retrieve-by-id has no scope filter in NGSI-LD, so Libra fetches the entity first and checks its scopes itself. The two paths need one rule, because a caller who can list an entity but cannot fetch it, or the reverse, has been shown an accident of implementation rather than a policy.

`scopeQ` cannot express "every scope of the entity is allowed". Its AND operator (`;`, inside parentheses) requires the entity to carry one scope for each operand. It cannot forbid a further scope. The grammar has no negation and no "only". So a collection query can only follow the any rule inside the broker, and the all rule can only be had by rewriting the response in Libra.

The question that decides between the two options is what a second scope means. If it means "also shared with", scopes are sharing tags and any one allowed scope is enough. If it means "also classified as", scopes are classification labels and every one has to be cleared.

## At a glance

| | Option A: any-scope reads, reduced | Option B: all-scope everywhere |
| --- | --- | --- |
| Scopes mean | sharing tags | classification labels |
| Status | implemented | designed, not implemented |
| Retrieve by id | allowed if any scope is allowed | allowed only if every scope is allowed |
| Collection and batch query | `scopeQ` narrowing, and every entity of the answer judged as a retrieval of it would be | `scopeQ` narrowing, and every entity of the answer with a scope outside the restriction dropped |
| Scope array in a response | reduced to the allowed scopes | whole, because every scope is allowed |
| Write, update or delete by id | every scope must be allowed | every scope must be allowed |
| Create or batch write | every scope in the payload must be allowed | every scope in the payload must be allowed |
| Pagination | intact while the broker honours `scopeQ` | broken unless Libra over-fetches and re-pages |
| Extra work in Libra | a rewrite of the `scope` member, and a check of each entity of a query answer | a response filter, plus pagination handling |
| Failure mode if the broker ignores `scopeQ` | entities outside the restriction are withheld, so the page comes back short | the same |

## Option A: any-scope reads, reduced (implemented)

An entity is visible to a caller when at least one of its scopes is allowed, and the caller is shown only the allowed scopes.

- **Retrieve by id.** Libra fetches the entity, and the read is allowed if any scope matches an allowed pattern. An entity with no scope is refused, in the same way that a `scopeQ`-filtered collection query would not return it.
- **Collection and batch query.** The restriction is injected into `scopeQ`, or narrowed to the overlap with what the caller asked for, and the broker matches on any scope. Each entity of the answer is then judged as a retrieval of it by id would be. An entity with no allowed scope, or with no `scope` member at all, is withheld from the answer. A broker that honours `scopeQ` never returns such an entity, so the check withholds nothing there. It is what keeps a broker that ignored `scopeQ` from leaking. The linked entities of a join answer (NGSI-LD clause 4.5.23) are judged the same way.
- **Reduction.** For every read of an entity, a collection or a batch query, the successful response is rewritten so each entity's `scope` member keeps only the allowed scopes. The bare string, array, normalized `Property` and temporal instance forms are all handled. A value of any other shape cannot be compared, and is removed. In a GeoJSON response the member is read from `properties`. The reduction applies to an entity's own `scope` member and no deeper: an attribute named `scope` is an attribute.
- **Projections.** A `pick` that leaves `scope` out, or an `omit` that lists it, is refused with 400. Every entity of the answer would arrive without the member it is judged by, and would be withheld. The caller would get an empty answer with no reason. `attrs` selects attributes and never removes `scope`.
- **Writes.** A write that names an entity requires every one of its scopes to be allowed. A payload that creates or moves an entity requires every scope it declares to be allowed. A caller who can see an entity through one scope must not be able to alter or delete it for the holders of another. Reads are the lenient side, and writes are the strict side.
- **Compression.** The outbound request carries no `Accept-Encoding` while a scope restriction is in force, because a compressed body cannot be rewritten. Returning it untouched would be the leak this prevents. A success response that is encoded, over the body limit, not JSON or not parseable is refused.

Costs: one parse and serialisation per read response, bounded by the payload limit and sitting beside the attribute filter's own rewrite. Under a broker that honours `scopeQ` there is no pagination effect, because no entity leaves a page. Under one that ignores it, the withheld entities leave short pages, and a `NGSILD-Results-Count` that counts them.

What stays open under A is the `/types` and `/attributes` indexes. They are not narrowed by scope, because neither the request nor the aggregate the broker answers with carries a scope (NGSI-LD 5.7.5 to 5.7.10), so a scope-restricted caller sees type and attribute names, and their counts, from outside the restriction.

## Option B: all-scope everywhere (designed)

An entity is visible to a caller only when every one of its scopes is allowed. The most restrictive scope wins, as with classification labels.

- **Retrieve by id.** The fetch requires every scope to match an allowed pattern. The response needs no reduction, because nothing outside the restriction is in it.
- **Collection and batch query.** `scopeQ` still narrows the request, which keeps the broker's work down, but the answer has to be filtered more strictly than under A. An entity with any scope outside the restriction is dropped, including the ones `scopeQ` rightly matched on another scope. This is the only way to get the all rule, for the reason given under the problem above.
- **Writes.** Identical to A.

The difficulty is pagination. Under A, a conformant broker returns only entities the caller may see. Under B, it returns entities that Libra then drops as a matter of course. The broker applies `limit` and `offset` before Libra sees the page, so dropping entities leaves short pages, a wrong `NGSILD-Results-Count`, and `Link` headers (RFC 8288) that point at the wrong next page. A correct implementation has to do one of these:

1. **Over-fetch and re-page.** Libra reads from the broker until it has a full page of visible entities, recomputes the count by reading every page, and rewrites `Link` itself. It is correct. It costs a variable number of broker round trips per request, and the cost grows with the share of entities the caller may not see.
2. **Make the broker exclude them.** Push a negative condition into the request so only entities whose every scope is allowed match. `scopeQ` has no way to say it, so this needs a broker extension and is not portable.
3. **Accept short pages and a wrong count.** Simple, and wrong for any client that reads `Results-Count` or stops on a short page.

The all rule also changes what the `/types` and `/attributes` indexes can report, since an entity with a scope outside the restriction no longer counts toward them. Narrowing those indexes by scope needs a recompute rather than a response filter, which is the same gap option A leaves.

## Choosing

Use A when a second scope means the entity was published into another audience. Use B when it means the entity carries a stricter label than the first one suggests. A mixed deployment, where some tenants use tags and some use labels, needs a per-policy switch, and neither option provides one today.

Moving from A to B later changes the read rule and the response filter's test for each entity. The request side, the writes and the reduction are shared. Both readings are written down, so that the move is a decision about meaning rather than a redesign.
