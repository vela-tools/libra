# Architecture

Libra is a proxy assembled from many small parts, each with a single concern, and one binary that knows all of them exist. This page covers the rules that decide which part a piece of behaviour belongs in, and what a build may and may not change. [The request path](request-path.md) covers the runtime view. It explains what runs in what order, and why that order is what it is.

## The composition root is the only place that knows the whole system

One part of Libra, the composition root, assembles the proxy. It builds the services that require I/O, assembles the Tower stack, loads the policies, opens the key store, and stops cleanly when asked to. The binary is thin beside it. It supplies the program's identity and hands the rest to the composition root.

**No enforcement logic lives there.** If the composition root decided something about a request, that decision would be invisible to every test that does not start the whole process, and unavailable to any other part that should have owned it. The root wires the parts together. The parts make the decisions. The root is allowed to know one thing that no other part knows: the layer order. The order is a property of the assembled stack, not of any single layer, so it is stated in one place where the whole order can be reviewed at once.

**Startup is where every avoidable failure is made to happen.** The JSON-LD core context is processed, the policy set is compiled against its declared context, the signing keys are fetched, and the key store is opened and its lease claimed, all before the listener binds. Each of these could be deferred to the first request. If it were, it would have nowhere to fail but on a request. At that point the only available answers are to refuse everything or to allow something nobody checked.

## A concern defined over HTTP owns its layer; a concern over domain values does not

The security rules are written without knowing that HTTP exists. Stripping an inbound header, limiting a payload, rewriting a response body, and refusing a method with no NGSI-LD meaning are all statements about requests and responses. The part that owns one owns the Tower layer that applies it. Attribute filtering is an example. The restriction it applies comes from the policy model, and the decision comes from the policy engine. Editing a response body is HTTP-shaped work, though, so the layer that does it lives beside the filtering.

A concern defined over domain values, by contrast, stays HTTP-free. What shape a response will have, what a tenant is, and how a JSON-LD context resolves are all answered from values. Those answers need no knowledge of what a request is. Each such concern gets a thin sibling. Its only job is to read the answer's inputs off the request once and put the result where the layers below can read it. The split lets a model be exercised exhaustively without an HTTP dependency. It also stops that dependency from spreading into the parts that decide who may see what.

**Anything resolved once per request is resolved in one layer and read from the extensions below it.** The tenant, the identity, the JSON-LD context, the response representation and the authorization decision are each written into the request extensions by one layer only. Two resolutions of one request can disagree. A cached context can expire between them, or a header can be read two ways. Then one layer authorizes against a meaning that a later layer does not share. A layer that finds an extension it needs missing refuses the request rather than resolving it again. A missing extension means the stack was assembled in the wrong order.

## A build adds to the proxy in exactly three places

Libra Pro is a separate binary built around these parts. For that to work without a fork, the composition root exposes the places a binary may add to the proxy. Nothing else about the stack is open to change.

| Extension point | What it is for |
| --- | --- |
| Authenticators | Recognition of a kind of credential this build does not read |
| Layers | Layers placed around the enforcement stack, below authorization |
| Management routes | Routes mounted behind a privilege gate the binary chooses |

The binary in this repository supplies none of them and adds nothing. Everything else that differs between one build and another is data: a policy or a configuration file. A layer a binary adds sits below authorization by construction. So whatever answers from memory, such as a cache, answers only a request that has already been authenticated and carries the decision that shaped it. An authenticator a binary adds must recognize credentials no other authenticator does. A credential that two of them recognize is refused.

## Nothing claimed by nobody is read

A configuration section is claimed by the part that owns it. Loading the configuration hands out the sections every build reads. A part that adds behaviour claims its own section besides those. Loading refuses to complete while any section nobody claimed remains. The binary in this repository claims nothing beyond what its parts own. So a section written for a build with more in it stops the process at startup, rather than being read and ignored.

The same refusal guards the policy schema. Every key a policy file carries must be a key this build reads. An unrecognised key is a load error that names the file, the line and the key. The failure this prevents is a quiet one. A gateway that loaded a policy with a restriction it could not enforce, and answered the request anyway, would have allowed what the operator believes the restriction withholds. [Writing policies](policies/index.md) shows the error and the misspelling it also catches.
