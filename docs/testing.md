# Testing

The workspace tests run with `cargo test --workspace`. Unit tests and property tests need nothing outside the repository. The end-to-end suite and the broker parity harness need a context broker, and both skip when none is named.

## End-to-end suite

The suite in `tests/integration` runs the real Libra binary against a real NGSI-LD context broker. It signs its own tokens with an issuer it starts itself, so no identity provider is needed. The proxy is not run in a container. It is spawned from the binary that cargo built, so no image sits between the binary and its tests, where the two could drift apart.

The broker comes from `tests/docker-compose.yaml`, which pins Scorpio 6.0.1 and its database by digest, because the suite is sensitive to the broker's version. Bring it up, then name it with `LIBRA_INTEGRATION_BROKER`:

```sh
docker compose --file tests/docker-compose.yaml up --detach --wait
LIBRA_INTEGRATION_BROKER=http://localhost:9090 cargo test --test integration
```

Its `parity` module sends the same read through Libra and straight to the broker. It requires the two answers to differ only by what the policy removes.

Without the variable the suite skips, so that a developer without Docker can still run the rest of the workspace. A broker that is named but unreachable is a failure. It is never a skip, because a skip must never produce a green run for a service that is broken. CI sets the variable.

## Authorization matrix

`tests/authorization_matrix` sends every operation that clause 6 of ETSI GS CIM 009 v1.9.1 binds, plus one path it does not, through the real Libra binary. It runs under each of seven policy sets: a deny over every resource family, an unrestricted allow, and an allow carrying each restriction kind (scope, entity type, time, attribute, aggregation). An origin stands in for the broker and answers with a document of the shape the operation returns. So no broker is needed, and the matrix runs with the rest of `cargo test --workspace`. Each cell has one of three outcomes. It is forwarded (the broker was asked and its answer returned), refused (a client error, and the broker never saw the request), or withheld (the broker was asked, and its answer replaced by a client error). A server error is never an expected outcome.

A test checks the table for completeness, so nobody has to keep it complete by hand. Every resource Libra classifies, with each batch action counted separately, has to be reached by a row. A resource added to the classification fails the matrix until it has a row. The restriction kinds are read from the policy model's access block by a destructuring pattern, and each row names its outcome under every kind. So a restriction added to the model does not compile here until every row says what it expects under it. The request bodies are chosen to be allowed under every restriction at once, so a refusal in a cell is about the operation, never about a body that broke one restriction.

## Repository checks

Three tests at the root of the repository check the workspace, not a single crate, and run with `cargo test --workspace`. `foss_stack` assembles the request path in process and checks that a decision and its attribute restriction reach both the request and the response. `lint_policy` refuses `#[allow]` anywhere and `#[expect]` outside test code, and checks that every crate inherits the workspace lint levels. `terminology` refuses the retired words for the policy vocabulary (`permit`, `grant`, `verdict`, `clamp`, `redact`) in identifiers and comments.

## Broker parity harness

`crates/libra-jsonld-context/tests/broker_parity.rs` checks Libra's JSON-LD context rules (what a caller-supplied context does to a term, what an undefined term expands to, which context channels a request may use) against a live broker. Those rules were established by probing a broker and are only worth anything while they stay true, so a broker upgrade that changes one of them must fail this harness. It skips unless `LIBRA_PARITY_BROKER` names a broker:

```sh
LIBRA_PARITY_BROKER=http://localhost:9090 cargo test -p libra-jsonld-context --test broker_parity
```

CI sets the variable.

## Fuzz targets

`fuzz/` holds one `cargo-fuzz` target per parser that reads input from outside Libra's trust boundary: the query string and each selector in it (`q`, `scopeQ`, `type`, `attrs`/`pick`/`omit`, `orderBy`), a request body with its `Content-Type` and `Link` headers through the context layer, a self-contained `@context`, the `Link` header, the headers and parameters that choose a representation, `NGSILD-Tenant`, the method and path that classify an operation, a bearer token through the validator, a key id, a JWKS document, token claims, and a policy file. Every target fails on a panic. Where Libra writes a parsed value back out, as it does with a narrowed `q`, `scopeQ`, `type` or projection, the target also requires that the text it writes reads back to the same text. The query string target requires the same of the parameters it forwards. The bearer token target validates against a key set nobody holds the private key for, so an accepted token is a failure.

The fuzz crate is a workspace of its own, because libFuzzer builds only on nightly. It needs `cargo-fuzz`, installed with `cargo install cargo-fuzz`. Each target's seeds are in `fuzz/corpus/<target>`. Give it a scratch directory first. Then the inputs a run discovers are written there, and the checked-in seeds stay the reviewed ones:

```sh
cargo +nightly fuzz run q_filter "$(mktemp -d)" fuzz/corpus/q_filter -- -max_total_time=60
```

The targets that read several values take them one per line, since no header value holds a line break. `media_type` reads `Accept`, `Content-Type`, `options` and `format` in that order. `tenant` reads one `NGSILD-Tenant` header per line. `context_layer` reads the `Content-Type` on the first line, one `Link` header on each further line, a blank line, then the body. `resource_path` reads a method, a space and a path. The JWKS and bearer token targets serve their key set from a server on the loopback interface, and no target reaches any other network.

CI runs every target for 60 seconds on each change. A crash writes the failing input to the run's temporary directory and prints it in the job log, which is public. A crash that could be a vulnerability is reported privately, as `SECURITY.md` describes. Its input is committed only together with the fix.

CI runs no long campaign, because its log would be public too, and a long run is the one most likely to find a vulnerability in code already released. Before each release, a maintainer runs every target for at least 30 minutes on a private machine, each with its own scratch directory, and treats any crash as a private report:

```sh
for target in $(cargo +nightly fuzz list); do
  cargo +nightly fuzz run "$target" "$(mktemp -d)" "fuzz/corpus/$target" -- -max_total_time=1800
done
```

## Mutation testing

`cargo-mutants` changes the code that decides and enforces access, one small edit at a time (a comparison flipped, a branch removed, a return value replaced), and runs that crate's tests against each change. A change no test fails on is a surviving mutant: a way the enforcement path could break without anyone noticing. The crates examined are the policy engine, the policy layer, the five restriction enforcement crates (aggregation, attribute, scope, time and type), the steps the scope and type restrictions share (`libra-enforcement-member`), the policy vocabulary the engine decides with (`libra-policy-model`), the statuses refusals answer with (`libra-problem-details`) and the layer that withholds a registration's source information (`libra-registration-disclosure`), listed in `.cargo/mutants.toml`. Each mutant is tested against its own crate's tests only. A surviving mutant is killed by a new test. Only a mutant that changes no behaviour at all (an equivalent mutant) is excluded instead, in the configuration, with the reason beside it. The expected result of a run is no survivor. It needs `cargo-mutants` and `cargo-nextest`, installed with `cargo install --locked cargo-mutants cargo-nextest`. The configuration builds each mutant with the `mutants` profile, which leaves out debug information, and runs its tests with nextest, both to shorten a run. `--jobs` tests several mutants at once; about one job per two cores keeps the machine busy without starving the builds. Every run passes `--workspace`. The repository root is itself a package, and without the flag only that package is mutated, which the configuration does not examine. A full run, or one over the uncommitted changes:

```sh
cargo mutants --workspace --jobs 8
changes="$(mktemp -d)/changes.diff"
git diff > "$changes" && cargo mutants --workspace --jobs 8 --in-diff "$changes"
```

The results are written to `mutants.out`. `missed.txt` lists the survivors. CI runs the mutants in the code a pull request changes, and the whole path every week in eight shards. A surviving mutant fails either job.
