# M0-14a Nango free boot proof implementation plan

## Goal

Deliver a reviewed, exact-pinned, disposable proof that the free self-hosted
Nango v0.70.5 server boots with PostgreSQL as its only service dependency and
returns database-backed readiness to a product-side client on a private test
network.

## Execution rules

- Use Tests-first RED before every production slice.
- Follow only the M0-14a source task and approved design boundary.
- Treat Docker output, image/container/network metadata, files, and HTTP as
  hostile input.
- Do not load dotenv, provider credentials, Docker authentication, profiles,
  proxies, product database values, or external endpoints.
- Do not enable or claim Functions, Webhooks, MCP, RBAC, Connect UI,
  Enterprise-only runtime behavior, OAuth, API-key connections, or proxy calls.
- Do not mark M0-14a Complete or change R-08 before live proof and clean review.

## Task 1 — start contract and architecture

1. Add the repository contract before design/status records and capture RED.
2. Record the exact current official Nango source/image, PostgreSQL image, and
   already reviewed product-probe image pins.
3. Lock the two-service free Auth/Proxy boot boundary, separate storage/key,
   private network, database-backed readiness, ownership, deadline, and cleanup
   design.
4. Move only M0-14a to In progress with counts 713/1/12/1 while preserving
   M0-13 Complete, M0-09/PROV-01 Blocked, R-03 incomplete, and R-08 Not run.
5. Run focused GREEN, full repository verification, audit, diff, and redacted
   secret scans; commit atomically.

## Task 2 — exact runtime manifest and strict parsers

1. Capture missing-module RED for immutable image/runtime constants and strict
   Docker/HTTP parsers.
2. Implement exact source/image pins, supported platform resolution, names,
   labels, complete allowlisted environments, and fixed container/network
   specifications.
3. Require exactly Nango server plus PostgreSQL as long-running services;
   encode the one-shot product probe separately.
4. Add recursive duplicate-key rejection, bounded Docker metadata parsing, and
   an exact bounded `/ready` response parser.
5. Prove that Redis, Elasticsearch, Connect UI, Functions, Webhooks, MCP, RBAC,
   Enterprise, ambient credentials, profiles, proxies, and public ports cannot
   enter the generated runtime.
6. Run six focused stability passes, affected regressions, and full gates;
   commit.

## Task 3 — exact-owned filesystem and secret boundary

1. Capture RED for missing temporary-root and synthetic-secret helpers.
2. Create canonical direct-child Docker-config and proof roots with retained
   device/inode identity, no symlinks, exact permissions, and cleanup-time
   reproof.
3. Generate marker-scoped synthetic database credentials and database, plus
   the pinned Nango `nango` and `nango_records` schema names required by its
   v0.70.5 migration set, and a valid per-run encryption key without reading
   ambient state.
4. Keep raw synthetic values only in bounded process memory/container config;
   public output and diagnostics remain fixed and redacted.
5. Add replacement, traversal, symlink, FIFO, oversized, cancellation, and
   cleanup-precedence tests; run focused/full hermetic gates; commit.

## Task 4 — disposable Docker lifecycle and product probe

1. Capture RED for the absent orchestrator and fixed-output CLI.
2. Resolve immutable images, create the exact private internal network, start
   PostgreSQL, start Nango, and retain every exact full container ID before
   interpreting mutation results.
3. Run the one-shot product probe only on the private internal network and
   require database-backed `/ready` HTTP 200 with exact bounded JSON.
4. Implement complete image/container/network/peer ownership, definitive versus
   ambiguous mutation handling, mutation settlement, deadline fencing, hard
   child supervision, independent cleanup, and prefix-wide absence.
5. Add concrete runtime tests for delayed mutations, replacements, extra
   peers/env/ports/mounts/security fields, false liveness, malformed readiness,
   stale prefixes, cleanup continuation, and cleanup precedence.
6. Run six focused passes and full pinned gates; commit.

## Task 5 — root commands and documentation

1. Add repository-contract RED for missing hermetic/live scripts and README.
2. Expose `proof:nango-boot:test` and `proof:nango-boot:run` under pinned Node
   22.23.1/npm 10.9.8.
3. Document the fixed success line, exact images, two-service boundary, private
   product network, separate database/schema/key, and excluded features.
4. State clearly that OAuth, API-key, feature-boundary, proxy, public-ingress,
   and production claims remain deferred, and R-08 remains Not run.
5. Run focused/full verification, audit, license inventory, diff, and secret
   scans; commit.

## Task 6 — live proof, review, and completion

1. Prove preflight global absence, resolve/pull the exact images without ambient
   Docker authentication, and run the exact root command twice.
2. Require both long-running services, exact database-backed `/ready`, exact
   product test network reachability, and fixed success inside the timebox.
3. Prove exact container/network/temp cleanup and global prefix/proof-label/run-
   marker absence after every run.
4. Run six final hermetic passes, repository verification, production audit,
   license/secret scans, and whitespace checks.
5. Obtain independent review and fix every finding through separate RED/GREEN
   commits until the verdict is zero findings.
6. Exercise the completion contract, move M0-14a to Complete, keep R-08 Not run,
   push, and watch exact-SHA Runnable UI CI to success.

## Completion checklist

- [x] exact free self-hosted Nango v0.70.5 image
- [x] exact PostgreSQL dependency and no Redis/Elasticsearch/orchestrator
- [x] separate database, schema, and per-run encryption key
- [x] private internal network with no host port
- [x] database-backed `/ready` from one-shot product probe
- [x] complete exact ownership and mutation settlement
- [x] independent cleanup and prefix-wide zero-resource audit
- [x] two consecutive live runs
- [x] full gates, audit, license, and secret scans
- [x] independent review with zero findings
- [x] completion transition and exact-SHA CI success
