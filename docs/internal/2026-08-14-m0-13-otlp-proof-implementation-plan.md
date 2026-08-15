# M0-13 OTLP ingest proof implementation plan

## Goal

Deliver a reviewed, exact-pinned, disposable proof that one synthetic semantic
trace passes through a real local OpenTelemetry Collector and reaches the
product-owned ingest adapter unchanged at every required identity boundary.

## Execution rules

- Use Tests-first RED before each production slice.
- Use only the exact M0-13 design and source-plan boundary.
- Treat external output, Docker inspection, OTLP JSON, and files as hostile.
- Do not load `.env`, provider credentials, profiles, proxies, or remote OTLP.
- Do not mark M0-13 Complete or R-12 PASS before live proof and clean review.

## Task 1 — start contract and architecture

1. Add the repository contract before the design/status records and capture RED.
2. Record the exact current official Collector image/index and the ingest-only
   data, identity, privacy, ownership, deadline, and cleanup design.
3. Move only M0-13 to In progress with counts 715/1/11/1 and preserve every
   blocked/complete boundary.
4. Run focused GREEN, full repository verification, audit, diff, and redacted
   secret scans; commit atomically.

## Task 2 — strict OTLP source and ingest adapter

1. Add tests for the exact synthetic OTLP/HTTP request and capture missing-module
   RED.
2. Implement a strict OTLP JSON parser with recursive duplicate-key rejection,
   exact key/type/cardinality bounds, exact trace/span IDs, and the six required
   semantic attributes.
3. Reject raw prompt text, arbitrary tool arguments, secret-like data, events,
   links, extra spans/resources/scopes, aliases, coercion, and oversized input.
4. Normalize one immutable product trace-evidence value and prove deterministic
   Organization scoping.
5. Run six focused stability passes and the M0-12 regression boundary; commit.

## Task 3 — Collector config and filesystem boundary

1. Capture RED for the missing exact Collector configuration and safe artifact
   reader.
2. Generate only the OTLP/HTTP receiver, bounded processors, and local file
   exporter; remote OTLP export stays disabled.
3. Validate the config and output roots as canonical direct-child owned
   directories and the artifact as a stable regular non-symlink file.
4. Enforce a 64 KiB plus one read cap, descriptor identity, close handling, and
   exact cleanup-time reproof.
5. Run focused and full hermetic gates; commit.

## Task 4 — exact Docker lifecycle and CLI

1. Capture RED for the absent orchestrator and fixed-output CLI.
2. Implement exact image resolution, random marker/name, proof labels, owned
   Docker config/temp roots, loopback-only random port, strict container
   metadata, readiness, trace submission, artifact polling, and adapter call.
3. Retain the exact full container ID and image identity. Reconcile only truly
   ambiguous mutations and re-authorize immediately before cleanup.
4. Use independent cleanup, cleanup precedence, mutation settlement, and a
   prefix-wide zero-resource audit.
5. Add adversarial tests for replacements, stale prefixes, duplicate inspection
   JSON, delayed mutations, deadline revocation, output caps, and cleanup
   continuation; run six passes and full gates; commit.

## Task 5 — root commands and documentation

1. Add repository-contract RED for missing hermetic/live scripts and README.
2. Expose `proof:otlp:test` and `proof:otlp:run` under pinned Node 22.23.1.
3. Document the fixed success line, exact image, privacy boundary, local-only
   meaning, and why R-12 remains Not run pending M0-22.
4. Run focused/full verification, audit, license inventory, diff, and secret
   scans; commit.

## Task 6 — live proof, review, and completion

1. Prove preflight absence, pull/resolve the exact image, then run the exact root
   command twice. Each must complete inside the source-plan timebox.
2. Retain only fixed/non-sensitive evidence: one trace, one span, matching trace
   ID, all required attributes, and exact cleanup.
3. Prove container, label, output, Docker-config, and temporary-prefix absence.
4. Run six final hermetic passes, repository verification, production audit,
   license/secret scans, and whitespace checks.
5. Obtain independent review and fix every finding through separate RED/GREEN
   commits until the verdict is zero findings.
6. Exercise the completion contract, move M0-13 to Complete, keep R-12 Not run,
   push, and watch exact-SHA Runnable UI CI to success.

## Completion checklist

- [ ] strict source and product adapter
- [ ] real exact-pinned Collector lifecycle
- [ ] exact trace ID and six required identity attributes
- [ ] remote exporter absent and privacy boundary enforced
- [ ] exact full container ID cleanup
- [ ] prefix-wide zero-resource audit
- [ ] two consecutive live runs
- [ ] full gates, audit, license, and secret scans
- [ ] independent review with zero findings
- [ ] completion transition and exact-SHA CI success
