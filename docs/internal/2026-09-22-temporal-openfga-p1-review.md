# SPEC: needs fixes

P1 has one blocking staging configuration defect. The local connection packet, shared configuration and entrypoint wiring match the brief; the documented staging OpenFGA certificate won't pass the rendered health probes.

## What holds up

- Shared validation. `services/platform/runtimeservices/config.go:26` and `:48` reject incomplete enabled authority, unsafe transport and unbounded timeouts. Both actual parsers consume it (`agentsec-api/runtime.go:105`, `agentsec-worker/runtime_config.go:201`).
- `services/platform/runtimeservices/clients.go:31` uses the official SDKs, bounds connection/readiness calls, checks the requested namespace and pinned model, and redacts service errors. The FGA transport disables ambient proxies at `:82` and redirects in its HTTP client configuration.
- The production builders connect readiness and cleanup at `services/platform/agentsec-api/production_runtime.go:81` and `services/platform/agentsec-worker/production_runtime.go:58`. The worker cleanup test covers an existing close error (`agentsec-worker/runtime_services_test.go:16`).
- Separate local datastores and official migration commands are explicit in `deploy/local/temporal-openfga.compose.yaml:19`. The opt-in smoke provisions only a connection fixture (`services/platform/runtimeservices/local_smoke_test.go:15`); the report doesn't call that product authorization evidence.
- Version pins and dependency metadata agree in the scoped patch (`services/platform/go.mod:3`, `build/dependencies.lock.yaml:259`, `scripts/validate-dependencies.mjs:144`). Product deployment wiring reaches the existing renderer at `deploy/production/release-contract.mjs:357`, with a rendered API/scheduler credential test at `deploy/production/runtime-services.test.mjs:6`.

## Important: fix the OpenFGA TLS probes

**Finding P1-R1:** `deploy/staging/openfga.values.yaml:26` enables gRPC TLS but leaves the chart's default readiness/liveness probes unchanged. The existing render at `/tmp/zasp-p1-baseline.YnmB3B/staging-rendered.yaml:1388` and `:1402` connects each probe to `0.0.0.0:8081`, enables certificate verification, and supplies no `-tls-server-name`. Yet `docs/operations/temporal-openfga.md:76` tells the operator to issue the certificate for the private service SAN. A certificate valid for `openfga.zasp-runtime.svc.cluster.local` doesn't validate against `0.0.0.0`. Readiness stays false; liveness then restarts the container, and the deployment command's Helm wait cannot complete.

This is an application configuration failure, not a missing staging credential. The probe's own [TLS contract](https://github.com/grpc-ecosystem/grpc-health-probe/blob/master/README.md#health-checking-tls-servers) documents the hostname override. Chart 0.3.15 supports `customReadinessProbe` and `customLivenessProbe` (cached chart `openfga/values.yaml:104`, `templates/deployment.yaml:399`). Set both to verify the documented service name while connecting locally; retain CA verification. Add a focused rendered-probe assertion and one bounded check with a DNS-SAN certificate. Don't disable verification to make the probe green.

Critical findings: none. No separate minor finding.

## Checks and limits

I reviewed the supplied 31-path dirty-overlay patch, its hashes and the complete implementer report. No HEAD-wide diff, implementation edits, commits, pushes or suite reruns.

Focused checks outside the diff addressed these named risks:

- Secret readability: the changed workload hunks omit their pod security context. Existing `deploy/staging/product/templates/workloads.yaml:35` and `:188` set `fsGroup: 65532`, consistent with the new mode 0440 secret volume.
- New egress policy isolating DNS or product storage: existing `deploy/staging/product/templates/resilience.yaml:100`, `:177` and `:224` retain DNS, API dependencies and scheduler database access alongside the new additive service policy.
- Chart TLS/migration settings being ignored: inspected the existing staging render and the cached pinned chart's probe hooks. TLS, database CA mounts, migration credentials and namespace creation render; P1-R1 is the defect found. The official Temporal 1.32.0 [SQL tool flags](https://github.com/temporalio/temporal/blob/v1.32.0/tools/sql/main.go) accept the migration job's `SQL_TLS` and `SQL_TLS_CA_FILE` names.
- Retained local-service evidence: read-only `docker compose ... ps -a --format json` showed the dependency services running and migration/namespace jobs exited zero. This doesn't replace or repeat the reported SDK smoke.

The report lists passing targeted config/client tests, dependency validation, local smoke and rendering (`docs/internal/2026-09-22-temporal-openfga-p1-report.md:15`). I didn't rerun them. Its raw staging render was available; its summary is the evidence supplied for the other completed test runs.

## QUALITY: needs fixes

The Go connection boundary is small and keeps adoption separate from activation. The staging TLS probe mismatch blocks approval of the complete P1 packet.

Controller checks still open: retain all 728 original IDs and their acceptance classifications; P1 changes no ledger classification. P2-P7 must still supply orchestration, product model publication, projection and enforcement (`docs/operations/temporal-openfga.md:3`). Live staging certificates/secrets, measured capacity, backup/restore evidence, advisory clearance, runnable UI checks and mandatory CI remain gates, as the report records at `docs/internal/2026-09-22-temporal-openfga-p1-report.md:38`. Fix P1-R1 before calling this packet complete.

## Fix round 1: P1-R1 addressed

**P1-R1: ADDRESSED.** `deploy/staging/openfga.values.yaml:29` and `:43` now configure both custom probes with a loopback connection, the documented service DNS name and the trusted CA. Neither disables certificate verification. One-second connection/RPC limits and a three-second Kubernetes timeout keep each check bounded. The saved fix-round render confirms these commands in both probes (`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p1-evidence/fix1/staging-rendered.yaml:1379`).

The regression assertions cover both rendered probes (`deploy/staging/runtime-services-probes.test.mjs:14`). Its opt-in real check at `:28` issues a DNS-only SAN certificate, starts the pinned OpenFGA image in an isolated container, runs the rendered probe, and rejects a wrong server name. The appended implementation report records two passing tests with no skips and the amended Go config/client/local-smoke tests passing (`docs/internal/2026-09-22-temporal-openfga-p1-report.md:44`, `:52`). I did not rerun them.

**GO-2026-6348 and GO-2026-5970: ADDRESSED for the pinned modules.** `services/platform/go.mod:50` pins gRPC 1.83.1; `:93` pins x/text 0.39.0, with matching checksums and their required genproto/x/sync updates. The official [gRPC advisory](https://pkg.go.dev/vuln/GO-2026-6348) and [x/text advisory](https://pkg.go.dev/vuln/GO-2026-5970) identify these fixed versions. Read-only checks of the downloaded module metadata confirmed both declare Go 1.25.0, and that the updated genproto and x/sync versions match their requirements. The direct-dependency validator wasn't changed by this fix.

**New breakage in the fix diff: none found.** Reviewed only the six-path fix patch, adjacent hashes, amended report, rendered probe evidence and dependency evidence. No unchanged suites were repeated; no implementation files, index or branch state were changed.

**Publication gate remains open.** The final saved scan ends with 26 reachable standard-library vulnerabilities, five imported-package findings and 18 required-module findings, followed by exit status 3 (`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p1-evidence/fix1/govulncheck-final.txt:287`). Neither patched module advisory appears in that output. The scan identifies host Go 1.25.6 and fixes through 1.25.13; `docs/operations/temporal-openfga.md:11` accurately records this as an unresolved gate. This review grants no advisory, container-image or production clearance.

**Out-of-scope observations: none added.** Previously recorded external gates and P2-P7 obligations remain unchanged.

**Final SPEC: compliant for the P1 local dependency/configuration packet, with recorded publication gates. Final QUALITY: approved.** All findings in this fix round are addressed; no new Critical or Important breakage was found. The original finding above is retained as review history.
