# Proof consumer lock closure — 2026-10-02

This source-only batch restores readonly Go resolution for proof consumers of the security-patched platform module. It changes six lock files and this evidence note. It preserves application source, tests, release guards, dependency/license policy, existing toolchain recommendations and the controlled Go 1.25.13 compiler.

| Proof | Exact lock change |
| --- | --- |
| Neon pooled | Existing `x/sync` 0.21.0 → 0.22.0 and `x/text` 0.39.0 → 0.41.0; four normal checksum additions, zero removals |
| LocalStack SQS, LocalStack storage, OpenSearch event | Existing Go minimum 1.25.0 → 1.25.4 |
| All five, including Neo4j graphstore | Add the exact root mapping `github.com/zasp-ai/zasp-sec/services/health => ../../services/health` |

There are no new requirements, unrelated version upgrades, tidy changes, existing replacement changes or checksum removals. The six-file lock delta is 19 insertions and five deletions. Existing `toolchain go1.26.5` recommendations remain where present; these checks explicitly select Go 1.25.13 with `GOTOOLCHAIN=local`.

## Causal evidence

The old source baseline is `08bc8d5c402ab1d80f653041f94bfbcd392f2d4e`; the patched platform source is `a87bde3beee9623d7221c7d3de0dde2a2d7454f6`. Isolated Git exports retain exact source and lock rosters.

- **New Neon regression:** identical original Neon source/locks pass readonly dependency resolution and full proof race tests with the old platform. With the patched platform they reject readonly resolution with `updates to go.mod needed`. Updating the two existing indirect requirements and their four verified sums restores the selected closure and full proof tests.
- **Older minimum mismatch:** LocalStack SQS, LocalStack storage and OpenSearch event reject readonly dependency resolution against both platform baselines. Changing only their existing minimum to 1.25.4 makes all three pass against both. Neo4j's selected graph already passes against both baselines.
- **Older full-graph mapping gap:** all five proof roots lack a root health replacement. Go does not inherit platform's nested replacement, so full MVS listing requests the nonexistent private `health@v0.0.0` through the ordinary proxy and receives 404. After supported minima are established, adding only the exact health mapping makes each old and patched full graph pass; these probes add no sums. This is missing local graph authority, not a network permission or live-provider failure.

The health target is the existing owned module, version `v0.0.0`, minimum Go 1.25.0. All five health source files match the repository. Its unchanged `go.mod` SHA-256 is `800feb2d307b99dc161ce73170609d4cbe535f840aedf013c7c8392977ba9737`; the unchanged license evaluator retains its internal `NOASSERTION` treatment. The two Neon module versions retain their reviewed BSD-3-Clause archive license bytes and normal h1 checksums.

## Validation

Before live mutation, all five private candidates passed readonly selected/full graphs, full package `go test -race -count=1 ./...`, CGO-disabled builds and module verification. Neon also passed the original `^TestTenantRLS|^TestRenderTenantRLS` selection. Neon has no Node test files; its live Go-run wrappers were not invoked. The existing nine offline Node proof test files passed 129/129, with no skips.

After applying the tested locks, **all nine platform replacement consumers**—four shipping services and five proofs—passed readonly selected graphs, full MVS graphs and module verification: 27/27 checks with `GOPROXY=off`. Go locks remained unchanged by these checks. Old/current full MVS comparisons add/remove no modules: Neon has 89 modules with eight version changes, and the other proofs each have 85 modules with six changes. These are exact subsets of the already approved nine-module security roster, reflecting dependency graph pruning; `x/term` is absent from both proof graphs.

The root independently reran the unchanged `npm run db:tenant-rls:test` stage on the live batch: PASS in 6.24 seconds with pinned Go 1.25.13, readonly resolution, serialized packages and race enabled. Its source hashes remained unchanged; log SHA-256 is `dfb7c3f2f66e070b0ab2ce95ba2bcc90feb3c6a72814443edcac6c2be184949b`.

The six lock files and causal/test receipts are frozen privately under `/workspace/scratch/go-proof-lock-closure`. The six-file roster SHA-256 is `69461f8b1da499d9b06f0a2317ab0d78795bf904eb3e7630332dd02cc840d01e`; its proof-artifact roster SHA-256 is `95543bce85eb56138cc76653ff6486d49a2fa391705e2f7b4846db00951f496e`.

## Remaining verification

The earlier default-parallel npm run failed two API readiness tests when their existing one-second contexts expired. Both passed in isolation, and the serialized npm run passed the full health stage before stopping at Neon's old locks. Those attempts remain separate, immutable evidence. This lock batch does not establish a full npm pass or solve the default-parallel failure; downstream UI tests, typecheck, release tests and build require a fresh run after review and commit.

Hosted UI causality remains unknown because its logs are inaccessible. Connected provider acceptance, advisory clearance (including the three unresolved crypto IDs and unknown severity), image scans, native packet acceptance and production readiness are not claimed. No provider operation, PostgreSQL fixture or image build was performed for this batch.

## Follow-up: exact proof minimum assertions

A fresh original `npm run verify` on committed proof locks at `d4226a98d96dcba9329d8000405927da570bb6ca`, with pinned tools, Go 1.25.13, readonly modules, race enabled, child umask 0022 and serialized Go package scheduling (`-p=1`), passed the Go/proof stages before failing exactly three UI contract assertions. Each still expected Go 1.25.0 after the reviewed lock batch set those three proof minima to 1.25.4. Its UI result was 2,532/2,535; later verification stages were not reached. The complete negative run was frozen before editing assertions; its log SHA-256 is `d52c401a28e9f9ca7739bd2f849f0fa6769a71bb063a5fa97ed76d91264699aa`.

This follow-up changes only the exact Go-minimum regex in the LocalStack SQS, LocalStack storage and OpenSearch event contract tests from 1.25.0 to 1.25.4. Other assertions, source, toolchain recommendations, guards, test contexts and timeouts are unchanged. The three focused files pass 10/10 tests, and a fresh original full UI suite passes 2,535/2,535 tests across 246/246 files in 127.41 seconds. The full UI log SHA-256 is `5dba13dc6a25e6ce2ae8a12b515b543cfb32eae702ef00ad17684d21514c4fa5`.

The separately invoked original verification tail starts at typechecking; it does not rerun the earlier Go/UI stages. Its first attempt passed typechecking and the three lint scope tests, then failed ESLint on an unnecessary regex escape in the new, untracked advisory collector. That negative is separately frozen with log SHA-256 `3c12fea0bde32ba0bd49268c59641eee821492d8b83f41f0c0bd50610b91bf9a`. The collector owner corrected that lexical escape; this four-file follow-up does not include collector changes.

After the separately owned collector correction, the original nine-stage tail passed on a fresh, uniquely named attempt: typecheck; lint (including 3/3 scope tests); production import tests (7/7) and source check; staging tests (30/30); production release tests (285/285, including both full-history source verification calls); production build; compiled import check; implementation status. Its actual exit was 0 after 864.78 seconds; log SHA-256 is `490623f279821916908bdc7b4ecb67d1b435a598864ac892ef43a8605b522c2a`. All 5,977 tracked input hashes, HEAD, ten pinned tools, narrow PostgreSQL libraries and the three separately recorded untracked collector source hashes remained unchanged during the attempt. The owned subreaper joined the main process and reaped one adopted descendant; no outer bound fired.

These are staged positive results after the preserved complete negative run, not a fresh complete `npm run verify` pass. Default-parallel API context failures remain unresolved, and hosted causality remains unknown. No test timeout, context, scheduling configuration or release guard changed. Provider connectivity, advisory/image clearance, native acceptance and production readiness remain outside this follow-up.
