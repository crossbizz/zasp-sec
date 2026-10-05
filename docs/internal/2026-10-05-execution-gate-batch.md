# Execution-gate continuation — October 5, 2026

Base: merged main `e13ccb95451b03107681ccb59b3fc6fe175a228f`.
Candidate branch: `codex/execution-readiness-20261005`.
This record supports the authoritative implementation ledger; it is not a
second task ledger or a production-readiness receipt.

## Scope and rulings

P3/P7 execution and worker registration depend on trustworthy source capture.
The A emitter copied a replay companion test but omitted the descriptor it
imports. Bind that companion's exact two local imports and follow them through
the existing regular-file/topology checks. Preserve the fixed 53-file reader,
its pins, historical archives and reference facts. Other tests include deliberate
dynamic negative probes; do not pretend a generic regex discovers every possible
JavaScript dependency. Unreviewed imports on this admitted edge must refuse.

The original registration capture's query helper discarded its driver error,
preventing diagnosis of the already-recorded PostgreSQL refusal. Keep refusal
behavior, but report only an allowlisted error class, validated SQLSTATE and
statement SHA-256. Never wrap or print driver messages, details, hints, SQL,
arguments or object names. This test-only change is not a fix for the underlying
native SQL failure; a new admitted frozen build is required to observe it.

Ruling: preserve fail-closed runtime and immutable-reference boundaries while
closing these source prerequisites. No task availability is promoted; the cost
of a wrong source-capture ruling is a refused or incomplete reference capture,
not permission to activate an unverified executor.

## Verification actually performed

- Node 22.23.1 grouped A-source and inventory/development checks: 18 passed,
  zero failed; the known stale immutable-packet case was explicitly excluded.
- A nested test runner inherited `NODE_TEST_*` context, so its initial exit-zero
  observation was insufficient. Clear that context and require explicit executed
  counts. Corrected RED against the original emitter failed with actual
  `ERR_MODULE_NOT_FOUND`. Corrected affected regressions: six passed, zero failed,
  zero skipped; the captured replay independently executed eight passing cases.
- Immutable A emitter `--check`: exit 1, current
  `ordered_current/consolidated-capture-contract.json` differs. This gate remains
  open; no generated output was refreshed to erase the discrepancy.
- Go 1.25.13 diagnostic RED: eight cases failed on missing classification/digest;
  five existing JSON-admission cases passed. GREEN: all thirteen cases passed.
  Sixteen affected registration unit/admission top-level controls passed without
  skips. CLI compilation and both capture opt-ins were outside that selected run.
- The first Go invocation lacked dependencies with the proxy disabled; that setup
  failure was not counted as RED. Subsequent commands used the preserved read-only
  toolchain/module cache and a fresh owned writable build cache, with readonly
  modules, CGO disabled, no network dependency fetch and no lock changes.
- UI `npm run typecheck` and `npm run build` passed under Node 22.23.1.
- Combined independent security/spec review approved the exact four-file code
  change below. No native PostgreSQL run was performed by that review. A normal
  main-push receipt must be verified separately before describing it as merged.

Reviewed source SHA-256 identities:

| File | SHA-256 |
| --- | --- |
| `authorization_worker_registration_reference_test.go` | `de0fd04c00580ebcd7d0caec4a3834e7730cbd7f0ddfd4f36b21b7ba8c9f565f` |
| `authorization_worker_registration_reference_admission_test.go` | `c44f8e90bc67308273bb3811951f7f8f45b7143320df2d04807e1bc257d329fb` |
| `build-ordered-current-consolidated-reference.mjs` | `8597de6ccc79fe0f4504ee353222d994e0ebc8b08337ae37dddee79364ed003c` |
| `build-ordered-current-consolidated-reference.test.mjs` | `53bc9c0d18dd7c835273cf45421dc73e537398cf8a2e8b04dbf83c07a6c60b95` |

Reproduction uses the existing A-emitter test with `--test-name-pattern='A companion'`,
and the A-emitter plus inventory tests with
`--test-skip-pattern='checked-in packet and immutable snapshot'`.
Run the emitter's `--check` separately; do not label its refusal as passing.
Go diagnostics select `^TestWorkerRegistrationReferenceQuery(Diagnostics|JSONAdmission)$`.
These are our capture/admission checks, not tests of Temporal/OpenFGA internals.

## Retained local evidence identities

These logs remain local; their hashes are observations, not deployed proof or a
claim that cloud received the files. Cloud can rerun the checked-in regressions.

| Local evidence | SHA-256 |
| --- | --- |
| `/tmp/zasp-capture-closure-20261005.HlKHfB/companion-red.log` | `90073bb426d0eb07b6ab6cc63e5a2835d67f8a28c236db6cf948b787d809c6f8` |
| `/tmp/zasp-capture-closure-20261005.HlKHfB/companion-green.log` | `fdb6e2a743e30dd1b0e010642221fdc8f31c9df60e0021ee50926f0c976c3d01` |
| `/tmp/zasp-capture-closure-20261005.HlKHfB/green.log` | `e5fa013efbcaa973b653a772bca8ef93cdf101e749fa4ff62eadffd3b4e91d31` |
| `/tmp/zasp-capture-closure-20261005.HlKHfB/immutable-check.log` | `a44ceda56b3affbb2740319330ee7e7781f61628b902075d08535665e4f3737e` |
| `/tmp/zasp-registration-query-diagnostics.Wtkc2E/red.log` | `9585cae4107b2d21b6b8bfa1e743ac92e3599c7b160d9c52a93623fbafc3be94` |
| `/tmp/zasp-registration-query-diagnostics.Wtkc2E/green.log` | `b6f5c3ae2af7d526fa1f785e0b8345f5e7e1671ef336718b4eac86f3acc1672c` |
| `/tmp/zasp-registration-query-diagnostics.Wtkc2E/guard-regressions.log` | `20551116a747dda0b4456a74e865e4b26ad10b1132435358a52ab25a8963e305` |
| `/tmp/zasp-execution-readiness-ui-build-20261005.log` | `be4ca7d8ec53bc7edea3a6c4dc0a38f42730ec0ba26c815d6d9d3e95602c1d67` |

## Next connected acceptance and external gates

Prepare and review a fresh immutable registration source/binary/input envelope
including the diagnostic change. Run the bounded original PostgreSQL fixture
with `LC_ALL=C`, its exact admitted environment and owned normal stop/join,
then diagnose the refused statement without relaxing SQL, caps or permissions.
Complete separate current A/B synchronization, native379 and installation
acceptance before enabling guarded production runtime paths.

The local audit found PostgreSQL 18.3 tools, Node 22.23.1 and a browser, but no
Docker daemon or listening product/Temporal/OpenFGA services. The required Go
1.25.13 toolchain was restored without changing global settings. Local absence
does not disprove the user's existing cloud credentials: cloud runtime/access
receipt is still unverified here. Real Stytch/provider browser journeys,
cross-tenant/revocation checks, backups, advisory clearance and deployed recovery
remain required. All 728 original requirements and milestones remain in scope.
