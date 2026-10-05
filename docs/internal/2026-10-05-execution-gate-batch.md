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

## Fresh registration build checkpoint

The diagnostic/source-capture batch landed as main
`e7bb2d85c89b993b3de37bb97c135f788b509711`. Separate local candidate
`356b25d3f2c7c8209aca71d0441b126ef9983e88` repairs one stale dispatch pin and
adds a seven-file actual-source control. The discrepancy was caused solely by
the previously reviewed synthetic credential-string split in
`authorization_worker_effect_postgres_test.go`. Independent byte comparison
confirmed the runtime string and all other file bytes are unchanged. Independent
pin review approved the exact two-file change. Historical SQL, installer behavior
and reference facts are not replaced by this repair.

Fresh compiler records in `/tmp/zasp-registration-build-20261005.JXnGEL`
record both apiserver and migrations test builds exiting zero from frozen source
at that candidate. The actual input inventory and independently reproduced
roster agree on 5,759 inputs and 74 resolved module identities. The actual
binary's 17 selected registration controls pass without skips; whole-module
byte verification passes. Root inspected the selected-control log and
independently hashed the report, envelope and both binaries. This is
build/component evidence only. Independent actual-build review approved this
exact envelope after independently reconstructing the full consumed closure,
checking source/Git identity, immutable roots, actual binaries, PG files and
admission controls. Root's one strict PostgreSQL execution completed as a
failure; reference acceptance remains unproved.

| Retained local artifact under that bundle | SHA-256 |
| --- | --- |
| `actual-build-report.md` | `6fd9849ffeb5d4c50c78748b0d98f6dce9a55dfae2e3d0c7d1acec0f6ce6b6a3` |
| `build-envelope-v1.json` | `32d57199c8c2148e8405edcf6e74052ec0148969e1119f2cdb4d1af717b0b29c` |
| `binaries/registration-apiserver.test` | `9fc6d4a1159f5e448cf5f55f48aea4528c0008d0687397c6e30d79d7e4455e49` |
| `binaries/registration-migrations.test` | `de779ff1a17577b3936eaee39d14cf2fb6a110403963a578568542824d8af40a` |

Optional offline `go list -mod=readonly -m -json all` exited one with 76
lookup-disabled errors for uncompiled whole-graph metadata. Its failure is
retained; it is not the successful consumed-package inventory or module-byte
verification. No cache expansion or network retry hid it. The independent
reviewer must assess the actual required closure, not infer whole-graph success.

The owned run uses physical frozen apiserver CWD, `env -i`, the admitted PATH
and envelope digest, `LC_ALL=C`, and a fresh exclusive output destination under
`/tmp/zasp-registration-reference-20261005.6WAnPi`. There are no competing capture
opt-ins or provider credentials in that environment. It exited one after
65.75 seconds: `error_class=postgres`, SQLSTATE `42703`, statement SHA-256
`e61fd5bc920a9960e4586d0eb2a66d624cf02579899cd84a5ac37d800f9d92fc`.
The owned server PID 70084 was stopped by pg_ctl and joined by Wait, both
exit zero with normal exit. A fresh filtered process inventory found no
remaining PostgreSQL or fixture processes; the private destination directory
contains only the execution log, no published reference packet. Log SHA-256:
`ab0ac0e7eb7d828a9dd7e108603dbed3542667a5787c862ca4499225369a8ea3`.
The new diagnostic changes the next action to tracing the exact undefined-column
statement, not retrying an unchanged capture or relaxing authorization. Current
native379, installed execution, real-provider/deployed flows and cloud runtime
receipt remain open. Credentials already configured in cloud need not be
re-entered or copied here. No availability row is promoted.
