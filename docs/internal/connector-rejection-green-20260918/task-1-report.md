# Task1 implementation report

Implementation and connected verification are GREEN, including the full UI
suite and types/lint/build on pinned Node22.23.1/npm10.9.8. Independent root
review remains required. No commit, staging, push, migration, privilege or ledger edit.

## Exact scope and identity

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.

`task-1-source-manifest.log` contains BEFORE/AFTER SHA256 for exactly10 touched
source files; `before/` and `after/` retain those bytes (ABSENT for new files).
`task-1-scoped.patch` is against those BEFORE bytes, not the extensive inherited
HEAD diff. Patch SHA256:
`7de38817e78aa2d0946344b2fcbdce60f86ca676e172d75e5e7a4eb065f74c9e`.
Existing workflow_handler.go has only two error-branch replacements. Runtime
capabilities are in a new companion file, leaving production_runtime.go intact.
The existing RED test is expanded; original RED evidence remains unchanged in
`docs/internal/connector-rejection-20260918/`.

`finalize-evidence.mjs` verified all193 migration sources from original RED AFTER
are byte-identical. Compiled56 checksum
`f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1`, fingerprint
`8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced` remain exact.
No57 migration or predecessor adapter exists in this change.

## Behavior and authority

- The narrow safe command carries credential digest, fixed operation, server
  target, audit ID and correlation ID. It cannot hold submitted configuration,
  names, URLs, raw credential, intent or idempotency key.
- Real HTTP rejection handling covers early secret-filter and later setup
  validation, preserves existing400 invalid_request and successful-key409,
  and maps missing/persistence capability failures to fixed503. Explicit typed
  authority errors preserve401/403/404 without exposing raw SQL errors.
- A dedicated READ COMMITTED transaction checks exact current authority,
  inserts the safe event, checks readiness again, then performs fresh locked
  authorization and wall-clock expiry before commit. Rollback is deferred with
  a bounded independent context, including panic/cancellation paths.
- Final lock order is membership, credential, direct scope or group mappings,
  then update target. PAT requires direct-scope plus token permission
  intersection; browser group-only permission is supported. API cannot read
  authority member-group rows; it receives no new privilege.
- Source enumeration found the registered member-group writers in release19:
  resolve_session and reconcile_deprovision. Both first take membership
  FOR UPDATE. The final membership FOR SHARE plus existing mapping-row locks
  stabilizes their positive grant witnesses. New positive mappings cannot
  revoke those witnesses. Owner/bypass database tampering is outside this
  registered product-writer concurrency proof.
- Legacy release10 already granted API audit CRUD and release52 preserved it.
  Tests explicitly observe registered non-superuser/non-bypass API INSERT.
  This does not claim global audit-table immutability or lack of direct INSERT.
- The actual production pgxpool driver uses explicit ReadCommitted; the actual
  traced decorator forwards only the dedicated capability with safe tracing.
  No compliance authorization helper is used; existing compliance_api_ready
  is only the exact compiled56 and registered API readiness predicate.

## Tests and evidence

All commands ran with explicit worktree cwd. Go used local1.25.6 and offline
`GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`, cache
`/private/tmp/zasp-budget-go-cache`. The retained run-focused.sh enumerates
anchored test names before executing. It compiles linux/arm64 binaries and runs
cached PostgreSQL image
`postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`
with `--network none --pull=never --read-only --user postgres` and owned tmpfs.

Final combined command:

```sh
bash .superpowers/sdd/2026-09-18-connector-rejection-plan/run-focused.sh apiserver '^TestConnector(Rejection(Classification|HTTPBoundary)|RejectedAuthorityOverridesPostgres)$'
```

`green-combined.log`: PASS, mounted parent14.75seconds. The log includes named
enumeration, all original10 create/update overrides with one exact safe durable
event each, unchanged state snapshots, original four auth/CSRF/scope/target
controls, safe GitHub201 and webhook201. It additionally proves:

- rejected retries append events; conflicting successful key remains409;
  corrected request can reuse rejected key and succeed201;
- real audit GET with a separate authorized reader exposes13 rejected events
  as public denied outcomes without submitted data;
- PAT permission intersection, and observed blocked-INSERT revocation,
  expiry and token-permission removal;
- six browser blocked-INSERT revocations: session revoke/expiry, inactive
  membership, member role reduction, direct scope deletion, target deletion;
- database cancellation and final wall-clock expiry after observed target wait;
- group-only allowed session, actual resolve-removal revocation401, mapping
  role reduction/removal403, and observed actual resolve/deprovision writer
  contention behind the final membership lock;
- absent transaction support, closed DB, commit failure, rollback-report
  failure, panic and context cancellation after actual INSERT, forged actor,
  wrong credential kind/scope, unregistered role: no event persists;
- child TestConnectorRejectionRuntimePostgres exercises actual pgxpool,
  production traced database and repository under asserted registered
  non-super/non-bypass role; durable event, missing and closed capabilities.

Fault tests inject failures around real transactions; rollback-report fault is
reported *after successful real cleanup*, not a simulated unreachable server.
They prove this boundary's behavior, not every network failure mode. Mounted
setup create/update has no provider transport dependency. Default HTTP and
connector-dispatch tripwires are local checks, not proof of all custom
transports or live egress.

Combined log SHA256:
`5c6ecb1cd27cca6efea4bd4680e2826714e608dd412e09370fa98567cf4e6018`.
Final parent binary SHA256:
`46a8548ac45f87a2159b5497c06f7acc0fe1c0f68ccacd7e862058b1ced9a927`.
Child binary SHA256:
`b30fba69bdb90ed31172f44fd35123e390529372e14fe5a315181d2335ebf85a`.

Grouped affected Go race command:

```sh
go test -C services/platform -race -count=1 ./apiserver ./agentsec-api -run '^(TestConnectorRejection(Classification|HTTPBoundary)|TestWorkflowHandler.*|TestPostgresJSONDatabase.*|TestTracedDatabase.*|TestOperational.*)$' -v
```

`affected-race.log`:48 top-level tests PASS, apiserver4.603s and runtime1.956s.
SHA256 `e121859201fd34c9084edb303f75ae42a5278b5724b4d79b1b29654f8a3dd717`.

UI boundary: focused2files/7tests PASS, then typecheck, lint and all5 build
stages PASS on identical source (`ui-boundary.log` is a labeled tool-output
summary). Node26.8.2 is the available host runtime, not pinned22.23.1; nonfatal
module.register/localStorage warnings are recorded. No package installation.
Node26 full UI diagnostic also passed224files/2136tests in27.55seconds
(`ui-full.log`, process21766 joined0). Authoritative supported-runtime grouped
gate used PATH prefix `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin`:

```sh
node --version; npm --version
npm test && npm run typecheck && npm run lint && npm run build
```

`ui-pinned22.log` prints actual v22.23.1 and10.9.8. Full UI224files/2136tests
PASS in32.65seconds; typecheck, lint and all5 build stages PASS. Process58935
joined exit0. The earlier26 run is distinct diagnostic evidence, not a claim
about the pinned runtime. Only this runtime correction required repeating the
boundary; unchanged exact-source Go/database tests were reused.

## Diagnostic runs, not extra claims

Preserved green-1 through green-authority-4 and green-final logs document
setup corrections. Initially calling an authority-only readiness function was
corrected to the existing API-ready wrapper without grants. Canceling the
reused single fixture connection was corrected to server query cancellation;
separate connections retain real context-cancellation coverage. Real group
resolution revokes existing sessions, so group setup now asserts old credential
revocation and creates distinct sessions through CreateSession+Authenticate.
Runtime fixture first omitted its required exporter; then its ConnString
serialized the original owner DSN despite modified Config.User (pgx source
conn.go63 preserves the original string). The corrected child explicitly
serializes and asserts the registered API role; readiness was not weakened.
Only green-combined.log is final connected GREEN evidence. Earlier test
failures are not counted as passing or as product missing-audit RED.

## Cleanup and review handoff

All focused processes and runtime child processes joined. Final PostgreSQL
server pid24: pg_ctl exit0 and server Wait exit0; Docker --rm removed owned
containers. task-1-cleanup.log confirms no connector-rejection container and
the ten unrelated voxeval containers untouched. Go race and UI boundary
processes joined0. Both full UI processes and the pinned grouped gate joined0;
no live process handle remains.
No source edits after the final combined run; subsequent work is evidence-only.
Root independent review and final classification remain outstanding.
