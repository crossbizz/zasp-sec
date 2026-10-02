# P6 can proceed, with one small command-output fix

September 24, 2026. Independent combined spec and quality review.

SPEC: PASS for the local P6 synchronization/revocation component, with the minor observability exception below. QUALITY: PASS WITH MINOR FINDING. I found no Critical or Important issue in this frozen batch. This is permission to accept the P6 component and continue P7, not production-release approval.

## What I reviewed

The review uses the captured P6 baseline and its scoped patch, not the shared dirty worktree. HEAD is still `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. I independently checked all 19 frozen candidate hashes and every listed evidence hash against the manifest; none differed.

Manifest SHA-256: `84b90821ae560f240b30b2ff11e45a14fcf1f6273470b0c407ac49261318326f`.

Patch SHA-256: `481b803d591634060414f523d32abe0b2d4fe94ed29a6b7d4cad1de07897b7b2`.

I read the review instructions, approved design and execution plan, P6 implementation brief and mutation-boundary notes, full frozen implementation report, candidate source/tests, scoped changes, P5 mapping contracts and retained terminal evidence. I also traced the existing administration statements and SQL0019/SQL0025 permission sources where the new triggers attach. The requesting-code-review workflow supplied the spec/quality/severity split. Writing guidance came from `/Users/manishmaheshwari/.codex/writing-style.md` after the controller supplied its location.

For source references below, `C/` means this exact frozen root:

`/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p6/candidate/`

`SQL79` means `C/services/platform/migrations/sql/0079_production_authorization_projection.up.sql`. Evidence files are immediately above `candidate/` in the same packet. Other developers' changes weren't reviewed as part of P6.

## The parts that hold up

Source capture reaches the real writes. SQL79:62-80 advances the organization revision and outbox in the source transaction; SQL79:190-208 installs triggers on membership, direct scopes, group mappings, verified member groups, hierarchy, resource and machine/task sources. That catches existing repository statements and registered SQL0019 session resolution/deprovisioning without rewriting historical migrations. The source-column lists match the projection's dependencies.

Scoped permissions remain scoped. SQL79:142-149 joins active human membership to direct scopes and verified-group mappings, then `C/services/platform/authorization/projection_build.go:46-54` emits exact environment roles. I checked the apparent omission of `authorized_scopes.permissions`: canonical SQL0025's `zasp_effective_scope_permissions` deliberately returns the role matrix and ignores that argument. It isn't a newly broadened grant here.

Ancestry and machine identity checks are separate. SQL79:137-139 rejects conflicting or unresolved resource parents; the Go builder checks its own scope/resource inputs too. SQL79:93-102 derives agents from active product definitions and services from enabled schedules with active integrations/current verified connections. Task grants join the exact run/definition or schedule/sync identity and scope. P5's delegation key includes the task, target, principal, permission and scope, so simultaneous tasks don't share a revocation key. No Stytch machine membership is invented.

Delivery is recoverable. `C/services/platform/authorization/reconcile.go:49-59` stages before calling the writer and only acknowledges success. SQL79:154-177 keeps the union inventory, checks the current revision/generation/store/model and exact stage, then records the receipt and applied prefix atomically. The SDK writer pins store/model on every bounded request and deduplicates delete keys across conditions (`projection_openfga.go:38-65`). External calls occur after the SQL statements finish, while the dedicated session keeps organization serialization.

The fence fails closed. `C/services/platform/authorization/revision.go:38-58` checks pending/pins before Check and compares the full revision after it. `projection_postgres.go:164-175` binds the proof to the exact request, then SQL79:123-128 locks and checks the organization row in the caller's transaction. Current identity/session/PAT, tenant ownership and product policy remain explicit caller obligations. Correctly so.

The lock inversion is real, acknowledged and tested. The connected fixture executes registered membership-first SQL against an organization-first fenced transaction, rolls both attempts back, and repeats from a fresh Check with the same effect ID (`C/services/platform/apiserver/authorization_projection_conflict_test.go:42-95`). This does not establish a globally inversion-free lock order. P7 must carry the rollback/fresh-Check contract into its actual callers.

SQL79:209-221 limits runtime access to registered readers and the outbox worker; it doesn't give the API raw grant/configuration writes. Installation and configuration have separate authority checks. The commands provide bounded passes and repair without model publication, direct FGA-database writes or destructive reseeding.

## Findings

Critical: none found.

Important: none found.

### Minor: an explicitly selected organization loses its pending timestamp

Exact frozen location: [reconciliation command, line 92](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p6/candidate/services/platform/cmd/zasp-authorization-reconcile/main.go:92). The output consumes that value at line 118.

After loading pending rows, `-organization` replaces them with an ID-only `PendingProjection`. Its `PendingSince` is Go's zero time, and the JSON output prints `0001-01-01T00:00:00Z`, even for a genuinely pending organization. Operators can't read a useful pending age from the targeted repair command. Queue-wide mode retains the SQL timestamp, and authorization still reads a fresh snapshot, so this isn't a permission bypass or a local acceptance blocker.

Fix: load status for the selected organization, including rows outside the queue limit, or explicitly omit an unavailable timestamp. Add one command-output assertion covering `-organization`. This finding comes from the frozen source; no executable invocation is claimed.

## Evidence, and where it stops

`connected-final.txt` records the private-PostgreSQL/local-FGA application test passing with 11 durable receipts. The source matches its recorded checks: pending grants, SQL group replacement, generation/revision rejection, crash-before-ack recovery, immediate membership/session/PAT deprovision, independent machine tasks, activation/connection removal, cross-tenant denial, duplicate ancestry rejection, installation replay and the deadlock rollback/retry.

`application-final.txt` records the projection/revision/reconciliation tests and migration-dispatch test passing. The HTTP-edge delivery test fails a later SDK batch, leaves the organization unacknowledged, then repairs it with bounded calls. Initial failures and the corrected SQL fixture/race failures remain in `initial-red.txt` and `sql-and-race-red.txt`.

I reused those logs. No test rerun, provisioning, service reset, new store or vendor-internal test was needed for this review. My only write is this report.

The passing scoped vet excludes apiserver. `vet.txt` records the broader invocation failing on the unrelated `apiserver/security_agent_attack_lab_settlement_postgres_test.go:330:9` append-with-no-values issue; it isn't broad-suite green. Command evidence covers dispatch/registration tests and compilation/vet, not an end-to-end shell run using deployment configuration. Reconcile still uses the connector's Temporal readiness check. That dependency must stay visible in operational expectations.

Release is still pending. P7 has to wire API/worker/list/search/export/capability enforcement, fresh identity/PAT commit checks and explicit grant admission. Production model promotion, migration rollout, actual Stytch/provider evidence, deployment and scale/lock-contention acceptance remain open. The full-organization snapshot/delete-rewrite design can deny a busy organization while projection catches up; the local receipt count isn't a capacity result.

Accept the local P6 batch with the timestamp issue tracked. Keep the P7 and release gates open.
