# P3B-I: the owner-portable install boundary

Staged, not activated. P3B-I is ready for independent review; parent P3B and P3 remain open.

The controller approved this smaller dependency packet after inspection showed that executor grants would first require a new readiness authority. This packet implements the shipped install/readiness cutover only. It does not implement the lease-free executor, linked-test protocol, compensation, Temporal workflow or OpenFGA runtime fence.

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`. HEAD remained `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. Existing dirty dependencies were retained.

## What changed

`agentsec-migrate up-temporal-domain` now invokes the real registered wrapper and `Runner.UpProductionTemporalDomain`. The wrapper checks the configured migration login against `session_user` and its existing discovery-authority binding before DDL. It does not register or replace runtime principals. SQL installation, forwarding changes and final67 registration commit in one transaction, under the existing schema/evidence locks.

The supported predecessors are exact60, exact registered61 (with any installed62/65 validated), and exact registered66. A clean60 installation executes the unchanged61 candidate and promotion sources inside the new transaction, retaining their historical ledger/checksum metadata. It then installs the62/65/66 objects that are absent. Only62's installation-time predecessor guard is replaced with the new, already checked67 base guard; its complete persisted catalog must still match the original62 fingerprint before the forwarding change.

Existing62/65/66 installations must pass their old readiness before any rewrite. All three complete catalogs must match their compiled original fingerprints immediately before the new forwarding definitions are installed. This binds the copied source, owners and ACLs; arbitrary observed definitions are not accepted. The original62/65/66 readiness definitions and62 mutation definition, with owners and raw ACLs, are retained in an immutable67 evidence table. The new67 fingerprint binds those saved rows too.

On a clean `zasp_test` installation, historical61 readiness is still false and67 readiness is true. That is the explicit authority transition. No historical61 readiness function was replaced, no principal was renamed, and no observed61 hash was registered as a new historical pin. The retained `zasp_e2e` installation keeps its original61 readiness definition byte-for-byte as well.

## The readiness graph

Before cutover,66 readiness calls62 and65;62 calls historical61;65 calls either exact60 or62 according to its registration. This is the owner-specific dependency that blocked fresh installation.

After cutover, the62/65/66 readiness entries retain their existing checksum/fingerprint wire arguments, but forward to67's full registered boundary. That boundary checks:

- The complete historical61 catalog through a new portable fingerprint, plus the retained ledger, metadata and private predecessor checks.
- Exact scope-helper authority. Both `lock_scope` and `pricing_lock_scope` must be owned by the actual `zasp_authorized_scopes` owner, that owner must be a registered migration authority, and each ACL must contain exactly the two expected EXECUTE grants. Grantors must be that owner; grant options, PUBLIC grants, missing grants and extra grantees fail.
- Every67 function, schema, table, column, constraint, index, policy and trigger, the saved predecessor definitions, and the full post-transition62/65/66 catalogs.
- Original62/65/66 registration identities. The65 predecessor selection must match the value retained in immutable67 registration.
- Retired63/64 evidence and catalogs, including absence of restored worker EXECUTE rights.

Only the owner/ACL display identity of the two explicitly checked scope helpers is symbolic in the new base fingerprint. Their definitions, execution attributes and all other catalog identities remain bound. The old public61 fingerprint and readiness definitions are untouched.

The graph has no readiness cycle:67 calls catalog fingerprint functions, not62/65/66 readiness. `current_ready` is the single forwarding entry. The new `api_transition` is a private copy of the validated61 decision function;62 mutation calls it with the same domain request and old61 wire identity, while its readiness check goes through67. It retains the original current-membership, scope, version, approval and budget checks. No worker receives EXECUTE on this copy.

Portable base fingerprint: `b8b6e336ec72fa1b056c5e8a2f65cdd8275e9bbaee498ef1064d5f90133cf191`.

Registered67 fingerprint: `149a29373083b8d36130eefd97fb61ca6735ca279917c14260f825770fc506e2`.

Both fingerprints were compared across `zasp_test` and the exact registered `zasp_e2e` fixture. The pin was not used to excuse an owner/ACL mismatch: a failed cross-owner comparison exposed a quoting error in the new ACL identity replacement, which was traced with `pg_get_functiondef` and corrected before the successful comparison.

## Product behavior retained

The actual API repository still selects the66 manual/read/cancel facades; those facades now reach67 through their existing readiness call. Ordered API entry62 follows the same new boundary. Manual and ordered admission work on each tested installation, in the same database. Stale versions and deactivated requesters still fail; receipt replay and transaction rollback retain their prior behavior.

An existing Temporal-owned ordered run's65 command and66 ownership row survive the retained66 cutover byte-for-byte. The old worker selectors still cannot claim it. The immutable owner, lease backstops and API inability to activate routes remain. Test-only superusers configure a candidate route in disposable databases; the migration installs no route and grants no activation capability.

The decision test admits and plans a legacy run through the existing bounded local planner fixture before cutover, then uses the real public Go repository to approve and cancel after67. It checks the authorized step, cancellation result and three65 commands, including exact approval/cancel receipt identities and retained legacy ownership. It performs no policy deployment or linked-test send.

Optional63/64 installations retain their evidence and lose only the obsolete execution grants through66's existing retirement operation. Both already-retired66 and registered61 with live optional63/64 were tested. The existing refusal to install63/64 after66 remains. Removing62 or65 after67 now fails before either authority can be dropped, even with no product rows.

## Grouped RED, then GREEN

Commands below ran from `services/platform`. Superpowers grouped TDD and verification-before-completion guided this packet. Systematic debugging was used for the failed cross-owner comparison. SQL formatting/compilation mistakes and deliberately unset fingerprint pins are not counted as product RED evidence.

1. `go test ./agentsec-migrate -run '^TestTemporalDomainShippedCommandPostgres$' -count=1 -v`
   Initial RED: `owner-portable shipped command invalid release migration command`, package8.314s. The new command, wrapper and transaction were absent. A later regression assertion in this same group failed with `retained67 outbox authority was dropped`, package19.050s. The old65 down path gained an explicit67 retention guard.
2. `go test ./apiserver -run '^TestTemporalDomainUpgradePostgres/retire_optional_false$' -count=1 -v`
   Cross-owner RED during development: new base identity differed between owners despite valid ACL semantics. Diagnostic source showed that the owner expression had changed but the ACL expression had not. The SQL replacement needle had excess quote escaping. A dollar-quoted needle fixed it. The final test names are `registered66`, `registered66_optional`, `registered61_optional`, and `clean60`.
3. `go test ./apiserver -run '^TestTemporalDomainRetainedGuardsPostgres$' -count=1 -v`
   RED: `retained67 public authority was dropped`, package11.449s. The old62 down path gained the matching retention guard.
4. `go test ./agentsec-migrate -run '^TestTemporalDomainPrincipalBeforeDDLPostgres$' -count=1 -v`
   RED: `mismatched deployment principal reached domain DDL`, package10.861s. The wrapper now checks that binding before the transaction starts. Focused GREEN: package8.943s.
5. Final submitted-source command:
   `go test ./agentsec-migrate ./apiserver -run '^TestTemporalDomain(ShippedCommand|PrincipalBeforeDDL|Upgrade|RetainedGuards|Decision)Postgres$' -count=1 -v`
   GREEN, exit0: agentsec-migrate52.901s; apiserver123.487s. All cases passed. Output is retained in `p3bi-final-tests.log`; the shell used `set -o pipefail` while teeing it.

The final command covers fresh60 with and without a retained legacy60 outbox, real CLI execution, correct and mismatched deployment principals, real API/worker roles, migration replay, and failure injected into the final67 registration after all preceding DDL. That failure leaves exact60 ready and no partial61/62/66/67 installation; an existing65 installation is preserved.

Drift probes change a helper owner, PUBLIC execution grant, grant option, grantor, helper execution attribute,65 predecessor registration,62 fingerprint registration, private67 execution ACL,67 immutability trigger,66 ownership function attribute and65 readiness body. Each makes67 readiness false. The actual CLI also refuses the PUBLIC-grant drift and succeeds again after its removal. Runtime API/worker roles cannot mutate67 registration, invoke the private decision copy or activate a66 route.

The final public integration group also checks real manual admission/read/cancel, default ownership, owner and receipt rollback, scope/version/deactivation checks, immutable ownership, old-selector exclusion, old lease refusal and optional extension retirement across all four predecessor cases. The original passing P3A test was not rerun as a separate group; its product assertions were reused against the changed67 graph. No shared-memory production code changed, so no new race-test group was required.

These are disposable PostgreSQL and bounded local-fixture results. They are not deployed-provider evidence. Every disposable PostgreSQL process and the planning fixture process reported a normal join.

## Scope and self-review

Pre-edit bytes are in `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p3bi-baseline/`. The baseline contains the dirty platform bytes and linked Node runner bytes captured before this packet's edits. `p3bi-scoped.diff` compares against those bytes, not HEAD. `p3bi-hashes.json` records each before/after SHA-256, the report hash and scoped diff hash. `p3bi-capture-evidence.mjs` reproduces those artifacts and checks whitespace.

Ten source paths changed:

- `services/platform/agentsec-migrate/bootstrap_release.go`
- `services/platform/agentsec-migrate/main.go`
- `services/platform/agentsec-migrate/temporal_domain_test.go`
- `services/platform/apiserver/security_agent_temporal_domain_postgres_test.go`
- `services/platform/apiserver/security_agent_temporal_ownership_postgres_test.go`
- `services/platform/migrations/production_security_agent_public.go`
- `services/platform/migrations/production_temporal_domain.go`
- `services/platform/migrations/production_temporal_outbox.go`
- `services/platform/migrations/sql/0067_production_temporal_domain.base.sql`
- `services/platform/migrations/sql/0067_production_temporal_domain.up.sql`

Self-review checked the complete scoped diff, the readiness-call graph, exact source checks before copying, scope-helper privilege semantics, the private decision ACL, source/evidence immutability, old selector fences and migration removal paths. It found and fixed the two orphaning down paths and the pre-DDL principal-ordering issue. The evidence script confirms all148 historical SQL files through66 and the linked Node runner are unchanged. No dependency, runtime executor, provider adapter, UI, controller status ledger or deployment configuration was changed.

The scoped source diff SHA-256 is `f3b124152f6824b4443d667b697bd9ed96ee70dee58d9273e3d471d0519a3503`.

## Still closed

P3B's next packet must implement the real lease-free executor and compensation authority, stable effect identity, atomic budget/effect checks, unknown-outcome reconciliation, signing/readback/artifact checks, and the authenticated linked-test journal protocol in actual adapter and Node composition. This packet grants none of that authority.

P3C must supply deterministic Temporal workflows/Activities and the full API-to-worker-to-receipt path. P7 must supply the active OpenFGA model/revision fence. Independent review of this staged67 cutover, the remaining P3 implementation, deployed provider/cleanup acceptance and publication gates are still required. No commit, push, shared database operation or runtime activation occurred.

## Review fix1: bind permanent authority tables

The independent P3B-I review found one Important P2: the new67 table fingerprint omitted `pg_class.relpersistence`. Changing either `registration` or `predecessor_functions` to UNLOGGED preserved accepted readiness, despite changing the required durability of registration and predecessor evidence. This appendix records the fix; the original report, evidence and review remain preserved as the pre-fix record.

New67's table identity now includes `c.relpersistence`. The permanent table definitions stay unchanged. The registered67 fingerprint above is the original reviewed pin; the fix supersedes it with `3559e54be45e44575699fb6fad8f23edffe3e98a5b8228f2b2b96ae42057ae92`. Only this new67 pin was refreshed. The portable base pin and every historical SQL file through66 remain unchanged. The authority graph, ownership checks and grants did not change.

The grouped regression test uses a disposable PostgreSQL installation and probes both tables. Each subtest changes persistence inside a transaction and requires readiness to be false. It then commits the drift before running the actual CLI replay, so a lock timeout cannot masquerade as refusal. Cleanup restores LOGGED persistence and checks replay through the runner again. This tests our readiness policy, not PostgreSQL crash recovery.

Commands ran from `services/platform`, with `set -o pipefail` and output retained through `tee`:

1. RED before the production fix:
   `go test ./agentsec-migrate -run '^TestTemporalDomainPersistencePostgres$' -count=1 -v | tee ../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p3bi-fix1-red.log`
   Exit1, package15.430s. Both `registration` and `predecessor_functions` reported `readiness accepted unlogged` and `shipped domain CLI: <nil>`. Both halves of the review finding were reproduced.
2. Final GREEN after the SQL field and new67 pin changes:
   `go test ./agentsec-migrate ./apiserver -run '^TestTemporalDomain(ShippedCommand|PrincipalBeforeDDL|Persistence|Upgrade|RetainedGuards|Decision)Postgres$' -count=1 -v | tee ../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p3bi-fix1-green.log`
   Exit0: agentsec-migrate67.888s; apiserver132.905s. Both persistence cases passed, as did fresh installation with and without retained65, principal-before-DDL, retained guards, decision approval/cancel, and all four upgrade predecessors. The bounded planner and disposable PostgreSQL processes joined normally. This affected suite ran once after the final production changes.

A temporary diagnostic test derived the changed67 fingerprint inside the installation transaction; its source and output are retained as `p3bi-fix1-pin-probe.go.txt` and `p3bi-fix1-pin-probe.log`. It was removed before the final test command. Its passing result is pin-derivation evidence, not product acceptance evidence.

Pre-fix bytes are in `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p3bi-fix1-baseline/`. The fix-only artifact `p3bi-fix1-scoped.diff` contains three source changes and this report appendix; `p3bi-fix1-hashes.json` records before/after hashes, test-log hashes and the scoped diff hash. `p3bi-fix1-capture-evidence.mjs` checks whitespace, unchanged source outside those three paths, unchanged historical SQL, and preservation of the original diff/manifest/review. The source paths are:

- `services/platform/agentsec-migrate/temporal_domain_test.go`
- `services/platform/migrations/production_temporal_domain.go`
- `services/platform/migrations/sql/0067_production_temporal_domain.up.sql`

Fix self-review checked that both owned authority tables use the fingerprint branch, the CLI sees committed drift, restoring permanence restores readiness, and no historical pin or authority permission changed. Fix-only independent rereview is pending. Parent P3B/P3 and all later execution, deployment and activation gates remain open; no commit, push or runtime activation occurred.
