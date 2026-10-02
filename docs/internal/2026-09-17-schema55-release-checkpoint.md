# Schema55 release integration, in progress

Scope: finish the existing-test reconciler release path without enabling an
incomplete deployment. This is part of M7A-21, not an availability promotion.
The original728 scope and feature-batch shipping policy are unchanged.

## Private monitoring and availability alerts

The opt-in worker now has a ClusterIP-only metrics service, a ServiceMonitor,
and availability/readiness rules. Unready endpoints remain published for scraping;
only the monitoring namespace receives TCP8081 ingress. Existing egress rules
are unchanged. Chart monitoring-off removes scrape resources and closes ingress;
the production release validator requires monitoring on for reconciler opt-in.
Exact validation rejects public service types, widened selectors/ports, missing
resources, label overrides and modified alerts.

RED70cb7e reproduced missing monitoring resources. Grouped chart checks4d2034
passed13/13. Final full release regression090ee4 passes222/222, zero skipped,
28.225s. Prometheus3.14.0 was fetched from its official release; Darwin-arm64
archive SHA256a9623f7f4fe65b1b171b423c1a72bbf23dfdf41a171dcb33e7dd302af80dc01c
matches the published checksum. Actual rule evaluation3f5fda passes the three
grouped alert suites, zero skipped,1.416s. The new suite exercises seven cases:
healthy, readiness0, scrape failure, missing per-replica metric, absent targets,
zero available replicas and absent deployment, including holdoff and recovery
for every failure case. No live scrape or alert delivery is claimed.

Independent review found no Critical/Important issues; its minor missing-recovery
coverage was added and evaluated. CI now runs this rule suite with its existing
checksum-pinned Linux Prometheus tool. Workflow contract05c206 exposed stale
expected commands for the earlier IAM filter and new alert suite; only those two
expectations were corrected. See the operational candidate guidance in
docs/operations/observability-and-canaries.md.

Final CI contract2dc98d passes250/250. Independent follow-up finds no new
actionable issues in recovery coverage, CI expectations or runbook guidance.
Ledgeraeb8ba remains534/133/61 across728 rows, zero missing. All test/download
sessions are terminal; no fresh UI build or full push-candidate clearance claimed.

Registered multi-tenant restart/reclaim, settlement-progress telemetry, load,
actual ServiceMonitor discovery, notification delivery, CNI/cloud permissions
and all existing exact-candidate shipping gates remain open. Monitoring manifests
and controlled Prometheus inputs do not establish deployed production readiness.
M7A-21 remains component-only/disabled by default; no commit, push or promotion.

## Full reconciler render and authority validation

The release renderer now accepts an explicit testReconciler configuration only
at schema55 in either precision phase. It snapshots authority before asynchronous
Helm work, passes the closed configuration through a private temporary values
file, and validates the composed chart. Audit exports can be enabled separately;
omission still leaves the reconciler disabled.

Validation covers the dedicated service account and database CSI object, exact
worker image shared with the security-agent deployment, command/environment,
read-only credential/token mounts, STS audience, pod hardening, health/readiness,
shutdown grace, rollout/spread, PDB and bounded HPA. Duplicate/missing resources,
sidecars, extra credentials, additional authority and selecting network policies
are rejected. These are rendered-manifest checks, not live admission guarantees.

REDc0f0e5 reproduced the missing renderer option. Initial grouped testsb2d18a
passed11/11; full release regression3137df passed219/219, zero skipped,27.948s.
Independent review then found an indirect RBAC gap: a group binding could grant
permissions without naming the worker. RED3c5da4 reproduced it. The validator now
rejects RoleBinding and ClusterRoleBinding subjects granting any of the three
groups covering the worker, even when a RoleBinding targets another namespace.
Other-namespace service-account groups remain accepted. Corrected grouped checks
66418e pass12/12, zero skipped,3.495s; independent re-review reports no remaining
actionable findings in this correction.

Final post-correction `npm run production:release:test` c6a5c8 passes220/220,
zero failed/skipped,26.909s; session65264 is terminal. No UI source changed in
this bounded integration batch; a fresh UI build/smoke is still required for
the eventual exact push candidate.

No deployment was enabled or applied. Monitoring, registered multi-tenant process
restart/reclaim, load characterization, actual cloud permissions/CNI, advisory
evidence and exact-candidate shipping gates remain open. Ledgera839db validates
728 rows:534 production-available,133 component-only,61 external,0 missing.
M7A-21 stays component-only/disabled. No commit, push or availability promotion.

## Rendered network authority guard

Added validateTestReconcilerNetwork. It checks the actual rendered labels,
default-deny policy and exact database5432/cloud443/kube-dns53 dependency rules.
Every other same-namespace policy is evaluated for whether it selects this pod;
an additional selecting policy is rejected regardless of its name. Label and
In/NotIn/Exists/DoesNotExist expression semantics are covered, including absent
labels and malformed expressions. This prevents additive policies from silently
broadening the named worker policy.

The behavioral test composes the real schema55 shared chart with the actual
isolated reconciler template. It tests19 mutations across dependency rules,
labels, duplicate/missing policies, default deny, shared DNS and unrelated-looking
additive policies. An unrelated workload's policy remains accepted. REDa3abdd
demonstrates the missing guard. Grouped config/chart tests74affd pass9/9, zero
skipped,3.020s. Independent review reports no Critical/Important findings and
also retracts the prior JavaScript-newline concern based on reproduced evidence.

This guard is not connected to release activation yet. Full pod/credential,
identity/scaling validation and renderer wiring are still required before opt-in
activation. Live CNI enforcement is unproven. No commit, push or promotion;
all sessions terminal and ledgerd1ef6b remains534/133/61 with zero missing.

## Reconciler configuration boundary, not activated

Added normalizeTestReconciler plus an independent release fixture and tests.
It accepts only a closed plain data object, explicit enabled=true, schema55 and
a precision phase. Account/region bindings cover the role, database secret and
evidence key. All four endpoint arrays use the existing canonical bounded CIDR
validator. Object and array accessors are rejected without invocation. A
synchronous deep copy prevents later caller mutation of validated authority.

RED91b41d demonstrated missing validation and input aliasing; GREENe1dfac
passed. Grouped normalizer/shared-network checks69c555 passed7/7, zero skipped,
0.837s; session31577 terminal. The canonical release-test command includes the
new test file, but the full release suite was not rerun for this isolated helper.
Run it after renderer/resource-validator integration, following batch policy.

Independent review found no Critical/Important issues. Its minor terminal-newline
claim did not reproduce: actual normalization rejects those inputs (fa8e22), and
Node22 no-multiline anchors reject LF/CR/CRLF/U2028/U2029 (e468f1). Added the
regression case; no speculative matcher change. Review feedback was returned
with that evidence.

The helper is deliberately not connected to release activation yet. Next work
must validate the complete rendered workload, credential mounts, scaling and
all additive network policies before wiring the explicit release option.
No commit, push, activation or ledger category change.

## Full-chart schema compatibility

Schema55 now renders through the production release renderer in both explicit
precision phases, with audit exports independently enabled or disabled. Default
schema49 remains unchanged; omitted/incompatible55 phases and future56 are
rejected. Reconciler activation remains disabled and is not yet accepted as a
release option.

Four real Helm comparisons against54 assert identical resource graphs except
the migration target, API expected schema and deployment schema annotations.
Validator mutations reject stale migration commands, API versions and runtime
coordinator annotations. Audit-export registration/configuration remains in the
same migration-hook sequence when exports are enabled. This is rendered artifact
compatibility, not deployed workload compatibility or live activation proof.

RED893142: four schema55 renders rejected. GREEN764213: all four pass. Full
regression444f32 initially211/212 because an older budget test still designated55
as future; focused97afea reproduced the outdated expected rejection. That test
now rejects56. Final `npm run production:release:test` a78198 passes212/212,
zero skipped,27.607s. Independent review found no Critical/Important findings.
All sessions terminal; no commit, push, deployment or availability promotion.

Next: closed reconciler release configuration and full-resource validation,
including additive network policies, explicit worker identity and immutable
input snapshots. Operational monitoring, process/reclaim and live gates remain.

## Fresh bootstrap correction

The direct empty-database bootstrap gap is now fixed. The executable wraps only
the51→52 transition: compiled51 readiness is checked before any registration,
principal registration and51 readiness finish before audit-export DDL, then the
existing migration validates again under its transaction/locks. Commands staying
at51 or below and commands starting above51 do not use this bootstrap barrier.
This does not promise atomic rollback of registration if a later step fails.

Component RED18fc28 proved the missing barrier and progression after failure.
Tests now cover all18 query failure positions (false and error), exact precheck
pins, preservation of historical/later paths, and registration completion at the
instant the underlying audit migration is entered. Independent review found no
Critical/Important findings; its minor interleaving-test gap was addressed.

Owned executable acceptance e6e202 passes6.72s: one `up-to-55` invocation from an
empty disposable PostgreSQL reaches55, followed by replay, historical refusal,
drift refusal, rollback54 and reupgrade. No operator predecessor command is used.
Executable /private/tmp/zasp-schema55-cli-20260917-r4, test executable
/private/tmp/zasp-schema55-cli-tests-20260917-r10. These are offline Linux/arm64
builds in the same pinned read-only/network-isolated container. The fixture uses
its owned superuser and does not prove least-privilege deployment credentials.

No SQL identity/pin changes in this correction. Fullschema55 rendering,
operational monitoring, multi-scope process/reclaim and live release evidence
remain open. No commit, push or production-availability promotion.

## Latest verified state: registered upgrade repaired

The schema53→54 refusal below is resolved. Fresh constituent comparison
0d774a/7962f8 isolated the difference to the private lock_env function's owner
and ACL. Its owner intentionally follows the environment-table owner, which is
the registered migration login (zasp_e2e in the API fixture, zasp_test in CLI).
Raw login spelling was included in the fingerprint. Prior hash, schema, every
index and every other function were identical. Index ownership was investigated
and ruled out; no index ownership change was made.

The exact lock_env owner/ACL now use existing registered-owner normalization.
Normalization requires the environment-table owner, registered migration binding
and intact source/workflow ACLs. Other identities remain literal. Independent
source review found no Critical/Important findings. New real database cases
altering helper ownership and granting API EXECUTE still reject readiness.
Temporary transactional diagnostics were removed after isolation.

Owned calibration f53fb2 established54 fingerprint
9fb3045069cc65a134e1c37dddd9f3c8871a8abc253840b458f511816660bceb.
Dependent55 calibration cd052f established
b05ba68ba560ebb1f69ddc25426d0a11d22b86be93bbcb463fe384cd3a64984c.
These unpublished candidate pins were updated only after the source defect was
understood. Fresh grouped database run78246 passed both compiled fingerprints
and both release/rollback suites (5.07s,12.03s,4.18s,4.57s; final1c3dac).

Actual CLI acceptance612853 passed6.97s, using compiled executable
/private/tmp/zasp-schema55-cli-20260917-r3 and test binary
/private/tmp/zasp-schema55-cli-tests-20260917-r9. This verifies registered51
bootstrap, upgrade54→55, replay55, historical refusal, metadata-drift refusal,
empty rollback54, no-op rollback and reupgrade55. An earlier test-only failure
18d028 assumed every refusal was a migration error; it now accepts the separate
fixed principal-registration/readiness error too. No database behavior changed
for that assertion correction.

Grouped CLI race2cc5ff passed2.005s. Full migrations/worker race63205f/d38016
passed6.936s/41.617s. All handles terminal. No skipped tests in the explicitly
selected owned database runs. No commit, push, live deployment or promotion.

Still open: direct empty-database bootstrap across51→52, fullschema55 renderer,
operational monitoring, multi-scope process/reclaim and live rollout evidence.
The registered upgrade proof does not establish least-privilege production
migration credentials, retained-link rollback or a fresh production install.
Historical failures below remain as investigation evidence, superseded only
where this section supplies passing evidence.

## CLI dispatch evidence

The existing schema55 migration runner was unreachable from the release CLI.
The explicit `up-to-55` command now traverses predecessors through54 and calls
that runner; `down-to-54` invokes its guarded rollback. Default `up` remains49.
Historical commands cannot cross55, and future commands remain refused.
The forward command enters the existing principal-registration path.

Superpowers RED: command tests failed with invalid release migration command
(tool output ed4923). GREEN: focused tests passed358ce2. Independent source
review found no Critical/Important dispatch issues; its minor order/no-op
coverage gap was addressed. Final grouped race run e675fd passed1.789s,
including existing-test, audit-export, precision, sandbox, run-context,
historical target, drift/deadline and principal-registration command tests.
These tests exercise real CLI dispatch with a scripted migration boundary.
They do not prove PostgreSQL migration execution or a deployed binary.

Files: agentsec-migrate/main.go and existing_tests_command_test.go, plus four
historical unsupported-command assertions advanced from55 to56. All paths are
under services/platform. No SQL/checksum/fingerprint change in this step.

## Remaining work in this feature batch

- Schema55 post-registration readiness is implemented in registerForwardRelease,
  which also preserves the51..54 checks extracted from main. Component RED
  ede9b4 proves missing final readiness is caught. Grouped race ca4020 passes
  1.959s, including all17 false/error failure positions, exact pins and canceled
  contexts. Independent review reports no Critical/Important findings.
- Owned binary/PostgreSQL acceptance is **failing**, not completed. New
  existing_tests_binary_postgres_test.go runs a mounted compiled CLI against
  disposable PostgreSQL, with upgrade/replay/drift/rollback assertions.
  Direct empty-to54 failed at51 (8cd22b): audit exports requires registered
  migration-owner binding, but the CLI registers only after the entire chain.
  Bootstrapping through explicit51 registers those principals, then attempting54
  reaches53 and fails there (4350e5). Transactional diagnostics053a54 establish
  the53 predecessor readiness is true with exact compiled fingerprint
  10ac4fb7b3212c5b89164911070c184e5aa3525cb29aacbb526bf5e183e20eb5.
  Schema54 SQL executes in a rolled-back diagnostic transaction, producing live
  fingerprint14493f6e907f6b593642deb93e4d12f24df69b80d75d272c5531d7365bff6e7c.
  Root cause of this second refusal is not yet established. Compare registered
  CLI and existing apiserver fixture identities before changing any release pin.
  Do not weaken readiness or report schema55 binary acceptance as passing.
- Extend the closed release normalizer and rendered-resource validator to
  support explicit reconciler configuration. Preserve default-disabled behavior.
- Admit55 in session-search and audit-export compatibility only with full
  composed rendering and migration-hook tests. Existing guards still reject55.
- Complete operational monitoring and registered multi-scope process
  restart/reclaim acceptance. Keep live deployment, provider permissions and
  load proof separate from local component evidence.
- Run UI/build/smoke and required release gates on the exact push candidate.

All command sessions terminal. No commit or push. Ledger check1b798b remains
534 production-available /133 component-only /61 external /0 missing.
Main ledger categories are unchanged; this checkpoint is evidence of partial
release integration, not completion of the reconciler or the full feature batch.

Owned binary handles: build52801 and test-build33386/37912/91399 are terminal.
Docker35466/32425/63593/7036 terminated with failed acceptance; --rm disposable
containers, isolated network, read-only root and tmpfs PostgreSQL only. No host
PostgreSQL or cloud activity. Executable /private/tmp/zasp-schema55-cli-20260917-r1;
latest diagnostic test executable /private/tmp/zasp-schema55-cli-tests-20260917-r4.
Test review confirms its limited upgrade scope, not least-privilege production
migration credentials or retained-link rollback. Source diagnostics remain to
support the next investigation; binary acceptance currently fails before55.
