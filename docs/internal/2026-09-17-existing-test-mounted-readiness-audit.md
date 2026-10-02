# Existing-test mounted workflow readiness audit

Status: incomplete, component-only. No production promotion or browser proof.
Inspected candidate on ecc047ee2e90c36ec702ade129a2b08eae0a7a1a in the
budget-recovery-20260916 worktree. Existing uncommitted changes are preserved.

The public proof/UI batch is complete at its stated component boundary.
It does not make the user-facing create-to-execution path runnable. The next
action is lifecycle integration before browser acceptance, not merely launching
the browser against existing dispatch fixtures.

## Confirmed gaps

| Boundary | Current evidence | Required integration |
| --- | --- | --- |
| Catalog | securityagent/action_readiness.go keeps run_test/rerun_test component-only with autonomy none; workflow_handler.go filters templates/actions through production readiness. | A reviewed rollout capability must expose the complete executor without falsely relabeling local evidence as production evidence. Default production disablement remains until release gates pass. |
| Builder | securityagent/templates.go has no single-action test_run template. SecurityAgentsView.tsx Builder requires exactly one test action, test_run verification and matching catalog action. | Add usable run/rerun templates and their catalog path. Existing multi-action templates cannot be silently substituted. |
| Activation | security_agent_existing_test_lifecycle.sql rejects target_activation other than validated for existing tests, both fresh and replay paths. | Complete versioned activation with current binding, fresh-auth, controls and post-wait authority checks; preserve legacy-caller fences. |
| Reload | security_agent_repository.go GetSecurityAgentActivation accepts existing_test only when disabled and draft/validated. | Capability-aware validation of enabled supervised/autonomous definitions, with exact reference and schema authority. |
| Controls | security_agent_handler.go validators/mutation, repository, OpenAPI and browser decoder admit only older actions. SQL control detail/mutation remains the older implementation. Existing-test dispatch requires three enabled global/environment/action rows. | Connect test-specific control reads/writes through registered scoped authority, including browser decoding and stale-version/replay/fresh-auth refusal. Do not seed enabled controls behind the UI. |
| Trigger | RunSecurityAgent routes to run_v24, which delegates finding admission to older action-specific code and accepts session isolation only. Automatic scheduling delegates through older action-specific wrappers. | Add schema55 manual and automatic admission for supported existing-test trigger kinds, preserving bounded scheduling, exact evidence, tenant scope, replay, budget and concurrency. |
| Browser database | scripts/production-combined-e2e.mjs starts initdb/postgres/pg_ctl on the host. | Replace the owned database lifecycle with cached, loopback-only Docker before running this harness. Host SQL clients are acceptable; host server startup is not. |

The SQL activation and reload restrictions are deliberate intermediate fences.
Deleting those checks alone would leave creation, controls and trigger admission
broken. Direct fixture insertion of activated definitions, trigger receipts or
prepared runs would skip the public path and cannot satisfy original Batch D.

## Existing connections, not new completion claims

The production API mounts the Security Agent surface with its separate database
and schema capability probing. The security-agent worker already selects
schema55 dispatch. Actual linked execution uses red-team-outbox, red-team and the
adapter. The security-agent-test-reconciler reads stored artifacts and settles
the linked result. These paths have earlier bounded evidence in the public-proof
checkpoint; this audit did not rerun those tests.

deploy/staging/product/values.yaml still has testReconciler.enabled=false and
unset cloud authority. Paid planner policy, deployed queue/storage credentials,
provider canary, reference load and fresh approved advisory evidence remain
separate release/external gates. Controlled services cannot prove those gates.

## Batched execution decision

Ruling: integrate template/catalog, activation/readback, controls and trigger
admission as one public lifecycle batch, then run one grouped integration/UI
build/review gate. Focused RED/GREEN tests still protect each changed security
boundary. Cost if wrong: a larger batch takes more diagnosis when its shared
gate fails; exact per-boundary evidence must remain attributable.

Ruling: keep production disablement and existing private authority intact while
building the full public path. Any acceptance/rollout mechanism must be designed
explicitly, fail closed, and use the same production handler/worker contracts.
Do not add a fixture-only bypass or a global environment flag that silently
advertises an unavailable executor. Cost if wrong: rollout design needs rework
before browser acceptance, but no premature production enablement occurs.

The owned database prerequisite is separately bounded in
2026-09-17-owned-browser-postgres-brief.md and does not alter product readiness.

## Runtime support versus production certification

Follow-up independent review found an acceptance cycle: the current catalogs
require static production certification, but that certification requires a
browser flow which needs the catalogs. Resolve this through runtime protocol
support, not a test-only bypass.

Ruling: use the existing per-request compiled55 repository capability plus
existing durable execution controls for candidate acceptance. Keep static
ProductionActionReadiness and ledger certification unchanged. Catalog consumers
may discover supported test actions before enabling them; actual writes still
require the same scoped, audited, fresh-authenticated controls. Cost if wrong:
if candidate55 has already been deployed before acceptance, this alone cannot
prevent a tenant administrator enabling it. Do not deploy this candidate early.

Local evidence: security_agent_existing_tests_release.go is untracked and absent
from local main at 5acb3442c9d727116b5c1ff7eb7098814632db4f. This does not prove
remote or deployed absence. Confirm deployment state before any publication.
If pre-acceptance deployment becomes necessary, design a platform-owned
default-off DB rollout grant enforced through invocation, not an environment
flag. No such grant is needed for an unpublished owned local candidate.

Implementation interfaces for the lifecycle batch:

- Catalog helpers take a small capability value including existing-test
  protocol support, checked per request through
  SecurityAgentExistingTestDefinitionsAvailable(ctx). Include only the two
  exact test metadata entries and usable single-action templates. Catalog text
  must describe runtime availability, not claim production certification.
- Registered55 lifecycle permits enabled definitions only with exact test
  binding, current authority and controls. Keep legacy activation fences.
  Readback checks schema and saved identity, but must remain readable when a
  kill switch is off. Do not make historical reads depend on execution being on.
- Registered55 controls include run_test/rerun_test, absent rows disabled.
  Harness enablement uses the actual authenticated control API, not SQL seeds.
- Manual admission includes attack_path; automatic admission includes finding,
  attack_path and runtime_decision. UI already types manual attack_path, while
  current Go repository refuses it. Preserve bounded total scheduling and exact
  trigger/version deduplication across manual and automatic paths.
- Kill switches stop new work without disabling cancellation, reconciliation
  or history. No test-only planner/preparation bypass.

The combined runner currently migrates to48 by default, with run-context mode
reaching54. Original Batch D needs an explicit owned55 composition mode with
registered principals, exact pin assertion and real worker startup. Merely
changing its database lifecycle will not provide schema55 browser acceptance.

## Mounted composition preflight

Read-only checks during lifecycle implementation found the following reusable
pieces and limits. No services were started for this preflight.

- The pinned Promptfoo image is cached locally, arm64:
  ghcr.io/promptfoo/promptfoo:0.121.19@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96,
  image ID sha256:093c25ae2183c1ed3cc2e1df2b2576751f7a411337bf2caad2f3718962e7bb05.
- Pinned LocalStack4.7.0 is also cached, arm64:
  localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c,
  image ID sha256:ad4f76a02108f52479a33bbe0de40690d63ef51713971731f21f1de1e4eedb85.
- The initial preflight found unconditional pulls in both runtime preparation
  methods. This is now fixed and independently reviewed: exact cached digest
  inspection comes first, only confirmed missing images permit a bounded pull,
  and all three current images passed an inspection-only smoke. See
  2026-09-17-cached-runtime-image-report.md. For strictly offline acceptance,
  retain a command boundary that refuses pulls if a cache entry disappears.
- TestProductionCombinedE2ERedTeamRuntime uses the actual production processor,
  runner, engine, TLS adapter, outbox, queue and artifact authority with a
  controlled customer boundary. Its resolver is explicitly the old schema38
  resolver. It cannot establish linked55 execution unchanged. The new mounted
  path must use the persisted linked-versus-legacy routing and reconciler.
- TestSecurityAgentPlannerWorkerOwnedPostgres uses the actual planner/processor
  and controlled provider transport, but targets a temporary-policy definition
  with fixed older fixture IDs. Reuse the production constructors, not its
  acceptance claim. New publicly admitted test runs must supply the exact test
  reference and scoped evidence through actual planner authority.
- Production planner endpoint remains pinned to OpenRouter. A bounded test
  process may inject controlled transport through the existing constructor;
  changing production endpoint policy or bypassing the planner is unnecessary.
  Such a test proves local composition, never real provider pricing or canary.
- agentsec-migrate already supports up-to-55 and down-to-54. The combined runner
  supplies separate API, Security Agent worker, Red Team worker/outbox/adapter
  principals. Verify complete55 registration/pins before mounting consumers.

The next browser implementation must exercise actual API mutations from a real
browser and worker loops against this owned infrastructure. Do not reuse the
older run-context browser fixture's direct plan/receipt inserts as activation,
planning or trigger proof.

## Integration findings during implementation

Public activation test5e54cb passes for both test actions through registered55
SQL controls and draft -> validated -> supervised -> autonomous. It also checks
missing action controls refuse activation without durable state change. This is
focused SQL evidence, not completed HTTP/browser/release acceptance.

The preceding run dbf5f7 failed at an unnecessary owner UPDATE of the already-on
deployment-global control. Release18 seeds that row enabled; release27's generic
tenant recovery trigger rejects the wildcard scope ('*','*','*') because
zasp_recovery_scope_mutable requires Product IDs. The fixture now asserts the
existing global prerequisite and mutates tenant/action controls through public
authority. No guard was relaxed.

Important follow-up for whole-feature safety review: establish the supported
operator path for changing the platform-global kill switch on the current
release. The raw owner UPDATE is demonstrably rejected after recovery guards,
and release20 revokes the underlying setter from the tenant API. Older global
control tests run before those recovery guards and are insufficient proof for
the current release. Do not claim global stop/re-enable acceptance from the
new activation test or treat the fixture correction as a fix for that separate
operator-path question. Preserve tenant API refusal of global mutations.

## Evidence and limits

2026-09-17 operator-path follow-up (read-only, ad8572/b6ccfd): release27
scope-mutability rejects wildcard IDs before hold lookup, and installs its
generic trigger on both kill-switch and Security Agent audit tables. A control
row-only workaround would still fail when writing the wildcard audit row.
The legacy setter also checks registered Security Agent API principal readiness,
while release20 revokes its direct API EXECUTE grant. It is not an established
operator API merely because its name suggests a low-level control operation.
Scoped searches found no later replacement of that setter/recovery guard or
operator command in agentsec-migrate. This is supporting source evidence, not
a fresh SQL reproduction. The operator stop/re-enable acceptance gate stays
open; do not bypass either guard in the mounted fixture.

Read-only independent audit: /root/linked_browser_readiness_audit. Main inspected
the lifecycle rejection/replay, Go reload/run routing, template definitions,
Builder requirements, catalog filtering, HTTP controls, dispatch control
requirement and disabled reconciler configuration. No browser run, API mutation,
provider request, production activation, commit or push occurred for this audit.
Counts remain 534 production-available / 133 component-only / 61 externally
blocked across all 728 original rows. M7A-21 remains component-only.
