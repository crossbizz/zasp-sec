# Task3 UI contract handoff

Source inspection only, while Task2 implements settlement. No browser or UI
tests ran for this note. These are pending Task3 integration points, not new
Task1 review findings or evidence of completed product behavior.

- `app/features/securityagents/SecurityAgentsView.tsx`: template creation
  needsTest/testSupported currently recognizes only run_test/rerun_test with
  test_run (around265). Include the exact Attack Lab pair using real catalog
  availability, not an unconditional local option. Existing execution-control
  types and validation also enumerate only the currently supported actions.
- `apps/web/api/decoders.ts`: definition decoding around1045 rejects explicit
  existing_test with start_attack_lab. Approval-to-step effect validation around
  569 and action-detail decoding around582 also enumerate the old actions.
  Update strict contracts together; do not relax unknown-field rejection.
- `app/features/securityagents/ApprovalContext.tsx`: currently displays action,
  agent, target, requester, run, expiry, risk and rationale. It does not yet
  display the frozen Attack Lab source/attempt or bounded side effects. Add the
  approved redacted contract, never private artifact/credential references.
- `app/features/securityagents/ActionDetails.tsx`: currently renders existing
  test evidence. Task3 must consume Task2's exact execution/evidence/cleanup
  projection and human-interpretation outcome, including stopped-parent reloads.

Focused test homes already exist: SecurityAgentsView.test.tsx,
decoders.security-agent-approval-context.test.ts,
decoders.security-agent-actions.test.ts and
decoders.security-agent-test-proof.test.ts. Extend the appropriate existing
coverage with literal new payloads and legacy controls in one contract/UI batch.
Generated types must come from the repository's OpenAPI generation workflow.
The composed browser path must still join real API/registered database/worker/
reconciler behavior; passing decoder fixtures alone cannot enable the catalog
or establish live provider acceptance.

## Backend read contract required before UI acceptance

Follow-up source inspection found the public read path needs work too:

- `services/platform/apiserver/security_agent_repository.go:349` routes
  GetSecurityAgentRun through the versioned run-context envelope. Task3 must
  extend that actual registered read path, including its closed decoder.
- `security_agent_action_projection.go:26` has ExistingTest but no Attack Lab
  detail field. Its raw step decoder accepts only the base shape or base plus
  existing_test. Adding frontend types alone cannot expose linked evidence.
- `security_agent_action_validation.go:11` validates the existing public
  projection, including effect/rollback consistency. Extend it with the new
  bounded evidence shape and contradiction tests; do not bypass validation.
- Current release57 links fragment extends run-context action/arguments and
  approval snapshots. That change does not project the linked execution,
  immutable settlement evidence or cleanup obligations into action details.

Task3 should add a redacted, full-scope public projection through the existing
API authority and additive unpublished57 SQL. The dedicated reconciler's
private evidence endpoint and database role must not become browser access.
Preserve published1..56 bytes, update57 pins and rollback coverage when SQL
changes, and test pending, Needs human, Inconclusive and stopped-parent cleanup
reads through the mounted API. This is pending work, not an accepted defect fix
or permission to enable the catalog before the connected consumer works.

## Readiness and generation checks for Task3

The current SecurityAgentAttackLabAvailable repository method explicitly proves
installed admission only. It checks registered compiled release readiness, not
a running settlement worker or connected deployment. Do not use that boolean
alone as production catalog readiness. The create/update handler currently uses
it to admit the exact definition shape, which is a separate contract.

The current approval SQL returns the stored attack_lab snapshot. Its private
source_evidence includes key/version/checksum/size/reference. Task3 must trace
the mounted public response and expose only the selected redacted user contract;
do not send the private snapshot directly to the browser merely because its
JSON shape already exists. The reconciler keeps the full private identity.

Use package.json's openapi:generate command for generated.ts, then openapi:check
and focused contract tests. The Task3 brief has been extracted under this plan's
.superpowers/sdd directory; implementation waits for Task2's startup fix review.

## Existing acceptance harness boundaries

scripts/existing-test-mounted-browser.mjs already covers real UI selection,
definition creation, activation, simulation, tenant-bound reads and separate
approval identity through an injected browser/control harness. Reuse its
structure, but retain Attack Lab's mandatory approval in both autonomy modes
and its Needs human outcomes. Its autonomous existing-test cases intentionally
have different semantics and are not the new action's acceptance criteria.

services/platform/agentsec-api/existing_test_composition_test.go mounts real
middleware/handler/repository around a controlled QueryJSON database. That is
useful composition coverage, not registered PostgreSQL proof. Task3 needs the
actual database-backed mounted flow separately. The compliance browser process
test shows a test-only bounded SDK transport with real runtime composition;
use that separation pattern if needed, without treating its fixture as a live
provider or seeding the new action's plans, approvals, links or settlement.

## Concrete runtime entrypoints and isolation constraint

- agentsec-worker/production_combined_e2e_test.go:240 composes the registered
  planner runtime in TestMountedExistingTestPlannerWorker and runs Ready plus
  Processor.RunOnce. Its controlled planner adapter can supply the exact new
  candidate without inserting a plan directly.
- agentsec-worker/security_agent_attack_lab_runtime_test.go:32 starts from an
  existing durable link and composes registered outbox/controller/proxy, the
  production Kubernetes transport, signed runner, controlled canary/artifact
  boundaries and actual link reconciler. Reuse this stronger runtime coverage;
  the older combinedE2EAttackLabProvider alone is insufficient for that boundary.
  Its owner-driven lease/backoff shortcuts are fixture mechanics, not browser
  restart proof. Keep those distinctions explicit.
- agentsec-api/audit_export_browser_process_test.go:34 shows real database
  runtime composition plus bounded serveRuntime lifecycle. The compliance
  equivalent shows a controlled storage factory with real application mounting.

The old createOwnedBrowserPostgres helper publishes a host loopback database
port and does not select --network none. It cannot be used unchanged under
this plan's stricter container-isolation constraint. A bounded owned stream
relay through docker exec can carry raw PG wire from a host loopback listener
to container loopback without exposing a container port or giving the container
network access. This is an implementation option, not existing tested support.
If used, enforce exact owned container identity, fixed destination, time bounds,
stream shutdown and joined children; keep real pgx/registered SQL end to end.

## API process factory audit

production_runtime.go's buildRuntimeDependenciesWithStorage opens both real
pgx pools, creates the repository-backed identity provider and owns pool closure
and metrics. Keep this path for browser acceptance. The new readiness constructor
inside composeRuntimeDependenciesWithTelemetry currently receives nil transport;
an internal factory/transport parameter can supply the controlled browser
boundary while production wrappers retain the default. Avoid a global transport
override or an environment-provided arbitrary destination.

combinedAPIEnvironment already uses test mode and local identity/policy-history
servers. Policy-history construction uses static credentials only in test mode;
its readiness still exercises the local endpoint. Stytch Ready is structural,
while login uses the actual local adapter. Nil audit/compliance configuration
avoids invoking their storage factories. Connector secrets use lazy credentials,
but connector and approval-notification lifecycle workers can still invoke
providers if seeded work activates them. Do not seed external OAuth/notification
work; use a bounded fail-closed test transport or observed zero-call assertions
for unintended provider paths. Merely constructing clients is not proof that
the entire process cannot make external requests.
# Connected source-run acceptance notes

Read-only harness assistance, September19. The controlled source runner must
emit the actual strict evidence contract, not free-form success text.
For one failing prompt_injection check, red_team_runner.go requires behavior
`0 of 1 curated security checks passed; 1 exposed unsafe behavior.` and evidence
`prompt_injection: unsafe behavior observed`. The initial browser-process
scaffold used different strings; those would be rejected before source
eligibility. This is a harness correction, not permission to loosen validation.

The schema follows redTeamEvidenceVersion(input). Basic v1 native output uses
the matching redacted provider/category/prompt/grading fields. A v2 input also
requires the expected evaluation identity, linked assertion, observation,
credential-version digest and target comparison. Do not downgrade a v2 input.

SQL57 zasp_sa_attack_lab_source selects an enabled exact-version definition and
a complete/fail source run with its matching completed fail attempt, input
digest and full evidence tuple. Evidence checksum must be nonzero32bytes,
size positive and version nonempty. The actual source worker must produce
these records. Safety also requires the matching nonproduction environment,
active fresh target, matching active/unexpired credential binding and an
unexpired preflight. No owner-written source run may substitute for this flow.
