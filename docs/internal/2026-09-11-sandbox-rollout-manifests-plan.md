# Sandbox rollout manifests implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Follow the checkboxes in order, with independent review before publication.

**Goal:** Render and validate the three reviewed session-search deployment phases.

**Architecture:** Keep the original v1 resources. Add a target-specific v2 worker
and ordered initializer only on50; choose the API target by a closed phase enum.
Rendering is not authorization to apply a transition.

**Tech Stack:** Helm, Kubernetes YAML, Node22, existing release validator.

**Spec:** `docs/internal/2026-09-11-sandbox-rollout-design.md`

## Global constraints

Preserve all728 original tasks. No producer activation, canonical receipt edits,
checkpoint reset, new database authority or live apply in this manifest task.
Keep existing48/49 renders supported. Do not renumber the default chart solely
to clear the embedded50 gate. Actual transition authorization and fresh ingestion
remain required follow-on work, not completion inferred from rendering.

## 1. Phase-aware resources and validation

Modify `deploy/staging/product/values.yaml` and templates `migration.yaml`,
`runtime.yaml`, `workloads.yaml`, `projection-init.yaml`, `resilience.yaml` and
the monitoring template identified by its existing runtime-index list.
Modify `deploy/production/release-contract.mjs`; create
`deploy/production/session-search-rollout.test.mjs`.

Consumes existing `renderRelease(value, options)` and
`validateRenderedRelease(resources, account, schemaVersion)` interfaces.
Extend options with optional `sessionSearchPhase`; extend validation with the
same optional fourth argument. Missing phase defaults to `compatibility` only.
The allowed combinations are48/49 compatibility and50 backfill/query.

- [x] Add real render tests that fail on missing50 support:
  ```js
  const resources = await renderRelease(release, {
    schemaVersion: 50, sessionSearchPhase: "backfill",
  });
  const find = (kind, name) => resources.find(r => r.kind === kind && r.metadata.name === name);
  const env = name => Object.fromEntries(find("Deployment", name).spec.template.spec.containers[0].env.map(e => [e.name, e.value]));
  assert.equal(env("agentsec-api").ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v1");
  assert.equal(env("agentsec-runtime-index").ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v1");
  assert.equal(env("agentsec-runtime-session-index-v2").ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v2");
  ```
  Add query-phase API-v2 and compatibility-no-v2-resource assertions. Reject
  unknown phase,50 without phase and49/query. Run with Node22:
  `node --test deploy/production/session-search-rollout.test.mjs` and record RED.
- [x] Add a Helm helper for allowed combinations and a helper returning runtime
  deployment names. Reuse those names for services, PDB/HPA and monitoring.
  ```yaml
  runtime:
    sessionSearchPhase: compatibility
  ```
  Append a v2 worker descriptor only for backfill/query. It uses existing
  runtimeIndex service account/secret/role and runtime-index-v1 raw stage, but
  explicit v2 session target and its own selector/pod identity. Keep v1 explicit.
- [x] Add v2 initializer descriptor with distinct job name, existing initializer
  service account and hook weight-6; keep v1 at-7 and migration at-10. Pass the
  selected session index as `ZASP_RUNTIME_SESSION_INDEX`. Do not duplicate
  service-account or network-policy resources. API chooses v2 only in query.
- [x] Expand release validator's exact deployment/job sets by phase. Validate
  one literal target env per API/index worker/initializer; reject duplicate,
  absent, wrong or valueFrom entries. Enforce mode, database authority, raw stage,
  service account, bounded independent probes, selector and companion resources.
  Require both target workers in backfill/query and initializer order.
- [x] Add mutation tests on rendered resources: remove the v2 deployment, point
  it at v1, change its database authority, remove v2 network/monitor coverage,
  reorder initializer hooks, or select API-v2 during backfill. Every mutation
  must make `validateRenderedRelease(resources, account,50,"backfill")` throw.
  Retain exact schema command checks and unchanged48/49 acceptance.
- [x] Wire the new test into `production:release:test` and the release gate's
  test invocation. Run the focused suite, full release suite, workflow contract,
  typecheck, lint, UI build and ledger validation. Record any existing full
  release failure honestly; do not claim deployment or original task completion.
- [x] Request independent review, resolve findings and inspect the final diff.
  Commit/publish only after the whole rollout's required gates pass, including
  live-state transition enforcement and composed product acceptance.

## Follow-on boundary

Local task reviewed September11. Final release suite46/46 passed in
`/tmp/zasp-rollout-init-hooks-green.log`. Full UI suite1238/197, UI build,
typecheck, lint and ledger validation passed. Independent review approved the
bounded manifest task after negative controls caught missing reachability and
hook-type checks. Publication remains pending the gates below; these checked
steps do not claim original microtask or deployment completion.

The reviewed design also requires actual pod/config identity observations and
single-use,30-second database/provider receipt coverage evidence. Those are not
implemented by Helm values or this render validator. Keep deployment unapproved
until that transition mechanism has its own implementation and negative tests.
Fresh producer activation, ingestion/recovery and browser acceptance remain in
the existing session-search plan and authoritative ledger.
