# Compatibility deployment observation

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development; request independent review.

**Goal:** Capture and revalidate deployment identity before the schema50 hook.
**Architecture:** A read-only collector gets Namespace, Deployment, ReplicaSet
and Pod documents using an explicit kubeconfig/context. A separate evaluator
requires intended admitted pod-template digests and container image identities.
The result is evidence, never a reusable authorization token.
**Tech Stack:** Node22, kubectl JSON, Kubernetes apps/v1 and core/v1.
**Spec:** `2026-09-11-sandbox-rollout-design.md`, transition evidence section.

The prior turn completed reviewed manifests, not a running rollout. Preserve all
728 tasks. No deployment mutation, secret reads, producer activation or task
credit in this task. User has authorized autonomous implementation decisions.

## Task 1: Read-only compatibility identity

Files: create `deploy/production/compatibility-observation.mjs` and matching
`.test.mjs`; wire the test into the existing release suite and gate.
Export `observeCompatibility({ kubeconfig, context, namespace, namespaceUID,
expected }, { run, now } = {})`. Each expected entry contains `name`,
`templateDigest` (SHA256 of the admitted template), and `imageIDs` keyed by
container name, including successful completed init containers. Ephemeral
containers are not accepted. Require the complete API/runtime consumer set, not a caller
selected subset. Expose `templateDigest(template)` for release artifact tooling.
Export `revalidateCompatibility(previous, options, dependencies)` to read again
and reject changed identity or evidence older than30seconds.

- [x] Add tests using Kubernetes-shaped controlled command responses, verifying
  emitted evidence and rejection of stale generations, old replicas, non-ready
  pods, owner substitution, config/image drift, wrong namespaceUID and expiry.
  Example: set `deployment.status.observedGeneration = 1` for generation2 and
  require `assert.rejects(observeCompatibility(options, dependencies))`.
- [x] Run `node --test deploy/production/compatibility-observation.test.mjs`
  and confirm RED before implementation.
- [x] Collect explicit context/namespace JSON with bounded child processes.
  Validate full Deployment -> ReplicaSet -> Pod ownership chains, current
  generation, complete replica readiness and schema49 template annotation.
  Hash exact admitted templates and compare intended digests. Validate every
  running container's resolved imageID and readiness. Bind namespaceUID,
  Deployment UID/generation, template digest, ReplicaSet UID and Pod UIDs/images.
- [x] Re-read identities before any later caller can use them. Reject expiry,
  changed pod/config/deployment identity and malformed or incomplete responses.
- [x] Run focused and full release tests, lint, ledger validation and independent
  review. Record controlled-provider limitations. Commit/publication still waits
  for the whole rollout's gates.

## Required integration, still open

Parent implementation used manual TDD because collector/evaluator/revalidation
are one coupled task. Empty-stub RED failed15 tests; initial implementation
passed15. Independent review found extra Pod privilege fields and unchecked
labels/annotations. Expanded RED failed8 of24 cases. Corrected collector rejects
extra spec fields except nodeName, checks all intended metadata, and includes
init image/status evidence. Full release suite passed70/70 in
`/tmp/zasp-compatibility-final.log`. Independent Superpowers scoped review
approved this local observer checkpoint. Fresh UI build and1238 tests across197
files passed; lint, ledger validation and diff checks passed.
Tests use controlled kubectl responses, including rendered chart templates;
they do not prove live Kubernetes defaulting, admission, credentials or RBAC.

The release orchestrator must produce intended admitted-template digests from
the exact compatible release with Kubernetes defaulting applied, verify its
image provenance, and pin the kubeconfig's server/CA identity. It must call this
collector immediately before the guarded migration. This observer does not
establish database49 readiness or prevent a concurrent rollout after its final
read. The mutation path needs serialization and database readiness checks.
Query authorization still requires the canonical receipt-set/provider proof,
manifest binding, expiry and single-use enforcement in the existing design.
Fresh ingestion/recovery and browser acceptance remain required.
