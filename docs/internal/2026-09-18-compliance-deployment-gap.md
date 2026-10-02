# Compliance56 deployment gap

Resolution checkpoint: the local deployment gap is now implemented and
independently accepted. See `compliance-deployment-20260918/report.md` and
`compliance-deployment-20260918/fix-1/independent-review.md`, plus accepted
registration and storage reports. Real rendered configuration and non-superuser
CLI-chain evidence support local acceptance. The diagnosis below is retained
as historical RED evidence, not the current code state. Terraform provider
evaluation, live cloud/secret provisioning, hosted CI and publication remain
open. No production promotion follows from this resolution.

September 18, 2026. This is a local launch blocker, separate from external
cloud/advisory gates. It was found by the connected M1A-04 queue verification
batch, not caused by the one-entry queue repair.

## Observed failure and cause

`staging-original-queue-20260918/affected-node.log` retains 81 passing checks and
one failure, `embedded migration release has explicit compatibility and forward
chart phases`. The assertion at `deploy/staging/gate.test.mjs:15` expects latest
migration55, but the current embedded migration is56.

The guard is detecting missing release support:

- `deploy/production/session-search-rollout.mjs:2` only permits48/49
  compatibility,50 backfill/query and51..55 precision-consumers/intake.
- `deploy/production/release-contract.mjs:74` rejects unsupported phases before
  rendering; its option allowlist has no compliance configuration.
- `deploy/staging/product/templates/_session-search.tpl:4` independently caps
  precision phases at55. The migration template invokes that validation.
- A scoped search of `deploy/` found no compliance configuration or
  `ZASP_COMPLIANCE_*` bindings. This search is supporting source evidence, not a
  rendered-manifest or infrastructure-plan proof.
- The real API loader in `services/platform/agentsec-api/compliance_config.go`
  requires either all five reader settings or none, rejects worker role
  credentials and keeps legacy behavior when absent. The worker loader in
  `services/platform/agentsec-worker/compliance_export_config.go` requires
  dedicated compliance-export/cleanup modes and forbids unrelated authorities.

The source mismatch is consistent with local compliance API/worker/browser
acceptance having been completed before deployment integration. It does not
invalidate those bounded local results, but they cannot prove the product can
be released through the current chart.

## Next connected deployment batch

Implement and verify an explicit56 rollout, dedicated compliance worker and
cleanup identities, API reader configuration, scoped database and object-store
authority, resource/network constraints and corresponding release validation.
First trace the existing accepted compliance runtime and migration registration
contracts and compare the existing audit-export deployment pattern. Preserve
legacy disabled operation and all earlier schema phase rejection/acceptance.
Do not simply change55 to56 in the failing assertion or enable a service without
its required isolated authority.

Local acceptance needs rendered resources and mutation rejection checks, actual
runtime configuration parsing, migration principal/readiness proof and the
connected affected release suite. Mocked/source checks must be labeled as such.
Real selected-account Terraform plans, hosted rollout, live storage/KMS and
production canaries remain separately gated; no credentials or cloud actions
are authorized by this diagnosis.

The binding implemented design is
`2026-09-18-compliance-production-design.md`, especially its durable artifact
protocol. Deployment must preserve its dedicated reader/writer/cleanup
authorities, immutable-version receipts, configured 24-hour retrieval period,
matching object lifecycle/retention, and exact-version cleanup after read leases
end. Provider uncertainty retains quota; denial alone does not prove deletion.
The runtime config loaders forbid sharing unrelated worker authorities.
Enabling schema56 without those bindings would only make the version gate green.
The existing audit-export rollout normalizer also only accepts52..55, so
compliance rollout must test coexistence with already deployed audit exports,
not silently disable that predecessor service.

Ruling: finish the frozen queue repair review, then address this release
integration before starting the new M7A-22 runtime action. It directly blocks
shipping already implemented compliance behavior. Cost if wrong: work-order
delay for the next action, with original scope unchanged.
