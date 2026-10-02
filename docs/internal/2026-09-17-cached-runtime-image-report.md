# Cached runtime image preparation

Status: implemented, locally verified and independently reviewed. No commit,
push, production promotion or scope reduction.

The mounted browser/runtime harness previously pulled all pinned images on every
preparation. It now inspects the exact digest locally, reuses arm64/amd64 images,
and pulls once only when Docker reports that exact image missing. A successful
pull still requires local inspection. Daemon/permission/unknown errors do not
become permission to download. Closing either owner during inspection prevents
later pulls; existing bounded ownership cleanup remains unchanged.

Scope: scripts/pinned-runtime-image.mjs and its tests, plus the existing
red-team-runtime-proof and runtime-pipeline-dependencies scripts/tests.

## Evidence

- Consumer RED3fc8e4: two cache-preparation tests failed because the first Docker
  command was pull, not local inspection. Missing-helper import RED was not used
  as behavioral proof.
- Focused GREENd9ff73: 30 tests pass, zero failures.
- Added consumer close-during-inspection regressions for engine and pipeline.
- Grouped e67a8e/c553dd: 96 tests, 94 pass, zero failures, two opt-in skips,
  3.612 seconds. Command: Node22 --test scripts/pinned-runtime-image.test.mjs
  scripts/red-team-runtime-proof.test.mjs scripts/runtime-pipeline-dependencies.test.mjs
  scripts/owned-browser-postgres.test.mjs scripts/production-combined-e2e.test.mjs.
  Skips are the real runtime-pipeline and Red Team container SIGTERM opt-ins.
- Actual Docker cache smoke e67a8e: both consumers prepared with exactly three
  image inspections; Promptfoo architecture arm64, pipeline preparation succeeds.
  The external command boundary refused every non-inspection command. No image
  download or container creation occurred. This covers cached Promptfoo,
  LocalStack and OpenSearch, not cold-registry availability or production behavior.

Full original lifecycle/mounted browser/release acceptance remains pending.
Availability counts remain 534 production / 133 component / 61 external.

## Review and final regression

Independent reviewer /root/cached_runtime_image_review found malformed Docker
references could reach inspection. Three explicit zero-command regressions
reproduced that issue (RED35ddca). The validator now uses a documented narrow
repository/tag/digest grammar for this harness; registry ports and IPv6 literals
are unsupported. Grouped rerun71219e/ab1d1e exits0. The reviewer reran all32
scoped tests and cleared the change with no remaining Critical/Important/Minor
findings. This review is scoped to the six cache-preparation files.
Scoped ESLint57ae3c/07e0f0 exits0; whitespace and authoritative ledger validation
ed001a pass all728 rows. No new runtime process or container remains from the
read-only smoke. Full container SIGTERM opt-ins were not run by this change.
