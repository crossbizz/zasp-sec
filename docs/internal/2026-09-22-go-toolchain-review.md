# SPEC: compliant. QUALITY: approved for this repair.

Reviewed on 2026-09-22 using the Superpowers requesting-code-review/task-reviewer workflow. This is the 11-path dirty-overlay repair in `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/toolchain-scoped.diff`, not a HEAD-wide review or release approval.

## The pins agree

CI selects Go 1.25.13 at `.github/workflows/runnable-ui.yml:27` and still checks the exact GOVERSION at line 123. The subprocess gate accepts only `go1.25.13` with LF or CRLF at `deploy/production/go-test-runtime.mjs:14`. No relaxed comparison.

Each builder now uses `golang:1.25.13-alpine3.23@sha256:42fc3368d1c50170a452f2bf4a1dfd292a065870c3f258d799aad4316671cb69` at line 1 of these files:

| File | Check |
| --- | --- |
| `deploy/production/api.Dockerfile` | Exact official-image tag and index digest |
| `deploy/production/worker.Dockerfile` | Same pin |
| `deploy/production/attack-lab-runner.Dockerfile` | Same pin |
| `deploy/production/redteam-worker.Dockerfile` | Same pin |
| `deploy/production/event-ingest.Dockerfile` | Same pin |
| `deploy/production/gateway-control.Dockerfile` | Same pin |
| `deploy/production/runtime-gateway.Dockerfile` | Same pin |
| `deploy/production/sensor-agent.Dockerfile` | Same pin |

The report records registry inspection and arm64 execution for that index, plus an amd64 child-image package test (`docs/internal/2026-09-22-go-toolchain-release-gate.md:17`, `:35`, `:36`). The controller also confirmed its registry inspection directly. I did not repeat those passing checks or independently refetch registry metadata.

## What I checked

All 11 current SHA-256 hashes match `toolchain-hashes.json`; all 11 before hashes match bytes read from `/tmp/zasp-toolchain-fix.kTWzBM/baseline.tar`. I compared every non-Go `FROM` line with the archive. All eight runtime bases are unchanged. The complete launcher prefix before `requireGoTestVersion` is byte-identical, preserving explicit executable selection and its filtered environment without reading another implementation's application changes.

The changed environment assertions still require `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off` and `GOENV=off`, while excluding supplied credentials (`deploy/production/compliance-export-toolchain.test.mjs:11`, `:13`). Version tests accept both line endings and reject 1.25.6, 1.25.12, 1.26.0, development, malformed and empty output (`:26`, `:27`). These assert behavior, not merely configuration text.

Named risk: an active CI or production test consumer could retain the old pin. A focused `rg` check across `.github` and `deploy/production`, excluding artifacts and Markdown, found 1.25.6 only in the intentional rejection fixture (`deploy/production/compliance-export-toolchain.test.mjs:27`). Existing rendered-runtime consumers call the shared guard at `deploy/production/attack-lab-reconciler-runtime.test.mjs:19`, `deploy/production/compliance-export-runtime.test.mjs:21` and `deploy/production/security-agent-webhook-runtime.mjs:49`. No missed active consumer appeared within that scope.

The supplied RED/GREEN record reports an initial 1-of-3 failure and subsequent 3-of-3 pass (`docs/internal/2026-09-22-go-toolchain-release-gate.md:30`); the actual filtered host launch, container check and build-definition inspection are recorded at lines 34-37. I reviewed these results against the diff. No new test run was needed.

## Findings, and the limit

Critical: none. Important: none.

Minor operational note, resolved: the first amd64 Docker attempt failed with `cannot overwrite digest`; the recorded retry used the verified amd64 child successfully (`docs/internal/2026-09-22-go-toolchain-release-gate.md:36`). That failed attempt is not passing evidence, and it does not establish a code defect in these pins.

The reviewed delta contains no application, module-manifest or runtime-base changes. Preservation outside these 11 files relies on the controller's dirty-overlay isolation and reverse-apply check; I did not inspect unrelated P3A application/SQL work. The only file I wrote is this report.

Full product and security clearance remains unproven. The report explicitly leaves full release-package advisory checks, actual candidate product-image builds and scans, runnable-UI acceptance and CI open (`docs/internal/2026-09-22-go-toolchain-release-gate.md:39`). Package compatibility and compiler identity do not close those gates. Complete them before publication.
