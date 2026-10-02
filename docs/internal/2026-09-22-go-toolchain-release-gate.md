# Patched compiler candidate, not release clearance

The P1 final scoped scan under host Go1.25.6 reports26 reachable standard-library advisories with fixes through1.25.13. CI and eight product Dockerfiles still pin1.25.6. These are implementable release gates; no missing external credential prevents changing the build configuration.

Controller checks on2026-09-22, while P2 implements separate application changes:

| Command from services/platform | Observed result |
| --- | --- |
| `GOTOOLCHAIN=go1.25.13 go version` | `go version go1.25.13 darwin/arm64` |
| `GOTOOLCHAIN=go1.25.13 go test ./runtimeservices -count=1` | PASS,0.664s |
| `GOTOOLCHAIN=go1.25.13 go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./runtimeservices` | Exit0; zero reachable vulnerabilities; one imported-package and one required-module advisory not reported as called |

The test invocation did not enable the opt-in real-service smoke. The scan covers only the unchanged runtime-service package, avoiding P2's in-flight API/worker files. It does not prove the whole product, deployed binaries, test paths, operating-system images or every architecture are clear. The compiler was selected per command; no default host configuration, repository CI pin, Dockerfile or dependency manifest was changed.

Registry inspection found `golang:1.25.13-alpine3.22` unavailable. Candidate official image indexes that resolved:

- `golang:1.25.13-alpine3.23@sha256:42fc3368d1c50170a452f2bf4a1dfd292a065870c3f258d799aad4316671cb69`
- `golang:1.25.13-alpine3.24@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946`

These are inspected candidates, not adopted or image-scanned versions. Choose the supported target with container build and dependency evidence before replacing all eight builder pins. Inspect runtime base images separately. Existing `.github/workflows/runnable-ui.yml` has both a setup-go pin and an exact GOVERSION assertion; update both in the reviewed release-toolchain change, preserving what that assertion protects.

Required before publication: update and review actual compiler/build pins; verify build/test compatibility on the release platform; rerun the complete release advisory and image scans; triage imported/required findings instead of discarding them; preserve the mandatory runnable-UI/CI gates. P1's patched gRPC/x/text evidence remains separate. No original task is promoted by these candidate checks.

Controller dependency check: `deploy/production/go-test-runtime.mjs` also rejects any compiler version except1.25.6. Its contract is exercised by `deploy/production/compliance-export-toolchain.test.mjs`; the shared helper is imported by rendered runtime proofs. Update this exact-version guard and its tests together with CI and container pins. Preserve its credential-filtered environment, `GOTOOLCHAIN=local`, disabled proxy/sumdb and disabled Go environment file. Merely setting `GOTOOLCHAIN` on an outer test command will not switch these subprocess proofs. The helper supports an explicit `ZASP_GO_BIN` for selecting the already-installed verified compiler.

## Compiler repair implemented, review pending

This checkpoint supersedes the earlier unchanged-pin statements. CI setup-go and its exact version assertion now require1.25.13. All eight Go builder lines use the verified1.25.13-alpine3.23 index digest above; runtime base images are unchanged. Alpine3.23 is the smaller available base-version step from3.22. The filtered Go launcher now requires1.25.13 and still forbids ambient credentials, network dependency/toolchain fetching and Go environment-file overrides. No application, module manifest or host default compiler was changed.

Scoped pre-edit archive: `/tmp/zasp-toolchain-fix.kTWzBM/baseline.tar` (11paths). The repair uses grouped TDD for the application test-launch guard. `node --test deploy/production/compliance-export-toolchain.test.mjs` first failed1/3 because the old guard rejected1.25.13. After the fix, it passed3/3 (64.572ms). Coverage accepts LF/CRLF output and rejects vulnerable1.25.6, unselected1.25.12/1.26.0, development, malformed and empty versions. Credential filtering and explicit executable selection remain covered.

Additional checks:

- Actual `goTestRuntime` subprocess launch using `ZASP_GO_BIN=/Users/manishmaheshwari/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.13.darwin-arm64/bin/go` accepted `go env GOVERSION` output with its filtered environment.
- `docker run --rm golang:1.25.13-alpine3.23@sha256:42fc3368d1c50170a452f2bf4a1dfd292a065870c3f258d799aad4316671cb69 go version` returned `go version go1.25.13 linux/arm64`.
- The first amd64 run hit Docker's local `cannot overwrite digest` error after pulling another architecture under the same index. No image was deleted. Retrying with the verified index's amd64 child `golang@sha256:c2f0ee3ca26cc2f4109f8a2631875168494e4e8b689d41c71e0020dbe7b41e70` succeeded. With the platform source mounted read-only, `docker run --rm --platform linux/amd64 ... --workdir /src --env GOTOOLCHAIN=local ... go test ./runtimeservices -count=1` passed (`ok .../runtimeservices 0.109s`). This is application-package compatibility on the container compiler, not a full product image build or live-service smoke.
- The existing `inspectContainerBuilds()` consumer accepted all9 definitions: digest-pinned, nonroot/read-only compatible, with no embedded build credentials. `git diff --check` passed for the affected tracked scope.

Independent scoped review is still required. Neither Trivy nor Docker Scout is installed here; no image scan was performed by this repair. Full release-package advisory scans, actual product-image builds/scans, UI/CI acceptance and publication remain open. The earlier narrow runtime-service advisory result does not clear the full product, and changing compiler pins does not certify deployed binaries.

Independent review subsequently passed: SPEC compliant and QUALITY approved,
with all11 before/after hashes checked and no blocking finding. See
[the scoped review](2026-09-22-go-toolchain-review.md). This closes review of
the compiler-pin repair only. All full-candidate build/scan/UI/CI and deployed
binary gates above remain open; nothing was committed or pushed here.
