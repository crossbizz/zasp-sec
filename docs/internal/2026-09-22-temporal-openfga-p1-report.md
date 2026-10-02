# P1 handoff, 2026-09-22

P1's dependency/configuration packet is implemented and locally verified. Independent review is pending. No commit, push, live staging deployment, workflow cutover or permission activation occurred.

API and worker use one validated config and the official SDK clients. Enabled startup verifies the configured Temporal namespace and authenticated pinned FGA model with finite deadlines. Partial enabled configuration, unsafe non-local transport, malformed ports and unavailable services fail closed. Disabled adoption preserves existing product behavior. The worker closes the new P1 connections even if an existing worker shutdown returns an error; existing borrower/database lifetime handling stays intact.

The Compose stack has three isolated PostgreSQL databases/roles and official migrations. Temporal server 1.32.0 and OpenFGA 1.21.0 started successfully. The real SDK smoke passed against both. It created only an isolated FGA connection fixture, not the product model. Local services and volumes remain available; nothing was deleted.

Staging uses the pinned official charts, TLS/mTLS, FGA preshared authentication, separate database secrets, bounded resources/pools, private endpoints, restricted ingress and disabled UIs. The deployment command consumes the checked-in values. The existing product `renderRelease` entrypoint now consumes `runtimeServices`; a rendered-resource test proves API and discovery-scheduler env/secret mounts. Other workflow families remain untouched. Temporal chart 1.7.0's schema job lacks its server CA mounts, so a bounded application-owned Job invokes the official migration tool before Helm installation. No upstream schema implementation was changed.

## Checks that ran

| Command | Result |
| --- | --- |
| Existing API/worker config baseline tests | Passed before edits |
| Both actual entrypoint enabled-without-authority tests | RED: accepted missing authority; GREEN after shared parser wiring |
| Shared authority/transport/deadline tests | Passed; malformed port cases also observed RED then GREEN |
| `go test ./runtimeservices ./agentsec-api ./agentsec-worker -run 'Config\|RuntimeServices\|FGAReadiness\|ConnectUnavailable' -count=1` | All three packages passed |
| `go mod verify` | All modules verified |
| `npm run dependencies:check` | Lock valid; 9 parser/runtime regressions passed |
| `docker compose -f deploy/local/temporal-openfga.compose.yaml config --quiet` | Passed |
| Compose startup/migrations | Temporal persistence, visibility, FGA and namespace initialization exited 0 |
| `ZASP_LOCAL_RUNTIME_SMOKE=1 go test ./runtimeservices -run '^TestLocalServiceConnectionSmoke$' -count=1 -v` | Passed; real namespace and authenticated pinned-model reads |
| `node deploy/staging/temporal-openfga.mjs --render` | Both pinned upstream charts, migration and network policy rendered |
| `node --test deploy/production/runtime-services.test.mjs` | RED before renderer support; GREEN with actual API/worker mounts |
| Scoped `git diff --check` | Passed |

Go commands run from `services/platform`; other commands run from the repository root. The SDK graph is Temporal SDK 1.48.0/API 1.63.4, OpenFGA 0.8.2, minimum Go 1.25.4 and existing direct x/sys raised to 0.45.0. Existing direct dependencies were retained. Exact versions, image/chart checksums, credential contracts and operational commands are in `docs/operations/temporal-openfga.md`.

## Review evidence

Pre-edit overlapping files were archived at `/tmp/zasp-p1-baseline.YnmB3B/overlap.tar`, then extracted read-only for comparison. Review `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p1-evidence/scoped.patch` and `paths-and-hashes.json`. They compare this packet against pre-edit dirty content, not HEAD. The controller's status-ledger append is excluded. Raw dependency-chart rendering is `/tmp/zasp-p1-baseline.YnmB3B/staging-rendered.yaml`.

The patch includes shared config/client code and tests; API/worker config/build composition; Go manifest/checksums and exact dependency metadata; local Compose/server config; staging chart values, deployment/migration/network files and product helpers; release-renderer integration; operations and this report. No scheduler64/worker63 feature work or P2-P7 migration is included.

## Still gated

Live staging needs the operator-owned private databases/DNS, certificates, secrets, enforced network policies, product image release values and P5 store/model publication. Backup/restore drills and measured capacity are not demonstrated. Advisory/image-security clearance remains a publication gate; checksums and module verification are not that clearance. UI build/typecheck and mandatory CI must run before any push. This packet changes no original task's production-availability classification.

## Fix round 1: P1-R1 and reachable dependency advisories

The reviewer confirmed that inherited OpenFGA TLS probes verified `0.0.0.0`, which doesn't match the documented private-service DNS SAN. Both probes now use custom commands: loopback connection, explicit `openfga.zasp-runtime.svc.cluster.local` server name, trusted CA file, one-second connect/RPC bounds and a three-second Kubernetes probe timeout. Verification is never disabled.

`deploy/staging/runtime-services-probes.test.mjs` first failed against the inherited rendered probe. After the fix, its rendered assertions and one bounded real DNS-SAN certificate check passed (2 tests, no skips). The check invokes the actual image's health-probe binary with the rendered arguments against a disposable TLS-enabled OpenFGA instance, then confirms a wrong server name fails. Generated test keys and containers were removed; the persistent P1 Compose stack was left alone. An initial fixture mount error was corrected by placing the CA file in the single read-only certificate mount before container creation.

The controller's scan identified reachable GO-2026-6348 in gRPC 1.82.1. The official 1.83.1 module declares Go 1.25.0 and fixes that advisory, so `go.mod`/`go.sum` now pin it. The amended full-output scan exposed the existing reachable x/text advisory GO-2026-5970. Its fixed 0.39.0 also supports Go 1.25; it is now pinned with required x/sync 0.21.0. gRPC raises the two genproto submodules to `v0.0.0-20260526163538-3dc84a4a5aaa`. No direct dependency, license rule or lock validation was removed. Minimum Go stays 1.25.4; this is compatibility, not security clearance.

Fix verification only:

| Command | Result |
| --- | --- |
| `ZASP_RUNTIME_TLS_PROBE_SMOKE=1 node --test deploy/staging/runtime-services-probes.test.mjs` | 2 passed, including real DNS-SAN check |
| `ZASP_LOCAL_RUNTIME_SMOKE=1 go test ./runtimeservices ./agentsec-api ./agentsec-worker -run 'Config\|RuntimeServices\|FGAReadiness\|ConnectUnavailable\|LocalServiceConnectionSmoke' -count=1` | All three packages passed under the final patched graph |
| `go mod verify` and `go list -m google.golang.org/grpc golang.org/x/text golang.org/x/sync` | Verified; 1.83.1 / 0.39.0 / 0.21.0 |
| `node scripts/validate-dependencies.mjs` | Dependency lock valid |
| `node deploy/staging/temporal-openfga.mjs --render` | Updated pinned charts/probes render |
| `go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./runtimeservices ./agentsec-api ./agentsec-worker` | Not clean: 26 reachable host-Go standard-library findings remain; neither patched module advisory appears |

The final scan used Go 1.25.6 and exited 3 (the `go run` wrapper exited 1). Standard-library fixes extend through Go 1.25.13. It also reports 5 imported-package and 18 required-module findings that this scoped code doesn't appear to call. Toolchain remediation, a fresh full release scan and container-image checks remain publication gates. No broad unchanged suite, deployment, commit or push was performed.

Complete scan output, not a tool-truncated excerpt, is saved in `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p1-evidence/fix1/govulncheck-final.txt`. The preceding gRPC-only scan is adjacent as `govulncheck-grpc-patched.txt`. Updated manifests are `staging-rendered.yaml`. Review only `fix-only.patch` with `paths-and-hashes.json` in that directory for this round. They compare against `/tmp/zasp-p1-fix1.WwLaKA/pre-fix.tar`, captured before the fix. The original P1 diff and controller ledger changes are untouched.
