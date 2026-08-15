# M1-01 Repository Skeleton Design

Date: August 15, 2026

## Goal

Add one repository-root build command that invokes every deployable boundary
created by M1-01d through M1-01c. The command must succeed from a prepared
checkout without installing or downloading runtime dependencies, must leave no
compiled artifacts in the repository, and must not add runtime product behavior.

## Selected structure

The root `package.json` gains `build:repo`, implemented by the dependency-free
Node module `scripts/build-repo.mjs`. Its fixed target inventory is:

1. `services/platform/agentsec-api`
2. `services/platform/agentsec-worker`
3. `services/event-ingest`
4. `services/runtime-gateway`
5. `workers/security-python`
6. `workers/redteam-node`
7. `apps/web`
8. `cmd/agentsecctl`

Each Go command is built independently with `GOTOOLCHAIN=local`, `GOPROXY=off`,
`GOSUMDB=off`, and `GOENV=off`. Its output goes to Node's platform-specific
null device, so the command proves compilation without creating a binary. The
Python and Node workers execute their exact no-op health boundaries; Python runs
with bytecode disabled and an explicit package root. The web target delegates to
`npm --prefix apps/web run build`, which uses only the locked root install. The
CLI is built as its independent Go module.

The orchestrator accepts no arguments or configuration. Every child has a fixed
executable, arguments, working directory, environment additions, output cap, and
deadline. Child output is never forwarded. A complete run writes exactly
`Repository build passed: targets=8` plus one newline; every failure writes only
`Repository build rejected` plus one newline to stderr and exits nonzero.

## Dependency and authority boundary

The command never runs `npm install`, `npm ci`, `go get`, `go install`, `pip`,
`uv`, `curl`, `wget`, a package registry client, Docker, or a provider CLI. Go
network resolution and automatic toolchain downloads are disabled. It reads no
dotenv file, credential, profile, proxy, endpoint, provider, Kubernetes,
database, customer, or product state and opens no listener or network client.

## Alternatives rejected

- A shell command chain would make environment, signal, output, and portability
  behavior implicit and difficult to test.
- A root Go workspace belongs to later repository/dependency work and is not
  required to build independent modules.
- Writing binaries into `dist`, `bin`, or package directories would create
  cleanup and ownership requirements without product value.
- Adding `build:repo` to the existing Runnable UI `verify` command would make
  the UI gate depend on Go and Python before their dedicated CI setup exists.

## Verification

Tests precede production. Hermetic Node tests bind the exact target inventory,
offline/local-toolchain environment, bounded execution, worker output, fixed
result, fail-fast behavior, argument rejection, and no install/provider command.
The real root command must then pass from the prepared checkout, followed by all
target races/tests/builds, six focused runs, the full pinned repository gate,
audit, whitespace, secret scans, and zero-finding review.

Only then may M1-01 move to Complete. M1-02 remains Pending. M0-09, M0-18,
M0-19, and PROV-01 remain Blocked; R-03 remains incomplete and R-11 Not run.
