# M1-36a M1 Build Check Design

Date: August 18, 2026

## Goal

Prove from a clean checkout that every service, worker, web, and CLI build target
completed in M1 still succeeds. M1-36a is a verification task. It does not add
a ninth build target, a second build orchestrator, runtime product behavior, or
a new dependency.

## Selected boundary

The gate reuses the reviewed root command:

```bash
npm run build:repo
```

That command already owns the exact eight-target inventory:

1. `services/platform/agentsec-api`
2. `services/platform/agentsec-worker`
3. `services/event-ingest`
4. `services/runtime-gateway`
5. `workers/security-python`
6. `workers/redteam-node`
7. `apps/web`
8. `cmd/agentsecctl`

The four Go commands compile independently with local toolchain/network-disabled
module settings and write to the platform null device. The Python and Node
workers execute their fixed health boundaries. The web package delegates to the
locked root production build. The exact success line remains
`Repository build passed: targets=8`.

## Clean-checkout evidence protocol

The evidence run uses a unique owned temporary root and creates a detached local
clone at the reviewed M1-36a implementation commit. This excludes untracked and
ignored files from the source snapshot. Before installation, the clone must have
an empty tracked and untracked status and its HEAD must equal the selected commit.

The checkout installs only `package-lock.json` state with Node.js 22.23.1 and
npm 10.9.8. `NPM_CONFIG_USERCONFIG` points to the null device, `HOME` and the npm
cache are owned temporary directories, and `SHARP_IGNORE_GLOBAL_LIBVIPS=1` keeps
the locked platform binary boundary. The install may contact the public package
registry for exact lockfile artifacts; it receives no ambient npm token, proxy,
cloud credential, dotenv, provider profile, or product configuration.

The build runs with an explicit tool path containing the pinned Node runtime,
Go 1.25.6, Python 3.13, and base system tools. The existing build orchestrator
then reduces every child environment to its reviewed allowlist. Success requires
the one fixed line, exit zero, all eight targets, and no tracked source change.

The temporary clone, npm cache, and install are evidence-only artifacts. After
the result and clean-source check are recorded, the exact owned temporary root
is removed. No shared checkout, dependency cache, Docker object, provider
resource, or customer state is mutated.

## Contract and documentation

A repository quality contract binds the exact M1-36a source row, M1-35
dependency, eight-target inventory, root command, clean-checkout protocol,
fixed output, and status arithmetic. README documents the completed build gate
and its exact root command without claiming schema, OpenAPI, UI/API coverage, or
local-infrastructure evidence that belongs to M1-36b through M1-36e.

M1-36b remains Pending throughout this task. M0-09, M0-18, and M0-19 remain the
exact blocked source tasks; PROV-01 remains a separate blocked waiver; R-03 stays
incomplete and R-11 stays Not run.

## Alternatives rejected

- Adding a duplicate `m1:build-check` script would create two authorities for
  the same eight targets without adding evidence.
- Treating the current working directory as a clean checkout would allow
  ignored or untracked files to influence the result.
- Copying the current `node_modules` tree into the clone would weaken the
  lockfile-install evidence and could carry local modifications.
- Running Docker, Kubernetes, LocalStack, a database, or a cloud provider would
  exceed the M1-36a build-only boundary.
- Folding schema, OpenAPI, UI/API coverage, or local smoke checks into this task
  would pre-claim the successor gates.

## Completion evidence

M1-36a may move to Complete only after:

- the source/design/status contract passes;
- the exact build orchestrator tests pass six consecutive times;
- one clean-checkout lockfile install and exact eight-target build succeeds;
- the temporary checkout is removed and the implementation worktree stays clean;
- full pinned repository verification, production audit, dependency validation,
  whitespace checks, and pinned redacted secret scans pass; and
- whole-range review returns zero Critical, Important, and Minor findings.
