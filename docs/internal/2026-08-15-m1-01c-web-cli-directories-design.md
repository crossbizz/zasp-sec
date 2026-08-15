# M1-01c Web and CLI Directories Design

Date: August 15, 2026

## Goal

Create the approved `apps/web` and `cmd/agentsecctl` ownership boundaries. The
web boundary must build the existing runnable product UI without copying or forking it.
The CLI boundary must expose one exact build-version command. This
task adds no preflight, recovery, diagnostic, provider, credential, deployment,
network, or customer-data behavior.

## Selected structure

```text
apps/web/
  package.json
  README.md

cmd/agentsecctl/
  go.mod
  main.go
  main_test.go
```

The repository-root Vinext/React application is already the runnable web shell.
`apps/web/package.json` creates its approved deployable/package boundary with a
dependency-free private package whose `build` script delegates exactly to the
locked repository-root production build. This avoids duplicating the UI,
moving unrelated code, creating a second lockfile, or introducing unpinned
dependencies. M1-35 remains responsible for the later product-shell and route
scaffold behavior.

`cmd/agentsecctl` is an independent Go module at
`github.com/zasp-ai/zasp-sec/cmd/agentsecctl`. Later single-tenant preflight,
recovery, backup, restore, and diagnostic tasks can extend that command without
coupling it to a product service module.

The tracked command files are `cmd/agentsecctl/go.mod`,
`cmd/agentsecctl/main.go`, and `cmd/agentsecctl/main_test.go`.

## Command and build contracts

- `npm --prefix apps/web run build` invokes exactly the locked repository-root
  production build and must succeed without installing another dependency tree.
- `go run ./cmd/agentsecctl version` writes exactly
  `agentsecctl version <version>` plus one newline.
- The CLI development default is `dev`; release builds may inject a version only
  through Go link-time `-ldflags -X`.
- The CLI version grammar is one to sixty-four ASCII letters, digits, dots,
  underscores, plus signs, or hyphens, beginning with a letter or digit.
- Missing, extra, or different CLI arguments fail with no stdout. Invalid build
  versions fail before output. Writer errors propagate to a nonzero boundary.
- The CLI reads no environment, dotenv, profile, credential, proxy, endpoint,
  provider, Kubernetes, AWS, Stytch, Neon, or filesystem state and performs no
  listener or network operation.

## Alternatives rejected

- Moving the existing root UI during this microtask would create unrelated
  churn and risk the runnable-UI invariant before the later root-workspace and
  web-shell tasks.
- Copying the root application into `apps/web` would create two sources of
  truth and two deployment artifacts.
- Adding another JavaScript lockfile would widen dependency governance before
  M1-02.
- Implementing `agentsecctl preflight`, recovery, or diagnostics now would
  preempt M8 tasks and create provider authority without their contracts.

## Verification

Tests precede CLI production. The repository contract binds the web delegation
and CLI module. Go tests cover exact default/injected output, command and version
rejection, nil output, and writer failure. Verification runs six focused passes,
race/tidy/module/vet, artifact-free default/injected CLI execution, the exact web
build boundary, retained worker/service regressions, the full pinned repository
gate, production audit, whitespace, secret scans, and zero-finding review.

Only then may M1-01c move to Complete. M1-01 remains Pending. M0-09, M0-18,
M0-19, and PROV-01 remain Blocked; R-03 remains incomplete and R-11 Not run.
