# M1-01d Platform API Command Design

Date: August 15, 2026

## Goal

Create the first product-service command at the approved platform boundary and
prove that it compiles and prints its build version. This task establishes only
the command and module skeleton; it does not start an HTTP server, load
configuration, connect to a provider, or claim API readiness.

## Selected structure

Use one service-local Go module:

```text
services/platform/go.mod
services/platform/agentsec-api/main.go
services/platform/agentsec-api/main_test.go
```

The module path is `github.com/zasp-ai/zasp-sec/services/platform` and the Go
language version is `1.25.0`, matching the established repository Go proof
modules and the available pinned-compatible toolchain. M1-01e can add the
sibling `agentsec-worker` command to this module without changing ownership or
introducing a root module prematurely.

## Command contract

- Running the command with no arguments writes exactly one line:
  `agentsec-api build <version>`.
- The development default is `dev`.
- Release builds may inject the version only at link time with Go `-ldflags -X`.
- A build version is one to sixty-four ASCII characters drawn from letters,
  digits, dot, underscore, plus, and hyphen; it must begin with a letter or
  digit. Empty, whitespace-bearing, control-character, or multiline values
  fail closed with a nonzero exit and no version output.
- The command reads no environment variable, dotenv file, profile, credential,
  proxy, endpoint, or runtime argument. It opens no listener and performs no
  filesystem or network mutation.
- A write failure returns a nonzero process result without printing internal
  details.

## Alternatives rejected

- A root Go module would establish repository-wide build ownership before
  M1-01 creates the root build commands.
- A separate module per platform command would split the approved shared
  `services/platform` Go codebase and duplicate future shared dependencies.
- Deriving a version from ambient Git state, an environment variable, or a
  file at runtime would make the command nondeterministic and widen its input
  boundary.

## Verification

Tests are written before production code. Unit tests cover the default and
injected output, invalid build versions, write failure, and exact single-line
format. The task gate then runs Go race tests, five fresh command-test passes,
`go build`, an exact linked-version binary execution, `go mod tidy -diff`,
`go mod verify`, `go vet`, the full pinned repository verification, production
dependency audit, whitespace checks, and redacted secret scans.
