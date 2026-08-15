# M1-01e Platform Worker Command Design

Date: August 15, 2026

## Goal

Add the second command in the approved `services/platform` Go codebase and
prove that it compiles and prints its build version. This task creates only the
worker command skeleton; it does not start a worker loop, consume SQS, load
configuration, connect to a provider, or claim worker readiness.

## Selected structure

Add the sibling command to the module established by M1-01d:

```text
services/platform/go.mod
services/platform/agentsec-api/
services/platform/agentsec-worker/main.go
services/platform/agentsec-worker/main_test.go
```

The worker remains an independent `main` package. Its small version boundary is
kept local rather than introducing a shared abstraction before either command
has shared service behavior. Later health/config tasks can extract only the
common behavior they actually require.

## Command contract

- Running the command writes exactly `agentsec-worker build <version>` plus one
  newline.
- The development default is `dev`; releases may inject a version only through
  Go link-time `-ldflags -X`.
- The accepted version grammar is identical to M1-01d: one to sixty-four ASCII
  letters, digits, dots, underscores, plus signs, or hyphens, beginning with a
  letter or digit.
- Invalid values fail before output. Writer failures return a nonzero process
  result without emitting internal details.
- The command reads no runtime argument, environment variable, dotenv file,
  profile, credential, proxy, endpoint, Git state, or filesystem state. It
  opens no listener and performs no network or queue operation.

## Alternatives rejected

- A second Go module would split the approved two-command platform codebase.
- A shared version package would add an abstraction before shared runtime
  behavior exists and would broaden this microtask into an API-command refactor.
- Starting a polling loop or health server would preempt later config, external
  client policy, SQS, and shared health tasks.

## Verification

Tests precede production code and cover exact default/injected output, invalid
version values, nil output, and writer failure. Final gates run five focused
passes, race, artifact-free build, exact link-time execution, tidy-diff, module
verification, vet, both platform command tests/builds, full pinned repository
verification, production audit, whitespace, and redacted secret scans.
