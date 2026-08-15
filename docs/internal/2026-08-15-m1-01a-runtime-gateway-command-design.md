# M1-01a Runtime Gateway Command Design

Date: August 15, 2026

## Goal

Create the approved standalone `services/runtime-gateway` Go deployable and
prove that its minimal command compiles and prints its build version. This task
does not start a proxy, MCP server, tool/API listener, or OPA policy evaluator,
and it does not claim gateway readiness.

## Selected structure

Create a service-local module and command:

```text
services/runtime-gateway/go.mod
services/runtime-gateway/main.go
services/runtime-gateway/main_test.go
```

The module path is `github.com/zasp-ai/zasp-sec/services/runtime-gateway`.
Runtime gateway is a separate deployable and ownership boundary from platform
and event ingest, matching the authoritative deployables section. Later proxy,
auth, policy-bundle, OPA, and health tasks can extend this service without
coupling its dependency graph to other binaries.

## Command contract

- Running the command writes exactly `runtime-gateway build <version>` plus one
  newline.
- The development default is `dev`; releases may inject a version only through
  Go link-time `-ldflags -X`.
- The version grammar matches the completed Go commands: one to sixty-four
  ASCII letters, digits, dots, underscores, plus signs, or hyphens, beginning
  with a letter or digit.
- Invalid values fail before output. Writer failures return a nonzero process
  result without emitting internal details.
- The command reads no runtime argument, environment variable, dotenv file,
  profile, credential, proxy, endpoint, Git state, or filesystem state. It
  opens no listener and performs no network, MCP, tool, API, or OPA operation.

## Alternatives rejected

- Placing runtime gateway inside another service would violate the approved
  customer-side deployable boundary and couple independent release concerns.
- A repository-root Go module would mix service and later CLI dependency graphs.
- Starting a proxy or embedded evaluator would preempt later config, auth,
  policy-bundle, OPA, tool-proxy, and shared-health tasks.

## Verification

Tests precede production code and cover exact default/injected output, invalid
version values, nil output, and writer failure. Final gates run five focused
passes, race, artifact-free build, exact link-time execution, tidy-diff, module
verification, vet, retained platform and event-ingest regressions, full pinned
repository verification, production audit, whitespace, and redacted scans.
