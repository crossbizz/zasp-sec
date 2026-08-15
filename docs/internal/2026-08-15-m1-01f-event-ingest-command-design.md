# M1-01f Event Ingest Command Design

Date: August 15, 2026

## Goal

Create the approved standalone `services/event-ingest` Go deployable and prove
that its minimal command compiles and prints its build version. This task does
not accept events, start a listener, normalize payloads, batch records, contact
SQS, or claim ingest readiness.

## Selected structure

Create a service-local module and command:

```text
services/event-ingest/go.mod
services/event-ingest/main.go
services/event-ingest/main_test.go
```

The module path is `github.com/zasp-ai/zasp-sec/services/event-ingest`. Event
ingest is a separate deployable and ownership boundary from the two-command
`services/platform` module, matching the authoritative deployables section.
Future normalization, batching, auth, and health tasks will extend this service
without coupling its dependency graph to the platform API/worker binary.

## Command contract

- Running the command writes exactly `event-ingest build <version>` plus one
  newline.
- The development default is `dev`; releases may inject a version only through
  Go link-time `-ldflags -X`.
- The version grammar matches the completed platform commands: one to
  sixty-four ASCII letters, digits, dots, underscores, plus signs, or hyphens,
  beginning with a letter or digit.
- Invalid values fail before output. Writer failures return a nonzero process
  result without emitting internal details.
- The command reads no runtime argument, environment variable, dotenv file,
  profile, credential, proxy, endpoint, Git state, or filesystem state. It
  opens no listener and performs no network, SQS, normalization, or batching
  operation.

## Alternatives rejected

- Placing event ingest inside `services/platform` would violate the approved
  deployable boundary and couple independently scaled services.
- A repository-root Go module would mix later runtime-gateway and CLI dependency
  graphs with the ingest service.
- Starting an HTTP receiver or SQS client would preempt later configuration,
  auth, semantic normalization, batching, and shared-health tasks.

## Verification

Tests precede production code and cover exact default/injected output, invalid
version values, nil output, and writer failure. Final gates run five focused
passes, race, artifact-free build, exact link-time execution, tidy-diff, module
verification, vet, retained platform command regressions, full pinned repository
verification, production audit, whitespace, and redacted secret scans.
