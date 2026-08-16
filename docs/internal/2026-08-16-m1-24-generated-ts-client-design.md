# M1-24 Generated TypeScript Client Design

## Decision

Generate one committed immutable TypeScript schema surface from the reviewed
M1-23 OpenAPI root with exact-pinned `openapi-typescript` 7.13.0, then expose a
small typed Fetch client factory backed by exact-pinned `openapi-fetch` 0.17.0.
Both projects are MIT licensed and are the official paired approach documented
by the OpenAPI TypeScript project.

The generated file lives at `apps/web/api/generated.ts`; the stable handwritten
factory lives at `apps/web/api/client.ts`. The current root has `paths: {}`, so
the generated client intentionally exposes no callable endpoint. Later reviewed
OpenAPI operation tasks regenerate the same file and make only those literal
paths and methods available to the client. Normal UI code never writes raw
`/api/v1/` Fetch calls.

## Generation contract

The exact generation flags are:

- `--alphabetize` for stable declaration ordering;
- `--export-type` for a runtime-free generated surface;
- `--immutable` for readonly response/request/component state;
- `--root-types` and `--root-types-no-schema-prefix` for stable direct aliases
  to the reviewed shared components; and
- an explicit local input and output path.

`npm run openapi:generate` is the only supported writer. The generated file is
committed and must not be hand-edited. `npm run openapi:check` invokes the same
exact command with the generator's official `--check` flag and fails on any
source/output drift without rewriting the working tree. Root `npm run verify`
runs lint, strict OpenAPI tests, and this drift check before application tests.

## Client boundary

`createAPIClient(options)` delegates to `openapi-fetch` with the generated
`paths` type. It performs no I/O during construction and has no default remote
server, credential, token, cookie, provider URL, proxy, or environment lookup.
Callers may inject Fetch and other standard client options at the composition
boundary. Authentication validation, session/token retrieval, authorization,
operation schemas, and UI integration remain later M2 and operation tasks.

The wrapper exports the inferred `APIClient` type plus reviewed generated
component aliases. It does not duplicate an operation, path, parameter, error,
or authentication schema in handwritten TypeScript.

## Dependency boundary

`openapi-fetch` 0.17.0 becomes an approved exact runtime dependency owned by
`web-platform` in `build/dependencies.lock.yaml`. `openapi-typescript` 7.13.0
is an exact development-only generator pin. Both record MIT in the npm lock.
No install occurs in generation/check scripts, and the input has no remote
references, so generation performs no provider, network, credential,
environment-file, database, Docker, or shared-resource I/O.

## Verification and status boundary

Tests first require the absent generated module/client/scripts and capture a
genuine RED. GREEN requires exact generator/client pins, exact output shape,
readonly component types, zero construction I/O, typecheck/build success, and
byte-for-byte reproducibility. Hostile drift tests mutate the committed output,
require `openapi:check` to reject it, and restore the exact bytes before the
test ends.

M1-24 may move to Complete only after six generation/check stability cycles,
full repository verification/build, production and development dependency
audits, secret scans, zero-finding whole-range review, push, and exact-SHA
Runnable UI success. M1-25 remains Pending. M0-09, M0-18, and M0-19 remain
Blocked.
