# M1-26 UI API Coverage CI Design

## Decision

Add one hermetic repository validator that cross-checks the strict
`docs/product/ui-api-map.yaml` artifact against the actual
`openapi/openapi.yaml` operation inventory. The current empty OpenAPI root and
five `planned` forward references pass honestly; no operation, route, client
method, UI call, server, or provider integration is added.

The validator becomes the reusable coverage boundary for later OpenAPI and UI
tasks. Root verification runs it before application tests through the fixed
`ui-api:check` package command.

## Coverage model

Map action availability has exactly two states:

- `planned`: the operation is a forward reference and must be absent from the
  current OpenAPI document;
- `available`: the operation must exist exactly once as an interactive public
  operation.

An OpenAPI operation under `/api/v1` is interactive public product surface and
must have exactly one `available` screen/action mapping. An operation under
`/internal/v1` is internal data-plane surface and must have no screen/action
mapping. Any operation path outside those two namespaces is unclassified and
fails closed. Every operation has one nonempty, case-sensitive `operationId`,
and operation IDs are unique across the complete document.

This makes the source requirement deterministic without weakening M1-23 or
M1-25: the checked-in seed remains five planned, absent operations today. When
a later task defines one, that same change must move its map entry to
`available`; otherwise CI fails. Removing an available mapped operation or
adding an unmapped public operation also fails.

## Input and output boundary

The command reads only the two fixed repository files. Each must be a bounded,
regular, non-symlink UTF-8 file. YAML aliases, merge keys, duplicate mapping
keys, multiple documents, non-object roots, unknown map fields, invalid map
identifiers, duplicate screen/action/operation identities, and invalid
availability values fail closed. OpenAPI extraction accepts only standard HTTP
operation keys and ignores standard non-operation path-item metadata.

Success is one fixed line containing only aggregate counts:

```text
UI/API coverage passed: planned=5 available=0 public=0 internal=0.
```

Failure is one fixed line and a nonzero exit:

```text
UI/API coverage rejected.
```

No parser error, file content, path, operation ID, environment value, or stack
trace crosses the CLI boundary.

## Verification

Tests first require the absent validator and command. GREEN covers the current
empty root, a synthetic all-five-operation future document, deliberate removal
of one mapped operation, an unmapped public operation, an internal operation,
duplicate/missing operation IDs, namespace drift, planned/available mismatch,
hostile YAML representation, file-boundary failures, fixed output, and root
verification wiring. Six focused passes, full pinned repository gates,
audits/scans, and zero-finding review precede completion and exact-SHA CI.

M1-27 remains Pending. M0-09, M0-18, and M0-19 remain Blocked.
