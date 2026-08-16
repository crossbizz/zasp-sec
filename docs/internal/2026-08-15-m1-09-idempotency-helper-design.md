# M1-09 Idempotency Helper Design

## Decision

Add one dependency-free `services/platform/idempotency` package that binds an
Organization-scoped idempotency key to an exact operation and SHA-256 request
fingerprint. A small store interface owns the atomic claim and completion
transition; a request helper executes an operation only for the unique acquired
claim and returns a previously completed canonical product result for duplicates.

The package provides no database implementation, migration, HTTP middleware,
provider request, background retry, lease expiry, logging, or reconciliation.
M1-10 supplies the first persistence framework; later repositories may implement
the store without changing this behavior contract.

## Request identity

`Request` is an opaque comparable value created from:

- a validated product `Scope`;
- a lowercase bounded operation token;
- a bounded caller-generated idempotency key; and
- the exact canonical request bytes, retained only as a SHA-256 fingerprint.

The complete scope, operation, key, and fingerprint form the store identity.
The same key with a different operation, scope, or fingerprint is a conflict,
never a duplicate. The helper does not accept vendor identifiers as result
references and does not retain request payload bytes.

## Store protocol

The store exposes two context-aware methods:

1. `Claim` atomically returns exactly one of acquired, in-progress, or completed.
2. `Complete` atomically binds the acquired claim token to one nonzero canonical
   product result ID.

An acquired claim carries a bounded opaque token so a stale executor cannot
complete a newer ownership epoch. An in-progress claim carries neither token nor
result. A completed claim carries only the prior canonical product result. Every
claim shape is validated before the helper acts.

The store must return the fixed key-conflict sentinel when a key exists with a
different request identity. Other store failures are mapped to a fixed store
error so database/provider text cannot cross this package boundary.

## Execution behavior

`Helper.Execute` validates its context, request, store, and operation before
claiming:

- acquired: invoke the operation exactly once, validate its product result, then
  complete the claim and return `Prior=false`;
- completed: do not invoke the operation; return the stored result with
  `Prior=true`;
- in-progress: do not invoke the operation; return the fixed in-progress error;
- conflict or malformed store state: do not invoke the operation and fail closed.

The helper never releases or reassigns an acquired claim. If the operation
returns an error, panics, is canceled, produces an invalid result, or completion
fails, the claim remains in progress for later explicit reconciliation. This is
intentionally conservative: the helper cannot know whether an external mutation
was applied and therefore cannot authorize an automatic duplicate execution.

## Scope and safety

- Fixed helper errors contain no key, request, result, store, provider, or
  credential text.
- No operation begins after a canceled context or an invalid/malformed claim.
- Operation panics propagate after leaving the acquired claim intact.
- Store implementations must make claim and completion atomic and enforce exact
  request identity; this package does not emulate transactions with separate
  reads and writes.
- M1-10 remains Pending until M1-09 completes and exact-SHA CI passes.
- M0 blockers and the R-03/R-11 boundaries remain unchanged.
