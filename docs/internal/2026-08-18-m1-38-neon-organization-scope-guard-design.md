# M1-38 Neon Organization Scope Guard Design

## Decision

Add one dependency-free `services/platform/repository` package that sits
between customer-data repositories and the existing `database.Pool` query
boundary. The package requires one canonical product Organization ID before it
can invoke SQL and prepends that trusted ID as the first query argument.

This is a deliberately small guard, not a SQL builder or database policy
engine. Later repository packages continue to own fixed SQL text and must bind
the Organization argument at `$1`. M1-45a will add transaction-local tenant
context, and M1-45b/M1-45c will add and prove database row-level enforcement.

## Product interface

The package owns:

- `Queryer`, the narrow existing pool-shaped interface
  `QueryRow(context.Context, string, []any, ...any) error`;
- `Guard`, constructed by `New(Queryer) (*Guard, error)`; and
- `(*Guard).QueryRow(context.Context, domain.ProductID, string, []any,
  ...any) error`.

`QueryRow` accepts an Organization ID separately from caller arguments. It
validates that the ID is nonzero and round-trips through
`domain.ParseProductID`, then creates a fresh argument slice whose first value
is the canonical Organization string. Caller arguments follow unchanged. The
caller-owned slice is never mutated or retained.

The guard also rejects a nil or canceled context, invalid statement, missing
scan destinations, nil or typed-nil queryer, zero guard, downstream error, and
downstream panic. Every rejection happens through fixed `ErrConfiguration` or
`ErrQuery` values that contain no Organization ID, SQL, arguments, destination
values, driver message, or panic value.

## Boundary and threat model

The security invariant for M1-38 is call-boundary admission: a missing,
zero, malformed, or noncanonical Organization ID cannot reach the SQL
executor. A valid call reaches the executor with exactly one trusted
Organization argument in position zero.

This package does not parse SQL to guess whether `$1` is used correctly. A
lexical check would accept comments, dead expressions, or predicates with the
wrong semantics and would create false assurance. Fixed repository statements
remain responsible for binding `$1`; the later tenant-context and RLS tasks
provide database-side enforcement and cross-Organization proof.

The helper stores no Organization, connection, credential, statement,
argument, result, or provider error. It adds no Neon SDK, pgx dependency,
environment read, schema mutation, transaction, listener, command wiring, or
live provider call.

## Failure and concurrency behavior

Validation completes before the queryer is invoked. Downstream calls are
panic-contained and any non-nil error becomes `ErrQuery`. The helper is
stateless after construction, so independent callers may use it concurrently;
each call owns its fresh argument slice and shares no mutable tenant state.

The existing `database.Pool` continues to own statement bounds, configured
query deadlines, scan lifetime, pool close ordering, and driver error
containment. M1-38 does not duplicate or weaken those controls.

## Verification

Hermetic tests prove exact statement/argument/destination forwarding, canonical
Organization insertion at argument zero, caller-slice independence, concurrent
separation for two Organizations, and compatibility with the real
`database.Pool` method signature. Hostile tests cover zero and malformed IDs,
nil/canceled context, invalid statements, missing destinations, nil and
typed-nil queryers, zero guard, downstream errors/panics, and error secrecy.
Every invalid Organization fixture must leave the executor call count at zero.

Completion requires genuine RED/GREEN evidence, six race-enabled focused
passes, the complete platform race/tidy-diff/module-verify/vet matrix, pinned
repository verification, production audit, whitespace and redacted secret
scans, zero-finding review, push, and exact-SHA Runnable UI success.

## Status boundary

Starting M1-38 changes the source counts to 645 Pending / 1 In progress / 79
Complete / 3 Blocked and M1 to 12 Pending / 1 In progress / 55 Complete / 0
Blocked. Completion changes them to 645 / 0 / 80 / 3 overall and 12 / 0 / 56
/ 0 within M1. M1-37 remains Complete exactly once, M1-39 remains Pending,
R-03 remains incomplete, R-11 remains Not run, and M0-09, M0-18, and M0-19
remain the exact source blockers.

## Alternatives rejected

- Inspecting SQL text for an Organization predicate is not a sound parser or
  an authorization boundary.
- Storing one Organization on a long-lived repository object risks tenant
  bleed between concurrent requests.
- Passing an Organization string inside the caller argument slice permits
  omission, reordering, and noncanonical IDs.
- Setting transaction-local tenant state now would duplicate M1-45a and widen
  this task into adapter, transaction, and live-provider behavior.
