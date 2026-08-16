# M1-17 AuditEmitter Contract Design

## Decision

Add a dependency-free `services/platform/audit` package that owns the product
security-mutation audit contract and delegates append-only persistence to a
narrow typed driver. The public boundary is an `AuditEmitter` interface with a
single `Emit` operation. A concrete `Emitter` validates complete product state,
applies one bounded deadline, invokes the driver once, and accepts only an exact
acknowledgement.

A raw interface that leaves validation to each implementation is rejected
because callers could silently emit incomplete audit records. Reusing
`eventstore.EventStore` is rejected because session/tool events have different
required fields and source semantics. Adding provider storage, export,
retention, arbitrary metadata, or a generic event envelope is deferred to its
own source-plan tasks.

## Product contract

The package exports:

```go
type AuditEmitter interface {
    Emit(context.Context, domain.Scope, Mutation) error
}

type Mutation struct {
    Actor   domain.ProductID
    Action  string
    Target  domain.ProductID
    Outcome Outcome
}
```

Every call receives a separate validated `domain.Scope`. `Actor` and `Target`
are nonzero canonical product IDs. They may be equal because a legitimate
self-service security mutation can target the acting principal. Provider IDs,
display names, credentials, arbitrary customer content, and unbounded metadata
do not cross this boundary.

`Action` is an explicit product token between 1 and 127 bytes. It begins with a
lowercase ASCII letter and contains lowercase letters or digits separated by a
single `.`, `_`, or `-`. Empty segments, uppercase text, whitespace, controls,
Unicode aliases, leading/trailing separators, and repeated separators are
rejected. This supports stable names such as `policy.create` and
`credential.revoke` without freezing a task-specific allowlist.

`Outcome` is a closed enum with exactly `succeeded`, `failed`, and `denied`.
Zero and unknown values fail closed. A mutation missing any required
actor/action/target/outcome field is rejected before driver I/O.

M1-17 intentionally does not add a timestamp, audit-event ID, reason, request
body, or evidence payload. Those belong to later event-envelope, persistence,
retention, and export work. This task freezes the minimum security-mutation
contract named by the source plan.

## Driver boundary

The concrete emitter is constructed from a `Driver` and a positive operation
timeout no greater than 30 seconds:

```go
type Driver interface {
    Append(context.Context, DriverMutation) (DriverAppended, error)
}
```

`DriverMutation` contains canonical strings for Organization, Workspace,
Environment, Actor, Action, Target, and Outcome. `DriverAppended` repeats those
seven fields. Product success requires an exact acknowledgement; empty,
partial, foreign-scope, altered, or extra-state representations fail closed.
The driver method name and single invocation define an append-only boundary;
product code never retries a mutation.

Driver and acknowledgement values are product-owned structs. No database,
queue, HTTP, provider, credential, error, or serialization type appears in the
public `AuditEmitter` interface.

## Failure, deadline, and concurrency behavior

Construction rejects a nil or typed-nil driver and any timeout outside
`(0, 30s]`. `Emit` rejects a nil context, unusable receiver, invalid scope, or
invalid mutation before I/O. It creates one child context for the configured
total deadline, calls the driver exactly once, contains a driver panic, and
returns only fixed errors for configuration, mutation rejection, or emission
failure.

Cancellation, timeout, driver error, panic, malformed success, scope drift,
field drift, and typed-nil dependencies fail closed. Inputs are value-only and
the emitter retains no mutable request state, so independent calls are safe for
concurrent use. A failed audit append is visible to the caller; this contract
does not silently downgrade a required security audit.

## Verification and scope boundary

Hermetic Go tests use a deterministic fake driver to prove:

- every missing or malformed actor/action/target/outcome value is rejected
  before I/O;
- exact scope and canonical mutation fields are forwarded once;
- exact acknowledgement is required;
- cancellation, deadline, driver error, panic, typed nil, malformed success,
  and concurrent calls fail or succeed deterministically; and
- fixed product errors contain no provider state.

Repository contracts expose a root `audit:emitter:test` command and keep M1-18
Pending. M1-17 performs no Docker, network, cloud, database, credential, or
shared-resource I/O. It may move to Complete only after genuine compiler
RED/GREEN evidence, six focused race passes, full platform/repository gates,
dependency and secret audits, zero-finding review, push, and exact-SHA Runnable
UI success.
