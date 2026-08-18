# M1-43 Tenant Quota Primitive Design

## Decision

Add a dependency-free `services/platform/tenantquota` product package. It
provides one in-process, immediate-admission concurrency primitive whose keys
contain exactly a canonical product Organization and one fixed workload kind:
connector, graph query, test, or AI request.

Every admission accepts a complete M1-04 `domain.Scope`, but the resulting key
intentionally retains only its Organization. Workspaces and Environments in
the same Organization therefore share the same workload quota, while otherwise
identical requests from different Organizations use independent counters.

Limits are injected as one typed constructor value. The primitive does not read
process environment, files, profiles, credentials, or provider state. This
preserves the M1-07 injected-configuration boundary without adding speculative
deployment keys before a consumer owns their wiring.

## Product API and exact keys

The package exposes four fixed workload kinds and no caller-defined strings:

```go
type Kind string

const (
    Connector  Kind = "connector"
    GraphQuery Kind = "graph_query"
    Test       Kind = "test"
    AIRequest  Kind = "ai_request"
)

type Key struct { /* opaque Organization plus Kind */ }
func NewKey(domain.Scope, Kind) (Key, error)
func (Key) OrganizationID() domain.ProductID
func (Key) Kind() Kind

type Limits struct {
    Connectors  uint32
    GraphQueries uint32
    Tests       uint32
    AIRequests  uint32
}

type Usage struct {
    InUse uint32
    Limit uint32
}

type Counter struct { /* mutex-protected active counts */ }
func New(Limits) (*Counter, error)
func (*Counter) TryAcquire(domain.Scope, Kind) (*Permit, error)
func (*Counter) Usage(domain.Scope, Kind) (Usage, error)
func (*Permit) Release() error
```

`Key` is comparable and contains no pointer or mutable collection. Equal
Organizations and kinds yield equal keys even when Workspace and Environment
differ. Different Organizations or kinds never share a key.

Every configured limit is required and lies in `[1, 1024]`. This package does
not define defaults: accepting a zero value would silently disable or
unbound a workload class. A direct, partially initialized, or forged value
fails closed.

## Admission, release, and memory behavior

`TryAcquire` validates the counter, complete scope, and kind before locking. It
increments only when the Organization-and-kind count is strictly below the
configured limit. At the limit it returns the fixed `ErrQuotaExceeded`
immediately and changes no state; it never waits, retries, sleeps, or performs
I/O.

A successful admission returns one opaque `Permit` whose private pointer refers
to one shared release state. Copies therefore share the same release lock and
cannot decrement twice. `Release` decrements exactly its retained key once.
Nil, zero, forged, copied-after-release, concurrent, and repeated release return
the fixed `ErrInvalidPermit` without changing any counter. When the final permit
for a key is released, the map entry is deleted, so inactive Organizations are
not retained indefinitely.

`Usage` is an observation only. It returns the current count and configured
limit for one validated Organization/kind without creating state. Both
admission and observation are mutex-protected, and concurrent calls do not
retain caller scope values beyond the immutable Organization key.

## Failure and privacy boundary

Construction failure returns only `ErrInvalidConfiguration`. Invalid counter,
scope, or kind returns only `ErrInvalidRequest`; over-limit admission returns
only `ErrQuotaExceeded`; invalid release returns only `ErrInvalidPermit`.
Errors contain no Organization, Workspace, Environment, workload input,
counter, limit, or panic value.

The primitive has no provider, network, filesystem, clock, goroutine, or
background cleanup authority. It is not a distributed rate limiter, billing
meter, durable quota ledger, scheduler, fairness guarantee, or authenticated
authorization decision. Later consumers may place a distributed adapter behind
the same exact Organization/kind semantics.

## Verification and status boundary

Tests must prove exact key construction, all invalid/direct states, four-kind
independence, same-Organization cross-workspace sharing, different-Organization
counter separation, predictable over-limit rejection, release recovery,
double/forged release denial, zero-state deletion, and concurrent admission at
the configured bound. A binding mutation that removes Organization from key
equality must make the two-Organization fixture fail.

Starting M1-43 changes the source counts to 640 Pending / 1 In progress / 84
Complete / 3 Blocked and M1 to 7 / 1 / 60 / 0. Completion changes them to
640 / 0 / 85 / 3 overall and 7 / 0 / 61 / 0 within M1. M1-42 remains Complete,
M1-44 remains Pending, and M0-09, M0-18, and M0-19 remain the exact blockers.

Completion requires tests-first RED/GREEN evidence, six race passes, package
coverage, full platform and repository gates, audit, whitespace and redacted
secret scans, zero-finding review, push, and exact-SHA Runnable UI success.

## Alternatives rejected

- Keying by Workspace or Environment would permit one Organization to multiply
  its quota by creating lower-level scope values.
- Keying only by workload kind would make one Organization consume another's
  capacity.
- Caller-defined key strings would bypass the canonical ProductID and fixed
  workload vocabulary.
- A blocking semaphore would make over-limit behavior dependent on scheduling
  and cancellation instead of the required predictable rejection.
- Ambient environment loading here would duplicate M1-07 and make hermetic
  unit behavior depend on process state.
