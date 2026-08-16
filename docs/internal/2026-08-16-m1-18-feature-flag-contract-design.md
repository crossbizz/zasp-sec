# M1-18 Feature Flag Contract Design

## Decision

Add a dependency-free `services/platform/featureflags` package that owns the
product feature-flag boundary and delegates optional evaluation to a narrow
typed driver. The public `FeatureFlags` interface evaluates one boolean flag
for an exact product scope. Every request carries its code-defined default;
driver outage, panic, timeout, cancellation, or malformed state returns that
default with explicit fallback metadata instead of making an optional vendor a
product availability dependency.

A raw provider interface is rejected because it would let vendor identifiers,
arbitrary properties, and ambiguous cache state escape into product code.
Embedding PostHog is rejected because the source task defines a product
contract, not a provider adapter. Implementing storage, background refresh,
remote analytics, percentage rollouts, variants, or a shared cache is deferred.

Feature flags are restricted to non-security-critical behavior. They never
authorize authentication, tenant scope, policy, enforcement, data access,
credential use, audit emission, or another deterministic security decision.

## Product contract

The package exports:

```go
type FeatureFlags interface {
    Evaluate(context.Context, domain.Scope, Request) (Decision, error)
}

type Request struct {
    Key     string
    Default bool
}

type Decision struct {
    Value       bool
    UsedDefault bool
    Cache       CacheMetadata
}

type CacheMetadata struct {
    Hit bool
    Age time.Duration
}
```

Every call receives a separate validated `domain.Scope`. `Key` is an explicit
product token between 1 and 127 ASCII bytes. It begins with a lowercase letter
and contains lowercase letters or digits separated by a single `.`, `_`, or
`-`. Empty segments, uppercase text, whitespace, controls, Unicode aliases,
leading or trailing separators, and repeated separators fail before driver
I/O. The boolean `Default` is always supplied by code; there is no implicit
zero-value policy or provider-owned default.

A valid provider decision returns `UsedDefault=false` and exact validated cache
metadata. Every unavailable or invalid provider path returns the request's
exact default, `UsedDefault=true`, and zero cache metadata. A provider value
that happens to equal the code default remains distinguishable from fallback.

## Driver and cache-metadata boundary

The concrete evaluator is constructed from a `Driver`, a positive operation
timeout no greater than 30 seconds, and a positive maximum accepted cache age
no greater than 24 hours:

```go
type Driver interface {
    Evaluate(context.Context, DriverRequest) (DriverDecision, error)
}
```

`DriverRequest` contains canonical Organization, Workspace, Environment, and
flag key strings. It does not contain the code default: fallback authority
stays in the product layer. `DriverDecision` echoes those four ownership fields
and adds the boolean value, cache-hit bit, and cache age.

Product success requires an exact scope/key echo. A cache miss must report age
zero. A cache hit may report a non-negative age no greater than the configured
maximum. Negative, over-age, contradictory, partial, foreign-scope, or altered
representations are malformed and therefore select the code default.

This task carries cache metadata but implements no cache. A later adapter may
source a decision from provider state or an approved bounded cache while still
meeting this exact contract.

## Failure, deadline, and concurrency behavior

Construction rejects a nil or typed-nil driver and timeout/cache-age limits
outside their approved ranges. `Evaluate` rejects a nil context, unusable
receiver, invalid scope, or malformed key with fixed configuration/request
errors before I/O.

For a valid request, pre-cancellation, driver error, panic, deadline,
cancellation, malformed success, ownership drift, and cache-metadata drift all
produce the configured default and no provider error. The evaluator invokes
the driver at most once under one total bounded context and retains no mutable
request state, so independent calls are concurrency-safe. Raw provider errors,
identifiers, cache contents, endpoints, credentials, and arbitrary properties
never cross the public boundary.

## Verification and scope boundary

Hermetic Go tests use a deterministic fake driver to prove:

- every invalid scope/key is rejected before I/O;
- the exact scope/key is forwarded once without the code default;
- exact provider/cache metadata is accepted;
- cache contradictions, ownership drift, cancellation, timeout, driver error,
  panic, typed nil, and malformed success return the exact configured default;
- provider values equal to the default are not mislabeled as fallback; and
- concurrent calls are race-safe and retain per-call defaults.

Repository contracts expose a root `featureflags:test` command and keep M1-19
Pending. M1-18 performs no Docker, network, cloud, database, credential,
provider, or shared-resource I/O. It may move to Complete only after genuine
compiler RED/GREEN evidence, six focused race passes, full platform/repository
gates, dependency and secret audits, zero-finding review, push, and exact-SHA
Runnable UI success.
