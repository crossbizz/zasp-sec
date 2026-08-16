# M1-29 System Health Aggregator Design

## Goal and boundary

M1-29 defines one dependency-free system-health value model and aggregation
rule in the existing shared `services/health` module. Each component reports an
exact Healthy, Degraded, or Unavailable state together with whether the
component is required, a product-owned reason code, and its last successful
observation. Aggregation distinguishes required failures from optional
failures without hiding either one.

This task does not poll dependencies, open a listener, change `/healthz` or
`/readyz`, serialize an HTTP response, read configuration, call a provider,
persist state, or add deployment manifests. M1-30a remains Pending. M0-09,
M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **Extend the standalone `services/health` module (selected).** The model is
   pure, shared by all four commands, and independent of platform storage or
   transport code. Later tasks may consume it without importing the larger
   platform module.
2. **Add the model under `services/platform`.** This follows the current
   control-plane package layout but would couple event-ingest and
   runtime-gateway consumers to the platform module.
3. **Document the state table without executable types.** This is smallest in
   file count but cannot prove required-versus-optional aggregation or reject
   malformed state.

The shared module is the narrowest executable boundary and matches the health
handler introduced by M1-28a.

## Public value model

Add `aggregate.go` to the `health` package with these public types and values:

```go
type Status string

const (
    StatusHealthy     Status = "healthy"
    StatusDegraded    Status = "degraded"
    StatusUnavailable Status = "unavailable"
)

type Requirement string

const (
    RequirementRequired Requirement = "required"
    RequirementOptional Requirement = "optional"
)

type Component struct {
    Name        string
    Requirement Requirement
    Status      Status
    Reason      string
    LastSuccess time.Time
}

var ErrInvalidComponent = errors.New("invalid health component")
var ErrInvalidAggregation = errors.New("invalid health aggregation")

func NewComponent(
    name string,
    requirement Requirement,
    status Status,
    reason string,
    lastSuccess time.Time,
) (Component, error)
func (component Component) Validate() error
func Aggregate(components []Component) (Status, error)
```

`Component` is a comparable value and the package retains no caller-owned
slice, pointer, callback, or mutable collection. Constructors return a zero
component and the exact sentinel error on invalid input. Directly constructed
values must pass the same `Validate` boundary before aggregation.

## Exact component invariants

`Name` is 1-64 lowercase ASCII alphanumeric characters in nonempty segments
separated by single hyphens, using the existing health service-name grammar.
`Requirement` and `Status` accept only the declared constants.

`Reason` is empty only for Healthy. Degraded and Unavailable require a
1-64-character product-owned reason code made of lowercase ASCII alphanumeric
segments separated by single underscores. Raw provider errors, prose, customer
values, whitespace, punctuation, and control characters are rejected.

`LastSuccess` is required for Healthy. Degraded and Unavailable may use the
zero value only to mean the component has never succeeded. Every nonzero value
must be an exact four-digit-year UTC timestamp at millisecond precision, with
no monotonic component or alternate location. The model does not compare the
timestamp with wall-clock time; freshness policy belongs to the observer that
creates the component.

## Aggregation semantics

`Aggregate` validates every component before deriving state. It rejects an
empty list, duplicate names, and a list with no required component. It does not
sort, mutate, retain, or serialize the input.

The precedence is exact:

1. Any required Unavailable component makes the system Unavailable.
2. Otherwise, any Degraded component or optional Unavailable component makes
   the system Degraded.
3. Otherwise, every component is Healthy and the system is Healthy.

A required Degraded component therefore remains visible as Degraded rather
than being collapsed into Unavailable. An optional Unavailable component never
makes the whole system Unavailable, but it also never permits a false Healthy
result. Invalid input returns only `ErrInvalidAggregation` and the zero status.

## Security and failure behavior

The package performs no file, environment, clock, provider, credential,
database, Docker, subprocess, or network operation. Strict names and reason
codes prevent raw provider or customer data from entering the model. The pure
aggregation function is deterministic and race-safe for independently owned
input values.

This model is not itself a readiness decision. M1-29 records system health;
later command or deployment work must explicitly decide whether and how a
particular aggregate affects process readiness.

## Verification and completion

`aggregate_test.go` proves exact construction, direct-state validation,
canonical time handling, reason/name grammars, duplicate and missing-required
rejection, input immutability, deterministic concurrency, and the full
required/optional precedence matrix. The existing root
`npm run health:contract:test` race gate covers the new package tests without
adding another command.

Completion requires witnessed tests-only RED, six focused race passes, module
tidy-diff/verify/vet, all four health-command race suites, full pinned
repository verification, dependency/audit/whitespace/secret gates,
zero-finding independent review, push, and exact-SHA Runnable UI success.

M1-29 starts at `662/1/62/3` overall and `68/29/1/38/0` for M1. Completion
changes those values to `662/0/63/3` and `68/29/0/39/0`. M1-30a remains
Pending.
