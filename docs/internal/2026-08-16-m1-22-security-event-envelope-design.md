# M1-22 SecurityEvent Envelope Design

## Decision

Add one dependency-free `services/platform/securityevent` package that owns the
canonical product event envelope before transport, OpenAPI, queue, archive,
index, or provider adapters exist. The value composes the already reviewed
`domain.Scope`, `domain.EvidenceRef`, and M1-21 `observability.Correlation`
types. It does not accept a map, provider document, raw payload, or arbitrary
metadata.

The alternative was to promote the current OpenSearch-specific `eventstore.Event`
to the product contract. That type is deliberately shaped for the M1-14
runtime-gateway proof and contains session/agent/search projection fields. A
new closed envelope avoids coupling the canonical event model to one storage
projection while preserving a narrow conversion boundary for later work.

## Public contract

```go
type Version uint8

const Version1 Version = 1

type Source string

const (
    SourceRuntimeGateway Source = "runtime_gateway"
    SourceOTLP           Source = "otlp"
    SourceTetragon       Source = "tetragon"
    SourceAttackLab      Source = "attack_lab"
)

type SecurityEvent struct {
    Version     Version
    Scope       domain.Scope
    Source      Source
    Time        time.Time
    Evidence    domain.EvidenceRef
    Correlation observability.Correlation
}

func New(
    Version,
    domain.Scope,
    Source,
    time.Time,
    domain.EvidenceRef,
    observability.Correlation,
) (SecurityEvent, error)

func (SecurityEvent) Validate() error
```

`ErrEvent` is the only public rejection error. Errors contain no rejected
field values.

## Exact invariants

- `Version` is exactly `Version1`. Zero and every unknown future value fail
  closed until an explicit source/test change defines migration behavior.
- `Scope` is one valid and distinct Organization, Workspace, and Environment
  product scope.
- `Source` is exactly one of the four initial product source values. The
  catalog corresponds to the existing runtime/event flow and does not grant an
  adapter any authorization or I/O authority.
- `Time` is nonzero, UTC, and exactly millisecond precision. Formatting with
  `2006-01-02T15:04:05.000Z` and parsing back must reproduce the same instant.
  Local zones, offsets, sub-millisecond values, and invalid direct state fail.
- `Evidence` is one valid typed product evidence reference. Raw evidence,
  provider payloads, and external identifiers are not fields in this envelope.
- `Correlation` is one valid M1-21 correlation value: canonical product
  correlation ID plus exact nonzero lowercase 32-character trace and
  16-character span identifiers.

The constructor validates first and returns either the complete value or a
zero value plus `ErrEvent`. `Validate` also rejects zero, partially initialized,
and forged direct state. The value is fully comparable and contains no slices,
maps, pointers, or mutable customer content.

## Authority and privacy boundary

This task defines a value only. It performs no JSON encoding/decoding, event
ingest, batching, queueing, archiving, indexing, graph updates, logging,
telemetry export, network, environment, credential, filesystem, database,
Docker, provider, clock, or random I/O. Callers provide the already canonical
time and product references.

M1-23 owns the OpenAPI root, and later M3 tasks own Tetragon/OTLP adapters,
ingest authorization, batching, archive/index/correlation stages, and replay.
The envelope gives none of those future components permission to include raw
prompt text, tool arguments, secret material, provider payloads, or arbitrary
customer content.

## Verification and status boundary

Hermetic Go tests construct one exact version-1 event and reject zero/unknown
versions, zero/forged/duplicate scope, unknown source, noncanonical time,
zero/forged evidence, malformed correlation, and direct partial state. Tests
also prove the exact fields are retained without mutation and concurrent value
validation is race-safe.

Repository contracts bind the M1-22 source task, M1-21 prerequisite, M1-23
Pending state, PRD Organization-scope rule, runtime flow, design, root command,
README boundary, exact tracker arithmetic, and unchanged blocked tasks. M1-22
may move to Complete only after tests-first RED/GREEN, six race passes, full
platform/repository gates, dependency and secret audits, zero-finding
whole-range review, push, and exact-SHA Runnable UI success.
