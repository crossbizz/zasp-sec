# M1-19 Analytics Contract Design

## Decision

Add a dependency-free `services/platform/producttelemetry` package that owns
the product analytics boundary. `ProductTelemetry` records one closed catalog
event for an exact product scope. A product-owned allowlist serializer copies
only validated primitive values into a typed driver record; it never forwards
a caller map, arbitrary object, vendor property bag, or unknown field.

The first catalog event is `proof_completed`, matching the reviewed M0-20
privacy proof. It contains exactly a bounded product `source` token and a
boolean `success` value. Adding another event or field requires a source change
and tests. Prompt text, secrets, IP addresses, raw evidence, arbitrary context,
person profiles, feature-flag data, and vendor-native properties are not in the
catalog and therefore fail before driver I/O.

Embedding PostHog is rejected because M1-19 defines a provider-neutral product
contract, not an adapter. PostHog remains optional. Hosted delivery,
aggregation, batching, retries, persistence, background flushing, consent
policy, and a provider adapter are deferred.

## Product and field contract

The package exports:

```go
type ProductTelemetry interface {
    Track(context.Context, domain.Scope, Event) error
}

type Event struct {
    Name   EventName
    Fields []Field
}

type EventName string

const EventProofCompleted EventName = "proof_completed"

func TextField(name, value string) Field
func BooleanField(name string, value bool) Field
```

`Field` has an opaque tagged representation. Callers can name a prospective
field, but cannot forge its value kind or populate both text and boolean
storage. The serializer requires exactly one `source` text field and exactly
one `success` boolean field. Missing, duplicate, unknown, wrong-kind, zero,
malformed, or surplus fields fail closed. Field order does not affect the
canonical output.

`source` follows the existing bounded lowercase product-token grammar: 1 to 63
ASCII bytes, beginning with a lowercase letter, with lowercase letters or
digits separated by a single `.`, `_`, or `-`. Whitespace, controls, Unicode
aliases, uppercase text, empty segments, and repeated/edge separators fail.

## Allowlist serializer and driver boundary

The public serializer contract is:

```go
type EventSerializer interface {
    Serialize(domain.Scope, Event) (DriverRecord, error)
}

func NewAllowlistSerializer() EventSerializer
```

Successful serialization returns a fresh typed `DriverRecord` containing only
canonical Organization, Workspace, and Environment identifiers; an
Organization-derived pseudonymous distinct ID; the exact event name; fixed
`ProcessPersonProfile=false`; source; and success. There is no arbitrary
properties collection in the driver type.

The telemetry implementation delegates that record to:

```go
type Driver interface {
    Capture(context.Context, DriverRecord) (DriverCaptured, error)
}
```

The acknowledgement must echo every record field exactly. Its two boolean
fields use required pointer presence so an omitted `false` cannot collapse into
a valid zero value. The driver receives no raw input fields, unknown values,
credentials, endpoint, code default, prompt, secret, IP address, or evidence
payload.

## Failure, deadline, and concurrency behavior

Construction requires a non-nil driver and one positive total operation
timeout no greater than 30 seconds. `Track` rejects a nil context, unusable
receiver, invalid scope, invalid catalog event, or unknown field with fixed
configuration/event errors before I/O.

A valid event makes at most one driver attempt under the total deadline.
Provider error, panic, timeout, cancellation, or malformed acknowledgement
returns one fixed capture error. There is no retry because a capture is a
non-idempotent mutation. Raw provider errors and identifiers never cross the
product boundary. The implementation retains no mutable request state, so
independent calls are concurrency-safe.

Analytics is optional and non-authoritative. It never controls authentication,
scope, policy, enforcement, data access, credentials, feature-flag evaluation,
audit emission, or another deterministic security decision. A caller may
observe the fixed capture error, but product correctness must not depend on a
successful analytics export.

## Verification and scope boundary

Hermetic Go tests use a deterministic fake driver and direct serializer calls
to prove:

- exact canonical serialization and acknowledgement;
- missing, duplicate, unknown, wrong-kind, malformed, and surplus fields fail
  before driver I/O;
- prohibited prompt, secret, IP, evidence, context, person-profile,
  feature-flag, and vendor-native names are rejected;
- every scope, event-name, source-token, receiver, timeout, driver, panic,
  cancellation, and acknowledgement boundary fails closed;
- field order produces the same typed driver record; and
- concurrent calls are race-safe and never share caller state.

Repository contracts expose one hermetic root command and keep M1-20 Pending.
M1-19 performs no Docker, network, cloud, database, credential, provider, or
shared-resource I/O. It may move to Complete only after genuine compiler
RED/GREEN evidence, six focused race passes, full platform/repository gates,
dependency and secret audits, zero-finding review, push, and exact-SHA Runnable
UI success.
