# M1-05 Evidence Model Design

## Decision

Add dependency-free platform-domain values for evidence identity, correlation
confidence, and capability/path state. These values describe evidence; they do
not assign finding severity, authorize access, dereference storage, or perform
I/O.

## Evidence reference

`EvidenceRef` is an opaque comparable wrapper around one canonical nonzero
`ProductID` belonging to an EvidenceArtifact. Its text form is the underlying
exact `pid_<canonical-uuid>` so product APIs can use the same primary-ID wire
grammar without accepting arbitrary external identifiers.

The constructor and text decoder revalidate the ProductID. Rejected input
returns the fixed `ErrInvalidEvidenceRef` and the zero reference. The value
offers `ArtifactID`, `String`, `IsZero`, and strict text marshal/unmarshal
methods. A reference alone grants no access; callers must separately enforce
the M1-04 `Scope` boundary.

## Evidence confidence

`EvidenceConfidence` accepts exactly these lowercase values:

- `exact`
- `strong`
- `probable`
- `unattributed`

The zero value and every alias, case variant, whitespace variant, unknown value,
or finding-severity value are invalid. Parse and text round trips return the
fixed `ErrInvalidEvidenceConfidence` on rejection.

## Capability/path state

The canonical source defines one shared state vocabulary for capabilities and
paths. `CapabilityPathState` accepts exactly:

- `configured`
- `reachable`
- `observed`
- `verified`
- `blocked`

The zero value and all aliases/case/whitespace/unknown forms are invalid. Parse
and text round trips return the fixed `ErrInvalidCapabilityPathState` on
rejection.

## Safety properties

- Evidence confidence, capability/path state, and severity remain separate
  semantic types and vocabularies.
- Unmarshal clears the receiver before parsing and rejects nil receivers.
- All values are immutable by value, comparable, bounded, deterministic, and
  dependency-free.
- No JSON schema, storage, provider, credential, configuration, network, or
  authorization behavior is added in this task.
