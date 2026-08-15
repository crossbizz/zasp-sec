# M1-03 Canonical ID Design

## Decision

Define the first product-domain identity boundary in the existing
`services/platform` Go module under package `domain`.

`ProductID` is an opaque product-owned UUIDv4 wrapper. Its external text form is
the exact lowercase string `pid_<canonical-uuid>`. The product prefix makes a
raw vendor identifier, including a UUID-shaped vendor identifier, invalid at
the product-ID parser boundary.

`ExternalSourceRef` is a separate value containing:

- a bounded lowercase source token;
- a bounded lowercase object-kind token; and
- an exact bounded external identifier wrapped as `ExternalID`.

All fields are unexported. Values are created only through validating
constructors and exposed through read-only accessors.

## Invariants

- The zero `ProductID` is invalid and serializes to no identifier.
- New product IDs use `crypto/rand` and set RFC 4122 UUID version 4 and variant
  bits explicitly.
- Parsing accepts only the exact lowercase `pid_` plus canonical UUIDv4 form;
  uppercase, missing prefix, nil UUID, other versions, and other variants fail.
- `ProductID` and `ExternalID` have different concrete types and storage.
- Product IDs are never derived, hashed, normalized, or copied from an
  `ExternalSourceRef`.
- External identifiers remain exact after validation; leading/trailing space,
  control characters, invalid UTF-8, empty values, and values over 512 bytes
  fail closed.
- Source and kind tokens use `[a-z][a-z0-9._-]{0,62}` and remain vendor-neutral
  product metadata rather than primary identity.
- Text marshal/unmarshal round trips preserve valid product IDs and never leave
  a prior receiver value behind after invalid input.
- The package adds no third-party dependency, I/O beyond injected/random UUID
  generation, network, provider, credential, environment, or persistence
  behavior.

## API

```go
type ProductID struct { /* opaque UUID bytes */ }
type ExternalID struct { /* opaque exact text */ }
type ExternalSourceRef struct { /* opaque source, kind, external ID */ }

func NewProductID() (ProductID, error)
func ParseProductID(string) (ProductID, error)
func NewExternalSourceRef(source, kind, externalID string) (ExternalSourceRef, error)
```

`ProductID` exposes `String`, `IsZero`, and text marshal/unmarshal behavior.
`ExternalID` exposes only `String`; `ExternalSourceRef` exposes only `Source`,
`Kind`, and `ExternalID` accessors.

## Verification

Tests must prove:

- deterministic UUIDv4 generation through an injected entropy reader;
- strict canonical parse and text round trip;
- malformed, nil, non-v4, uppercase, truncated, and trailing inputs fail;
- valid and invalid external-reference boundaries;
- a vendor ARN and a UUID-shaped vendor ID both fail as product primary IDs;
- creating an external reference never creates or mutates a `ProductID`;
- entropy failure and short entropy reads return fixed errors without partial
  identity.

Only after focused stability, service regressions, full repository gates,
review, audit, scans, and exact-SHA CI may M1-03 become Complete. M1-04 remains
Pending. M0-09, M0-18, M0-19, and PROV-01 remain Blocked; R-03 remains
incomplete and R-11 remains Not run.
