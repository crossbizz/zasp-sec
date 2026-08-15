# M1-06 Product Error Envelope Design

## Decision

Add one dependency-free opaque API error value in the platform domain package.
It exposes exactly a stable product error code, customer-facing message,
canonical product correlation ID, and retryable flag. It contains no vendor
exception, stack, cause, provider payload, credential, or arbitrary metadata.

## Product error code

`ProductErrorCode` is an opaque comparable value. Its exact text grammar is one
to 64 ASCII bytes: a lowercase letter followed by lowercase letters, digits, or
single underscore-separated segments. Empty segments, leading/trailing
underscores, case variants, punctuation, whitespace, aliases, and oversize
values fail with `ErrInvalidProductErrorCode`.

The task defines the stable code boundary, not the complete future code
catalog. Later API operations select durable product-owned codes within this
grammar.

## Envelope

`ProductErrorEnvelope` has unexported fields and is created only through
`NewProductErrorEnvelope(code, message, correlationID, retryable)`.

- `code` is a valid nonzero `ProductErrorCode`.
- `message` is valid UTF-8, trimmed, contains no control characters, and is one
  to 512 bytes. Callers must supply product language rather than a vendor error.
- `correlationID` is a distinct opaque `CorrelationID` backed by a valid
  canonical nonzero `ProductID`; it cannot be confused with an Organization,
  Workspace, Environment, or other generic product ID and is not authorization.
  Invalid construction returns the fixed `ErrInvalidCorrelationID`.
- `retryable` is an explicit boolean and is never inferred from message text.

The value is comparable, validates itself, and exposes read-only accessors.

## JSON contract

`MarshalJSON` validates first, then emits exactly this stable field order and
names with no optional or null fields:

```json
{"code":"scope_invalid","message":"Scope is invalid.","correlation_id":"pid_60000000-0000-4000-8000-000000000006","retryable":false}
```

Invalid or zero direct values return the fixed `ErrInvalidProductErrorEnvelope`
and emit no JSON. JSON decoding is deferred until a consumer contract requires
it; this task establishes the public response snapshot only.

## Safety properties

- The four-field shape cannot accumulate incidental provider/debug data.
- Fixed errors never include rejected code, message, or correlation content.
- JSON escaping is delegated to the Go standard library.
- No HTTP status mapping, handler, logging, storage, provider, credential,
  configuration, network, retry policy, or authorization behavior is added.
