# M1-20 AI Gateway Contract Design

## Decision

Add a dependency-free `services/platform/aigateway` package that owns the
product AI-egress boundary. `AIGateway` accepts one typed, scoped request only
after its purpose and data-policy metadata validate. The package exposes no
arbitrary prompt map, provider-native request, raw evidence collection,
credential, endpoint, model selector, tool catalog, URL, or executable action.

The initial production catalog approves only `finding_explanation`. Although
the M0-21a proof established a safe synthetic planner boundary, production
Security Agent planning depends on later typed plan/action domains and is not
pre-authorized here. `security_plan`, chat, code generation, summarization, and
every unknown purpose therefore fail before driver I/O. Adding a purpose
requires an explicit source and test change.

Embedding OpenRouter is rejected because M1-20 defines a provider-neutral
product contract, not an adapter. Hosted delivery, provider selection, model
routing, retry, fallback, streaming, caching, persistence, token accounting,
and planner authorization are deferred. OpenRouter remains optional and off
when Organization policy does not approve AI egress.

## Product contract

The package exports:

```go
type AIGateway interface {
    Generate(context.Context, domain.Scope, Request) (Result, error)
}

type Purpose string

const PurposeFindingExplanation Purpose = "finding_explanation"

type Request struct {
    Purpose         Purpose
    SubjectID       domain.ProductID
    RedactedSummary string
    DataPolicy      DataPolicyMetadata
}

type Result struct {
    Purpose           Purpose
    SubjectID         domain.ProductID
    SchemaVersion     string
    Explanation       string
    Recommendation    string
    DataPolicyVersion string
}
```

The request uses an exact product scope and product subject ID. The redacted
summary is a bounded UTF-8 product-generated value, not a raw prompt or raw
evidence payload. It must be 1 to 2,048 bytes, have no leading/trailing
whitespace, and contain no control characters. Empty, malformed, oversized,
or invalid summary input fails before I/O.

The initial result schema is exactly version `1`. Explanation and
recommendation are separately bounded UTF-8 product values with the same
control and whitespace restrictions. The result must echo the request purpose,
subject ID, and data-policy version exactly. This contract does not make AI
text authoritative: deterministic policy, authorization, action execution,
and observed verification remain outside the gateway.

## Data-policy metadata

Every request carries a complete product-owned policy record:

```go
type ContentMode string
type RetentionMode string

const ContentModeRedactedSummary ContentMode = "redacted_summary"
const RetentionModeNoProviderStorage RetentionMode = "no_provider_storage"

type DataPolicyMetadata struct {
    Version             string
    ApprovedPurpose     Purpose
    ContentMode         ContentMode
    EgressApproved      bool
    SecretsExcluded     bool
    PIIExcluded         bool
    PHIExcluded         bool
    RawEvidenceExcluded bool
    RetentionMode       RetentionMode
}
```

The version follows the bounded lowercase product-token grammar. The approved
purpose must equal the request purpose. Content mode must be
`redacted_summary`; egress approval and every exclusion must be true; retention
must be `no_provider_storage`. Zero values, unknown enum values, a purpose
mismatch, or any false safety assertion fail closed before driver I/O. ZDR is
not represented as a BAA or compliance claim; provider and contractual review
remain separate deployment prerequisites.

## Driver boundary

Construction accepts a driver and one positive total timeout no greater than
30 seconds:

```go
type Driver interface {
    Generate(context.Context, DriverRequest) (DriverResult, error)
}
```

`DriverRequest` is a fresh typed copy of the exact scope IDs, purpose, subject,
redacted summary, and data-policy fields. It contains no map or provider-native
property bag. `DriverResult` is the exact typed response envelope. The product
validates it into `Result`; unknown provider response fields never enter this
contract.

A valid request makes at most one driver attempt under the total deadline.
Generation is not assumed idempotent, so there is no retry. Provider errors,
panic, timeout, cancellation, malformed output, identity drift, schema drift,
or policy-version drift return one fixed generation error. Raw provider errors
and content never cross the failure boundary. The implementation retains no
mutable per-request state and is safe for concurrent independent calls.

## Failure and authority boundary

Construction, request validation, and result validation use fixed sentinel
errors for configuration, request, and generation failure. Nil context,
unusable receiver, invalid scope, unapproved purpose, malformed subject,
incomplete policy metadata, or unsafe summary are rejected without invoking
the driver.

The gateway has no authority to authorize an action, choose an arbitrary
network destination, resolve a secret, evaluate deterministic security policy,
approve data egress, or persist raw input/output. Callers may surface a fixed
planner-unavailable state, but an unavailable or disallowed gateway cannot
weaken already-deployed deterministic enforcement.

## Verification and scope boundary

Hermetic Go tests use a deterministic fake driver and prove:

- exact request copying and exact structured result validation;
- unapproved, zero, forged, or mismatched purposes fail before driver I/O;
- every missing, false, unknown, or mismatched data-policy field fails closed;
- malformed scope, subject, summary, result, schema, and policy echo fail;
- nil context/driver, timeout, cancellation, panic, and acknowledgement drift
  return fixed errors with one attempt and no retry; and
- independent concurrent calls are race-safe.

Repository contracts expose one hermetic root command and keep M1-21 Pending.
M1-20 performs no Docker, network, cloud, database, credential, provider, or
shared-resource I/O. It may move to Complete only after genuine compiler
RED/GREEN evidence, six focused race passes, full platform/repository gates,
dependency and secret audits, zero-finding review, push, and exact-SHA Runnable
UI success.
