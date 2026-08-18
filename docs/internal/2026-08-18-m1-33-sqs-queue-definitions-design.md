# M1-33 SQS Queue Definitions Design

## Decision

Add one dependency-free `services/platform/queuedefinition` package that owns
the exact version-1 product definitions for the three SQS workloads named by
the source plan:

- `agentsec-background` with `agentsec-background-dlq`;
- `agentsec-runtime-events` with `agentsec-runtime-events-dlq`; and
- `agentsec-tests` with `agentsec-tests-dlq`.

All six are Standard queues. The package is immutable provider-neutral
configuration: it constructs no AWS client and performs no network or provider
operation. A new exact-pinned disposable LocalStack mode provisions the six
definitions, reads every queue, DLQ, tag, retention setting, and redrive policy
back, then removes only freshly re-proved proof-owned queues.

The alternatives are rejected. M1-33 will not add Terraform before M1A-04,
reuse a shared development LocalStack instance, widen the M1-13 `JobQueue`
interface, define consumers, implement Organization-envelope enforcement before
M1-41, or claim production queue hardening before M8-03.

## Product contract

```go
var ErrDefinitions = errors.New("queue definitions rejected")

type Kind string

const (
    KindBackground    Kind = "background"
    KindRuntimeEvents Kind = "runtime_events"
    KindTests         Kind = "tests"
)

type Settings struct {
    MessageRetentionSeconds    int
    DeadLetterRetentionSeconds int
    VisibilityTimeoutSeconds   int
    DeadLetterVisibilityTimeoutSeconds int
    ReceiveWaitSeconds         int
    MaximumMessageBytes        int
    DelaySeconds               int
    MaxReceiveCount            int
}

type Definition struct { /* private exact state */ }

func Definitions() []Definition
func (Definition) Validate() error
func (Definition) Kind() Kind
func (Definition) Name() string
func (Definition) DeadLetterName() string
func (Definition) SchemaID() string
func (Definition) RequiredFields() []string
func (Definition) Settings() Settings
func JSON() ([]byte, error)
```

`Definitions` is the only constructor. It returns a fresh three-element slice
in background, runtime-events, tests order. A zero or forged `Definition`
rejects; its accessors return zero values. `RequiredFields` and `JSON` return
fresh values on every call. The exact compact JSON plus one newline gives M1A-04
and later configuration code a deterministic reviewed artifact without exposing
mutable internal state.

## Exact message schemas

The definitions freeze schema metadata; they do not serialize, accept, or
authorize customer payloads. Each schema has exactly seven required top-level
fields in this canonical order:

| Queue | Schema ID | Required fields |
| --- | --- | --- |
| `agentsec-background` | `agentsec.background.v1` | `version`, `organization_id`, `workspace_id`, `environment_id`, `job_id`, `kind`, `payload` |
| `agentsec-runtime-events` | `agentsec.runtime-events.v1` | `version`, `organization_id`, `workspace_id`, `environment_id`, `batch_id`, `event_count`, `events` |
| `agentsec-tests` | `agentsec.tests.v1` | `version`, `organization_id`, `workspace_id`, `environment_id`, `test_run_id`, `kind`, `payload` |

`organization_id`, `workspace_id`, and `environment_id` are present in every
schema because the architecture requires scoped messages. Presence in metadata
is not an authorization check. M1-41 remains responsible for validating that a
consumer's expected Organization exactly matches the received envelope before
side effects. M2 tasks remain responsible for runtime-event batching and worker
execution semantics.

The background schema intentionally matches the existing M1-13 `JobQueue`
envelope. Runtime events have one batch identity, count, and bounded event array;
they are not one message per syscall. Tests have a typed test-run identity and
payload. Arbitrary dynamic fields, nested schema additions, provider-native
identifiers, raw credentials, and schema aliases are not part of these
definitions.

## Exact baseline settings

Every source queue has these explicit baseline settings:

- `MessageRetentionPeriod=345600` seconds (4 days);
- `ReceiveMessageWaitTimeSeconds=20`;
- `MaximumMessageSize=262144` bytes;
- `DelaySeconds=0`;
- `maxReceiveCount=5`; and
- one exact paired Standard DLQ.

Every DLQ has `MessageRetentionPeriod=1209600` seconds (14 days),
`ReceiveMessageWaitTimeSeconds=20`, `MaximumMessageSize=262144`,
`DelaySeconds=0`, `VisibilityTimeout=30`, and a `byQueue` redrive-allow policy
naming only its paired source ARN. Source visibility timeouts match the baseline
workload:

| Queue | Visibility timeout |
| --- | ---: |
| `agentsec-background` | 300 seconds |
| `agentsec-runtime-events` | 120 seconds |
| `agentsec-tests` | 900 seconds |

AWS currently allows retention from 60 through 1,209,600 seconds and long-poll
waits from 0 through 20 seconds. Its DLQ guidance recommends retaining DLQ
messages longer than source messages. The explicit baseline follows those
bounds while leaving production tuning, encryption, least-privilege IAM, alarm
thresholds, and redrive operations to M8-03 and staging infrastructure to
M1A-04:

- https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
- https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
- https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html

## Determinism and rejection

The product package uses fixed structs and `[7]string` field arrays. Validation
compares every scalar and required-field position against the canonical value.
Exact names, suffixes, schema IDs, ordering, settings, and field membership are
closed. JSON uses private serialization structs and returns only
`ErrDefinitions` on invalid or impossible serialization state.

Tests independently pin exact bytes and hostile mutations. They reject missing,
extra, reordered, duplicated, dotted, control-bearing, invalid UTF-8, and
oversized schema fields; unknown kinds; queue/DLQ name drift; retention,
visibility, wait, message-size, and retry drift; zero/forged state; returned
slice mutation; and nondeterministic output. Error text contains no rejected
content.

## Disposable LocalStack proof

Extend the reviewed M1-13 LocalStack runner with one `queue-definitions` mode:

- image remains exact
  `localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c`;
- only SQS is enabled, persistence is disabled, and
  `SQS_ENDPOINT_STRATEGY=dynamic` remains explicit;
- the container name and labels use the separate `zasp-m1-33-<marker>` and
  `zasp.proof=m1-33` namespace;
- only the random numeric-loopback published port is used;
- build and child environments remain allowlisted and proxy/profile/credential
  state is absent; and
- output is exactly one fixed success or fixed-category rejection line.

The child creates DLQs before sources. Each queue carries exact proof marker,
proof, role, kind, schema, and paired-name tags. Source creation includes the
exact scalar settings plus redrive policy; each DLQ receives an exact `byQueue`
redrive-allow policy. The proof lists the LocalStack account, requires exactly
the six canonical names, and reads back exact URLs, ARNs, tags, Standard-queue
state, scalar attributes, source redrive policies, and DLQ allow policies.

Mutation calls execute once. Definitive create/delete rejection is not adopted;
thrown, timed-out, signaled, or malformed-success outcomes enter bounded exact
name/URL/ARN/tag/attribute reconciliation. Candidate authority is retained
before interpreting every mutation result. Cleanup runs independently in
source-first then DLQ order, continues after failures, and accepts deletion only
after exact absence. Final audit requires all six exact names and the global
M1-33 proof prefix absent. Cleanup failure wins.

The orchestrator removes only its freshly re-proved exact-owned container and
owned temporary build directory. It proves container and temp absence and never
selects a shared LocalStack container. No real AWS, `.env`, profile, IMDS,
proxy, provider credential, or ambient Docker authentication is read.

## Verification and completion

Hermetic tests cover the product value, exact JSON, LocalStack lifecycle,
definitive and ambiguous mutations, delayed visibility, foreign replacement,
cleanup continuation/precedence, prefix-wide audit, runner mode, fixed output,
and no ambient authority. The opt-in live command must provision and re-read all
three queues plus all three DLQs, then leave zero M1-33 queues, containers, and
temporary roots while any known shared LocalStack fingerprint remains
unchanged.

Root commands will be:

```bash
npm run sqs:definitions:test
npm run sqs:definitions:run
```

M1-33 may move to Complete only after genuine RED/GREEN, six focused passes,
the exact live proof, cleanup audit, full Go and repository gates, dependency
and production-audit checks, pinned secret scans, zero-finding whole-range
review, push, and exact-SHA Runnable UI success. M1-34 remains Pending.
