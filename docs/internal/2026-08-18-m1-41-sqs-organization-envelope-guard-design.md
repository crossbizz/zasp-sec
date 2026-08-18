# M1-41 SQS Organization Envelope Guard Design

## Decision

Add an Organization-bound envelope consumer beside the existing M1-13
`JobQueue` in `services/platform/jobqueue`. The consumer validates one complete
background, runtime-event, or test envelope and compares its canonical
`organization_id` with the immutable Organization identity supplied when the
consumer is constructed. Only an authorized envelope can cross the handler
boundary.

Do not change the M1-13 `JobQueue` or provider `Driver` interfaces, add a
worker loop, contact SQS, or infer Organization identity from a queue name,
receipt, payload, session, ambient process state, or provider metadata. M1-13
remains the SQS adapter and disposable LocalStack compatibility authority;
M1-33 remains the queue-definition and provider-provisioning authority.

## Product boundary

The package adds three fixed envelope kinds:

- `background`, with the exact M1-13 outer members `version`,
  `organization_id`, `workspace_id`, `environment_id`, `job_id`, `kind`, and
  `payload`;
- `runtime_events`, with the exact M1-33 outer members `version`,
  `organization_id`, `workspace_id`, `environment_id`, `batch_id`,
  `event_count`, and `events`; and
- `tests`, with the exact M1-33 outer members `version`, `organization_id`,
  `workspace_id`, `environment_id`, `test_run_id`, `kind`, and `payload`.

`NewEnvelopeConsumer` requires one nonzero canonical product Organization ID
and one non-nil typed handler. The resulting consumer retains only those two
values. `ConsumeEnvelope` accepts a context, one exact kind, and at most
262,144 bytes. It first validates the complete outer envelope, constructs one
canonical `domain.Scope`, and compares that scope's Organization ID with the
retained worker Organization. It then calls the handler exactly once with a
fresh immutable message projection.

The projection exposes the validated kind and scope plus a defensive copy of
the original envelope bytes. It does not expose SQS message IDs, receipt
handles, queue URLs, ARNs, credentials, or provider errors. A zero projection
exposes no state.

## Strict envelope validation

Validation is complete before handler entry and has no side effects. The
consumer requires:

- valid UTF-8, one JSON object, no trailing JSON or whitespace-only aliases;
- exactly the seven kind-specific top-level keys, with no duplicate, unknown,
  missing, or alternate-cased key;
- integer `version` exactly `1` rather than a float, string, or boolean;
- canonical nonzero product IDs for Organization, Workspace, Environment, and
  the kind-specific job, batch, or test-run identity;
- one valid `domain.Scope`, including its distinct-identity invariant;
- a lowercase bounded kind token for background and test envelopes;
- a nonempty valid opaque `payload` for background and test envelopes; and
- a nonnegative integer `event_count` equal to the bounded runtime `events`
  array length.

The opaque payload and individual runtime events are not interpreted. M2
workers continue to own job-specific payload semantics and durable side
effects. JSON member order and insignificant whitespace are accepted because
they do not alter the authenticated envelope state; the original accepted
bytes are passed defensively to the handler.

## Failure, side effects, and concurrency

Configuration failure returns only `queue envelope consumer configuration
rejected`. Envelope, kind, scope, size, context, or Organization mismatch
returns only `queue envelope rejected`. A handler error, panic, or context
cancellation during handler execution returns only `queue envelope processing
failed`. Customer bytes and provider state never enter these errors.

The handler is not called for any rejected envelope. The implementation does
not acknowledge, retry, delete, or mutate a queue message. The later worker
must perform durable work and only then use M1-13's opaque receipt boundary to
acknowledge it. This preserves the existing durability order.

The consumer stores no per-message state. Concurrent calls use call-local
parsers, scopes, and defensive byte copies. Tests alternate two Organizations
through one consumer and prove that only the configured Organization reaches
the handler without cross-call contamination.

## Verification and non-goals

Hermetic tests cover all three exact envelope kinds; missing, malformed, and
mismatched Organization values; every top-level schema drift class; duplicate
JSON keys; invalid identities; size and UTF-8 bounds; canceled contexts;
handler errors and panics; defensive copies; and concurrent alternating
Organization fixtures. The binding fixture supplies an Organization-B
envelope to an Organization-A consumer and proves the handler side-effect
counter remains zero.

M1-41 is product-only. It does not run Docker or LocalStack, make a provider
request, change the M1-13 live proof, claim SQS authorization, or implement an
M2 worker. M1-42 remains Pending throughout. Completion requires the focused
race gate, full platform and inherited SQS regressions, pinned repository
verification, scans, zero-finding review, push, and exact-SHA Runnable UI
success.
