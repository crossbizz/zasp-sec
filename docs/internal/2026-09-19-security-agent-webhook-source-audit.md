# M7A-24 webhook source audit

Read-only inspection in the shipping worktree, September 19, 2026. This is
preparation for the original dependent task after M7A-23, not implementation,
new test evidence, a selected design or permission to enable the catalog.

Original requirement: register send_response_webhook with a configured
allowlisted destination; reject arbitrary URL arguments; redact and sign the
payload. Production execution must preserve tenant scope and durable retries.

## Current component boundary

`services/platform/securityagent/builtin_actions.go` defines destination_id and
evidence_id, validates evidence by a run-ID prefix, and signs a fixed four-field
event with HMAC-SHA256. Its result cache is an in-memory map. The signer accepts
only destinationID, without an explicit tenant scope in its interface. This
does not itself establish persisted destination ownership or evidence membership.

Source search finds WebhookSigningSecret's concrete implementation only in
automation_test.go, and RegisterResponseActions callers only in tests.
action_readiness.go retains component-only/no-autonomy publication status for
this action. Keep that status until the connected implementation is verified.

## Existing code to inspect for reuse

`services/platform/apiserver/integration_webhook.go` has real repository
reservation/completion/status operations with scope, integration version,
payload digest, delivery identity and lease. Its service uses a secret resolver,
bounded delivery and separate finalization time, and clears resolved secret
bytes. It is specifically an integration test event, not the response action.
Do not invoke it unchanged and call that a Security Agent response delivery.

`services/platform/apiserver/finding_ticket_webhook.go` already supplies shared
production transport for finding tickets, approval notifications and integration
tests. It denies redirects, checks configured CIDRs and all DNS answers, rejects
private/loopback addresses, pins the dialed IP while preserving TLS hostname,
disables ambient proxies, bounds request/response duration and bytes, and signs
payloads with delivery/digest headers. This is a reuse candidate, not a reason
to copy a second unrestricted HTTP client into the action worker.

The three event methods have distinct event/header and response contracts.
The integration-test method expects HTTP204 with an empty body; that alone is
not a cryptographically signed receiver acknowledgement. Any chosen response
action contract must state exactly what its delivery receipt proves, and must
not equate successful HTTP delivery with remediation or downstream execution.

## Remaining integration questions and acceptance

Resolve the actual configured destination/version and secret reference under
current full tenant scope; never accept caller/model URLs, payloads or signing
material as authority. Resolve evidence membership from M7A-23's persisted
run-evidence mapping rather than string prefixes. Freeze the authorized,
redacted payload/digest and delivery identity before dispatch.

The design must specify behavior for secret/destination rotation, permission
revocation, worker restart, expired lease, stop, receiver acknowledgement loss
and database receipt loss. An in-memory cache cannot settle these questions.
Use stable delivery identity and explicit uncertainty; do not claim exactly-once
receiver side effects without a receiver contract that proves it.

Reuse the existing registered PostgreSQL and controlled HTTP test patterns in
integration_webhook_postgres_test.go and finding_ticket_webhook_test.go. Required
new acceptance connects actual agent dispatch and durable receipt/replay with
foreign-scope, URL/redirect/DNS denial, redaction, signature verification and
lost-response cases. Controlled receivers remain local evidence. Do not send
real customer webhooks or provision secrets during this source audit.
