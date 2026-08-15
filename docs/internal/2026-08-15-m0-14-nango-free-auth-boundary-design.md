# M0-14 Nango free Auth boundary design

## Decision

M0-14 records the validated MVP feature boundary for exact-pinned Nango
v0.70.5. It consumes the completed M0-14a boot, M0-14b OAuth, and M0-14c
API-key proofs and makes one bounded product decision: the free self-hosted
runtime is accepted only for long-tail Auth plus the Proxy surface that M0-15
still has to prove.

This task adds no new provider call, Docker lifecycle, credential path, or
customer state. The three completed proofs are the runtime evidence; M0-14 is
the product-boundary record that prevents unsupported Nango features from
becoming accidental MVP dependencies.

## Considered approaches

### Selected: evidence-only boundary consolidation

Record the exact accepted and excluded surfaces in one design, one
implementation plan, the operator README, the authoritative tracker, and a
repository contract. Bind each accepted claim to completed proof evidence and
leave the unproved Proxy claim pending M0-15.

This matches the source task's deliverable, avoids another disposable runtime,
and keeps the claim narrower than the evidence.

### Rejected: excluded-route runtime probing

Calling Functions, Webhooks, or MCP routes could show a particular response in
one pinned runtime, but the source task asks to mark those surfaces out of
scope, not to prove every route absent. A route probe would confuse product
scope with implementation reachability and create an unsupported security
claim.

### Rejected: a fourth Nango evidence aggregator

A command that reruns the three hermetic or live proof suites would add
orchestration without new evidence. Existing root commands and immutable
delivery SHAs already provide independently repeatable evidence.

## Accepted MVP boundary

The product may use the exact free self-hosted Nango v0.70.5 boundary for:

- long-tail OAuth connection authorization that returns a durable opaque
  connection reference;
- long-tail API-key connection authorization where Nango owns encrypted
  credential state and product state keeps only a durable opaque connection
  reference;
- the authenticated Proxy surface only after M0-15 proves one provider GET
  without product persistence of the raw provider token.

Core launch connectors remain product-owned and bypass Nango. OAuth or API-key
availability is not evidence of full connector depth, normalized security
semantics, sync coverage, webhook processing, or function execution.

## Explicitly excluded surface

MVP does not invoke, depend on, expose, or claim support for:

- Nango Functions or function runners;
- Nango Webhooks as a product delivery or ingestion dependency;
- the Nango MCP server or MCP tools;
- Nango RBAC;
- Nango full observability, Elasticsearch, or logs UI;
- Nango Enterprise-only features;
- Connect UI, jobs/orchestrator services, Redis, or other optional runtime
  components omitted by the accepted two-service boot boundary.

“Out of scope” is a product dependency and support statement. It is not a
claim that every corresponding route or source module is absent from the
image.

## Evidence chain

M0-14 accepts only these completed facts:

1. M0-14a proved the exact free self-hosted server and PostgreSQL dependency
   reach database-backed readiness on a private internal product network with
   no host publication.
2. M0-14b proved one private OAuth authorization-code and PKCE connection and
   a durable Organization-scoped connection reference without product
   persistence of provider credentials.
3. M0-14c proved one private API-key connection, exact single-use provider-key
   verification, a durable Organization-scoped connection reference, and no
   raw provider key in product state.
4. All three proofs completed exact cleanup, zero-resource audits, pinned
   repository gates, secret/license checks, and zero-finding final review.

The boundary record references these facts without copying credentials,
container identifiers, fixture artifacts, or provider responses.

## Status and risk handling

M0-14 moves from Pending to In progress while the design, contract, and record
are reviewed, then to Complete after focused and full repository verification
and zero-finding review. This is a documentation-and-contract task, so it does
not require another live Nango run.

R-08 remains Not run throughout M0-14. M0-15 alone may advance R-08 after it
proves one authenticated provider GET through the accepted Proxy surface and
proves product code never persists the raw provider token.

M0-09 and PROV-01 remain Blocked, R-03 remains incomplete, and no unrelated
task changes status.

## Contract and failure behavior

The repository contract must reject:

- a missing or duplicate M0-14 tracker row;
- any simultaneous In progress task;
- count drift from the exact one-task transition;
- wording that claims Functions, Webhooks, or MCP are supported or proved
  absent;
- wording that marks R-08 PASS or starts M0-15;
- loss of the Auth-plus-Proxy-only product boundary;
- regression of M0-14a, M0-14b, or M0-14c completion.

The contract is deterministic, filesystem-only, and uses no Docker, network,
provider, environment credential, or generated artifact.

## Verification and completion

Completion requires a genuine contract RED before the boundary/status record,
focused GREEN, affected Nango/status regression tests, full pinned repository
verification, production dependency audit, whitespace and redacted secret
scans, and a read-only review with no remaining Critical, Important, or Minor
finding. The exact completion SHA is then pushed and its Runnable UI run is
watched to terminal success before M0-15 starts.
