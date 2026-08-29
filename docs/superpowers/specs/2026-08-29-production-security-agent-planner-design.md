# Production Security Agent Planner Design

## Scope

Promote M7A-40, M7A-41, M7A-51, and M7A-91 from component-only evidence by composing the existing Security Agent worker with a real bounded OpenRouter-compatible planner. Preserve the existing action registry, approval floors, lease fencing, idempotent execution, verification, and runtime policy enforcement. This design adds no service and no new action type.

## Authority and data flow

1. The existing worker claims a tenant-scoped Security Agent run under its PostgreSQL lease.
2. A v32 security-definer function returns one exact planner context only while that lease remains live. The context contains the scope and run identifiers, definition version, action catalog version, fixed operator goal, allowed action keys, product limits, and canonical redacted evidence records. It contains no provider credential, raw evidence body, email, secret, arbitrary URL, or foreign-tenant reference.
3. The worker sends one bounded `security_response_plan` request to the configured OpenRouter-compatible endpoint. System policy, operator goal, and untrusted evidence remain distinct JSON fields. The request uses an exact approved model, no-storage metadata, a JSON schema response format, a fixed token ceiling, one attempt, no proxy, and no redirects.
4. The worker strictly decodes one version-1 candidate plan. A candidate contains a bounded summary and one or more ordered `{index, action, target_id}` steps only. Provider prose and provider errors are never persisted.
5. A v32 security-definer function locks the run and current definition/evidence authority, reconstructs the exact allowed candidate from database state, rejects any action/target/count/version drift, records input and output digests, and only then delegates to the existing v24 preparation authority that creates the durable plan, approval, and step.
6. Network, timeout, rate-limit, denial, malformed-output, or validation failures call a separate lease-fenced v32 failure function. It records one stable `planner_unavailable` or `planner_rejected` result and one redacted audit event, clears the lease, and moves the run to `failed`. It creates no plan, step, approval, effect, provider job, or action.

## Runtime composition

The existing `security-agent` worker mode owns the planner. Its required production configuration is:

- exact endpoint `https://openrouter.ai/api/v1/chat/completions`;
- approved model token;
- token file `/var/run/secrets/zasp-security-agent/openrouter-api-token`;
- request timeout between 1 and 30 seconds;
- maximum output tokens between 1 and 4096;
- data-policy version token;
- a bounded public CIDR snapshot for TCP/443 egress.

The OpenRouter token is delivered by the existing security-agent Secrets Store CSI volume. Terraform grants that worker role access only to its PostgreSQL DSN and the OpenRouter token secret with exact KMS encryption context. The workload still has no action-worker or gateway signing authority.

Planner health is evaluated per run rather than as a pre-claim readiness dependency. This is deliberate: an unavailable planner must durably fail a newly claimed run with a visible bounded outcome instead of leaving the queue silently stuck. Constructor/configuration errors still prevent the worker from starting.

## Failure and replay semantics

- Exactly one provider request is made per claimed planning attempt.
- A lease heartbeat remains active through request and durable accept/fail finalization.
- Lost provider responses and unknown outcomes are classified as unavailable and never authorize an action.
- A duplicate durable accept or fail under the same run/attempt/output digest replays the stored result; mismatched replay fails closed.
- Lease loss prevents both accept and failure mutation.
- Existing runtime-gateway policy evaluation is independent and must return the same enforced result before, during, and after planner outage.

## Verification

- Unit tests cover request separation, header/body bounds, no proxy/redirect/retry, exact model/purpose/policy, strict response schema, cancellation, and stable redacted failures.
- Real-PostgreSQL tests cover tenant binding, lease loss, accept replay, failure replay, action/target drift, provider error terminalization, and zero plan/step/approval/effect rows on failure.
- Worker tests prove heartbeat ownership through provider failure and durable finalization.
- The production combined E2E starts a local OpenRouter-compatible endpoint that returns 503 for one newly scheduled run, executes the shipped worker composition, observes `failed|planner_unavailable`, proves zero actions/effects, and proves a previously installed runtime policy still blocks the same request.
- Release tests prove the exact token mount, model/endpoint configuration, IAM secret authority, and public non-overlapping planner egress CIDRs.

## External boundary

The local fake endpoint proves source-complete composition and failure behavior. Hosted OpenRouter credentials, live model quality, live provider rate limits, and live egress CIDR correctness remain an explicit external launch gate and do not receive production-available evidence until exercised.
