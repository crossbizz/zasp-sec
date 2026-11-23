# Governed SQLite workflow inbox

Use this adapter when your application delivers agent work through a local SQLite inbox under the queue owner's control. Each delivery first requests a scoped ToolGuard decision from Zasp. The target then checks its signed run policy, applies the route's local controls and commits the message, action meter and local receipt in one transaction. Product evidence names this adapter `zasp.sqlite-workflow.v1`.

## Connect a staging queue

Construct `Scope(tenant, session, run, principal, audience)` from the authenticated host's identity and deployment configuration. Bind its ToolGuard to that workload's Zasp credential. Provision the SQLite database in a directory writable only by the trusted queue service. Keep the administrative interface, signing services and the raw database handle outside the agent's callable tools. The producer can submit a named request to an authorized route.

```python
from time import time
from zasp_guardrails import ToolGuard
from zasp_guardrails.workflow import (
    Attestation, Request, Route, RunPolicy, Scope, SQLiteWorkflowInbox, SQLiteWorkflowTarget,
)

scope = Scope(tenant_id, session_id, run_id, authenticated_host, "staging-ticket-queue")
route = Route("approval", "ticket.update", "support-agent")
now = int(time())
policy = RunPolicy(scope, "resolve-ticket", 1, now, now + 900, (route,),
                   max_actions=10, max_children=2, max_attempts=2, failure_limit=3)
# The run authority approves this policy in its trusted process.
run_signature = policy.sign(run_key)

# The receiving service provisions this route and configures local IAM.
queue = SQLiteWorkflowInbox(queue_database)
queue.set_route(tenant=scope.tenant, audience=scope.audience,
                destination="support-agent", available=True)
target = SQLiteWorkflowTarget(
    ToolGuard(zasp_origin, workload_token), queue, scope=scope,
    run_key=run_key, evidence_key=receipt_key,
    approvers={"review-ui": review_key}, senders={"service-agent": sender_key},
)

request = Request("ticket-update-17", route, policy.purpose, b"synthetic approved update")
# The approval service displays the actual scope, request.presented() fields,
# original message, and expiry to the authenticated reviewer before signing.
proof = Attestation.issue(policy, request, issuer="review-ui",
                          issued_at=now, expires=now+120, key=review_key)
ordinal = target.submit(policy, run_signature, request, attestation=proof)
```

Use separate, randomly generated keys of at least 32 bytes for the run authority, receipt references, each approval service and each sending agent. Attestation verification uses HMAC-SHA-256 between trusted services that share each dedicated secret. Scope and a content digest are part of every approval and handoff. In the approval example, the reviewer-facing UI and identity authentication belong to the host application's approval service. The target verifies that service's attestation. It does not record an individual reviewer's comprehension.

## Observe a result

| Route | Control exercised at this target | Evidence |
| --- | --- | --- |
| `purpose` | Match the declared purpose, operation, recipient, authenticated scope and time window. | A changed purpose or destination leaves the inbox unchanged. Intent behind the request remains unknown. |
| `approval` | Verify the approval service's signature over the exact action, recipient, payload digest, scope, policy revision, request ID and expiry. | An altered input requires a fresh attestation. |
| `handoff` | Verify the message from a configured sender and bind it to the receiving principal, target audience, destination and expiry. | An identical retry returns the existing delivery ordinal. A different recipient or sender fails authentication. |
| `child` | Bind child to the signed run's root or a committed parent. Count fan-out once per child and reserve attempts under a write transaction. | A paused destination produces a refusal. The circuit opens after consecutive failures. The per-run open circuit requires a new authorized run. |
| `budget` | Meter committed inbox actions against the signed per-run action limit. This meter applies to every route. | Concurrent retries of one logical request count once. A separate recipient readback can reconcile unique deliveries against the meter. |

Reuse the request ID for retries of the same logical delivery. Reuse the same database across workers and restarts. Distinct destinations require distinct signed routes. Conflicting policies for an active run fail closed. The host can recover from a paused recipient with `set_route(..., available=True)`. A new run is needed after a circuit opens or a run expires.

Successful delivery returns the durable per-run ordinal. `WorkflowDenied` carries a bounded local refusal reason. The queue operator can inspect `workflow_receipts` and independently query the authorized tenant/audience/destination with `queue.deliveries(...)`. A missing meter, an unregistered recipient or a database failure raises `WorkflowUnavailable` and cannot produce a target receipt. A central policy denial never enters the target transaction.

Zasp receives the workflow control kind, a keyed run/revision reference, a keyed request reference, the outcome and a receipt digest. The target stores the message locally for the recipient. Observation covers the inbox boundaries configured here. Verifying a subsequent ticket write, provider token use, external spend or a delivery through another channel requires evidence from that respective target.
