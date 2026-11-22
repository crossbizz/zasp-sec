# Zasp Python tool guard

Wrap the actual call site for an eager synchronous or asynchronous tool. Install with `python -m pip install ./sdks/python-guardrails`. Python 3.11+ and a verified Zasp HTTPS origin with the workload action-decision API are required. This companion has no third-party runtime dependencies.

```python
import os
from zasp_guardrails import PolicyDenied, ToolGuard

guard = ToolGuard(
    os.environ["ZASP_BASE_URL"],
    token=lambda: os.environ["ZASP_WORKLOAD_TOKEN"],
    timeout=0.3,
    on_unavailable="block",
)

def dispatch_ticket(tickets, ticket_id, new_title, session_id, call_id):
    attempt = guard.action(
        "ticket.update", resource_kind="ticket", classification="internal",
        session_ref=session_id, call_ref=call_id,
    )
    try:
        return attempt.run(tickets.update, ticket_id, new_title)
    except PolicyDenied as err:
        raise PermissionError(f"Review decision {err.decision.decision_id}") from err
```

For an asynchronous tool, call `await attempt.run_async(tickets.update_async, ticket_id, new_title)`. The guard checks policy before dispatch and reports a bounded observation afterward. Use trusted registration metadata for tool names and resource classes and only opaque references for the optional session and call fields. The API derives scope from the workload credential. Tool arguments, results, exception text and prompts stay in the application.

Issue a separate `decide_actions` API token for each workload in its Environment. The API uses the authenticated token ID for action-ID uniqueness and outcome ownership. The optional session and call references are evidence provided by this adapter. Calling the same method on an uninstrumented object has no middleware coverage.

In the existing Policies UI, create an Environment-scoped rule with trigger `tool`. An `action equals ticket.update` condition matches the registered operation above. A `resource equals internal` condition matches the resource classification. Roll out to Monitor to record would-blocks and then Enforce to block matching actions. The authenticated `principal_id` and `environment_id` are available for rules. For an admin-bound dedicated credential, rules can also use its verified agent and governed session IDs. An otherwise applicable rule requiring unverified agent/session identity returns an unsupported-context error. See the [credential binding and supervised containment guide](../../docs/operations/hosted-gateway.md#bind-a-dedicated-credential-to-a-governed-session). A receipt includes a digest of the active policy snapshot. Retrying admission for an already recorded action returns its original receipt even after policy changes. Identical IDs under different tokens belong to different workloads.

The default outage behavior stops dispatch with `DecisionUnavailable`. Configure `on_unavailable="allow"` explicitly for a monitoring cohort that permits operation during loss of service. The attempt records `coverage_gap="decision_unavailable"` and logs its action ID. Authentication failures, redirects and malformed receipts stop dispatch with `ProtocolError`. A confirmed application-level block raises `PolicyDenied`. A monitoring decision permits the tool and can include `would_block=True`.

An action instance represents one dispatch. Give duplicate in-process callbacks the same instance. A duplicate receives `AlreadyAttempted`. A subsequent user-initiated attempt gets a new action ID. Applications that can redeliver work after restart should use durable application-level deduplication. Retry outcome delivery on the same instance with `attempt.retry_outcome()`. This preserves the tool result and never runs the tool again. A failed outcome send leaves `outcome_delivered` false. After loss of the process, a pending in-memory outcome remains unknown. Local success `returned` means the callable returned. Verification of a target-side effect requires separate evidence.

The timeout is the socket-operation timeout for the decision and outcome separately. A dispatch returning a lazy generator or streaming callable requires an adapter for that lifecycle. Instrument the inner tool operation instead. Only wrapped tools have middleware coverage.

Local tests exercise real loopback HTTP and synchronous and asynchronous ticket callables:

```sh
PYTHONPATH=sdks/python-guardrails/src python3 -m unittest discover -s sdks/python-guardrails/tests
```

## Load a reviewed private skill

An application that controls how a skill is loaded can check the exact bytes before handing the instructions to its agent. Configure the private artifact source and origin in the deployment. Give the loader a current review resolver under the application's control. This example uses an in-process registry populated by the deployment owner.

```python
from datetime import datetime, timezone
from zasp_guardrails.loader import LocalReviews, Review, Source, load_reviewed

reviews = LocalReviews()
reviews.install(Review(
    environment="staging", origin="private-artifact-store:ticket-helper",
    digest="sha256:e103709f3188881a19797e525c4ca56ca415bb7c99a8a300ead5797f56ce3d11",
    revision=1, state="approved", expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
))
source = Source("private-artifact-store:ticket-helper", lambda: {"SKILL.md": b"# Ticket helper\n"})
skill = load_reviewed(source, environment="staging", lookup=reviews.lookup)
instructions = skill.instructions
```

The loader uses the CLI's versioned manifest encoding, binds approval to the Environment and origin, and returns immutable bytes. A changed bundle, an expired or revoked version, or an unavailable review raises `AdmissionDenied` before the caller receives instructions. Refresh the deployment-owned registry with higher revisions and hydrate current decisions on every restart. Applications with a durable authenticated policy service can supply its lookup directly. A laptop scan, a self-reported origin and the browser review response each require separate provenance verification before they can authorize admission.

Consume the returned bytes directly. Loading scripts, following references to other files, or importing a module through another path requires another verified boundary. A later revocation applies on the next load. The registry example has process-local scope and does not implement fleet policy distribution.
