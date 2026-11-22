"""Guard against generated path/body name collisions and incompatible decision receipts."""
import json
from pathlib import Path

import httpx

from zasp import Zasp
from zasp.guardrails.types.workload_action_request_resource import WorkloadActionRequestResource


def test_workload_decision_and_outcome_are_compatible_with_python_middleware(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "python-guardrails" / "src"))
    from zasp_guardrails import Decision

    action = "ticket-fixture-1"
    decision_id = "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    seen = []

    def respond(request):
        body = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer fixture-only"
        assert body["action_id"] == action
        seen.append(request.url.path)
        if request.url.path == "/api/v1/runtime/action-decisions":
            assert request.headers["Idempotency-Key"] == action
            assert body["schema_version"] == "action.v1"
            assert body["resource"]["destination_class"] == "internal"
            return httpx.Response(200, json={
                "action_id": action, "decision_id": decision_id, "mode": "monitor", "verdict": "allow",
                "reason_code": "no_matching_restriction", "would_block": False,
                "policy_revision_id": "sha256:" + "a" * 64, "coverage": "pre_action_supported",
            })
        assert request.url.path == f"/api/v1/runtime/actions/{action}/outcomes"
        assert request.headers["Idempotency-Key"] == action + "-outcome"
        assert body["schema_version"] == "action-outcome.v1"
        assert body["decision_id"] == decision_id
        return httpx.Response(200, json={"recorded": True})

    with httpx.Client(transport=httpx.MockTransport(respond)) as http:
        api = Zasp(base_url="https://fixture.invalid", token="fixture-only", httpx_client=http)
        receipt = api.guardrails.decide_action(
            idempotency_key=action, schema_version="action.v1", action_id=action, action_kind="tool_call",
            operation="ticket.update", resource=WorkloadActionRequestResource(
                kind="ticket", classification="synthetic", destination_class="internal",
            ),
        )
        parsed = Decision.parse(action, receipt.model_dump(mode="json"))
        confirmed = api.guardrails.record_action_outcome(
            action, idempotency_key=action + "-outcome", schema_version="action-outcome.v1",
            action_id=action, decision_id=parsed.decision_id, status="returned",
        )
        assert confirmed.recorded
    assert len(seen) == 2
