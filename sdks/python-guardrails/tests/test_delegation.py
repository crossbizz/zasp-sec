import asyncio
import base64
import json
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from zasp_guardrails import DelegationDenied, TaskDelegation, ToolGuard

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@unittest.skipUnless(Ed25519PrivateKey, "install zasp-guardrails[delegation] to exercise signed grants")
class TaskScope(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.binding = dict(organization_id="org", workspace_id="ws", environment_id="env",
                            parent_task_id="task", child_agent_id="child")
        self.now = int(time.time())

    def grant(self, **modify):
        claims = dict(self.binding, parent_agent_id="parent", allowed_operations=["draft_reply"],
                      allowed_resources=["inbox"], depth=1, max_depth=1, iat=self.now, exp=self.now+60)
        claims.update(modify)
        body = b64(b'{"alg":"EdDSA","typ":"zasp-task-delegation.v1+jwt"}') + "." + b64(json.dumps(claims).encode())
        return TaskDelegation(public_key=self.key.public_key().public_bytes_raw(), **self.binding,
                              token=body + "." + b64(self.key.sign(body.encode())))

    def test_shared_sdk_delegation_vector(self):
        path = Path(__file__).resolve().parents[2] / "fixtures" / "task-delegation.json"
        vector = json.loads(path.read_text(encoding="utf-8"))
        verifier = vector["verifier"]
        parts = [b64(json.dumps(vector[k], separators=(",", ":")).encode())
                 for k in ("protected_header", "claims")]
        grant = TaskDelegation(
            public_key=base64.b64decode(verifier["public_key"]),
            organization_id=verifier["organization_id"], workspace_id=verifier["workspace_id"],
            environment_id=verifier["environment_id"], parent_task_id=verifier["parent_task_id"],
            child_agent_id=verifier["agent_id"], token=".".join([*parts, vector["signature"]]),
        )
        with patch("time.time", return_value=vector["issued_at"]):
            grant.check("draft_reply", "inbox")
            with self.assertRaises(DelegationDenied):
                grant.check("send_reply", "inbox")
        with patch("time.time", return_value=vector["claims"]["exp"]):
            with self.assertRaises(DelegationDenied):
                grant.check("draft_reply", "inbox")

    def test_signature_tenant_task_and_bounds(self):
        grant = self.grant()
        grant.check("draft_reply", "inbox")
        for changes in [{"environment_id": "other"}, {"parent_task_id": "other"}, {"depth": 2},
                        {"exp": self.now}, {"iat": self.now+1}, {"exp": self.now+301}]:
            with self.subTest(changes=changes), self.assertRaises(DelegationDenied):
                self.grant(**changes).check("draft_reply", "inbox")
        for operation, resource in [("send_reply", "inbox"), ("draft_reply", "other"), ("draft_reply", None)]:
            with self.assertRaises(DelegationDenied):
                grant.check(operation, resource)

    def test_refusal_precedes_policy_and_both_dispatch_paths(self):
        guard = ToolGuard("https://example.invalid", "fixture", on_unavailable="allow", delegation=self.grant())
        target = Mock()
        guard._transport = Mock()
        for run_async in [False, True]:
            action = guard.action("send_reply", resource_kind="mailbox", classification="internal", resource_id="inbox")
            with self.assertRaises(DelegationDenied):
                if run_async:
                    asyncio.run(action.run_async(target))
                else:
                    action.run(target)
        target.assert_not_called()
        guard._transport.post.assert_not_called()

    def test_expiry_between_admission_and_dispatch(self):
        guard = ToolGuard("https://example.invalid", "fixture", delegation=self.grant())
        action = guard.action("draft_reply", resource_kind="mailbox", classification="internal", resource_id="inbox")
        decision = {"action_id": action.action_id, "decision_id": "decision", "mode": "enforce",
                    "verdict": "allow", "reason_code": "allowed", "policy_revision_id": "rev",
                    "coverage": "checked", "would_block": False}
        def post(path, payload, key, **kwargs):
            self.assertNotIn("token", payload)
            if "action-decisions" in path:
                self.assertEqual(kwargs["delegation_headers"]["X-Zasp-Delegation-Resource"], "inbox")
                return decision
            return {"recorded": True}
        action._transport.post = post
        target = Mock()
        with patch("zasp_guardrails.delegation.time.time", side_effect=[self.now,self.now+60]), self.assertRaises(DelegationDenied):
            action.run(target)
        target.assert_not_called()
