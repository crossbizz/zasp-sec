import json
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from zasp_guardrails import PolicyDenied, ToolGuard
from zasp_guardrails.workflow import (
    Attestation, Request, Route, RunPolicy, Scope, SQLiteWorkflowInbox,
    SQLiteWorkflowTarget, WorkflowDenied, WorkflowUnavailable,
)


class WorkflowIntegrationTests(TestCase):
    def setUp(self):
        from test_guardrails import GuardTests
        GuardTests.setUp(self)
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/"target.sqlite"
        self.inbox = SQLiteWorkflowInbox(str(self.path))
        self.scope = Scope("demo-tenant", "session-1", "run-1", "trusted-host", "staging-inbox")
        self.run_key, self.receipt_key, self.approval_key, self.sender_key = (os.urandom(32) for _ in range(4))
        self.now = int(time.time())
        self.routes = {kind: Route(kind, kind+".deliver", "ticket-inbox")
                       for kind in ("purpose", "approval", "handoff", "child", "budget")}
        self.policy = RunPolicy(self.scope, "update-ticket", 1, self.now-5, self.now+300,
                                tuple(self.routes.values()), 10, 3, 3, 3)
        self.set_available(True)

    def set_available(self, flag):
        self.inbox.set_route(tenant=self.scope.tenant, audience=self.scope.audience,
                             destination="ticket-inbox", available=flag)

    def instance(self, scope=None, fallback="block"):
        return SQLiteWorkflowTarget(ToolGuard(self.url, "fixture-only", timeout=2, on_unavailable=fallback),
                                    self.inbox, scope=scope or self.scope, run_key=self.run_key,
                                    evidence_key=self.receipt_key, approvers={"reviewer":self.approval_key},
                                    senders={"sender-bot":self.sender_key})

    def request(self, kind, key="request-1", parent="root"):
        return Request(key, self.routes[kind], self.policy.purpose, b"synthetic note", parent)

    def submit(self, req, *, target=None, policy=None, signature=None, attestation=None):
        p = policy or self.policy
        return (target or self.instance()).submit(p, signature or p.sign(self.run_key), req, attestation=attestation)

    def proof(self, req, issuer, key, **overrides):
        settings = {"issued_at": self.now, "expires": self.now+60, "issuer": issuer, "key": key}
        return Attestation.issue(self.policy, req, **{**settings, **overrides})

    def queue(self):
        return self.inbox.deliveries(tenant=self.scope.tenant, audience=self.scope.audience,
                                     destination="ticket-inbox")

    def outcomes(self):
        return [body for _,body,_ in self.requests if "decision_id" in body]

    def test_purpose_scope_and_independent_receipts(self):
        req = self.request("purpose")
        self.assertEqual(self.submit(req),1)
        for changed in [replace(req,purpose="second-task"),
                        replace(req,route=Route("purpose","external.update","ticket-inbox"))]:
            with self.assertRaisesRegex(WorkflowDenied,"outside_declared_purpose"):
                self.submit(changed)
        with self.assertRaisesRegex(WorkflowDenied,"untrusted_policy"):
            self.submit(req,target=self.instance(replace(self.scope,tenant="another-tenant")))
        self.assertEqual(self.queue(),[("request-1",b"synthetic note")])
        events = self.outcomes()
        self.assertEqual([b["context_evidence"]["result"] for b in events], ["allowed","rejected","rejected","rejected"])
        with sqlite3.connect(self.path) as observer:
            for event in events:
                raw = observer.execute("SELECT evidence FROM workflow_receipts WHERE action_id=?", (event["action_id"],)).fetchone()
                self.assertEqual(event["context_evidence"],json.loads(raw[0]))
        self.assertNotIn("synthetic note",json.dumps(self.requests))
        self.assertNotIn("ticket-inbox",json.dumps(self.requests))
        self.assertEqual(events[-1]["context_evidence"]["version"],0)

    def test_human_approval_binds_displayed_action_recipient_content_and_expiry(self):
        req = self.request("approval")
        signed = self.proof(req,"reviewer",self.approval_key)
        self.assertEqual(self.submit(req,attestation=signed),1)
        # Even if both destinations are in scope, a new recipient needs its own approval.
        alt = Route("approval",req.route.operation,"second-inbox")
        self.inbox.set_route(tenant=self.scope.tenant,audience=self.scope.audience,destination="second-inbox",available=True)
        alternate_policy = replace(self.policy,scope=replace(self.scope,run="run-2"),routes=self.policy.routes+(alt,))
        bound = Attestation.issue(alternate_policy,req,issuer="reviewer",issued_at=self.now,expires=self.now+60,key=self.approval_key)
        with self.assertRaisesRegex(WorkflowDenied,"invalid_approval_binding"):
            self.submit(replace(req,route=alt),target=self.instance(alternate_policy.scope),policy=alternate_policy,attestation=bound)
        for changed in [replace(req,body=b"modified"),replace(req,request="req-2")]:
            with self.assertRaisesRegex(WorkflowDenied,"invalid_approval_binding"):
                self.submit(changed,attestation=signed)
        stale = self.proof(req,"reviewer",self.approval_key,issued_at=self.now-3,expires=self.now-1)
        for invalid in [None,stale,replace(signed,issuer="unknown"),replace(signed,signature="bad")]:
            with self.assertRaisesRegex(WorkflowDenied,"invalid_approval_binding"):
                self.submit(req,attestation=invalid)
        self.assertEqual(self.queue(),[("request-1",b"synthetic note")])

    def test_signed_handoff_replay_recipient_issuer_and_audience(self):
        req = self.request("handoff")
        proof = self.proof(req,"sender-bot",self.sender_key)
        self.assertEqual(self.submit(req,attestation=proof),1)
        self.assertEqual(self.submit(req,target=self.instance(),attestation=proof),1)
        for invalid in [self.proof(req,"sender-bot",self.approval_key),
                        self.proof(req,"unauthorized-bot",self.sender_key),
                        self.proof(req,"sender-bot",self.sender_key,issued_at=self.now-3,expires=self.now-1)]:
            with self.assertRaisesRegex(WorkflowDenied,"invalid_handoff_binding"):
                self.submit(req,attestation=invalid)
        for other in [replace(self.scope,principal="different-recipient"),replace(self.scope,audience="second-audience")]:
            with self.assertRaisesRegex(WorkflowDenied,"invalid_handoff_binding"):
                self.submit(req,policy=replace(self.policy,scope=other),target=self.instance(other),attestation=proof)
        self.assertEqual(len(self.queue()),1)

    def test_child_outage_durable_retry_fanout_circuit_and_readback(self):
        self.policy = replace(self.policy,max_attempts=2,max_children=2,failure_limit=3)
        self.submit(self.request("purpose","parent"))
        first = self.request("child","child-a","parent")
        self.set_available(False)
        for _ in range(2):
            with self.assertRaisesRegex(WorkflowDenied,"downstream_paused"):
                self.submit(first,target=self.instance())
        with self.assertRaisesRegex(WorkflowDenied,"retry_limit"):
            self.submit(first)
        with self.assertRaisesRegex(WorkflowDenied,"downstream_paused"):
            self.submit(replace(first,request="child-b"))
        self.set_available(True)
        with self.assertRaisesRegex(WorkflowDenied,"circuit_open"):
            self.submit(replace(first,request="child-c"))
        fresh = replace(self.policy,scope=replace(self.scope,run="run-after-recovery"))
        target = self.instance(fresh.scope)
        for key in ["child-d","child-e"]:
            self.submit(self.request("child",key),policy=fresh,target=target)
        with self.assertRaisesRegex(WorkflowDenied,"fanout_limit"):
            self.submit(self.request("child","child-f"),policy=fresh,target=target)
        with self.assertRaisesRegex(WorkflowDenied,"unknown_parent"):
            self.submit(self.request("child","ghost","absent"),policy=fresh,target=target)
        self.assertEqual([key for key,_ in self.queue()],["parent","child-d","child-e"])

    def test_run_action_budget_concurrent_delivery_retries_restart_and_missing_meter(self):
        self.policy = replace(self.policy,max_actions=2)
        req = self.request("budget")
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.submit(req), range(4)))
        self.assertEqual(results,[1]*4)
        def attempt(key):
            try:
                return self.submit(replace(req,request=key))
            except WorkflowDenied as e:
                return str(e)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(attempt, ["next-1","next-2","next-3","next-4"]))
        self.assertEqual(results.count(2),1)
        self.assertEqual(results.count("action_budget_exhausted"),3)
        with self.assertRaisesRegex(WorkflowDenied,"request_changed"):
            self.submit(replace(req,body=b"changed"))
        with self.assertRaisesRegex(WorkflowDenied,"run_policy_changed"):
            self.submit(req,policy=replace(self.policy,max_actions=100))
        with self.assertRaisesRegex(WorkflowDenied,"expired"):
            self.submit(req,policy=replace(self.policy,issued_at=self.now-10,expires=self.now-5))
        self.assertEqual(len(self.queue()),2)
        with sqlite3.connect(self.path) as observer:
            self.assertEqual(observer.execute("SELECT deliveries FROM workflow_meter").fetchone()[0],len(self.queue()))
            before = observer.execute("SELECT count(*) FROM workflow_receipts").fetchone()[0]
            observer.execute("DELETE FROM workflow_meter")
        with self.assertRaisesRegex(WorkflowUnavailable,"meter missing"):
            self.submit(replace(req,request="new"),target=self.instance())
        self.assertNotIn("context_evidence",self.outcomes()[-1])
        with sqlite3.connect(self.path) as observer:
            self.assertEqual(observer.execute("SELECT count(*) FROM workflow_receipts").fetchone()[0],before)
        self.assertEqual(len(self.queue()),2)

    def test_missing_control_plane_and_target_produce_no_workflow_receipt(self):
        self.override = {"mode":"enforce","verdict":"block"}
        with self.assertRaises(PolicyDenied):
            self.submit(self.request("purpose"))
        self.assertEqual(self.queue(),[])
        self.assertTrue(all("context_evidence" not in body for body in self.outcomes()))
        self.override = {}
        self.reply_status = 503
        with self.assertRaisesRegex(WorkflowUnavailable,"authenticated central decision"):
            self.submit(self.request("purpose"),target=self.instance(fallback="allow"))
        self.assertEqual(self.queue(),[])
        self.reply_status = 200
        with sqlite3.connect(self.path) as admin:
            admin.execute("DELETE FROM workflow_routes")
        with self.assertRaisesRegex(WorkflowUnavailable,"instrumented"):
            self.submit(self.request("handoff"),attestation=self.proof(self.request("handoff"),"sender-bot",self.sender_key))
        self.assertNotIn("context_evidence",self.outcomes()[-1])
        self.assertEqual(self.queue(),[])
