import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest import TestCase

from zasp_guardrails import PolicyDenied, ToolGuard
from zasp_guardrails.context import ContextDenied, RecordApproval, SQLiteContext


class ContextIntegrationTests(TestCase):
    def setUp(self):
        from test_guardrails import GuardTests
        GuardTests.setUp(self)
        self.workspace = TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.path = Path(self.workspace.name) / "context.sqlite"
        self.key = os.urandom(32)
        self.value = b"canonical private value"
        self.record = RecordApproval("alpha", "collection", "record", "editor", ("editor", "viewer"),
                                     1, 4102444800, "document", hashlib.sha256(self.value).hexdigest())

    def context(self, principal="editor", tenant="alpha"):
        return SQLiteContext(self.path, ToolGuard(self.url, "fixture-only"), tenant=tenant,
                             principal=principal, session="run-1", approval_key=self.key)

    def install(self, context, approval, value=None):
        context.put(approval, approval.sign(self.key), self.value if value is None else value)

    def test_document_acl_grounding_and_scoped_receipts(self):
        editor = self.context()
        self.install(editor, self.record)
        viewer = self.context("viewer")
        self.assertEqual(viewer.retrieve("collection", "record"), self.value)
        self.assertEqual(viewer.grounded_value("collection", "record", self.value), self.value)
        with self.assertRaises(ContextDenied):
            viewer.grounded_value("collection", "record", b"unsubstantiated")
        for scope in [self.context("outsider"), self.context("viewer", "beta")]:
            with self.assertRaises(ContextDenied):
                scope.retrieve("collection", "record")
        outcomes = [body for _, body, _ in self.requests if "context_evidence" in body]
        with sqlite3.connect(self.path) as inspector:
            self.assertEqual(len(outcomes), inspector.execute("SELECT count(*) FROM context_receipts").fetchone()[0])
            for outcome in outcomes:
                receipt = inspector.execute("SELECT evidence FROM context_receipts WHERE action=?",
                                           (outcome["action_id"],)).fetchone()
                self.assertEqual(json.loads(receipt[0]), outcome["context_evidence"])
        self.assertEqual(outcomes[-1]["context_evidence"]["version"], 0)
        self.assertNotIn("digest", outcomes[-1]["context_evidence"])
        self.assertNotIn(self.value.decode(), json.dumps(self.requests))

    def test_signed_versioned_memory_and_promotion(self):
        source = self.context()
        current = replace(self.record, purpose="memory")
        self.install(source, current)
        self.assertEqual(source.recall("collection", "record"), self.value)
        for altered in [replace(current, version=2), replace(current, readers=("unknown",)),
                        replace(current, tenant="beta")]:
            with self.assertRaises(ContextDenied):
                source.put(altered, current.sign(self.key), self.value)
        changed = b"new reviewed memory"
        second = replace(current, version=2, digest=hashlib.sha256(changed).hexdigest())
        self.install(source, second, changed)
        with self.assertRaises(ContextDenied):
            self.install(source, current)
        self.assertEqual(source.recall("collection", "record"), changed)
        for kind in ["model", "dataset"]:
            item = replace(current, record=kind, purpose=kind)
            self.install(source, item)
            with self.assertRaises(ContextDenied):
                source.put(replace(item, version=2), item.sign(self.key), b"changed")
        self.override = {"verdict": "block"}
        with self.assertRaises(PolicyDenied):
            source.recall("collection", "record")
        self.assertNotIn("context_evidence", self.requests[-1][1])

    def test_private_markers_and_missing_recorder(self):
        adapter = self.context()
        marker = os.urandom(32).hex().encode()
        for scope in ("system_prompt", "retrieved_context"):
            adapter.check_synthetic_output(scope, marker, b"public answer")
            with self.assertRaises(ContextDenied):
                adapter.check_synthetic_output(scope, marker, marker)
        self.assertNotIn(marker.decode(), json.dumps(self.requests))
        with sqlite3.connect(self.path) as store:
            store.execute("DROP TABLE context_receipts")
        with self.assertRaises(sqlite3.DatabaseError):
            self.install(adapter, self.record)
        self.assertNotIn("context_evidence", self.requests[-1][1])
        with sqlite3.connect(self.path) as inspector:
            self.assertEqual(inspector.execute("SELECT count(*) FROM context_records").fetchone()[0], 0)



    def test_approval_scope_digest_expiry_and_concurrent_next_version(self):
        from concurrent.futures import ThreadPoolExecutor
        store = self.context()
        self.install(store, self.record)
        proposed = replace(self.record, version=2)
        with self.assertRaises(ContextDenied):
            self.install(store, replace(proposed, expires=1))
        with self.assertRaises(ContextDenied):
            self.install(store, proposed, b"different bytes")
        with self.assertRaises(ContextDenied):
            self.install(self.context("viewer"), proposed)

        def try_update(_):
            try:
                self.install(store, proposed)
                return True
            except ContextDenied:
                return False

        with ThreadPoolExecutor(2) as pool:
            self.assertCountEqual(list(pool.map(try_update, (1, 2))), [True, False])
