"""Application adapter for reviewed records in a private SQLite context store."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from . import ToolGuard, _label


class ContextDenied(RuntimeError):
    """The requested operation did not pass the application's context boundary."""


@dataclass(frozen=True)
class RecordApproval:
    tenant: str
    collection: str
    record: str
    writer: str
    readers: tuple[str, ...]
    version: int
    expires: int
    purpose: str
    digest: str

    def payload(self) -> bytes:
        for label in (self.tenant, self.collection, self.record, self.writer, *self.readers):
            _label(label)
        if (self.purpose not in ("memory", "document", "model", "dataset")
                or type(self.version) is not int or not 0 < self.version < 2**53
                or type(self.expires) is not int or not 0 < self.expires < 2**53
                or not 0 < len(self.readers) <= 128 or tuple(sorted(set(self.readers))) != self.readers
                or len(self.digest) != 64 or any(c not in "0123456789abcdef" for c in self.digest)):
            raise ValueError("Invalid record approval")
        return json.dumps([self.tenant, self.collection, self.record, self.writer, self.readers,
                           self.version, self.expires, self.purpose, self.digest],
                          separators=(",", ":")).encode()

    def sign(self, approval_key: bytes) -> str:
        """Run under the deployment owner's approval authority."""
        if type(approval_key) is not bytes or len(approval_key) < 32:
            raise ValueError("Use a dedicated approval key of at least 32 bytes")
        return hmac.digest(approval_key, b"zasp-record-approval.v1\0" + self.payload(), "sha256").hex()


class SQLiteContext:
    """One host-authenticated tenant, principal and session. Own the DB outside agent access."""

    def __init__(self, path: Path, guard: ToolGuard, *, tenant: str, principal: str,
                 session: str, approval_key: bytes):
        self.tenant, self.principal, self.session = map(_label, (tenant, principal, session))
        if type(approval_key) is not bytes or len(approval_key) < 32:
            raise ValueError("Use a dedicated approval key of at least 32 bytes")
        self._key = approval_key
        self._path = Path(path)
        self._guard = guard
        with closing(sqlite3.connect(self._path)) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS context_records (
                    tenant TEXT, collection TEXT, record TEXT, version INTEGER NOT NULL,
                    purpose TEXT NOT NULL, readers TEXT NOT NULL, value BLOB NOT NULL,
                    PRIMARY KEY (tenant, collection, record));
                CREATE TABLE IF NOT EXISTS context_receipts (
                    action TEXT PRIMARY KEY, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                    session TEXT NOT NULL, observed_at INTEGER NOT NULL, evidence TEXT NOT NULL);
            """)

    def _ref(self, *parts: str | bytes) -> str:
        mac = hmac.new(self._key, b"zasp-context-ref.v1\0", "sha256")
        for part in (self.tenant, *parts):
            data = part.encode() if isinstance(part, str) else part
            mac.update(len(data).to_bytes(8, "big"))
            mac.update(data)
        return mac.hexdigest()

    def _run(self, kind, collection, record, classify, operation):
        collection, record = _label(collection), _label(record)
        evidence = {"kind": kind, "collection_ref": self._ref("collection", collection),
                    "record_ref": self._ref("record", collection, record), "version": 0,
                    "result": "unavailable"}
        action = self._guard.action("context." + kind, resource_kind="sqlite_context",
                                    classification=_label(classify), destination_class="internal",
                                    session_ref=self.session, call_ref=evidence["record_ref"])

        def dispatch():
            with closing(sqlite3.connect(self._path)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                result, value = operation(db, evidence)
                evidence["result"] = result
                db.execute("INSERT INTO context_receipts VALUES (?,?,?,?,?,?)",
                           (action.action_id, self.tenant, self.principal, self.session, int(time.time()),
                            json.dumps(evidence, sort_keys=True)))
            # Publish only after the target commits the receipt and any mutation.
            action._record_context(evidence)
            if result != "allowed":
                raise ContextDenied(kind + " " + result)
            return value

        return action.run(dispatch)

    def put(self, approval: RecordApproval, signature: str, contents: bytes) -> None:
        """Install a signed, versioned memory entry, retrieval document, model or dataset manifest."""
        if type(contents) is not bytes or len(contents) > 4 * 1024 * 1024:
            raise ValueError("Expected at most 4 MiB of record data")
        expected = approval.sign(self._key)
        kind = "artifact_promotion" if approval.purpose != "memory" else "memory_write"

        def write(db, evidence):
            if (type(signature) is not str or not signature.isascii()
                    or not hmac.compare_digest(expected, signature)
                    or (approval.tenant, approval.writer) != (self.tenant, self.principal)
                    or approval.expires <= time.time()
                    or not hmac.compare_digest(approval.digest, hashlib.sha256(contents).hexdigest())):
                return "rejected", None
            key = self.tenant, approval.collection, approval.record
            prior = db.execute("SELECT version, purpose FROM context_records WHERE tenant=? AND collection=? AND record=?", key).fetchone()
            if (prior and prior[1] != approval.purpose) or approval.version != (prior[0] if prior else 0) + 1:
                return "rejected", None
            db.execute("INSERT INTO context_records VALUES (?,?,?,?,?,?,?) ON CONFLICT(tenant, collection, record) "
                       "DO UPDATE SET version=excluded.version, readers=excluded.readers, value=excluded.value",
                       (*key, approval.version, approval.purpose, json.dumps(approval.readers), contents))
            evidence.update(version=approval.version, digest=self._ref("content", contents))
            return "allowed", None

        self._run(kind, approval.collection, approval.record, approval.purpose, write)

    def _read(self, kind, collection, record, purpose, candidate=None):
        def read(db, evidence):
            row = db.execute("SELECT version, readers, value FROM context_records "
                             "WHERE tenant=? AND collection=? AND record=? AND purpose=?",
                             (self.tenant, collection, record, purpose)).fetchone()
            if row is None or self.principal not in json.loads(row[1]):
                return "rejected", None
            version, _, contents = row
            evidence.update(version=version, digest=self._ref("content", contents))
            if candidate is not None and not hmac.compare_digest(contents, candidate):
                return "rejected", None
            return "allowed", contents

        return self._run(kind, collection, record, purpose, read)

    def recall(self, collection: str, record: str) -> bytes:
        return self._read("memory_recall", collection, record, "memory")

    def retrieve(self, collection: str, record: str) -> bytes:
        """Check tenant and document ACL before exposing any retrieved bytes."""
        return self._read("retrieval", collection, record, "document")

    def grounded_value(self, collection: str, record: str, proposed: bytes) -> bytes:
        """Admit an exact canonical field value from a reviewed, readable document."""
        if type(proposed) is not bytes or len(proposed) > 4 * 1024 * 1024:
            raise ValueError("Invalid proposed value")
        return self._read("grounded_decision", collection, record, "document", proposed)

    def check_synthetic_output(self, scope: str, marker: bytes, output: bytes) -> None:
        """Evaluate a host-seeded marker on the named test boundary without retaining either string."""
        if (scope not in ("system_prompt", "retrieved_context") or type(marker) is not bytes
                or not 16 <= len(marker) <= 256 or type(output) is not bytes or len(output) > 4 * 1024 * 1024):
            raise ValueError("Invalid synthetic context test")
        self._run("hidden_context_check", "synthetic", scope, scope,
                  lambda db, evidence: ("rejected" if marker in output else "allowed", None))
