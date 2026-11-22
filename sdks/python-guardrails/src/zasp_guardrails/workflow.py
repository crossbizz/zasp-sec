"""Host-owned, scoped SQLite workflow inbox with pre-dispatch authorization."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path

from . import ToolGuard, _label

KINDS = ("purpose", "approval", "handoff", "child", "budget")


class WorkflowDenied(RuntimeError):
    """The target committed a refusal. The request produced no new delivery."""


class WorkflowUnavailable(RuntimeError):
    """A required decision or meter was unavailable. No target receipt is claimed."""


def _key(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) < 32:
        raise ValueError("Use distinct, protected keys of at least 32 bytes")
    return value


def _bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _mac(key: bytes, domain: str, value) -> str:
    return hmac.digest(_key(key), b"zasp.sqlite-workflow.v1\0" + domain.encode() + b"\0" + _bytes(value), "sha256").hex()


def _valid(mac: str, expected: str) -> bool:
    return type(mac) is str and len(mac) == 64 and mac.isascii() and hmac.compare_digest(mac, expected)


def _int(value: int, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Workflow limit or timestamp is outside its supported range")


@dataclass(frozen=True)
class Scope:
    tenant: str
    session: str
    run: str
    principal: str
    audience: str

    def __post_init__(self):
        for value in (self.tenant, self.session, self.run, self.principal, self.audience):
            _label(value)


@dataclass(frozen=True)
class Route:
    kind: str
    operation: str
    destination: str

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError("Unsupported workflow route")
        _label(self.operation)
        _label(self.destination)


@dataclass(frozen=True)
class RunPolicy:
    scope: Scope
    purpose: str
    revision: int
    issued_at: int
    expires: int
    routes: tuple[Route, ...]
    max_actions: int
    max_children: int
    max_attempts: int
    failure_limit: int

    def __post_init__(self):
        if not isinstance(self.scope, Scope):
            raise ValueError("A scoped run is required")
        _label(self.purpose)
        _int(self.revision, 1, 2**53-1)
        _int(self.issued_at, 1, 2**40)
        _int(self.expires, self.issued_at+1, self.issued_at+86400)
        for limit in (self.max_actions, self.max_children, self.max_attempts, self.failure_limit):
            _int(limit, 1, 10000)
        if type(self.routes) is not tuple or not 1 <= len(self.routes) <= 256 or not all(isinstance(r, Route) for r in self.routes):
            raise ValueError("Provide a bounded tuple of allowed workflow routes")
        # A caller must not switch to another route to avoid a mandatory approval.
        keys = {(r.operation, r.destination) for r in self.routes}
        if len(keys) != len(self.routes):
            raise ValueError("Assign exactly one control to each operation and destination")

    def sign(self, authority: bytes) -> str:
        return _mac(authority, "run", asdict(self))


@dataclass(frozen=True)
class Request:
    request: str
    route: Route
    purpose: str
    body: bytes
    parent: str = "root"

    def __post_init__(self):
        for value in (self.request, self.purpose, self.parent):
            _label(value)
        if self.request == "root" or self.request == self.parent or not isinstance(self.route, Route):
            raise ValueError("Invalid workflow request or parent")
        if type(self.body) is not bytes or len(self.body) > 65536:
            raise ValueError("Expected at most 64 KiB for the inbox message")

    def presented(self) -> dict:
        """The exact input an approval UI or authenticated sender must sign."""
        return {"request": self.request, "route": asdict(self.route), "purpose": self.purpose,
                "parent": self.parent, "content_sha256": hashlib.sha256(self.body).hexdigest()}


@dataclass(frozen=True)
class Attestation:
    issuer: str
    issued_at: int
    expires: int
    signature: str

    @classmethod
    def issue(cls, policy: RunPolicy, request: Request, *, issuer: str, issued_at: int,
              expires: int, key: bytes) -> Attestation:
        """Issue inside the trusted approval service or authenticated sending agent."""
        _label(issuer)
        _int(issued_at, 1, 2**40)
        _int(expires, issued_at+1, min(policy.expires, issued_at+300))
        if request.route.kind not in ("approval", "handoff"):
            raise ValueError("Only approval and handoff routes use an attestation")
        payload = {"scope": asdict(policy.scope), "revision": policy.revision, "request": request.presented(),
                   "issuer": issuer, "issued_at": issued_at, "expires": expires}
        return cls(issuer, issued_at, expires, _mac(key, request.route.kind, payload))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS workflow_runs (
    run_ref TEXT PRIMARY KEY, policy_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workflow_meter (
    run_ref TEXT PRIMARY KEY, deliveries INTEGER NOT NULL CHECK(deliveries>=0));
CREATE TABLE IF NOT EXISTS workflow_routes (
    tenant TEXT, audience TEXT, destination TEXT, available INTEGER NOT NULL,
    PRIMARY KEY(tenant,audience,destination));
CREATE TABLE IF NOT EXISTS workflow_bindings (
    run_ref TEXT, request_id TEXT, binding TEXT NOT NULL, PRIMARY KEY(run_ref,request_id));
CREATE TABLE IF NOT EXISTS workflow_children (
    run_ref TEXT, request_id TEXT, parent TEXT NOT NULL, binding TEXT NOT NULL, attempts INTEGER NOT NULL,
    PRIMARY KEY(run_ref,request_id));
CREATE INDEX IF NOT EXISTS workflow_child_parent ON workflow_children(run_ref,parent);
CREATE TABLE IF NOT EXISTS workflow_breakers (
    run_ref TEXT, destination TEXT, failures INTEGER NOT NULL,
    PRIMARY KEY(run_ref,destination));
CREATE TABLE IF NOT EXISTS workflow_messages (
    run_ref TEXT, request_id TEXT, binding TEXT NOT NULL, tenant TEXT NOT NULL,
    audience TEXT NOT NULL, destination TEXT NOT NULL, principal TEXT NOT NULL,
    operation TEXT NOT NULL, parent TEXT NOT NULL, body BLOB NOT NULL, sequence INTEGER NOT NULL,
    PRIMARY KEY(run_ref,request_id), UNIQUE(run_ref,sequence));
CREATE TABLE IF NOT EXISTS workflow_receipts (
    action_id TEXT PRIMARY KEY, run_ref TEXT NOT NULL, request_id TEXT NOT NULL,
    observed_at INTEGER NOT NULL, reason TEXT NOT NULL, evidence TEXT NOT NULL);
"""


class SQLiteWorkflowInbox:
    """Queue and owner controls. Keep its writable DB outside agent-controlled paths."""

    def __init__(self, database: str):
        self.path = str(Path(database).absolute())
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(_SCHEMA)

    def set_route(self, *, tenant: str, audience: str, destination: str, available: bool) -> None:
        """Trusted queue operator registers, pauses or resumes an actual destination."""
        scope = tuple(_label(i) for i in (tenant, audience, destination))
        if type(available) is not bool:
            raise ValueError("Expected a boolean queue state")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO workflow_routes VALUES (?,?,?,?) ON CONFLICT(tenant,audience,destination) "
                       "DO UPDATE SET available=excluded.available", (*scope, int(available)))

    def deliveries(self, *, tenant: str, audience: str, destination: str) -> list[tuple]:
        """Operator/recipient readback using a separate read-only SQLite connection."""
        scope = tuple(_label(i) for i in (tenant, audience, destination))
        with closing(sqlite3.connect(Path(self.path).as_uri()+"?mode=ro", uri=True)) as db:
            return db.execute("SELECT request_id,body FROM workflow_messages "
                              "WHERE tenant=? AND audience=? AND destination=? ORDER BY rowid", scope).fetchall()


class SQLiteWorkflowTarget:
    """Scope and verification keys must come from the authenticated hosting boundary."""

    def __init__(self, guard: ToolGuard, inbox: SQLiteWorkflowInbox, *, scope: Scope,
                 run_key: bytes, evidence_key: bytes, approvers: dict[str, bytes], senders: dict[str, bytes]):
        self._guard, self._inbox, self.scope = guard, inbox, scope
        self._run_key, self._evidence_key = _key(run_key), _key(evidence_key)
        self._authorities = {"approval": {_label(k): _key(v) for k,v in approvers.items()},
                             "handoff": {_label(k): _key(v) for k,v in senders.items()}}
        keys = [run_key, evidence_key, *self._authorities["approval"].values(), *self._authorities["handoff"].values()]
        if len(keys) != len(set(keys)):
            raise ValueError("Use independent run, receipt, approver and sender keys")

    def _ref(self, domain, *parts):
        return _mac(self._evidence_key, domain, [asdict(self.scope), *parts])

    def _attested(self, policy, request, proof, now):
        if request.route.kind not in self._authorities:
            return proof is None
        if not isinstance(proof, Attestation) or not isinstance(proof.issuer, str):
            return False
        key = self._authorities[request.route.kind].get(proof.issuer)
        if key is None or type(proof.issued_at) is not int or type(proof.expires) is not int:
            return False
        if not policy.issued_at <= proof.issued_at <= now < proof.expires <= policy.expires:
            return False
        if proof.expires - proof.issued_at > 300:
            return False
        expected = Attestation.issue(policy, request, issuer=proof.issuer, issued_at=proof.issued_at,
                                     expires=proof.expires, key=key).signature
        return _valid(proof.signature, expected)

    def submit(self, policy: RunPolicy, signature: str, request: Request,
               *, attestation: Attestation | None = None) -> int:
        """Append once to this instrumented inbox and return its per-run delivery ordinal."""
        kind = request.route.kind
        # Local ledger identity is stable across telemetry-key rotation. The
        # external receipt uses keyed refs so it never exposes those inputs.
        run_ref = hashlib.sha256(b"zasp.workflow.run.v1\0" + _bytes(asdict(self.scope))).hexdigest()
        record_ref = self._ref("request", request.request)
        binding_input = [run_ref, request.presented(), getattr(attestation, "issuer", None)]
        binding = hashlib.sha256(b"zasp.workflow.binding.v1\0" + _bytes(binding_input)).hexdigest()
        evidence = {"kind": "workflow_"+kind, "collection_ref": self._ref("revision", policy.revision),
                    "record_ref": record_ref, "version": 0, "result": "rejected"}
        action = self._guard.action("workflow."+kind, resource_kind="sqlite_workflow", classification="workflow",
                                    session_ref=self.scope.session, call_ref=record_ref, destination_class="internal")

        def dispatch():
            if action.decision is None:
                raise WorkflowUnavailable("Workflow admission needs an authenticated central decision")
            try:
                with closing(sqlite3.connect(Path(self._inbox.path).as_uri()+"?mode=rw", uri=True,
                                             timeout=5)) as db, db:
                    db.execute("BEGIN IMMEDIATE")
                    now = int(time.time())
                    reason, sequence = self._apply(db, policy, signature, request, attestation, run_ref, binding, now)
                    allowed = sequence is not None
                    evidence["result"] = "allowed" if allowed else "rejected"
                    if reason != "untrusted_policy":
                        evidence.update(version=policy.revision, digest=self._ref("outcome", binding, reason, sequence))
                    db.execute("INSERT INTO workflow_receipts VALUES (?,?,?,?,?,?)",
                               (action.action_id,run_ref,request.request,now,reason,json.dumps(evidence,sort_keys=True)))
            except sqlite3.Error as exc:
                raise WorkflowUnavailable("Workflow target or meter unavailable") from exc
            action._record_context(evidence)
            if not allowed:
                raise WorkflowDenied(reason)
            return sequence

        return action.run(dispatch)

    def _apply(self, db, policy, signature, request, proof, run, binding, now):
        if policy.scope != self.scope or not _valid(signature, policy.sign(self._run_key)):
            return "untrusted_policy", None
        if not policy.issued_at <= now < policy.expires:
            return "run_expired_or_not_yet_active", None
        if request.purpose != policy.purpose or request.route not in policy.routes:
            return "outside_declared_purpose", None
        if not self._attested(policy, request, proof, now):
            return "invalid_"+request.route.kind+"_binding", None
        if request.route.kind != "child" and request.parent != "root":
            return "invalid_parent", None
        prior = db.execute("SELECT policy_hash FROM workflow_runs WHERE run_ref=?", (run,)).fetchone()
        if not prior:
            db.execute("INSERT INTO workflow_runs VALUES (?,?)", (run,signature))
            db.execute("INSERT INTO workflow_meter VALUES (?,0)", (run,))
        elif prior[0] != signature:
            return "run_policy_changed", None
        meter = db.execute("SELECT deliveries FROM workflow_meter WHERE run_ref=?", (run,)).fetchone()
        if meter is None:
            raise WorkflowUnavailable("Required run meter missing")
        pinned = db.execute("SELECT binding FROM workflow_bindings WHERE run_ref=? AND request_id=?",
                            (run,request.request)).fetchone()
        if pinned and not hmac.compare_digest(pinned[0], binding):
            return "request_changed", None
        existing = db.execute("SELECT binding,sequence FROM workflow_messages WHERE run_ref=? AND request_id=?",
                              (run,request.request)).fetchone()
        if existing:
            if not hmac.compare_digest(existing[0], binding):
                return "request_changed", None
            return "already_delivered", existing[1]
        if meter[0] >= policy.max_actions:
            return "action_budget_exhausted", None
        target = request.route.destination
        state = db.execute("SELECT available FROM workflow_routes WHERE tenant=? AND audience=? AND destination=?",
                           (self.scope.tenant,self.scope.audience,target)).fetchone()
        if state is None:
            raise WorkflowUnavailable("Destination is not instrumented")
        if request.route.kind == "child":
            reason = self._reserve_child(db, run, request, policy, binding)
            if reason:
                return reason, None
        if not pinned:
            db.execute("INSERT INTO workflow_bindings VALUES (?,?,?)", (run, request.request, binding))
        if not state[0]:
            if request.route.kind == "child":
                db.execute("INSERT INTO workflow_breakers VALUES (?,?,1) ON CONFLICT(run_ref,destination) "
                           "DO UPDATE SET failures=failures+1", (run,target))
            return "downstream_paused", None
        sequence = meter[0] + 1
        db.execute("INSERT INTO workflow_messages VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (run,request.request,binding,self.scope.tenant,self.scope.audience,target,self.scope.principal,
                    request.route.operation,request.parent,request.body,sequence))
        db.execute("UPDATE workflow_meter SET deliveries=? WHERE run_ref=?", (sequence,run))
        if request.route.kind == "child":
            db.execute("DELETE FROM workflow_breakers WHERE run_ref=? AND destination=?", (run,target))
        return "delivered", sequence

    @staticmethod
    def _reserve_child(db, run, request, policy, binding):
        if request.parent != "root" and not db.execute(
                "SELECT 1 FROM workflow_messages WHERE run_ref=? AND request_id=?", (run,request.parent)).fetchone():
            return "unknown_parent"
        breaker = db.execute("SELECT failures FROM workflow_breakers WHERE run_ref=? AND destination=?",
                             (run,request.route.destination)).fetchone()
        if breaker and breaker[0] >= policy.failure_limit:
            return "circuit_open"
        child = db.execute("SELECT binding,attempts FROM workflow_children WHERE run_ref=? AND request_id=?",
                           (run,request.request)).fetchone()
        if child:
            if not hmac.compare_digest(child[0], binding):
                return "request_changed"
            if child[1] >= policy.max_attempts:
                return "retry_limit"
            db.execute("UPDATE workflow_children SET attempts=attempts+1 WHERE run_ref=? AND request_id=?",
                       (run,request.request))
        else:
            count, = db.execute("SELECT count(*) FROM workflow_children WHERE run_ref=? AND parent=?",
                                (run,request.parent)).fetchone()
            if count >= policy.max_children:
                return "fanout_limit"
            db.execute("INSERT INTO workflow_children VALUES (?,?,?,?,1)",
                       (run,request.request,request.parent,binding))
        return None
