"""Pre-dispatch checks for applications using Zasp runtime policy."""
from __future__ import annotations

import asyncio
import inspect
import logging
import re
import threading
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, ParamSpec, TypeVar

from .delegation import DelegationDenied, TaskDelegation
from .transport import DecisionUnavailable, ProtocolError, Transport

__all__ = [
    "Action", "AlreadyAttempted", "Decision", "DecisionUnavailable", "PolicyDenied",
    "ProtocolError", "ToolGuard", "TaskDelegation", "DelegationDenied",
]

P = ParamSpec("P")
T = TypeVar("T")
log = logging.getLogger(__name__)


def _label(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}", value):
        raise ValueError("Expected a bounded identifier or classification")
    return value


@dataclass(frozen=True)
class Decision:
    action_id: str
    decision_id: str
    mode: str
    verdict: str
    reason_code: str
    policy_revision_id: str
    coverage: str
    would_block: bool

    @classmethod
    def parse(cls, action_id: str, raw: dict) -> Decision:
        mode, verdict = raw.get("mode"), raw.get("verdict")
        would_block = raw.get("would_block", False)
        if (
            raw.get("action_id") != action_id or mode not in ("monitor", "enforce")
            or verdict not in ("allow", "block") or type(would_block) is not bool
            or (mode == "monitor" and verdict != "allow")
        ):
            raise ProtocolError("Decision does not match this action or has an unsupported verdict")
        try:
            return cls(
                action_id, _label(raw["decision_id"]), mode, verdict, _label(raw["reason_code"]),
                _label(raw["policy_revision_id"]), _label(raw["coverage"]), would_block,
            )
        except (ValueError, KeyError):
            raise ProtocolError("Decision is missing a valid receipt field") from None


class PolicyDenied(RuntimeError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Action blocked ({decision.reason_code}, decision {decision.decision_id})")


class AlreadyAttempted(RuntimeError):
    """A tool dispatch has already claimed this attempt."""


class ToolGuard:
    def __init__(
        self, base_url: str, token: str | Callable[[], str], *,
        on_unavailable: Literal["block", "allow"] = "block", timeout: float = 0.3,
        delegation: TaskDelegation | None = None,
    ):
        if on_unavailable not in ("allow", "block"):
            raise ValueError("on_unavailable must be allow or block")
        self._transport = Transport(base_url, token, timeout)
        self._fallback = on_unavailable
        self._delegation = delegation

    def action(
        self, operation: str, *, resource_kind: str, classification: str, resource_id: str | None = None,
        session_ref: str | None = None, call_ref: str | None = None, destination_class: str | None = None,
    ) -> Action:
        metadata: dict = {
            "schema_version": "action.v1",
            "action_id": str(uuid.uuid4()),
            "action_kind": "tool_call",
            "operation": _label(operation),
            "resource": {"kind": _label(resource_kind), "classification": _label(classification)},
        }
        if destination_class is not None:
            if destination_class not in ("internal", "approved_partner", "external", "public"):
                raise ValueError("Invalid destination class")
            metadata["resource"]["destination_class"] = destination_class
        if session_ref is not None:
            metadata["source_session_ref"] = _label(session_ref)
        if call_ref is not None:
            metadata["source_call_ref"] = _label(call_ref)
        return Action(self._transport, self._fallback, metadata, self._delegation, resource_id)


class Action:
    """One invocation. Share this instance with duplicate callbacks for the same invocation."""

    def __init__(self, transport: Transport, fallback: str, metadata: dict,
                 delegation: TaskDelegation | None = None, resource_id: str | None = None):
        self._delegation = delegation
        self._resource_id = resource_id
        self._transport = transport
        self._fallback = fallback
        self._metadata = metadata
        self._lock = threading.Lock()
        self._claimed = False
        self._decision: Decision | None = None
        self._outcome_status: str | None = None
        self._outcome_delivered = False
        self._context_evidence: dict | None = None
        self._coverage_gap: str | None = None

    @property
    def action_id(self) -> str:
        return self._metadata["action_id"]

    @property
    def decision(self) -> Decision | None:
        return self._decision

    @property
    def coverage_gap(self) -> str | None:
        return self._coverage_gap

    @property
    def outcome_status(self) -> str | None:
        return self._outcome_status

    @property
    def outcome_delivered(self) -> bool:
        return self._outcome_delivered

    def _claim(self) -> None:
        with self._lock:
            if self._claimed:
                raise AlreadyAttempted("Action already attempted")
            self._claimed = True

    def _request_decision(self) -> None:
        try:
            if self._delegation:
                headers = self._delegation.headers(self._metadata["operation"], self._resource_id)
                raw = self._transport.post("/api/v1/runtime/action-decisions", self._metadata,
                                           self.action_id, delegation_headers=headers)
            else:
                raw = self._transport.post("/api/v1/runtime/action-decisions", self._metadata, self.action_id)
        except DecisionUnavailable:
            self._coverage_gap = "decision_unavailable"
            log.warning("Zasp decision unavailable for action %s (fallback %s)", self.action_id, self._fallback)
            if self._delegation or self._fallback == "block":
                raise
            return
        self._decision = Decision.parse(self.action_id, raw)

    def _check_decision(self) -> None:
        if self._delegation:
            self._delegation.check(self._metadata["operation"], self._resource_id)
        if self._decision and self._decision.verdict == "block":
            raise PolicyDenied(self._decision)

    def _record_context(self, evidence: dict) -> None:
        """Called by the context adapter after its target transaction commits."""
        with self._lock:
            if not self._claimed or self._outcome_status is not None:
                raise RuntimeError("Context receipt outside dispatch")
            self._context_evidence = dict(evidence)

    def retry_outcome(self) -> bool:
        """Deliver the recorded observation if needed. This never executes the tool."""
        with self._lock:
            if not self._decision or not self._outcome_status:
                return False
            if self._outcome_delivered:
                return True
            payload = {
                "schema_version": "action-outcome.v1", "action_id": self.action_id,
                "decision_id": self._decision.decision_id, "status": self._outcome_status,
            }
            if self._context_evidence is not None:
                payload["context_evidence"] = self._context_evidence
            try:
                ack = self._transport.post(
                    f"/api/v1/runtime/actions/{self.action_id}/outcomes", payload,
                    f"{self.action_id}-outcome",
                )
                if ack.get("recorded") is not True:
                    raise ProtocolError("Missing workload outcome acknowledgement")
            except (DecisionUnavailable, ProtocolError):
                log.warning("Zasp outcome pending for action %s", self.action_id)
                return False
            self._outcome_delivered = True
            return True

    def _finish(self, status: str) -> None:
        self._outcome_status = status
        self.retry_outcome()

    def run(self, function: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> T:
        if inspect.iscoroutinefunction(function) or inspect.isasyncgenfunction(function) or inspect.isgeneratorfunction(function):
            raise TypeError("run expects an eager synchronous tool")
        self._claim()
        try:
            self._request_decision()
            self._check_decision()
        except (DecisionUnavailable, ProtocolError, PolicyDenied):
            self._finish("not_dispatched")
            raise
        try:
            result = function(*args, **kwargs)
            if inspect.isawaitable(result) or inspect.isgenerator(result) or inspect.isasyncgen(result):
                if inspect.iscoroutine(result) or inspect.isgenerator(result):
                    result.close()
                raise TypeError("run expects an eager synchronous result")
        except BaseException:
            self._finish("raised")
            raise
        self._finish("returned")
        return result

    async def run_async(self, function: Callable[P, Awaitable[T]], /, *args: P.args, **kwargs: P.kwargs) -> T:
        self._claim()
        admission = asyncio.create_task(asyncio.to_thread(self._request_decision))
        try:
            await asyncio.shield(admission)
            self._check_decision()
        except asyncio.CancelledError:
            # A completed admission can still have a receipt while dispatch was cancelled.
            try:
                await admission
            except (DecisionUnavailable, ProtocolError):
                pass
            await asyncio.to_thread(self._finish, "not_dispatched")
            raise
        except (DecisionUnavailable, ProtocolError, PolicyDenied):
            await asyncio.to_thread(self._finish, "not_dispatched")
            raise
        try:
            result = await function(*args, **kwargs)
        except asyncio.CancelledError:
            await asyncio.to_thread(self._finish, "cancelled")
            raise
        except BaseException:
            await asyncio.to_thread(self._finish, "raised")
            raise
        await asyncio.to_thread(self._finish, "returned")
        return result
