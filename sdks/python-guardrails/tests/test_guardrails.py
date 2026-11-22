import asyncio
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from zasp_guardrails import AlreadyAttempted, DecisionUnavailable, PolicyDenied, ProtocolError, ToolGuard


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.ack = {"recorded": True}
        self.reply_status = 200
        self.outcome_status = 201
        self.redirect = None
        self.override = {}
        self.release = None
        self.admitting = threading.Event()
        self.events = []
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                state.requests.append((self.path, body, self.headers["Idempotency-Key"]))
                if self.headers["Authorization"] != "Bearer fixture-only":
                    status, response = 403, {}
                elif self.path == "/api/v1/runtime/action-decisions":
                    state.events.append("decision")
                    state.admitting.set()
                    if state.release:
                        state.release.wait(2)
                    status = state.reply_status
                    response = {
                        "action_id": body["action_id"], "decision_id": "decision-1", "policy_revision_id": "rev-7",
                        "mode": "enforce", "verdict": "allow", "reason_code": "within_scope",
                        "coverage": "pre_action_supported", **state.override,
                    }
                elif self.path == f"/api/v1/runtime/actions/{body['action_id']}/outcomes":
                    state.events.append(body["status"])
                    status, response = state.outcome_status, state.ack
                else:
                    status, response = 404, {}
                data = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if state.redirect:
                    self.send_header("Location", state.redirect)
                self.end_headers()
                try:
                    self.wfile.write(data)
                except BrokenPipeError:
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def action(self, *, fallback="block", token="fixture-only", timeout=1.0):
        return ToolGuard(self.url, token, on_unavailable=fallback, timeout=timeout).action(
            "ticket.update", resource_kind="ticket", classification="synthetic", session_ref="session-1", call_ref="call-2",
        )

    def write_ticket(self, value):
        self.events.append("target_wrote")
        return value

    def test_sync_allow_order_privacy_and_idempotent_outcome(self):
        action = self.action()
        self.assertEqual(action.run(self.write_ticket, "local ticket contents"), "local ticket contents")
        self.assertEqual(self.events, ["decision", "target_wrote", "returned"])
        request, outcome = self.requests
        self.assertEqual(request[1], {
            "schema_version": "action.v1", "action_id": action.action_id, "source_session_ref": "session-1",
            "source_call_ref": "call-2", "action_kind": "tool_call", "operation": "ticket.update",
            "resource": {"kind": "ticket", "classification": "synthetic"},
        })
        self.assertNotIn("local ticket contents", str(self.requests))
        self.assertEqual(outcome[1]["decision_id"], action.decision.decision_id)
        self.assertTrue(action.retry_outcome())
        self.assertEqual(len(self.requests), 2)
        with self.assertRaises(AlreadyAttempted):
            action.run(self.write_ticket, "second")

    def test_optional_reported_destination_is_bounded(self):
        guard = ToolGuard(self.url, "fixture-only")
        with self.assertRaises(ValueError):
            guard.action("ticket.update", resource_kind="ticket", classification="internal", destination_class="https://private.example/user")
        self.assertFalse(self.requests)
        action = guard.action("ticket.update", resource_kind="ticket", classification="internal", destination_class="approved_partner")
        action.run(lambda: None)
        self.assertEqual(self.requests[0][1]["resource"]["destination_class"], "approved_partner")

    def test_deny_has_receipt_no_target_effect(self):
        self.override = {"verdict": "block", "reason_code": "restricted"}
        action = self.action()
        with self.assertRaises(PolicyDenied) as denied:
            action.run(self.write_ticket, "ticket")
        self.assertEqual(denied.exception.decision.policy_revision_id, "rev-7")
        self.assertEqual(self.events, ["decision", "not_dispatched"])
        self.assertTrue(action.outcome_delivered)

    def test_monitor_would_block_preserves_legitimate_work(self):
        self.override = {"mode": "monitor", "would_block": True, "reason_code": "restricted"}
        action = self.action()
        self.assertEqual(action.run(self.write_ticket, "monitored"), "monitored")
        self.assertTrue(action.decision.would_block)
        self.assertEqual(self.events, ["decision", "target_wrote", "returned"])

    def test_unavailable_modes_and_gap(self):
        self.reply_status = 503
        closed = self.action()
        with self.assertRaises(DecisionUnavailable):
            closed.run(self.write_ticket, "denied")
        self.assertEqual(closed.outcome_status, "not_dispatched")
        self.assertEqual(closed.coverage_gap, "decision_unavailable")
        opened = self.action(fallback="allow")
        self.assertEqual(opened.run(self.write_ticket, "permitted"), "permitted")
        self.assertEqual(opened.coverage_gap, "decision_unavailable")
        self.assertIsNone(opened.decision)
        self.assertEqual(self.events, ["decision", "decision", "target_wrote"])

    def test_rejection_and_invalid_receipt_cannot_fail_open(self):
        cases = [(409, {}), (200, {"action_id": "other"}), (200, {"verdict": "surprise"}),
                 (200, {"decision_id": ""}), (200, {"verdict": "block", "mode": "monitor"})]
        for status, override in cases:
            with self.subTest(status=status, override=override):
                self.reply_status, self.override = status, override
                with self.assertRaises(ProtocolError):
                    self.action(fallback="allow").run(self.write_ticket, "ticket")
        with self.assertRaises(ProtocolError):
            self.action(fallback="allow", token="unbound").run(self.write_ticket, "ticket")
        self.assertNotIn("target_wrote", self.events)

    def test_no_cross_origin_or_redirect_and_no_secret_diagnostics(self):
        for base in ("http://example.org", "https://user:password@example.org",
                     "https://example.org/?key=secret", "https://example.org/path"):
            with self.assertRaises(ValueError):
                ToolGuard(base, "fixture-only")
        self.reply_status = 307
        self.redirect = self.url + "/unexpected"
        with self.assertRaises(ProtocolError):
            self.action(fallback="allow").run(self.write_ticket, "ticket")
        self.assertEqual(len(self.requests), 1)
        with self.assertRaises(ProtocolError) as err:
            self.action(token="bad\ncredential").run(self.write_ticket, "")
        self.assertNotIn("credential\n", str(err.exception))
        self.assertEqual(len(self.requests), 1)

    def test_per_request_credentials_can_rotate(self):
        action = self.action(token=iter(["fixture-only", "expired", "fixture-only"]).__next__)
        self.assertEqual(action.run(self.write_ticket, "value"), "value")
        self.assertFalse(action.outcome_delivered)
        self.assertTrue(action.retry_outcome())
        self.assertEqual(self.events, ["decision", "target_wrote", "returned"])

    def test_failed_outcome_can_retry_without_double_dispatch(self):
        self.outcome_status = 503
        action = self.action()
        self.assertEqual(action.run(self.write_ticket, "written"), "written")
        self.assertFalse(action.outcome_delivered)
        self.outcome_status = 200
        self.assertTrue(action.retry_outcome())
        self.assertEqual(self.requests[1], self.requests[2])
        self.assertEqual(self.events.count("target_wrote"), 1)

    def test_missing_outcome_acknowledgement_stays_pending(self):
        self.ack = {}
        action = self.action()
        self.assertEqual(action.run(self.write_ticket, "ok"), "ok")
        self.assertFalse(action.outcome_delivered)
        self.ack = {"recorded": True}
        self.assertTrue(action.retry_outcome())
        self.assertEqual(self.events.count("target_wrote"), 1)

    def test_tool_failure_preserves_application_error(self):
        def failing():
            raise KeyError("private input")
        self.outcome_status = 503
        action = self.action()
        with self.assertRaisesRegex(KeyError, "private input"):
            action.run(failing)
        self.assertEqual(action.outcome_status, "raised")
        self.assertNotIn("private input", str(self.requests))

    def test_concurrent_duplicate_callbacks_dispatch_once(self):
        action = self.action()
        with ThreadPoolExecutor(2) as executor:
            calls = [executor.submit(action.run, self.write_ticket, "ticket") for _ in range(2)]
        self.assertEqual(sum(isinstance(c.exception(), AlreadyAttempted) for c in calls), 1)
        self.assertEqual(self.events, ["decision", "target_wrote", "returned"])

    def test_timeout_preserves_fail_closed(self):
        self.release = threading.Event()
        try:
            action = self.action(timeout=0.02)
            with self.assertRaises(DecisionUnavailable):
                action.run(self.write_ticket, "ticket")
            self.assertEqual(action.outcome_status, "not_dispatched")
        finally:
            self.release.set()

    def test_sync_entry_rejects_async_and_streaming(self):
        async def coroutine():
            return 42
        with self.assertRaises(TypeError):
            self.action().run(coroutine)
        self.assertEqual(self.requests, [])
        with self.assertRaises(TypeError):
            self.action().run(lambda: coroutine())
        self.assertEqual(self.events, ["decision", "raised"])

    def test_async_allow_and_raised(self):
        async def successful():
            return self.write_ticket("ok")
        async def failure():
            raise RuntimeError("app error")
        self.assertEqual(asyncio.run(self.action().run_async(successful)), "ok")
        with self.assertRaisesRegex(RuntimeError, "app error"):
            asyncio.run(self.action().run_async(failure))
        self.assertEqual(self.events, ["decision", "target_wrote", "returned", "decision", "raised"])

    def test_async_cancellation_after_dispatch_records_cancellation(self):
        async def scenario():
            started = asyncio.Event()
            async def pending():
                started.set()
                await asyncio.Future()
            action = self.action()
            task = asyncio.create_task(action.run_async(pending))
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(action.outcome_delivered)
        asyncio.run(scenario())
        self.assertEqual(self.events, ["decision", "cancelled"])

    def test_async_cancel_during_admission_reports_no_dispatch(self):
        self.release = threading.Event()
        async def scenario():
            async def should_never_run():
                self.fail("Cancelled admission dispatched")
            action = self.action()
            task = asyncio.create_task(action.run_async(should_never_run))
            self.assertTrue(await asyncio.to_thread(self.admitting.wait, 1))
            task.cancel()
            self.release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(action.outcome_delivered)
        asyncio.run(scenario())
        self.assertEqual(self.events, ["decision", "not_dispatched"])
