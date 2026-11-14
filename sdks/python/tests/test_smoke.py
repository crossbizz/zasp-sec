"""Smoke test of the generated client against a local fake of the API.

It checks what a generated client can get wrong without an import error: the
paths, the bearer header, the cursor of auto-pagination, the request body, the
parsing of contract-shaped responses, and the mapping of an error status to an
exception. The fake serves ../../fixtures/responses.json.

Run:  python -m pytest tests
"""

import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from zasp import Zasp
from zasp.core.api_error import ApiError

FIXTURES = json.loads((pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "responses.json").read_text())
TOKEN = FIXTURES["token"]


class Handler(BaseHTTPRequestHandler):
    requests: list = []

    def log_message(self, *args):  # keep the test output quiet
        pass

    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self):
        url = urlparse(self.path)
        query = {key: values[0] for key, values in parse_qs(url.query).items()}
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        Handler.requests.append({"method": self.command, "path": url.path, "query": query, "authorization": self.headers.get("Authorization"), "body": body})
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, FIXTURES["error_unauthenticated"])
        if self.command == "GET" and url.path == "/api/v1/agents":
            second = query.get("cursor") == FIXTURES["next_cursor"]
            return self._send(200, FIXTURES["agents_page_2" if second else "agents_page_1"])
        if self.command == "GET" and url.path == "/api/v1/findings":
            return self._send(200, FIXTURES["findings_page"])
        if self.command == "POST" and url.path == "/api/v1/guardrails/decisions":
            return self._send(200, FIXTURES["guardrail_decision"])
        return self._send(404, FIXTURES["error_not_found"])

    do_GET = _handle
    do_POST = _handle


@pytest.fixture(scope="module")
def base_url():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(autouse=True)
def clear_requests():
    Handler.requests.clear()


def test_lists_agents_across_pages(base_url):
    client = Zasp(base_url=base_url, token=TOKEN)
    names = [agent.name for agent in client.agents.list(limit=1)]
    assert names == ["support-copilot", "claims-triage-handler"]
    assert [request["path"] for request in Handler.requests] == ["/api/v1/agents", "/api/v1/agents"]
    assert Handler.requests[0]["authorization"] == f"Bearer {TOKEN}"
    assert Handler.requests[0]["query"] == {"limit": "1"}
    assert Handler.requests[1]["query"]["cursor"] == FIXTURES["next_cursor"]


def test_lists_findings(base_url):
    client = Zasp(base_url=base_url, token=TOKEN)
    findings = list(client.findings.list())
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].rule == "agent_guardrail_missing"
    assert Handler.requests[0]["path"] == "/api/v1/findings"


def test_creates_a_guardrail_decision(base_url):
    client = Zasp(base_url=base_url, token=TOKEN)
    decision = client.guardrails.create_decision(**FIXTURES["guardrail_request"])
    assert decision.decision == "redact"
    assert decision.redacted_text == FIXTURES["guardrail_decision"]["redacted_text"]
    assert decision.matched_rules[0].id == "pii.email"
    assert Handler.requests[0]["method"] == "POST"
    assert Handler.requests[0]["path"] == "/api/v1/guardrails/decisions"
    assert Handler.requests[0]["body"] == FIXTURES["guardrail_request"]


def test_raises_the_error_of_a_refused_request(base_url):
    client = Zasp(base_url=base_url, token="wrong", max_retries=0)
    with pytest.raises(ApiError) as raised:
        list(client.findings.list())
    assert raised.value.status_code == 401
