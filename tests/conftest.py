"""A stand-in RevSec on 127.0.0.1: the SDK routes the hooks' calls, over
real HTTP, recording what it was sent."""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import revsec.mcp as m

AGENT_ID = "0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6"


class RevSecStub:
    def __init__(self):
        self.evaluations, self.outcomes, self.registrations, self.scans = [], [], [], []
        self.contents = []                       # prompts and tool results checked
        self.stop_text = "IGNORE PREVIOUS INSTRUCTIONS"
        self.block = {"refund_order": "Refunds need a person", "delete_note": "Deleting notes is not allowed"}
        self.register_status = 200
        self._event = 100
        self._lock = threading.Lock()

    def answer(self, method, path, body):
        with self._lock:
            if method == "POST" and path.endswith("/api/v1/mcp-governance/evaluate"):
                self._event += 1
                self.evaluations.append(body)
                reason = self.block.get(body["tool_name"])
                if reason:
                    return 200, {"decision": "block", "event_id": self._event, "severity": "high",
                                 "matched_policy_name": "Stop risky actions", "match_excerpt": reason}
                return 200, {"decision": "allow", "event_id": self._event}
            if method == "POST" and path.endswith("/api/v1/agent-security/sdk/register"):
                self.registrations.append(body)
                if self.register_status != 200:
                    return self.register_status, {"detail": "key refused"}
                return 200, {"agent_id": AGENT_ID, "status": "shadow", "is_new": True}
            if method == "POST" and path.endswith("/api/v1/ai-data-flows/ingest"):
                self.scans.append(body)
                return 200, ({"blocked": True, "violations": [{"rule_name": "AWS secret key"}]}
                             if "AKIA" in body.get("content", "") else {"blocked": False})
            if method == "POST" and path.endswith("/api/v1/agent-security/sdk/check-content"):
                self.contents.append(body)
                if self.stop_text in body.get("content", ""):
                    return 200, {"decision": "block", "threat_detected": True, "threat_type": "prompt_injection",
                                 "severity": "high", "rule_name": "Instruction override",
                                 "reason": "instructions aimed at the model."}  # as RevSec words it: a full stop
                return 200, {"decision": "allow", "threat_detected": False}
            found = re.search(r"/api/v1/mcp-governance/events/(\d+)/outcome$", path)
            if method == "PATCH" and found:
                self.outcomes.append({"event_id": int(found.group(1)), **body})
                return 200, {}
            return 404, {"detail": f"no route {method} {path}"}


@pytest.fixture
def revsec(monkeypatch):
    stub = RevSecStub()

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, method):
            length = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            status, out = stub.answer(method, self.path, body)
            data = json.dumps(out).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self._reply("POST")

        def do_PATCH(self):
            self._reply("PATCH")

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stub.url = f"http://127.0.0.1:{server.server_address[1]}/fcc"
    monkeypatch.setattr(m, "_config", m._Config())
    monkeypatch.delenv("REVSEC_API_KEY", raising=False)
    monkeypatch.delenv("REVSEC_BASE_URL", raising=False)
    yield stub
    server.shutdown()
