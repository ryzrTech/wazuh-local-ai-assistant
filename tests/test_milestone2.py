import http.client
import json
import os
import socketserver
import sqlite3
import stat
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from orchestrator.server import READ_TOOLS, Server, Store
from provider_registry.openai_compatible import Provider, ProviderError


class FakeProvider(BaseHTTPRequestHandler):
    last_request = None
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data":[{"id":"test-model"}]}')

    def do_POST(self):
        content = int(self.headers["Content-Length"])
        request = json.loads(self.rfile.read(content))
        FakeProvider.last_request = request
        assert request["model"] == "test-model"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        if request.get("tools"):
            if any(message.get("content") == "Five searches" for message in request["messages"]):
                for index in range(5):
                    delta = {"choices": [{"delta": {"tool_calls": [{"index": index, "id": f"call_{index}",
                        "type": "function", "function": {"name": "search_alerts", "arguments": '{"hours":24}'}}]}}]}
                    self.wfile.write(("data: " + json.dumps(delta) + "\n\n").encode())
            elif any(message.get("content") == "Think aloud" for message in request["messages"]):
                if request.get("tool_choice") == "none":
                    self.wfile.write(b'data: {"choices":[{"delta":{"reasoning_content":"Review evidence. "}}]}\n\n')
                    self.wfile.write(b'data: {"choices":[{"delta":{"reasoning_content":"Answer concisely."}}]}\n\n')
                    self.wfile.write(b'data: {"choices":[{"delta":{"content":"Final answer."}}]}\n\n')
                else:
                    self.wfile.write(b'data: {"choices":[{"delta":{"reasoning_content":"Check the scope first. "}}]}\n\n')
                    self.wfile.write(b'data: {"choices":[{"delta":{"reasoning_content":"Then answer."}}]}\n\n')
                    self.wfile.write(b'data: {"choices":[{"delta":{"content":"Scoped answer."}}]}\n\n')
            elif any(message.get("content") == "Just explain" for message in request["messages"]):
                self.wfile.write(b'data: {"choices":[{"delta":{"content":"This "}}]}\n\n')
                self.wfile.flush()
                self.wfile.write(b'data: {"choices":[{"delta":{"content":"is text."}}]}\n\n')
            elif any(message.get("role") == "tool" for message in request["messages"]):
                self.wfile.write(b'data: {"choices":[{"delta":{"content":"Found one matching alert."}}]}\n\n')
            else:
                self.wfile.write(b'data: {"choices":[{"delta":{"content":"Checking now."}}]}\n\n')
                self.wfile.write(b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"search_alerts","arguments":"{\\\"hours\\\":24"}}]}}]}\n\n')
                self.wfile.write(b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":",\\\"rule_id\\\":\\\"100100\\\"}"}}]}}]}\n\n')
            self.wfile.write(b'data: [DONE]\n\n')
            return
        if any(message.get("content") == "Think aloud" for message in request["messages"]):
            self.wfile.write(b'data: {"choices":[{"delta":{"reasoning_content":"Review evidence. "}}]}\n\n')
            self.wfile.write(b'data: {"choices":[{"delta":{"reasoning_content":"Answer concisely."}}]}\n\n')
            self.wfile.write(b'data: {"choices":[{"delta":{"content":"Final answer."}}]}\n\n')
            self.wfile.write(b'data: [DONE]\n\n')
            return
        self.wfile.write(b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n')
        self.wfile.flush()
        self.wfile.write(b'data: {"choices":[{"delta":{"content":" world"}}]}\n\n')
        self.wfile.write(b'data: [DONE]\n\n')


class FastLoopbackServer(ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = self.server_address[0]
        self.server_port = self.server_address[1]


class Milestone2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = FastLoopbackServer(("127.0.0.1", 0), FakeProvider)
        cls.provider_thread = threading.Thread(target=cls.provider.serve_forever, daemon=True)
        cls.provider_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.provider.shutdown()
        cls.provider.server_close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        port = self.provider.server_address[1]
        self.adapter = Provider(f"http://127.0.0.1:{port}/v1", "test-model", "", "127.0.0.1", allow_http_loopback=True)
        self.db_path = Path(self.temp.name) / "db.sqlite"
        self.provider_path = Path(self.temp.name) / "provider.json"
        self.server = Server(("127.0.0.1", 0), Store(str(self.db_path)), self.adapter, False, "x" * 32,
                             "a" * 32, str(self.provider_path))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method, path, body=None, owner="analyst", token="x" * 32, admin=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=3)
        headers = {"X-Assistant-Token": token, "X-Assistant-User": owner}
        if admin:
            headers["X-Assistant-Admin-Token"] = "a" * 32
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        status, payload = response.status, response.read()
        conn.close()
        return status, payload

    def test_stream_and_persistence(self):
        status, payload = self.request("POST", "/api/sessions")
        self.assertEqual(status, 201)
        sid = json.loads(payload)["id"]
        status, stream = self.request("POST", f"/api/sessions/{sid}/messages", {"content": "Hello"})
        self.assertEqual(status, 200)
        self.assertIn(b'event: delta', stream)
        self.assertIn(b'event: done', stream)
        self.assertIn(b'Hello world', stream)
        status, payload = self.request("GET", f"/api/sessions/{sid}/messages")
        self.assertEqual(status, 200)
        self.assertEqual([m["content"] for m in json.loads(payload)["messages"]], ["Hello", "Hello world"])

    def test_tool_answer_stream_and_retry_without_duplicate(self):
        sid = json.loads(self.request("POST", "/api/sessions")[1])["id"]
        path = f"/api/sessions/{sid}/turn"
        status, payload = self.request("POST", path, {"content": "Any malware detections?", "retry": False})
        self.assertEqual(status, 200)
        self.assertEqual([item["role"] for item in json.loads(payload)["messages"]], ["system", "user"])
        status, payload = self.request("POST", path, {"content": "Any malware detections?", "retry": True})
        self.assertEqual(status, 200)
        self.assertEqual([item["role"] for item in json.loads(payload)["messages"]], ["system", "user"])
        self.assertEqual(self.request("POST", path, {"content": "Different question", "retry": True})[0], 409)
        status, payload = self.request("GET", f"/api/sessions/{sid}/messages")
        self.assertEqual(status, 200)
        self.assertEqual([item["content"] for item in json.loads(payload)["messages"]], ["Any malware detections?"])
        self.server.store.append("analyst", sid, "user", "Any malware detections?")
        status, payload = self.request("POST", path, {"content": "Any malware detections?", "retry": True})
        self.assertEqual(status, 200)
        self.assertEqual([item["role"] for item in json.loads(payload)["messages"]], ["system", "user"])

        messages = [
            {"role": "system", "content": "Answer using the search result."},
            {"role": "user", "content": "Any malware detections?"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "search_alerts", "arguments": "{\"hours\":24}"}}]},
            {"role": "tool", "tool_call_id": "call_1", "name": "search_alerts", "content": '{"records":[]}'},
        ]
        status, stream = self.request("POST", "/api/model/stream", {"messages": messages})
        self.assertEqual(status, 200)
        self.assertIn(b'event: delta', stream)
        self.assertIn(b'event: done', stream)
        self.assertEqual(FakeProvider.last_request["tool_choice"], "none")

    def test_first_model_turn_streams_and_resets_before_tools(self):
        messages = [{"role": "system", "content": "Use tools when needed"},
                    {"role": "user", "content": "Check alerts"}]
        status, stream = self.request("POST", "/api/model/complete-stream", {"messages": messages})
        self.assertEqual(status, 200)
        self.assertIn(b'event: delta', stream)
        self.assertIn(b'event: reset', stream)
        self.assertIn(b'event: turn', stream)
        self.assertIn(b'event: done', stream)
        status, stream = self.request("POST", "/api/model/complete-stream", {"messages": [
            {"role": "system", "content": "Explain"}, {"role": "user", "content": "Just explain"}]})
        self.assertEqual(status, 200)
        self.assertEqual(stream.count(b'event: delta'), 2)
        self.assertNotIn(b'event: reset', stream)
        self.assertIn(b'event: done', stream)

    def test_provider_accepts_bounded_multi_search_turn(self):
        turn = self.adapter.complete_with_tools([{"role": "user", "content": "Five searches"}], READ_TOOLS)
        self.assertEqual(len(turn["tool_calls"]), 5)

    def test_thinking_stream_and_owner_scoped_history(self):
        messages = [{"role": "user", "content": "Think aloud"}]
        status, stream = self.request("POST", "/api/model/complete-stream", {"messages": messages})
        self.assertEqual(status, 200)
        self.assertIn(b'event: thinking', stream)
        self.assertIn(b'Check the scope first.', stream)
        self.assertIn(b'event: delta', stream)
        self.assertIn(b'Scoped answer.', stream)
        status, stream = self.request("POST", "/api/model/stream", {"messages": messages})
        self.assertEqual(status, 200)
        self.assertIn(b'event: thinking', stream)
        self.assertIn(b'Review evidence.', stream)
        self.assertIn(b'Final answer.', stream)
        sid = json.loads(self.request("POST", "/api/sessions")[1])["id"]
        status, _ = self.request("POST", f"/api/sessions/{sid}/assistant", {
            "content": "Final answer.", "thinking": "Review evidence. Answer concisely.", "updates": "I will check the records.",
        })
        self.assertEqual(status, 200)
        status, payload = self.request("GET", f"/api/sessions/{sid}/messages")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["messages"][0]["thinking"], "Review evidence. Answer concisely.")
        self.assertEqual(json.loads(payload)["messages"][0]["updates"], "I will check the records.")
        self.assertEqual(self.request("GET", f"/api/sessions/{sid}/messages", owner="other")[0], 404)
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/assistant", {
            "content": "Answer", "thinking": "x" * 16001,
        })[0], 400)
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/assistant", {
            "content": "Answer", "updates": "x" * 4001,
        })[0], 400)

    def test_existing_message_table_gains_thinking_column(self):
        legacy = Path(self.temp.name) / "legacy.sqlite"
        with sqlite3.connect(legacy) as db:
            db.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        upgraded = Store(str(legacy))
        with upgraded.connect() as db:
            columns = [row[1] for row in db.execute("PRAGMA table_info(messages)")]
        self.assertIn("thinking", columns)
        self.assertIn("updates", columns)

    def test_cross_user_and_auth_denied(self):
        sid = json.loads(self.request("POST", "/api/sessions")[1])["id"]
        self.assertEqual(self.request("GET", f"/api/sessions/{sid}/messages", owner="other")[0], 404)
        self.assertEqual(self.request("GET", "/api/sessions", token="wrong")[0], 401)
        self.assertEqual(self.request("GET", "/api/sessions", owner="../bad")[0], 401)

    def test_provider_destination_is_approved(self):
        bad = Provider("http://169.254.169.254/v1", "test-model", "", "169.254.169.254", allow_http_loopback=True)
        with self.assertRaises(ProviderError):
            bad.destination()
        bad = Provider("https://example.com/v1", "test-model", "", "different.example")
        with self.assertRaises(ProviderError):
            bad.destination()

    def test_message_bounds(self):
        sid = json.loads(self.request("POST", "/api/sessions")[1])["id"]
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/messages", {"content": "x" * 4001})[0], 400)

    def test_admin_provider_configuration(self):
        self.assertEqual(self.request("GET", "/api/provider/config")[0], 403)
        self.assertEqual(self.request("POST", "/api/provider/test", {"url": self.adapter.base_url})[0], 403)
        status, payload = self.request("POST", "/api/provider/test", {"url": self.adapter.base_url, "key": "private-key"}, admin=True)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["models"], ["test-model"])
        status, payload = self.request("POST", "/api/provider/config", {"url": self.adapter.base_url, "key": "private-key", "model": "test-model"}, admin=True)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["has_key"])
        self.assertNotIn(b"private-key", payload)
        self.assertEqual(stat.S_IMODE(os.stat(self.provider_path).st_mode), 0o600)
        self.assertEqual(self.request("GET", "/api/models")[0], 200)
        self.assertEqual(self.request("POST", "/api/provider/test", {"url": "http://169.254.169.254/v1"}, admin=True)[0], 502)

    def test_history_deletion_and_retention(self):
        first = json.loads(self.request("POST", "/api/sessions")[1])["id"]
        second = json.loads(self.request("POST", "/api/sessions")[1])["id"]
        other = json.loads(self.request("POST", "/api/sessions", owner="other")[1])["id"]
        self.assertEqual(self.request("DELETE", f"/api/sessions/{other}")[0], 404)
        self.assertEqual(self.request("DELETE", f"/api/sessions/{first}")[0], 200)
        self.assertEqual(self.request("GET", f"/api/sessions/{first}/messages")[0], 404)
        self.assertEqual(self.request("POST", "/api/settings", {"retention_days": 7})[0], 200)
        db = sqlite3.connect(self.db_path)
        try:
            with db:
                db.execute("UPDATE sessions SET updated_at='2000-01-01 00:00:00' WHERE id=?", (second,))
        finally:
            db.close()
        self.server.store.prune_all()
        self.assertEqual(self.request("GET", f"/api/sessions/{second}/messages")[0], 404)
        self.assertEqual(self.request("GET", f"/api/sessions/{other}/messages", owner="other")[0], 200)
        self.assertEqual(self.request("POST", "/api/settings", {"retention_days": 8})[0], 400)
        self.assertEqual(self.request("DELETE", "/api/sessions", owner="other")[0], 200)
        self.assertEqual(self.request("GET", "/api/sessions", owner="other")[0], 200)

    def test_investigation_evidence_is_owner_scoped_and_sent_to_model(self):
        evidence = {"source_ref": "wazuh-alerts-example/abc", "record": {"rule": {"id": "1001", "description": "Example event"}}}
        status, payload = self.request("POST", "/api/investigations", {
            "source_type": "alert", "source_ref": evidence["source_ref"], "title": "Example investigation", "evidence": evidence,
        })
        self.assertEqual(status, 201)
        sid = json.loads(payload)["id"]
        self.assertEqual(self.request("GET", "/api/investigations", owner="other")[0], 200)
        self.assertEqual(json.loads(self.request("GET", "/api/investigations", owner="other")[1])["investigations"], [])
        self.assertEqual(self.request("GET", f"/api/investigations/{sid}", owner="other")[0], 404)
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/messages", {"content": "Investigate"})[0], 200)
        self.assertIn("wazuh-alerts-example/abc", json.dumps(FakeProvider.last_request["messages"]))
        self.assertEqual(self.request("DELETE", f"/api/sessions/{sid}")[0], 200)
        self.assertEqual(self.request("GET", f"/api/investigations/{sid}")[0], 404)

    def test_tool_turn_and_audit_are_owner_scoped(self):
        sid = json.loads(self.request("POST", "/api/sessions")[1])["id"]
        status, body = self.request("POST", f"/api/sessions/{sid}/turn", {"content": "Show recent root SSH logins"})
        self.assertEqual(status, 200)
        messages = json.loads(body)["messages"]
        self.assertIn("read-only tools", messages[0]["content"])
        self.assertEqual(messages[-1], {"role": "user", "content": "Show recent root SSH logins"})
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/turn", {"content": "test"}, owner="other")[0], 404)
        status, body = self.request("POST", "/api/model/complete", {"messages": messages})
        self.assertEqual(status, 200)
        call = json.loads(body)["tool_calls"][0]
        self.assertEqual(call["function"]["name"], "search_alerts")
        self.assertEqual(json.loads(call["function"]["arguments"]), {"hours": 24, "rule_id": "100100"})
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/tool-audit", {
            "name": "search_alerts", "arguments": {"hours": 24}, "status": "ok", "count": 1, "duration_ms": 12,
        }, owner="other")[0], 404)
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/tool-audit", {
            "name": "search_alerts", "arguments": {"hours": 24}, "status": "ok", "count": 1, "duration_ms": 12,
        })[0], 200)
        self.assertEqual(self.request("POST", f"/api/sessions/{sid}/assistant", {"content": "Found one matching alert."})[0], 200)
        self.assertEqual(self.request("GET", f"/api/sessions/{sid}/messages")[0], 200)
        self.assertEqual(self.request("DELETE", f"/api/sessions/{sid}")[0], 200)
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM tool_audit").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
