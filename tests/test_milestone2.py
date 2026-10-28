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

from orchestrator.server import Server, Store
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
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE sessions SET updated_at='2000-01-01 00:00:00' WHERE id=?", (second,))
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


if __name__ == "__main__":
    unittest.main()
