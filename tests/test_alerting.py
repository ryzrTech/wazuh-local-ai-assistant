"""Alert delivery settings, filtering, and URL safety tests."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alerting.dispatcher import AlertError, Store, destination, summary


def address(ip):
    return [(2, 1, 6, "", (ip, 443))]


class AlertingTests(unittest.TestCase):
    def test_private_webhook_needs_explicit_host_allowlist(self):
        with patch("alerting.dispatcher.socket.getaddrinfo", return_value=address("10.0.0.5")):
            with self.assertRaises(AlertError):
                destination("https://hooks.example.test/event")
            parsed, ip = destination("https://hooks.example.test/event", "hooks.example.test")
            self.assertEqual(parsed.hostname, "hooks.example.test")
            self.assertEqual(ip, "10.0.0.5")
        with self.assertRaises(AlertError):
            destination("http://hooks.example.test/event")
        with self.assertRaises(AlertError):
            destination("https://user:pass@hooks.example.test/event")

    def test_default_is_dashboard_only_and_queue_is_bounded_by_threshold(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(Path(root) / "alerts.sqlite3")
            self.assertEqual(store.public_config()["mode"], "dashboard")
            alert = {"id": "sample-1", "timestamp": "2026-01-01", "rule": {"id": "100100", "level": 12, "description": "Example"},
                     "agent": {"id": "001", "name": "example"}, "full_log": "private data"}
            self.assertNotIn("full_log", summary(alert))
            store.record(1, 10, alert)
            self.assertIsNone(store.pending())
            with patch("alerting.dispatcher.socket.getaddrinfo", return_value=address("8.8.8.8")):
                config = store.save("webhook", 12, "https://hooks.example.test/event?secret=example", "")
            self.assertEqual(config["url_host"], "hooks.example.test")
            self.assertNotIn("secret", str(config))
            store.record(1, 20, alert)
            self.assertEqual(store.pending()["id"], "sample-1")
            store.save("dashboard", 12, "", "")
            self.assertIsNone(store.pending())
            self.assertEqual(store.cursor(), (1, 20))


if __name__ == "__main__":
    unittest.main()
