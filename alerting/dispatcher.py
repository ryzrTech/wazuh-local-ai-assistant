"""Forward new, high-severity Wazuh alerts to an administrator-configured webhook."""

from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


class AlertError(ValueError):
    pass


def destination(url: str, allowed_private_hosts: str = ""):
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise AlertError("A webhook URL is required")
    parsed = urlsplit(url)
    host = parsed.hostname
    if parsed.scheme != "https" or not host or parsed.username or parsed.password or parsed.fragment:
        raise AlertError("Use an HTTPS webhook URL without embedded credentials")
    if any(ord(character) < 32 for character in url):
        raise AlertError("Webhook URL contains control characters")
    if parsed.port and parsed.port not in (443, 8443):
        raise AlertError("Webhook port must be 443 or 8443")
    allowed = {name.strip().lower() for name in allowed_private_hosts.split(",") if name.strip()}
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
    except OSError as error:
        raise AlertError("Webhook host could not be resolved") from error
    if len(addresses) != 1:
        raise AlertError("Webhook host must resolve to one address")
    address = ipaddress.ip_address(next(iter(addresses)))
    if not address.is_global and host.lower() not in allowed:
        raise AlertError("Private webhook hosts require an explicit server allowlist")
    if address.is_link_local or address.is_multicast or address.is_unspecified or str(address) == "169.254.169.254":
        raise AlertError("Webhook address is forbidden")
    return parsed, str(address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int):
        super().__init__(host, port, timeout=8, context=ssl.create_default_context())
        self.ip = ip

    def connect(self):
        raw = socket.create_connection((self.ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def deliver(url: str, payload: dict, allowed_private_hosts: str = ""):
    parsed, address = destination(url, allowed_private_hosts)
    connection = PinnedHTTPSConnection(parsed.hostname, address, parsed.port or 443)
    try:
        body = json.dumps(payload, ensure_ascii=False).encode()
        if len(body) > 4096:
            raise AlertError("Notification is too large")
        connection.request("POST", (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
                           body=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
        response = connection.getresponse()
        response.read(1024)
        if not 200 <= response.status < 300:
            raise AlertError(f"Webhook returned HTTP {response.status}")
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise AlertError("Webhook delivery failed") from error
    finally:
        connection.close()


def summary(alert: dict) -> dict | None:
    rule = alert.get("rule") if isinstance(alert, dict) else None
    if not isinstance(rule, dict) or not isinstance(alert.get("id"), str):
        return None
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    return {
        "event": "wazuh.alert", "id": alert["id"],
        "timestamp": str(alert.get("timestamp", ""))[:64],
        "rule": {"id": str(rule.get("id", ""))[:20], "level": rule.get("level"),
                 "description": str(rule.get("description", ""))[:300]},
        "agent": {"id": str(agent.get("id", ""))[:20], "name": str(agent.get("name", ""))[:100]},
    }


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL,
                min_level INTEGER NOT NULL, url TEXT NOT NULL);
              INSERT OR IGNORE INTO config VALUES(1,'dashboard',12,'');
              CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY CHECK(id=1), inode INTEGER NOT NULL, offset INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS queue (id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                next_at REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL);
            """)
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def config(self):
        with self.connect() as db:
            return dict(db.execute("SELECT mode,min_level,url FROM config WHERE id=1").fetchone())

    def public_config(self):
        config = self.config()
        return {"mode": config["mode"], "min_level": config["min_level"],
                "configured": bool(config["url"]), "url_host": urlsplit(config["url"]).hostname or ""}

    def save(self, mode: str, min_level: int, url: str, allowed_private_hosts: str):
        if mode not in ("dashboard", "webhook") or type(min_level) is not int or min_level not in (10, 12, 15):
            raise AlertError("Choose a supported delivery mode and threshold")
        current = self.config()
        if mode == "dashboard":
            url = ""
        else:
            url = url or current["url"]
            destination(url, allowed_private_hosts)
        with self.lock, self.connect() as db:
            db.execute("UPDATE config SET mode=?,min_level=?,url=? WHERE id=1", (mode, min_level, url))
            # An old pending alert must not be delivered to a newly chosen destination.
            db.execute("DELETE FROM queue WHERE status='pending'")
            db.commit()
        return self.public_config()

    def cursor(self):
        with self.connect() as db:
            row = db.execute("SELECT inode,offset FROM cursor WHERE id=1").fetchone()
            return (row[0], row[1]) if row else None

    def record(self, inode: int, offset: int, alert: dict | None):
        item = summary(alert) if alert else None
        level = item["rule"]["level"] if item else None
        with self.lock, self.connect() as db:
            config = db.execute("SELECT mode,min_level FROM config WHERE id=1").fetchone()
            if config["mode"] == "webhook" and item and type(level) is int and level >= config["min_level"]:
                pending = db.execute("SELECT COUNT(*) FROM queue WHERE status='pending'").fetchone()[0]
                if pending < 10000:
                    db.execute("INSERT OR IGNORE INTO queue(id,payload,created_at) VALUES(?,?,?)",
                               (item["id"], json.dumps(item), time.time()))
            db.execute("INSERT INTO cursor(id,inode,offset) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET inode=excluded.inode,offset=excluded.offset", (inode, offset))
            db.commit()

    def pending(self):
        with self.connect() as db:
            row = db.execute("SELECT id,payload,attempts FROM queue WHERE status='pending' AND next_at<=? ORDER BY created_at LIMIT 1", (time.time(),)).fetchone()
            return dict(row) if row else None

    def dispatch_one(self, allowed_private_hosts: str):
        with self.lock, self.connect() as db:
            config = db.execute("SELECT mode,url FROM config WHERE id=1").fetchone()
            if config["mode"] != "webhook":
                return
            row = db.execute("SELECT id,payload,attempts FROM queue WHERE status='pending' AND next_at<=? ORDER BY created_at LIMIT 1", (time.time(),)).fetchone()
            if not row:
                return
            attempts = row["attempts"] + 1
            try:
                deliver(config["url"], json.loads(row["payload"]), allowed_private_hosts)
                success = True
            except (AlertError, ValueError):
                success = False
            db.execute("UPDATE queue SET status=?, attempts=?, next_at=? WHERE id=?",
                       ("sent" if success else "dead" if attempts >= 5 else "pending",
                        attempts, 0 if success else time.time() + min(300, 2 ** attempts * 5), row["id"]))
            db.execute("DELETE FROM queue WHERE status='sent' AND created_at<?", (time.time() - 7 * 86400,))


def worker(store: Store, alerts_path: Path, allowed_private_hosts: str):
    handle = None
    inode = None
    while True:
        try:
            stat = alerts_path.stat()
            if handle is None or inode != stat.st_ino:
                if handle:
                    handle.close()
                handle = alerts_path.open("r", encoding="utf-8", errors="replace")
                previous = store.cursor()
                handle.seek(previous[1] if previous and previous[0] == stat.st_ino and previous[1] <= stat.st_size else
                            stat.st_size if previous is None else 0)
                inode = stat.st_ino
            elif handle.tell() > stat.st_size:
                handle.seek(0)
            for _ in range(200):
                pos = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    handle.seek(pos)
                    break
                try:
                    alert = json.loads(line)
                except ValueError:
                    alert = None
                store.record(inode, handle.tell(), alert)
            store.dispatch_one(allowed_private_hosts)
        except (OSError, sqlite3.Error, ValueError):
            pass
        time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def reply(self, status: int, value: dict):
        encoded = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def authorized(self):
        token = self.headers.get("X-Alert-Token", "")
        return bool(token and hmac.compare_digest(token, self.server.token))

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"status": "ok"})
        if self.path == "/config" and self.authorized():
            return self.reply(200, self.server.store.public_config())
        return self.reply(401 if self.path == "/config" else 404, {"error": "unauthorized" if self.path == "/config" else "not found"})

    def do_POST(self):
        if self.path not in ("/config", "/test"):
            return self.reply(404, {"error": "not found"})
        if not self.authorized():
            return self.reply(401, {"error": "unauthorized"})
        if self.path == "/test":
            config = self.server.store.config()
            if config["mode"] != "webhook":
                return self.reply(400, {"error": "Enable a webhook before testing delivery"})
            try:
                deliver(config["url"], {"event": "wazuh.test", "text": "Wazuh AI alert delivery test"}, self.server.allowed_private_hosts)
            except AlertError as error:
                return self.reply(502, {"error": str(error)})
            return self.reply(200, {"status": "delivered"})
        try:
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                raise AlertError("JSON required")
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 4096:
                raise AlertError("Invalid request size")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise AlertError("Invalid configuration")
            result = self.server.store.save(payload.get("mode"), payload.get("min_level"), payload.get("url", ""), self.server.allowed_private_hosts)
        except (AlertError, ValueError) as error:
            return self.reply(400, {"error": str(error)[:160]})
        return self.reply(200, result)


def main():
    token = os.environ.get("ASSISTANT_ALERT_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("ASSISTANT_ALERT_TOKEN must be at least 32 characters")
    store = Store(Path(os.environ.get("ASSISTANT_ALERT_DB", "/var/lib/wazuh-ai-alerts/alerts.sqlite3")))
    allowed = os.environ.get("ASSISTANT_ALERT_ALLOWED_PRIVATE_HOSTS", "")
    alerts_path = Path(os.environ.get("ASSISTANT_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"))
    threading.Thread(target=worker, args=(store, alerts_path, allowed), daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", 8767), Handler)
    server.token = token
    server.store = store
    server.allowed_private_hosts = allowed
    server.serve_forever()


if __name__ == "__main__":
    main()
