"""Narrow, reviewed apply/rollback executor for validated agent group SCA settings."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from policy_engine.agent_sca import GROUP_RE, ProposalError, build_candidate, validate
from policy_engine.proposals import ProposalStore, public_proposal


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def group_config(base: Path, group: str) -> Path:
    if not isinstance(group, str) or not GROUP_RE.fullmatch(group) or group in (".", ".."):
        raise ProposalError("Invalid agent group")
    root = base.resolve(strict=True)
    raw_group = root / group
    if raw_group.is_symlink():
        raise ProposalError("Symlinked group requires manual review")
    directory = raw_group.resolve(strict=True)
    if directory.parent != root:
        raise ProposalError("Agent group path is outside the shared directory")
    config = directory / "agent.conf"
    if config.is_symlink() or not config.is_file():
        raise ProposalError("Group configuration requires manual review")
    if config.stat().st_uid != os.geteuid():
        raise ProposalError("Apply service must own this group configuration")
    return config


def atomic_write(config: Path, content: bytes, mode: int):
    fd, staged = tempfile.mkstemp(prefix=".agent-conf-", dir=config.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(staged, config)
        directory_fd = os.open(config.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def apply_proposal(store: ProposalStore, proposal_id: str, owner: str, *,
                   base: Path = Path("/var/ossec/etc/shared"),
                   verifier: str = "/var/ossec/bin/verify-agent-conf",
                   backup_root: Path = Path("/var/lib/wazuh-ai-policies/backups")) -> dict:
    row = store.get(proposal_id, owner)
    if not row:
        raise ProposalError("Proposal not found")
    if row["status"] != "validated":
        raise ProposalError("Proposal is no longer pending")
    if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
        raise ProposalError("Proposal expired; validate again")
    config = group_config(base, row["group_name"])
    before = config.read_bytes()
    if digest(before) != row["base_sha256"]:
        raise ProposalError("Group configuration changed; validate again")
    mode = config.stat().st_mode & 0o777
    candidate = build_candidate(before.decode("utf-8"), row["settings"]).encode("utf-8")
    checked = validate(row["group_name"], row["settings"], base=base, verifier=verifier)
    if not checked["valid"] or checked["base_sha256"] != row["base_sha256"] or checked["diff"] != row["diff"]:
        raise ProposalError("Native validation changed or failed; validate again")
    if config.read_bytes() != before:
        raise ProposalError("Group configuration changed during validation")
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = backup_root / (proposal_id + ".agent.conf")
    if backup.exists() or backup.is_symlink():
        if backup.is_symlink() or not backup.is_file() or digest(backup.read_bytes()) != row["base_sha256"]:
            raise ProposalError("Saved backup failed integrity check")
    else:
        with backup.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(before)
            output.flush()
            os.fsync(output.fileno())
    try:
        atomic_write(config, candidate, mode)
        new_hash = digest(candidate)
        if digest(config.read_bytes()) != new_hash or not store.mark_applied(proposal_id, new_hash):
            raise ProposalError("Apply verification failed")
    except Exception:
        if digest(config.read_bytes()) == digest(candidate):
            atomic_write(config, before, mode)
        raise
    return {"status": "applied", "proposal_id": proposal_id, "base_sha256": row["base_sha256"],
            "applied_sha256": new_hash, "scope": row["group_name"],
            "next_check": "Check group synchronization and the next agent SCA scan"}


def rollback_proposal(store: ProposalStore, proposal_id: str, owner: str, *,
                      base: Path = Path("/var/ossec/etc/shared"),
                      backup_root: Path = Path("/var/lib/wazuh-ai-policies/backups")) -> dict:
    row = store.get(proposal_id, owner)
    if not row or row["status"] != "applied":
        raise ProposalError("Applied proposal not found")
    config = group_config(base, row["group_name"])
    current = config.read_bytes()
    if digest(current) != row["applied_sha256"]:
        raise ProposalError("Group configuration changed; manual review required")
    backup = backup_root / (proposal_id + ".agent.conf")
    if backup.is_symlink() or not backup.is_file():
        raise ProposalError("Saved backup is unavailable")
    original = backup.read_bytes()
    if digest(original) != row["base_sha256"]:
        raise ProposalError("Saved backup failed integrity check")
    mode = config.stat().st_mode & 0o777
    try:
        atomic_write(config, original, mode)
        if not store.mark_rolled_back(proposal_id):
            raise ProposalError("Rollback audit failed")
    except Exception:
        if digest(config.read_bytes()) == digest(original):
            atomic_write(config, current, mode)
        raise
    return {"status": "rolled_back", "proposal_id": proposal_id, "restored_sha256": row["base_sha256"]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"status": "ok"})
        return self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/status", "/apply", "/rollback"):
            return self.reply(404, {"error": "not found"})
        token = self.headers.get("X-Policy-Apply-Token", "")
        if not token or not hmac.compare_digest(token, self.server.token):
            return self.reply(401, {"error": "unauthorized"})
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            return self.reply(400, {"error": "JSON required"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 512:
                return self.reply(413, {"error": "request too large"})
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict) or set(payload) != {"proposal_id", "owner"}:
                return self.reply(400, {"error": "invalid request"})
            with self.server.apply_lock:
                if self.path == "/status":
                    row = self.server.store.get(payload["proposal_id"], payload["owner"])
                    return self.reply(200, public_proposal(row)) if row else self.reply(404, {"error": "not found"})
                if self.path == "/apply":
                    result = apply_proposal(self.server.store, payload["proposal_id"], payload["owner"])
                else:
                    result = rollback_proposal(self.server.store, payload["proposal_id"], payload["owner"])
        except (ProposalError, ValueError, OSError, UnicodeError) as error:
            return self.reply(409, {"error": str(error)[:180]})
        return self.reply(200, result)

    def reply(self, status: int, value: dict):
        encoded = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main():
    token = os.environ.get("ASSISTANT_POLICY_APPLY_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("ASSISTANT_POLICY_APPLY_TOKEN must be at least 32 characters")
    server = ThreadingHTTPServer(("127.0.0.1", 8768), Handler)
    server.token = token
    server.store = ProposalStore(os.environ.get("ASSISTANT_POLICY_DB", "/var/lib/wazuh-ai-policies/proposals.sqlite3"))
    server.apply_lock = threading.Lock()
    server.serve_forever()


if __name__ == "__main__":
    main()
