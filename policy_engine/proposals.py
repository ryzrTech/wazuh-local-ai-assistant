"""Private, owner-scoped store for reviewed agent/SCA proposals."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

OWNER_RE = re.compile(r"^[a-f0-9]{64}$")
AGENT_RE = re.compile(r"^\d{1,6}$")
ID_RE = re.compile(r"^[a-f0-9-]{36}$")


class ProposalStore:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, agent_id TEXT NOT NULL,
                group_name TEXT NOT NULL, settings_json TEXT NOT NULL,
                base_sha256 TEXT NOT NULL, diff TEXT NOT NULL,
                validator_output TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                applied_at TEXT, applied_sha256 TEXT, rolled_back_at TEXT
            )""")
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

    def save(self, owner: str, agent_id: str, result: dict) -> str:
        if not OWNER_RE.fullmatch(owner or "") or not AGENT_RE.fullmatch(agent_id or "") or not result.get("valid"):
            raise ValueError("Invalid validated proposal")
        proposal_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        with self.lock, self.connect() as db:
            db.execute("""INSERT INTO proposals(id,owner,agent_id,group_name,settings_json,base_sha256,diff,
                validator_output,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (
                proposal_id, owner, agent_id, result["group"], json.dumps(result["settings"], sort_keys=True),
                result["base_sha256"], result["diff"], result["validator_output"], "validated",
                now.isoformat(), (now + timedelta(minutes=30)).isoformat(),
            ))
        return proposal_id

    def get(self, proposal_id: str, owner: str) -> dict | None:
        if not ID_RE.fullmatch(proposal_id or "") or not OWNER_RE.fullmatch(owner or ""):
            return None
        with self.connect() as db:
            row = db.execute("SELECT * FROM proposals WHERE id=? AND owner=?", (proposal_id, owner)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["settings"] = json.loads(result.pop("settings_json"))
        return result

    def list_for_agent(self, owner: str, agent_id: str) -> list[dict]:
        if not OWNER_RE.fullmatch(owner or "") or not AGENT_RE.fullmatch(agent_id or ""):
            return []
        with self.connect() as db:
            rows = db.execute("""SELECT * FROM proposals WHERE owner=? AND agent_id=?
                ORDER BY created_at DESC LIMIT 5""", (owner, agent_id)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["settings"] = json.loads(item.pop("settings_json"))
            result.append(item)
        return result

    def mark_applied(self, proposal_id: str, sha256: str) -> bool:
        with self.lock, self.connect() as db:
            changed = db.execute("""UPDATE proposals SET status='applied', applied_at=?, applied_sha256=?
                WHERE id=? AND status='validated'""", (datetime.now(timezone.utc).isoformat(), sha256, proposal_id)).rowcount
        return changed == 1

    def mark_rolled_back(self, proposal_id: str) -> bool:
        with self.lock, self.connect() as db:
            changed = db.execute("""UPDATE proposals SET status='rolled_back', rolled_back_at=?
                WHERE id=? AND status='applied'""", (datetime.now(timezone.utc).isoformat(), proposal_id)).rowcount
        return changed == 1


def public_proposal(row: dict) -> dict:
    return {key: row[key] for key in ("id", "agent_id", "group_name", "settings", "base_sha256", "diff",
                                  "validator_output", "status", "created_at", "expires_at", "applied_at",
                                  "applied_sha256", "rolled_back_at")}
