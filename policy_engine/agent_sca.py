"""Stage and validate a bounded SCA group-config proposal without applying it."""

from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.etree import ElementTree

GROUP_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
VALUES = {
    "enabled": ("yes", "no"),
    "scan_on_start": ("yes", "no"),
    "skip_nfs": ("yes", "no"),
    "interval": ("1h", "6h", "12h", "24h", "7d"),
}
SCA_RE = re.compile(r"<sca(?:\s[^>]*)?>.*?</sca\s*>", re.DOTALL)
BLOCK_RE = re.compile(r"<agent_config(?:\s[^>]*)?>.*?</agent_config\s*>", re.DOTALL)


class ProposalError(ValueError):
    pass


def build_candidate(current: str, settings: dict) -> str:
    if not isinstance(settings, dict) or set(settings) != set(VALUES):
        raise ProposalError("Choose all four supported SCA settings")
    for name, allowed in VALUES.items():
        if settings[name] not in allowed:
            raise ProposalError(f"Invalid {name}")
    if len(current) > 32768:
        raise ProposalError("Group configuration is too large for this workflow")
    try:
        # Wazuh permits several top-level agent_config blocks, so parse inside a
        # synthetic root before selecting the single block this workflow handles.
        parsed = ElementTree.fromstring("<root>" + current + "</root>")
    except ElementTree.ParseError as error:
        raise ProposalError("Current group configuration is invalid XML") from error
    if len(parsed) != 1 or parsed[0].tag != "agent_config" or len(BLOCK_RE.findall(current)) != 1:
        raise ProposalError("This workflow requires one unscoped agent_config block")
    if parsed[0].attrib:
        raise ProposalError("Scoped agent_config blocks require manual review")
    blocks = SCA_RE.findall(current)
    if len(blocks) > 1:
        raise ProposalError("Multiple SCA blocks require manual review")
    if blocks and not blocks[0].startswith("<sca>"):
        raise ProposalError("Attributed SCA blocks require manual review")
    lines = [f"    <{name}>{settings[name]}</{name}>" for name in VALUES]
    if blocks:
        block = blocks[0]
        for name in VALUES:
            if len(re.findall(fr"<{name}\s*>.*?</{name}\s*>", block, re.DOTALL)) > 1:
                raise ProposalError(f"Multiple {name} settings require manual review")
            block = re.sub(fr"\s*<{name}\s*>.*?</{name}\s*>", "", block, count=1, flags=re.DOTALL)
        block = block.replace("<sca>", "<sca>\n" + "\n".join(lines), 1)
        if block == blocks[0]:
            raise ProposalError("Complex SCA blocks require manual review")
        candidate = current.replace(blocks[0], block, 1)
    else:
        insertion = "  <sca>\n" + "\n".join(lines) + "\n  </sca>\n"
        candidate = re.sub(r"</agent_config\s*>", insertion + "</agent_config>", current, count=1)
    try:
        ElementTree.fromstring("<root>" + candidate + "</root>")
    except ElementTree.ParseError as error:
        raise ProposalError("Generated configuration is invalid XML") from error
    return candidate


def validate(group: str, settings: dict, *, base: Path = Path("/var/ossec/etc/shared"),
             verifier: str = "/var/ossec/bin/verify-agent-conf") -> dict:
    if not isinstance(group, str) or not GROUP_RE.fullmatch(group) or group in (".", ".."):
        raise ProposalError("Invalid agent group")
    root = base.resolve(strict=True)
    group_dir = (root / group).resolve(strict=True)
    if group_dir.parent != root:
        raise ProposalError("Agent group path is outside the shared directory")
    config = group_dir / "agent.conf"
    if config.is_symlink():
        raise ProposalError("Symlinked group configuration requires manual review")
    current = config.read_text(encoding="utf-8")
    candidate = build_candidate(current, settings)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="agent-conf-", suffix=".tmp") as staged:
        staged.write(candidate)
        staged.flush()
        try:
            tested = subprocess.run([verifier, "-f", staged.name], capture_output=True,
                                    text=True, timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProposalError("Wazuh validator could not complete") from error
    diff = "".join(difflib.unified_diff(current.splitlines(keepends=True), candidate.splitlines(keepends=True),
                                        fromfile="active agent.conf", tofile="proposed agent.conf"))
    return {
        "group": group,
        "base_sha256": hashlib.sha256(current.encode()).hexdigest(),
        "settings": settings,
        "diff": diff[:12000],
        "valid": tested.returncode == 0 and "verify-agent-conf: OK" in tested.stdout,
        "validator_output": (tested.stdout + tested.stderr)[:2000],
        "applied": False,
        "scope": "All agents assigned to this group; no configuration was changed",
        "next_check": "After a separately approved apply, confirm group sync and compare the next agent SCA scan",
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Do not log proposed configuration, token, or user-specific group names.
        pass

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"status": "ok"})
        return self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/validate":
            return self.reply(404, {"error": "not found"})
        token = self.headers.get("X-Policy-Token", "")
        if not token or not hmac.compare_digest(token, self.server.token):
            return self.reply(401, {"error": "unauthorized"})
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            return self.reply(400, {"error": "JSON required"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 4096:
                return self.reply(413, {"error": "request too large"})
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                return self.reply(400, {"error": "invalid request"})
            result = validate(payload.get("group"), payload.get("settings"))
        except ProposalError as error:
            return self.reply(400, {"error": str(error)[:180]})
        except (ValueError, OSError):
            return self.reply(400, {"error": "Invalid or unavailable group configuration"})
        return self.reply(200, result)

    def reply(self, status: int, value: dict):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    token = os.environ.get("ASSISTANT_POLICY_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("ASSISTANT_POLICY_TOKEN must be at least 32 characters")
    server = ThreadingHTTPServer(("127.0.0.1", 8766), Handler)
    server.token = token
    server.serve_forever()


if __name__ == "__main__":
    main()
