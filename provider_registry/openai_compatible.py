"""Small OpenAI-compatible streaming adapter with a pinned, approved destination."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit


class ProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class Provider:
    base_url: str
    model: str
    api_key: str
    allowed_host: str
    timeout: int = 60
    allow_http_loopback: bool = False

    @classmethod
    def from_env(cls) -> "Provider":
        return cls(
            base_url=os.environ.get("ASSISTANT_PROVIDER_URL", ""),
            model=os.environ.get("ASSISTANT_MODEL", ""),
            api_key=os.environ.get("ASSISTANT_PROVIDER_KEY", ""),
            allowed_host=os.environ.get("ASSISTANT_ALLOWED_HOSTS", os.environ.get("ASSISTANT_ALLOWED_HOST", "")),
            timeout=int(os.environ.get("ASSISTANT_TIMEOUT_SECONDS", "60")),
            allow_http_loopback=os.environ.get("ASSISTANT_ALLOW_HTTP_LOOPBACK") == "1",
        )

    def destination(self):
        parsed = urlsplit(self.base_url)
        host = parsed.hostname
        allowed = {item.strip().lower() for item in self.allowed_host.split(",") if item.strip()}
        if not host or not allowed:
            raise ProviderError("Provider URL and approved host are required")
        if host.lower() not in allowed or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ProviderError("Provider destination is not approved")
        if parsed.path.rstrip("/") != "/v1":
            raise ProviderError("Provider URL must end at /v1")
        if parsed.scheme != "https" and not (
            self.allow_http_loopback and parsed.scheme == "http" and host in ("127.0.0.1", "localhost")
        ):
            raise ProviderError("HTTPS is required")
        if self.timeout < 1 or self.timeout > 180:
            raise ProviderError("Provider timeout must be 1–180 seconds")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal and (literal.is_link_local or literal.is_multicast or literal.is_unspecified or literal.is_reserved):
            raise ProviderError("Provider address is forbidden")
        # Resolve before every connection and pin the socket to the reviewed address.
        addresses = {entry[4][0] for entry in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
        if len(addresses) != 1:
            raise ProviderError("Provider host must resolve to exactly one address")
        ip = ipaddress.ip_address(next(iter(addresses)))
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or str(ip) == "169.254.169.254":
            raise ProviderError("Provider resolved to a forbidden address")
        if ip.is_loopback and not self.allow_http_loopback:
            raise ProviderError("Loopback provider requires explicit test mode")
        return parsed, str(ip)

    def _connection(self):
        parsed, ip = self.destination()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "https":
            conn = _PinnedHTTPSConnection(parsed.hostname, ip, port, self.timeout)
        else:
            conn = _PinnedHTTPConnection(parsed.hostname, ip, port, self.timeout)
        return parsed, conn

    def _headers(self):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        return headers

    def models(self):
        parsed, conn = self._connection()
        try:
            conn.request("GET", parsed.path.rstrip("/") + "/models", headers=self._headers())
            response = conn.getresponse()
            body = response.read(262145)
            if len(body) > 262144:
                raise ProviderError("Provider model list exceeded size limit")
            if response.status != 200:
                raise ProviderError(f"Provider returned HTTP {response.status}")
            payload = json.loads(body)
            return [item["id"] for item in payload.get("data", []) if isinstance(item, dict) and isinstance(item.get("id"), str)][:100]
        except (OSError, ValueError, KeyError) as exc:
            raise ProviderError("Provider model discovery failed") from exc
        finally:
            conn.close()

    def stream(self, messages):
        if not self.model:
            raise ProviderError("No model selected")
        parsed, conn = self._connection()
        body = json.dumps({"model": self.model, "messages": messages, "stream": True, "temperature": 0.2, "max_tokens": 1024}).encode()
        try:
            conn.request("POST", parsed.path.rstrip("/") + "/chat/completions", body=body, headers=self._headers())
            response = conn.getresponse()
            if response.status != 200:
                response.read(1024)
                raise ProviderError(f"Provider returned HTTP {response.status}")
            if "text/event-stream" not in response.getheader("Content-Type", ""):
                raise ProviderError("Provider did not return an event stream")
            total = 0
            while True:
                line = response.readline(65537)
                if not line:
                    break
                total += len(line)
                if len(line) > 65536 or total > 4 * 1024 * 1024:
                    raise ProviderError("Provider response exceeded size limit")
                if not line.startswith(b"data:"):
                    continue
                data = line[5:].strip()
                if data == b"[DONE]":
                    return
                try:
                    chunk = json.loads(data)
                    text = chunk["choices"][0]["delta"].get("content")
                except (ValueError, KeyError, IndexError, TypeError):
                    continue
                if isinstance(text, str):
                    yield text
            raise ProviderError("Provider stream ended without completion marker")
        except (OSError, ValueError) as exc:
            raise ProviderError("Provider stream failed") from exc
        finally:
            conn.close()

    def complete_with_tools(self, messages, tools):
        """Collect one bounded streamed assistant turn, including function calls."""
        if not self.model:
            raise ProviderError("No model selected")
        parsed, conn = self._connection()
        body = json.dumps({
            "model": self.model, "messages": messages, "tools": tools,
            "tool_choice": "auto", "stream": True, "temperature": 0.2, "max_tokens": 1536,
        }).encode()
        if len(body) > 65536:
            raise ProviderError("Model request exceeded size limit")
        content, calls, total, done = [], {}, 0, False
        try:
            conn.request("POST", parsed.path.rstrip("/") + "/chat/completions", body=body, headers=self._headers())
            response = conn.getresponse()
            if response.status != 200:
                response.read(1024)
                raise ProviderError(f"Provider returned HTTP {response.status}")
            if "text/event-stream" not in response.getheader("Content-Type", ""):
                raise ProviderError("Provider did not return an event stream")
            while True:
                line = response.readline(65537)
                if not line:
                    break
                total += len(line)
                if len(line) > 65536 or total > 4 * 1024 * 1024:
                    raise ProviderError("Provider response exceeded size limit")
                if not line.startswith(b"data:"):
                    continue
                data = line[5:].strip()
                if data == b"[DONE]":
                    done = True
                    break
                try:
                    delta = json.loads(data)["choices"][0]["delta"]
                except (ValueError, KeyError, IndexError, TypeError):
                    continue
                text = delta.get("content")
                if isinstance(text, str):
                    content.append(text)
                    if sum(map(len, content)) > 16000:
                        raise ProviderError("Answer exceeded size limit")
                for item in delta.get("tool_calls") or []:
                    if not isinstance(item, dict) or type(item.get("index")) is not int:
                        raise ProviderError("Malformed model tool call")
                    index = item["index"]
                    if index < 0 or index > 3:
                        raise ProviderError("Too many model tool calls")
                    call = calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                    if isinstance(item.get("id"), str):
                        call["id"] += item["id"]
                    function = item.get("function") or {}
                    if isinstance(function.get("name"), str):
                        call["function"]["name"] += function["name"]
                    if isinstance(function.get("arguments"), str):
                        call["function"]["arguments"] += function["arguments"]
                    if len(call["id"]) > 128 or len(call["function"]["name"]) > 64 or len(call["function"]["arguments"]) > 2048:
                        raise ProviderError("Model tool call exceeded size limit")
            if not done:
                raise ProviderError("Provider stream ended without completion marker")
            ordered = [calls[index] for index in sorted(calls)]
            for call in ordered:
                if not call["id"] or not call["function"]["name"]:
                    raise ProviderError("Incomplete model tool call")
            return {"content": "".join(content), "tool_calls": ordered}
        except (OSError, ValueError) as exc:
            raise ProviderError("Provider tool stream failed") from exc
        finally:
            conn.close()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, ip, port, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, ip, port, timeout):
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
