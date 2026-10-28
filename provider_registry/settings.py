"""Admin-managed provider settings kept in a private, atomic local file."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

from provider_registry.openai_compatible import Provider, ProviderError


class ProviderSettings:
    def __init__(self, default: Provider, path: str | None = None):
        self.default = default
        self.path = Path(path) if path else None
        self.lock = threading.RLock()
        self.provider = self._load()

    def _load(self) -> Provider:
        if not self.path or not self.path.exists():
            return self.default
        if self.path.stat().st_mode & 0o077:
            raise ProviderError("Provider settings file must be private")
        try:
            data = json.loads(self.path.read_text())
            return self._candidate(data["url"], data["key"], data["model"], use_saved_key=False)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ProviderError("Invalid provider settings file") from exc

    def current(self) -> Provider:
        with self.lock:
            return self.provider

    def public(self) -> dict:
        current = self.current()
        return {
            "url": current.base_url,
            "model": "" if current.model == "unconfigured" else current.model,
            "has_key": bool(current.api_key),
            "allowed_hosts": [item.strip() for item in self.default.allowed_host.split(",") if item.strip()],
        }

    def _candidate(self, url: str, key: str, model: str, *, use_saved_key: bool = True) -> Provider:
        if not isinstance(url, str) or not 1 <= len(url) <= 2048:
            raise ProviderError("Enter a valid API URL")
        if not isinstance(key, str) or len(key) > 4096:
            raise ProviderError("Invalid API key")
        if not isinstance(model, str) or len(model) > 256:
            raise ProviderError("Invalid model ID")
        if not key and use_saved_key:
            key = self.current().api_key
        return replace(self.default, base_url=url.strip(), model=model, api_key=key)

    def test(self, url: str, key: str = "") -> list[str]:
        candidate = self._candidate(url, key, "")
        models = candidate.models()
        if not models:
            raise ProviderError("The provider returned no models")
        return models

    def save(self, url: str, key: str, model: str) -> dict:
        if not model:
            raise ProviderError("Select a model")
        candidate = self._candidate(url, key, model)
        models = candidate.models()
        if model not in models:
            raise ProviderError("Selected model is not available from this provider")
        if not self.path:
            raise ProviderError("Provider settings storage is not configured")
        payload = {"url": candidate.base_url, "model": model, "key": candidate.api_key}
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.lock:
            temp_name = None
            try:
                with tempfile.NamedTemporaryFile("w", dir=self.path.parent, prefix=".provider-", delete=False) as handle:
                    temp_name = handle.name
                    os.chmod(temp_name, 0o600)
                    json.dump(payload, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, self.path)
                self.provider = candidate
            finally:
                if temp_name and os.path.exists(temp_name):
                    os.unlink(temp_name)
        return self.public()
