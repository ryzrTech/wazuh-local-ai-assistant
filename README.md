# Wazuh local AI assistant

Self-hosted, OpenAI-compatible AI assistant prototype for Wazuh. This checkpoint includes a native sidebar plugin for OpenSearch Dashboards 2.19.6 and a loopback chat service. It **does not** inspect Wazuh data, run autonomous investigations, change rules, or execute security responses.

## Milestone status

| Milestone | Status |
| --- | --- |
| 1. Discovery and architecture | Complete for the observed Wazuh 4.14.9 host; deployment-specific findings stay in private operator documentation. |
| 2. AI sidebar | Installed on a Wazuh 4.14.9 test host. The sidebar includes provider setup and per-user history controls. The AI investigations page searches alerts and raw events, shows agents and SCA results, and saves read-only AI analyses. Live model streaming remains to be tested by the operator. |
| 3. Read-only Wazuh investigations | Initial alert, archive, agent, and SCA views implemented; interactive Dashboard verification pending. |
| 4–6. Policy validation, continuous triage, remediation | Design only; no write path is implemented. |

## Run the isolated preview

Python 3.10+ is sufficient. The provider must be an administrator-approved OpenAI-compatible endpoint. The example below is for a test host; use a secret manager or protected environment file for the key and proxy token.

```sh
export ASSISTANT_PROVIDER_URL=https://model-gateway.example.internal/v1
export ASSISTANT_ALLOWED_HOST=model-gateway.example.internal
export ASSISTANT_MODEL=your-model-id
export ASSISTANT_PROVIDER_KEY=your-dedicated-key
python3 -m orchestrator.server --demo --db /tmp/wazuh-local-ai-demo.sqlite3
```

Open `http://127.0.0.1:8765/` on that same host. Demo mode is unauthenticated and **refuses non-loopback binding**. Never expose it through a reverse proxy. For native Dashboard use, omit `--demo`, set a random `ASSISTANT_PROXY_TOKEN` of at least 32 characters in both services, and use the plugin server proxy to supply an authenticated owner. Set a separate `ASSISTANT_ADMIN_TOKEN` in both services for provider setup. The Dashboard server requires the `all_access` role by default before forwarding those requests.

Run the tests with `python3 -m unittest discover -s tests -v`. The tests simulate an OpenAI-compatible stream on loopback and verify persistence and user isolation. No model key or Wazuh account is needed.

## Layout

- `dashboard-plugin/`: isolated sidebar preview and native 2.19.6 plugin source with an esbuild build script.
- `orchestrator/`: loopback HTTP service with SQLite conversation storage.
- `provider_registry/`: approved-destination OpenAI-compatible adapter.
- `wazuh_tools/`, `policy_engine/`, `response_executor/`, `rule_staging/`: reserved for later policy and action milestones; intentionally empty.
- `docs/`: architecture, compatibility, security, API, deployment, rollback, and test notes.

The project has no runtime third-party Python dependencies. Its isolated preview uses plain HTML, CSS, and JavaScript. The native source uses OpenSearch Dashboards' shared React and EUI packages and resolves user identity through the indexer's current-user security endpoint. Each user can delete conversations and set a 7, 30, 90, or 365-day retention period, or keep them until deletion. Live model streaming still needs verification.

## License

MIT. See [LICENSE](LICENSE).
