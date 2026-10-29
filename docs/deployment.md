# Deploy the native sidebar

This integration targets Wazuh 4.14.9 with OpenSearch Dashboards 2.19.6. Check installed versions before deploying. Chat and investigations read bounded Wazuh alerts, raw events, agents, and SCA results in the signed-in user's context. The model has no configuration write or response tools; a separate administrator-reviewed workflow can apply bounded agent/SCA settings. A model API key and valid model ID are required for AI replies; investigation browsing and conversation storage can run without them.

## Build

On a build machine with Node.js and npm:

```sh
cd dashboard-plugin/native
npm ci
npm run build
```

The build creates `server/index.js` and `target/public/wazuhAiMarkdown.plugin.js`. It uses Dashboard's shared React and EUI libraries; no Dashboard source checkout is required. The build files are ignored by Git. Package only the manifest, package metadata, compiled server entry point, and public bundle for installation.

## Configure the service

Install `orchestrator/` and `provider_registry/` together in a root-owned directory. Create a dedicated unprivileged account and a private writable SQLite directory. Set these variables in a root-readable systemd `EnvironmentFile`:

```ini
ASSISTANT_PROXY_TOKEN=<random 32-character-or-longer secret>
ASSISTANT_PROVIDER_URL=https://model-gateway.example.internal/v1
ASSISTANT_ALLOWED_HOSTS=model-gateway.example.internal
ASSISTANT_MODEL=<discovered model ID>
ASSISTANT_PROVIDER_KEY=<dedicated model API key>
ASSISTANT_ADMIN_TOKEN=<different random 32-character-or-longer secret>
```

Use the same proxy and admin tokens in a protected `EnvironmentFile` for the Dashboard service. Never expose either token or the provider key to the browser or commit them. Run `python3 -m orchestrator.server --db /path/to/private/assistant.sqlite3 --provider-config /path/to/private/provider.json` without `--demo`; it binds to `127.0.0.1:8765`. Verify `/health` returns 200 and `/api/sessions` without the proxy token returns 401.

## Activate the Dashboard plugin

Place the compiled plugin in `plugins/wazuhAiMarkdown` under the installed Dashboard root. The directory must contain `opensearch_dashboards.json`, `package.json`, `server/index.js`, and `target/public/wazuhAiMarkdown.plugin.js`. Add the protected proxy and admin tokens to the Dashboard systemd environment, then restart Dashboard. Confirm the plugin appears in `opensearch-dashboards-plugin list --allow-root`, startup logs include `wazuhAiMarkdown`, and the HTTPS entry page responds. Verify the sidebar in an authenticated session. Provider setup requires the `all_access` role by default; `ASSISTANT_ADMIN_ROLES` can define other indexer roles.

The Dashboard distribution serves plugin JavaScript with a one-year browser cache lifetime. Deployments that reuse an existing plugin ID and asset path may leave users on the old UI even after a service restart. Use a fresh plugin asset path for a forced update, or have users explicitly clear the cached plugin asset. The current `wazuhAiMarkdown` ID uses a fresh asset path.

In sidebar settings, an administrator enters an approved `/v1` API URL and dedicated key, tests the connection, selects a returned model, and saves. The key is stored in a mode 0600 server file and is never returned to the browser. Changing allowlisted hosts or service tokens requires a service restart. Conversation retention and deletion are per user. See [investigations.md](investigations.md) for raw-event archiving and retention setup.

Assistant replies and saved investigation analyses render Markdown for headings, lists, emphasis, links, and code. Raw HTML and Markdown images are displayed as text, so model output cannot create HTML elements or trigger image requests. User messages remain plain text.

## Validate and apply agent and SCA proposals

Install `policy_engine/` beside `orchestrator/` under `/opt/wazuh-local-ai`. Create `/var/lib/wazuh-ai-policies` and its `backups/` child as mode 0700 directories owned by the Wazuh service account. Install `deploy/wazuh-ai-policy-validator.service` and `deploy/wazuh-ai-policy-apply.service`, adjusting the account and Wazuh shared-config path for the installation. Generate distinct 32-character-or-longer tokens as `ASSISTANT_POLICY_TOKEN` and `ASSISTANT_POLICY_APPLY_TOKEN` in root-only service environment files and the Dashboard's protected environment file. Start both services and confirm loopback `/health` on ports 8766 and 8768. Both services must reject unauthenticated requests. The validator has only the private policy directory writable; the apply service additionally has the Wazuh shared group directory writable.

In the AI investigations page, select an agent in **Agents & SCA**, choose one of its assigned groups, select the SCA settings, and click **Validate proposal**. The Dashboard checks the administrator role and the agent's group membership before forwarding the request. The validator stages the candidate in a private temporary file, runs Wazuh `verify-agent-conf`, and returns the complete diff. Valid proposals remain available to their owner for 30 minutes. After reviewing the diff and scope, an administrator must explicitly click **Apply reviewed change**. The executor rechecks the active hash and native syntax, saves a private backup, and writes atomically. **Check agent sync and scan** reports the selected agent's current status and latest SCA scan; review other group members separately. **Roll back** restores the saved file only when no intervening edit occurred. The model cannot invoke apply or rollback.

## Set up alerting

Install `rules/local_ssh_root_login.xml` under `/var/ossec/etc/rules/`, run `wazuh-analysisd -t`, and use the three SSH fixtures with `wazuh-logtest`. Activate it with a manager restart only after the positive case matches `100100` and the negative cases remain on the built-in rules.

Install `alerting/` beside `orchestrator/` under `/opt/wazuh-local-ai`. Create a private writable directory `/var/lib/wazuh-ai-alerts` owned by the Wazuh service account. Install `deploy/wazuh-ai-alert-dispatcher.service` and adjust its user or alert-file path for your installation. Generate a distinct 32-character-or-longer `ASSISTANT_ALERT_TOKEN` in root-only `/etc/wazuh-local-ai/alert.env` and the Dashboard environment file. Start the service and verify `http://127.0.0.1:8767/health` returns 200. Default mode is Dashboard only, so the service does not send anything externally until an administrator saves an HTTPS webhook in the assistant settings. Use `ASSISTANT_ALERT_ALLOWED_PRIVATE_HOSTS` in the alert service environment only when an explicitly approved private webhook host is needed. See [alerting.md](alerting.md) for behavior and limitations.
