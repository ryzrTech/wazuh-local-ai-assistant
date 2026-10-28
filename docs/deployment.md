# Deploy the native sidebar

This integration targets Wazuh 4.14.9 with OpenSearch Dashboards 2.19.6. Check installed versions before deploying. The investigations application reads bounded Wazuh alerts, raw events, agents, and SCA results in the signed-in user's context. It has no configuration write or response tools. A model API key and valid model ID are required for AI replies; investigation browsing and conversation storage can run without them.

## Build

On a build machine with Node.js and npm:

```sh
cd dashboard-plugin/native
npm ci
npm run build
```

The build creates `server/index.js` and `target/public/wazuhAiPolicyStudio.plugin.js`. It uses Dashboard's shared React and EUI libraries; no Dashboard source checkout is required. The build files are ignored by Git. Package only the manifest, package metadata, compiled server entry point, and public bundle for installation.

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

Place the compiled plugin in `plugins/wazuhAiPolicyStudio` under the installed Dashboard root. The directory must contain `opensearch_dashboards.json`, `package.json`, `server/index.js`, and `target/public/wazuhAiPolicyStudio.plugin.js`. Add the protected proxy and admin tokens to the Dashboard systemd environment, then restart Dashboard. Confirm the plugin appears in `opensearch-dashboards-plugin list --allow-root`, startup logs include `wazuhAiPolicyStudio`, and the HTTPS entry page responds. Test the sidebar from a normal authenticated Dashboard session. Provider setup requires the `all_access` role by default; `ASSISTANT_ADMIN_ROLES` can define other indexer roles.

The Dashboard distribution serves plugin JavaScript with a one-year browser cache lifetime. Deployments that reuse an existing plugin ID and asset path may leave users on the old UI even after a service restart. Use a fresh plugin asset path for a forced update, or have users explicitly clear the cached plugin asset. The current `wazuhAiPolicyStudio` ID uses a fresh asset path.

In sidebar settings, an administrator enters an approved `/v1` API URL and dedicated key, tests the connection, selects a returned model, and saves. The key is stored in a mode 0600 server file and is never returned to the browser. Changing allowlisted hosts or service tokens requires a service restart. Conversation retention and deletion are per user. See [investigations.md](investigations.md) for raw-event archiving and retention setup.

## Validate agent and SCA proposals

Install `policy_engine/` beside `orchestrator/` under `/opt/wazuh-local-ai`. Install `deploy/wazuh-ai-policy-validator.service` as a systemd unit and adjust its Wazuh service account if the installation uses a different account. Generate a **third**, independent 32-character-or-longer token as `ASSISTANT_POLICY_TOKEN` in `/etc/wazuh-local-ai/policy.env` and the Dashboard's protected environment file. Restrict both files to root. Start the validator service and confirm `http://127.0.0.1:8766/health` returns 200. The service accepts only authenticated `POST /validate` requests with a group name and the four enumerated SCA settings; it has no apply endpoint.

In the AI investigations page, select an agent in **Agents & SCA**, choose one of its assigned groups, select the SCA settings, and click **Validate proposal**. The Dashboard checks the administrator role and the agent's group membership before forwarding the request. The validator stages the candidate in a private temporary file, runs Wazuh `verify-agent-conf`, and returns the exact diff. A successful result checks syntax only; apply and post-change SCA verification remain separate operational steps.
