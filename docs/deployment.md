# Deploy the native sidebar

This integration targets Wazuh 4.14.9 with OpenSearch Dashboards 2.19.6. Check installed versions before deploying. Chat and investigations read bounded Wazuh alerts, raw events, agents, SCA results, Syscollector inventory, and vulnerability state in the signed-in user's context. A model API key and valid model ID are required for AI replies; investigation browsing and conversation storage can run without them. The chat broker additionally supports bounded reads of rootcheck, FIM, services, users, network inventory, rules, decoders, group membership, manager status, and other named Wazuh sources. An administrator may ask the model to stage an agent/SCA proposal or a one-agent response proposal. The model cannot apply or dispatch either; a human must review and approve each proposal in AI investigations. Arbitrary commands are not exposed to chat.

## Build

On a build machine with Node.js and npm:

```sh
cd dashboard-plugin/native
npm ci
npm run build
```

The build creates `server/index.js` and `target/public/wazuhAiChatOps.plugin.js`. It uses Dashboard's shared React and EUI libraries; no Dashboard source checkout is required. The build files are ignored by Git. Package only the manifest, package metadata, compiled server entry point, and public bundle for installation.

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

Place the compiled plugin in `plugins/wazuhAiChatOps` under the installed Dashboard root. The directory must contain `opensearch_dashboards.json`, `package.json`, `server/index.js`, and `target/public/wazuhAiChatOps.plugin.js`. Add the protected proxy and admin tokens to the Dashboard systemd environment, then restart Dashboard. Confirm the plugin appears in `opensearch-dashboards-plugin list --allow-root`, startup logs include `wazuhAiChatOps`, and the HTTPS entry page responds. Verify the sidebar in an authenticated session. Provider setup requires the `all_access` role by default; `ASSISTANT_ADMIN_ROLES` can define other indexer roles.

The Dashboard distribution serves plugin JavaScript with a one-year browser cache lifetime. Deployments that reuse an existing plugin ID and asset path may leave users on the old UI even after a service restart. Use a fresh plugin asset path for a forced update, or have users explicitly clear the cached plugin asset. The current `wazuhAiChatOps` ID uses a fresh asset path.

In sidebar settings, an administrator enters an approved `/v1` API URL and dedicated key, tests the connection, selects a returned model, and saves. The key is stored in a mode 0600 server file and is never returned to the browser. Changing allowlisted hosts or service tokens requires a service restart. Conversation retention and deletion are per user. See [investigations.md](investigations.md) for raw-event archiving and retention setup.

The chat composer accepts up to 16,000 characters and shows a count when approaching that limit. Pastes are retained in the composer even when over the limit, so the operator can shorten them deliberately. Provider responses that end at their token limit are treated as incomplete; the broker does not save the partial answer as a successful reply.

Assistant replies and saved investigation analyses render Markdown for headings, lists, emphasis, links, and code. Raw HTML and Markdown images are displayed as text, so model output cannot create HTML elements or trigger image requests. User messages remain plain text.

When the provider emits `reasoning_content` or `reasoning` chunks, the assistant streams them into an expandable **Thinking…** section and stores them with the owner-scoped conversation. Literal `<think>...</think>` content is also separated from the visible answer. **Show thinking by default** is a browser-local preference; otherwise each section starts collapsed. The provider may omit thinking entirely. Chat history deletion and retention remove stored thinking along with its message. Thinking is not sent back to the model as conversation history.

Text emitted before a tool call stays visible as an **Investigation updates** note and is saved with the answer. Syscollector package, process, and port records are scan snapshots, so a missing port or process cannot establish what owned a port when an earlier alert fired. Vulnerabilities come from the current `wazuh-states-vulnerabilities-*` index and may require additional signed-in user permissions.

Chat responses stream into the panel as model text arrives. The transcript stays at the newest message during a turn. With an empty composer, Up Arrow recalls the last question from the active conversation. If a model request fails after saving the question, sending that same question again resumes the unanswered turn without storing a duplicate user message. The model can make four bounded tool rounds, with at most eight actual tool calls, before a final answer; searches stay under the signed-in user's Wazuh permissions.

Dashboard serves assistant SSE with identity encoding to prevent HTTP compression from buffering incremental text. The broker can recover complete trailing XML-style read-tool calls from models that emit them as text, but still applies the normal allowlist, argument checks, and signed-in user's permissions. Malformed or unauthorized text calls do not execute. The final-answer request omits tool definitions; if it still emits tool syntax, the broker hides it and reports only calls that actually ran.

## Validate and apply agent and SCA proposals

Install `policy_engine/` beside `orchestrator/` under `/opt/wazuh-local-ai`. Create `/var/lib/wazuh-ai-policies` and its `backups/` child as mode 0700 directories owned by the Wazuh service account. Install `deploy/wazuh-ai-policy-validator.service` and `deploy/wazuh-ai-policy-apply.service`, adjusting the account and Wazuh shared-config path for the installation. Generate distinct 32-character-or-longer tokens as `ASSISTANT_POLICY_TOKEN` and `ASSISTANT_POLICY_APPLY_TOKEN` in root-only service environment files and the Dashboard's protected environment file. Start both services and confirm loopback `/health` on ports 8766 and 8768. Both services must reject unauthenticated requests. The validator has only the private policy directory writable; the apply service additionally has the Wazuh shared group directory writable.

In the AI investigations page, select an agent in **Agents & SCA**, choose one of its assigned groups, select the SCA settings, and click **Validate proposal**. The Dashboard checks the administrator role and the agent's group membership before forwarding the request. The validator stages the candidate in a private temporary file, runs Wazuh `verify-agent-conf`, and returns the complete diff. Valid proposals remain available to their owner for 30 minutes. After reviewing the diff and scope, an administrator must explicitly click **Apply reviewed change**. The executor rechecks the active hash and native syntax, saves a private backup, and writes atomically. **Check agent sync and scan** reports the selected agent's current status and latest SCA scan; review other group members separately. **Roll back** restores the saved file only when no intervening edit occurred. The model cannot invoke apply or rollback.

## Review response actions

An administrator can ask chat to stage a restart for one agent or an IP block for one Linux agent. A block proposal must cite an exact Wazuh alert whose agent ID and source IP match the requested target. Chat saves the proposal for 30 minutes and cannot dispatch it. In **AI investigations**, inspect the agent, target, evidence, and reason, then approve or deny that exact proposal. Approval checks the agent and alert again and sends the fixed Wazuh API request through the signed-in administrator's Wazuh permissions. A proposal is claimed once before dispatch and cannot be retried automatically. If the API outcome is uncertain, inspect Wazuh before making a new request. API acceptance does not prove the endpoint applied the action. The queue is limited to ten pending actions per owner. No arbitrary commands, group-wide actions, or exclusion-rule writes are available in this workflow.

## Set up alerting

Install `rules/local_ssh_root_login.xml` under `/var/ossec/etc/rules/`, run `wazuh-analysisd -t`, and use the three SSH fixtures with `wazuh-logtest`. Activate it with a manager restart only after the positive case matches `100100` and the negative cases remain on the built-in rules.

Install `alerting/` beside `orchestrator/` under `/opt/wazuh-local-ai`. Create a private writable directory `/var/lib/wazuh-ai-alerts` owned by the Wazuh service account. Install `deploy/wazuh-ai-alert-dispatcher.service` and adjust its user or alert-file path for your installation. Generate a distinct 32-character-or-longer `ASSISTANT_ALERT_TOKEN` in root-only `/etc/wazuh-local-ai/alert.env` and the Dashboard environment file. Start the service and verify `http://127.0.0.1:8767/health` returns 200. Default mode is Dashboard only, so the service does not send anything externally until an administrator saves an HTTPS webhook in the assistant settings. Use `ASSISTANT_ALERT_ALLOWED_PRIVATE_HOSTS` in the alert service environment only when an explicitly approved private webhook host is needed. See [alerting.md](alerting.md) for behavior and limitations.
