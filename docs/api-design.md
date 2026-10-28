# Prototype API

All routes except `/health` require `X-Assistant-Token` and `X-Assistant-User` in proxy mode. The proxy must supply both server-side. Demo mode assigns the fixed owner `local-demo` on loopback.

| Method and route | Result |
| --- | --- |
| `GET /health` | Service status, no secret or model details. |
| `GET /api/models` | Available model IDs and selected model; 502 if discovery fails. |
| `GET /api/sessions` | Up to 200 sessions for the owner. |
| `POST /api/sessions` | Creates a session, returns its ID. |
| `DELETE /api/sessions` | Deletes all sessions for the owner. |
| `DELETE /api/sessions/{id}` | Deletes one owner-scoped session. |
| `GET /api/settings` | Returns the owner’s retention period. |
| `POST /api/settings` | Sets retention to 0, 7, 30, 90, or 365 days and prunes expired sessions. |
| `GET /api/provider/config` | Returns URL, model, key-present flag, and approved hosts; requires admin token. |
| `POST /api/provider/test` | Tests URL and key and returns discovered models; requires admin token. |
| `POST /api/provider/config` | Re-tests URL, key, and model, then saves provider settings; requires admin token. |
| `GET /api/investigations` | Lists owner-scoped saved investigations. |
| `POST /api/investigations` | Creates a saved investigation from server-verified evidence. |
| `GET /api/investigations/{id}` | Returns the owner-scoped evidence snapshot. |
| `POST /api/sessions/{id}/turn` | Internal: saves a user message and returns bounded model context for the Dashboard tool broker. |
| `POST /api/model/complete` | Internal: returns one streamed-provider turn, including bounded function calls. |
| `POST /api/sessions/{id}/tool-audit` | Internal: saves owner-scoped tool metadata without returned log bodies. |
| `POST /api/sessions/{id}/assistant` | Internal: saves the final assistant reply after tool execution. |
| `GET /api/sessions/{id}/messages` | Up to 200 owner-scoped messages. |
| `POST /api/sessions/{id}/messages` | JSON `{ "content": "..." }`; streams `delta`, `done`, or `error` SSE events. |

Error responses contain generic messages. Model provider errors do not reveal response bodies or credentials. A failed model call saves the user's message but not a partial assistant answer.

The Dashboard plugin adds fixed, user-scoped read routes for recent alerts, raw events, agents, and SCA results. It resolves exact source IDs before creating an investigation; callers cannot supply arbitrary evidence through the client route. `GET /api/wazuh_local_ai/capabilities` returns the server-derived read-tool and policy capability list. The normal chat POST route now runs a bounded model/tool loop in Dashboard's authenticated request context; the loopback model service does not access Wazuh directly. Tool results are capped and cited, and each call writes private audit metadata.

`POST /api/wazuh_local_ai/policies/agent-sca/validate` is a Dashboard route for administrators. It accepts an agent ID, one of that agent's groups, and four enumerated SCA settings. The plugin checks group membership through Wazuh Core, then forwards the bounded request to a separate loopback service on port 8766 using `ASSISTANT_POLICY_TOKEN`. That service exposes `GET /health` and authenticated `POST /validate`; it returns a diff, active-file hash, native validator result, and `applied: false`. There is no policy apply route.

The administrator-only Dashboard routes `GET/POST /api/wazuh_local_ai/alerts/config` and `POST /api/wazuh_local_ai/alerts/test` proxy to a separate loopback alert service on port 8767 using `ASSISTANT_ALERT_TOKEN`. Its configuration response returns only mode, minimum level, whether a destination is configured, and the hostname; the full webhook URL is never returned. The test route sends one synthetic notification to the saved destination when the operator explicitly clicks the test button.
