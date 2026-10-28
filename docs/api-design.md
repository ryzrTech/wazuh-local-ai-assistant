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
| `GET /api/sessions/{id}/messages` | Up to 200 owner-scoped messages. |
| `POST /api/sessions/{id}/messages` | JSON `{ "content": "..." }`; streams `delta`, `done`, or `error` SSE events. |

Error responses contain generic messages. Model provider errors do not reveal response bodies or credentials. A failed model call saves the user's message but not a partial assistant answer.

The Dashboard plugin adds fixed, user-scoped read routes for recent alerts, raw events, agents, and SCA results. It resolves exact source IDs before creating an investigation; callers cannot supply arbitrary evidence through the browser route.
