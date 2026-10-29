# Architecture

## Observed compatibility target

The deployment examined for this design runs Wazuh manager, indexer, and dashboard 4.14.9, with OpenSearch Dashboards 2.19.6 and bundled Node.js 18.19.0. The Dashboard has the `wazuh`, `wazuhCore`, and `securityDashboards` plugins. The Wazuh Dashboard's manager API configuration has `run_as: true`. The current Wazuh AI Assistant source is associated with the newer 5.x plugin line and is an architectural reference, not a compatible binary for this host.

The observed test host has 4 vCPUs and 8 GiB RAM. A second full Wazuh stack on the same host is unsuitable without a resource plan. The configured local model has since passed chat streaming and synthetic streamed tool-call probes.

## Intended data flow

```text
Browser → authenticated Dashboard plugin → loopback orchestrator → approved local model gateway
                     │                         │
                     │                         └─ SQLite sessions and bounded job queue (later)
                     └─ Wazuh user context → scoped read-only Wazuh API / indexer queries
```

The browser never receives a model key. The orchestrator binds only to loopback. The native plugin registers a Dashboard header control and an AI investigations application, resolves the authenticated indexer user from `/_plugins/_security/authinfo`, and proxies requests with a server-only token. Interactive Wazuh reads run through the current user's indexer and Wazuh Core clients. The isolated preview exercises the sidebar and backend without Wazuh data.

Milestone 3 uses fixed, bounded read queries with the authenticated user's effective privileges and does not treat the orchestrator's service identity as an elevation path. Background jobs will use separate, explicitly scoped service identities. The policy executor is a separate service with a distinct trust boundary.

The first policy validator is a separate loopback service running under the Wazuh service account with a read-only systemd filesystem and private temporary directory. It accepts only enumerated agent/SCA settings, stages a candidate, and invokes `verify-agent-conf` without a shell. It cannot apply a change. The Dashboard route requires an indexer admin role and confirms that the selected agent belongs to the target group; the separate apply service requires its own authorization and stale-file hash check.

## Design decisions

1. Keep vendor-owned Dashboard code untouched. Build an external plugin against the exact OpenSearch Dashboards version and place its compiled output in the Dashboard plugins directory.
2. Keep model configuration server-side. Provider changes require the indexer administrator role and a separate server-only token. The URL is limited to server-approved hosts, and the key is saved in a private file without being returned to the browser.
3. Use SQLite for prototype conversation durability. A persistent job queue with bounded retries and dead-letter handling is a later milestone.
4. The model has bounded read tools through the authenticated Dashboard broker. Do not enable response actions or rule writes in the chat service.
5. Fail closed when the configured provider is unavailable; never fall back to an external provider.

## References pinned for implementation planning

- [Wazuh Dashboard Plugins release tag `v4.14.9`](https://github.com/wazuh/wazuh-dashboard-plugins/tree/v4.14.9), OpenSearch Dashboards `2.19.6`.
- [Wazuh Dashboard AI Assistant source](https://github.com/wazuh/wazuh-dashboard-plugins/tree/main/plugins/wazuh-ai-assistant) in the `5.0.0` line as a catalog and UX reference only.
- [OpenSearch Dashboards plugin installation](https://docs.opensearch.org/latest/install-and-configure/install-dashboards/plugins/) and [build helper](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/main/packages/osd-plugin-helpers/README.md) documentation, accessed 2026-10-27.
- [OpenSearch Dashboards 2.19.6 header control](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/2.19.6/src/core/public/chrome/nav_controls/nav_controls_service.ts) and [stream response type](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/2.19.6/src/core/server/http/router/response.ts).
- [Cloudflare Agents SDK repository](https://github.com/cloudflare/agents) for interaction patterns only; no Cloudflare runtime or copied code.
