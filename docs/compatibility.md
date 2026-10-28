# Compatibility

| Component | Observed target | Current checkpoint |
| --- | --- | --- |
| Wazuh manager, indexer, dashboard | 4.14.9 | Read-only alert, archive, agent, and SCA calls implemented. |
| OpenSearch Dashboards | 2.19.6 | Native plugin built and loaded on the first test host; operator UI review pending. |
| Dashboard Node.js | 18.19.0 | Prototype backend is separate Python process. |
| Python | Ubuntu 24.04 system Python | Code targets Python 3.10+ standard library. |
| Model API | OpenAI-compatible `/v1` | Model chat validated on the test installation; endpoint and model are configurable. |

Do not install a Wazuh 5.x AI Assistant plugin into a 4.14.9 Dashboard. OpenSearch Dashboards requires matching plugin versions. Do not upgrade the production stack merely to enable this integration.

The test Dashboard startup proves plugin registration. An operator should verify the investigations and chat UI in their own authenticated session on each installation.
