# Rollback

For a deployment using the paths in `deployment.md`, stop and disable the assistant service, remove only `plugins/wazuhAiWorkspace`, remove the assistant Dashboard systemd drop-in, reload systemd, and restart Dashboard. Verify the Dashboard HTTPS page, `wazuh-dashboard`, `wazuh-manager`, and `wazuh-indexer`. Leave Wazuh data and vendor plugins untouched.

Preserve the SQLite database and protected environment files until the operator decides whether to delete conversation history and secrets. The isolated demo needs only its local process and test SQLite file removed.
