# Rollback

For a deployment using the paths in `deployment.md`, stop and disable the assistant and policy-validator services, remove only `plugins/wazuhAiPolicyStudio`, remove their Dashboard systemd environment entries, reload systemd, and restart Dashboard. Verify the Dashboard HTTPS page, `wazuh-dashboard`, `wazuh-manager`, and `wazuh-indexer`. Leave Wazuh data and vendor plugins untouched. A previously installed assistant plugin can be restored from its backup instead.

Preserve the SQLite database and protected environment files until the operator decides whether to delete conversation history and secrets. The isolated demo needs only its local process and test SQLite file removed.
