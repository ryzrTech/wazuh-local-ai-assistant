# Rollback

For a deployment using the paths in `deployment.md`, stop and disable the assistant, policy-validator, and alert-dispatcher services, remove only `plugins/wazuhAiTools`, remove their Dashboard systemd environment entries, reload systemd, and restart Dashboard. Remove the custom `local_ssh_root_login.xml` file and restart the manager to roll back the detection rule. Verify the Dashboard HTTPS page, `wazuh-dashboard`, `wazuh-manager`, and `wazuh-indexer`. Leave Wazuh data and vendor plugins untouched. A previously installed assistant plugin can be restored from its backup instead.

Preserve the SQLite database and protected environment files until the operator decides whether to delete conversation history and secrets. The isolated demo needs only its local process and test SQLite file removed.
