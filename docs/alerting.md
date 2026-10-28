# Alerting policy and delivery

## First custom detection

`rules/local_ssh_root_login.xml` adds rule `100100` at level 12 for a successful direct SSH login to the root account. It is a child of Wazuh's built-in successful SSH authentication rule `5715` and also requires the log text `for root from`. This keeps normal SSH logins and failed root attempts on their existing rules. The three synthetic fixtures in `tests/fixtures/` cover those positive and negative cases. Install the rule in `/var/ossec/etc/rules/`, run `wazuh-analysisd -t`, run each fixture through `wazuh-logtest`, and only then restart the manager.

This rule creates an indexed Dashboard alert. It does not enable email or automatic response. Wazuh's built-in rules remain active.

## Configurable delivery

The assistant settings gear has an administrator-only **Alert delivery** section. Default mode is **Dashboard only**, with external delivery off. Administrators can select a minimum level of 10, 12, or 15 and explicitly save a generic HTTPS webhook URL. New matching alerts are then sent as small JSON summaries: alert ID and time, rule ID/level/description, and agent ID/name. Full logs and provider credentials are omitted. The full URL is stored privately on the server and is never returned to the browser. A separate **Send test notification** button sends a synthetic message only when clicked.

The dispatcher runs as the Wazuh service account, tails `/var/ossec/logs/alerts/alerts.json`, and stores its cursor and retry queue in a private SQLite database. It starts at the end of the file on first install, so enabling delivery does not replay old alerts. Failed webhook posts are retried up to five times and then marked dead. Saving a new destination clears pending deliveries to avoid sending old alerts to a new receiver. The service does not follow redirects. It resolves and pins one IP for each HTTPS connection, checks the TLS certificate against the configured hostname, and rejects private destinations unless their hostname is explicitly allowlisted in its server environment. Metadata and link-local addresses remain forbidden.

The generic JSON webhook may require an adapter for a specific service such as Teams, Slack, or an email provider. The service does not send mail directly. The current settings UI does not include a delivery audit or dead-letter retry control; inspect its private SQLite queue during operations. For environments needing guaranteed delivery, add monitoring for dead-letter count, file-tail lag, and queue depth before relying on it as the sole notification path.
