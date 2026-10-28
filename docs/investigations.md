# AI investigations and policy workflow

## Current investigation slice

The native Dashboard plugin registers an **AI investigations** application alongside the chat sidebar. Operators can search recent `wazuh-alerts-*` and `wazuh-archives-*` documents, inspect agent inventory and SCA summaries, and create saved investigations from a selected record or agent. Every interactive read uses the signed-in user's OpenSearch or Wazuh Core scoped client. The browser cannot submit arbitrary index names, Wazuh API paths, or search DSL.

Searches are bounded to 40 recent records, a 1–720 hour time range, and fixed index patterns. Investigation evidence stores one selected record or a bounded agent/SCA summary in the same owner-scoped SQLite database as chat. Evidence is at most 6,000 characters and is presented to the model as untrusted data. The model produces advisory analysis with source references. It does not perform its own tool calls, execute shell commands, or modify Wazuh.

The first agent posture flow drafts recommendations from SCA policy scores and a bounded set of failed checks. Model-written recommendations are **unvalidated drafts**. A separate administrator-only form supports four bounded SCA settings for a selected agent group: enablement, scan-on-start, scan interval, and skipping NFS. The validator reads the active group `agent.conf`, preserves existing policy declarations, returns a precise diff and active-file hash, and runs Wazuh's `verify-agent-conf` on a temporary candidate. It rejects ambiguous multi-block or scoped configurations. It never writes the active file.

A passing result confirms Wazuh accepts the candidate syntax. It does not establish that an endpoint received the settings or that a later SCA score improved. The result names the whole group as the change scope and tells the operator to verify group synchronization and the next scan after a separately approved deployment.

## Thirty-day raw-event search

Wazuh alerts are indexed by default. To search events that did not trigger an alert, enable `<logall_json>yes</logall_json>` in the manager and the Filebeat `wazuh/archives` fileset. Create an ISM policy on only `wazuh-archives-*` with a transition to delete at `min_index_age: 30d`. Verify the policy is attached to the first new archive index. Rotate and remove local compressed archive files older than 30 days with a dedicated timer. Monitor index size, event rate, Filebeat errors, and free disk space during the first week.

The archive policy does not change alert-index retention. It does not retroactively reconstruct events from before archiving was enabled.

## Next policy slices

1. **Agent and SCA configuration:** expand the current syntax validation to more agent modules and SCA policy YAML. Add proposal persistence, a separately approved deployment service with backups and hash checks, and post-apply group-sync and scan verification.
2. **Detection rules:** inspect existing custom and built-in rules, generate candidate XML with collision checks and positive/negative fixtures, run Wazuh logtest, then stage for approval and controlled activation.
3. **Access and response policies:** render current RBAC and active-response configuration read-only first. Proposals need a separate policy engine, independent authorization checks, and an emergency disable switch before any write path is enabled.
4. **Continuous triage:** add a durable intake queue after interactive investigations produce reliable, cited analyses. Start in observe mode with bounded event filters and no automatic security response.

The model gateway was tested with synthetic OpenAI-compatible tool definitions and produced valid streamed tool calls. Model-directed tools can therefore be considered later, but each tool still needs a strict server-side schema, per-user authorization, bounds, and audit records. The current release uses deterministic Dashboard retrieval so it works predictably even if the selected model changes.
