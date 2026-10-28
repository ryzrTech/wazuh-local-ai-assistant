# AI investigations and policy workflow

## Current investigation slice

The native Dashboard plugin registers an **AI investigations** application alongside the chat sidebar. Operators can search recent `wazuh-alerts-*` and `wazuh-archives-*` documents, inspect agent inventory and SCA summaries, and create saved investigations from a selected record or agent. Every interactive read uses the signed-in user's OpenSearch or Wazuh Core scoped client. The browser cannot submit arbitrary index names, Wazuh API paths, or search DSL.

Searches are bounded to 40 recent records, a 1–720 hour time range, and fixed index patterns. Investigation evidence stores one selected record or a bounded agent/SCA summary in the same owner-scoped SQLite database as chat. Evidence is at most 6,000 characters and is presented to the model as untrusted data. The model produces advisory analysis with source references. It does not perform its own tool calls, execute shell commands, or modify Wazuh.

The first agent posture flow drafts recommendations from SCA policy scores and a bounded set of failed checks. These are **unvalidated drafts**, because Wazuh agent and SCA configuration cannot be safely activated or tested from a chat answer. The application labels this state explicitly.

## Thirty-day raw-event search

Wazuh alerts are indexed by default. To search events that did not trigger an alert, enable `<logall_json>yes</logall_json>` in the manager and the Filebeat `wazuh/archives` fileset. Create an ISM policy on only `wazuh-archives-*` with a transition to delete at `min_index_age: 30d`. Verify the policy is attached to the first new archive index. Rotate and remove local compressed archive files older than 30 days with a dedicated timer. Monitor index size, event rate, Filebeat errors, and free disk space during the first week.

The archive policy does not change alert-index retention. It does not retroactively reconstruct events from before archiving was enabled.

## Next policy slices

1. **Agent and SCA configuration:** read effective group and agent settings, generate a structured proposal with target agent/group and exact diff, validate XML/YAML and allowed settings, compare failed SCA checks with the proposal, stage in an isolated directory, and require human approval before a separate deployment service applies it. Verify group synchronization and the next SCA scan; keep a backup and rollback path.
2. **Detection rules:** inspect existing custom and built-in rules, generate candidate XML with collision checks and positive/negative fixtures, run Wazuh logtest, then stage for approval and controlled activation.
3. **Access and response policies:** render current RBAC and active-response configuration read-only first. Proposals need a separate policy engine, independent authorization checks, and an emergency disable switch before any write path is enabled.
4. **Continuous triage:** add a durable intake queue after interactive investigations produce reliable, cited analyses. Start in observe mode with bounded event filters and no automatic security response.

The model gateway was tested with synthetic OpenAI-compatible tool definitions and produced valid streamed tool calls. Model-directed tools can therefore be considered later, but each tool still needs a strict server-side schema, per-user authorization, bounds, and audit records. The current release uses deterministic Dashboard retrieval so it works predictably even if the selected model changes.
