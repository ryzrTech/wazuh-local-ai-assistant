# AI investigations and policy workflow

## Current investigation slice

The native Dashboard plugin registers an **AI investigations** application alongside the chat sidebar. Operators can search recent `wazuh-alerts-*` and `wazuh-archives-*` documents, inspect agent inventory and SCA summaries, and create saved investigations from a selected record or agent. Every interactive read uses the signed-in user's OpenSearch or Wazuh Core scoped client. The browser cannot submit arbitrary index names, Wazuh API paths, or search DSL.

Investigation-page searches are bounded to 40 recent records, a 1–720 hour time range, and fixed index patterns. Investigation evidence stores one selected record or a bounded agent/SCA summary in the same owner-scoped SQLite database as chat. Evidence is at most 6,000 characters and is presented to the model as untrusted data. Chat now offers model-directed read-only tools for alerts, raw events, one agent, and that agent's SCA results. Each tool runs under the signed-in user's Wazuh permissions with a ten-record search cap, source references, and audit metadata. The model cannot execute shell commands or modify Wazuh.

The first agent posture flow drafts recommendations from SCA policy scores and a bounded set of failed checks. Model-written recommendations are **unvalidated drafts**. A separate administrator-only form supports four bounded SCA settings for a selected agent group: enablement, scan-on-start, scan interval, and skipping NFS. The validator reads the active group `agent.conf`, preserves existing policy declarations, returns a complete diff and active-file hash, and runs Wazuh's `verify-agent-conf` on a temporary candidate. It rejects ambiguous multi-block or scoped configurations. A valid proposal is saved for 30 minutes. An administrator can explicitly apply it through a separate narrowly writable service that rechecks the hash and native validation, saves a private backup, and writes atomically. Rollback is available while the applied file still matches the recorded hash.

A passing result confirms Wazuh accepts the candidate syntax. Applying updates the group configuration; it does not establish that every endpoint received the settings or that a later SCA score improved. The UI can display the selected agent's current group sync status and latest SCA scan time after apply. Review other agents in the group separately before declaring rollout complete.

## Thirty-day raw-event search

Wazuh alerts are indexed by default. To search events that did not trigger an alert, enable `<logall_json>yes</logall_json>` in the manager and the Filebeat `wazuh/archives` fileset. Create an ISM policy on only `wazuh-archives-*` with a transition to delete at `min_index_age: 30d`. Verify the policy is attached to the first new archive index. Rotate and remove local compressed archive files older than 30 days with a dedicated timer. Monitor index size, event rate, Filebeat errors, and free disk space during the first week.

The archive policy does not change alert-index retention. It does not retroactively reconstruct events from before archiving was enabled.

## Next policy slices

1. **Agent and SCA configuration:** expand the current reviewed workflow to more agent modules and SCA policy YAML, and add group-wide distribution/scan verification.
2. **Detection rules:** inspect existing custom and built-in rules, generate candidate XML with collision checks and positive/negative fixtures, run Wazuh logtest, then stage for approval and controlled activation.
3. **Access and response policies:** render current RBAC and active-response configuration read-only first. Proposals need a separate policy engine, independent authorization checks, and an emergency disable switch before any write path is enabled.
4. **Continuous triage:** add a durable intake queue after interactive investigations produce reliable, cited analyses. Start in observe mode with bounded event filters and no automatic security response.

The configured model produced valid streamed `get_capabilities` and `search_alerts` calls through the loopback provider API. Dashboard executes only fixed, bounded read tools; unsupported calls fail. If the model or provider stops returning valid tool calls, searches cannot proceed and the assistant must not invent results. Interactive tool use is separate from the future continuous-triage queue.
