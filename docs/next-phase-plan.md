# Next phase: usable Wazuh tools and reviewed policy changes

## Current gap

Before Phase 3A, chat sent a system prompt that said it could not independently search Wazuh, and its provider request contained no tool definitions. The separate Investigations application could retrieve selected alerts, raw events, agents, and SCA evidence under the signed-in user's permissions. Chat could analyze an attached evidence snapshot but could not initiate those reads. Phase 3A closes that gap with bounded read tools.

## Phase 3A — read-only chat tools (first)

**Status:** Implemented on the test host. Local protocol, bounds, permission-propagation, and broker tests pass. The configured model emitted valid capability and alert-search tool calls. The operator still needs to review the updated chat UI in an authenticated session.

1. Add a server-derived capability manifest for the signed-in user. Expose it in chat and use it to answer access questions. It must distinguish available read tools, proposal/validation workflows, and unavailable write actions. Do not rely on the model to guess its permissions.
2. Move chat tool orchestration into the authenticated Dashboard request path, where the current-user OpenSearch and Wazuh Core clients are available. Keep model credentials in the existing loopback provider service. Never let the model call Wazuh APIs or the policy validator directly.
3. Start with four bounded tools: `search_alerts`, `search_raw_events`, `get_agent`, and `get_sca_results`. Each accepts a strict schema, enforces the signed-in user's Wazuh permissions, fixed sources, time/result caps, and a response-size cap. No arbitrary search DSL, index name, API path, shell command, or network destination is accepted.
4. Give every tool result a source reference and retrieval time. Record the request, tool name, bounded arguments, result count, duration, and outcome in a private audit log without storing full log bodies or secrets. Show a concise tool-use trace in chat.
5. Bound each model turn by tool-call count, elapsed time, output size, and token budget. Treat event text as untrusted. If the model or provider lacks tool support, report that capability as unavailable instead of inventing results.

**Acceptance:** “What can you access?” reports the actual manifest. “Show recent root SSH logins” invokes a real alert search and cites returned IDs and times. A raw-event query returns only permitted 30-day archive results. A user without source permission gets a clear denial. The model cannot run a write action, arbitrary query, or out-of-bounds search. These checks run through API and service tests; visual review is performed by the operator.

## Phase 3B — controlled agent/SCA apply

**Status:** The core reviewed workflow is deployed. Saved proposals expire after 30 minutes, and administrator apply/rollback uses owner, group membership, native validation, hash, backup, and atomic-write checks. The UI can inspect one selected agent's group sync status and latest SCA scan. Group-wide distribution and scan confirmation remains for a later increment; no active group setting was changed during deployment.

1. Save a validated proposal with group scope, exact diff, base-file hash, validator output, author, and expiry. Present the proposal and affected agents for administrator review.
2. Require an explicit administrator action in the policy UI to apply. A separate narrowly privileged service rechecks the active file hash and group membership, takes a timestamped backup, writes atomically, and runs native validation. A stale proposal or failed validation cannot proceed.
3. Record who applied or rolled back the change, the before/after hashes, and the validation result. Provide a one-click rollback to the saved version, also guarded by a hash check.
4. Report group synchronization and the next SCA scan separately. A syntax pass or file write must never be labeled an endpoint verification.

**Acceptance:** A valid proposal applies only after explicit review; stale and unauthorized proposals fail; backup and rollback work; the UI distinguishes applied, distributed, and observed-on-agent states. Chat may draft a proposal but cannot invoke apply or rollback.

## Phase 3C — broader policy visibility and alert operations

- Inventory custom detection rules and show proposals with rule-ID collision checks, positive and negative logtest fixtures, validation, backup, and reviewed activation. The existing SSH rule is the first reference case.
- Add delivery status, retry/dead-letter visibility, and a test result to the alert settings. Keep Dashboard-only delivery until a destination is explicitly configured. Add a service-specific adapter only after a destination type is chosen.
- Show RBAC and active-response configuration read-only. Design proposals and emergency disable separately before any write or execution path is considered.

## Phase 3D — continuous triage

After interactive investigations produce reliable cited results, add a durable, bounded intake queue in observe mode. Deduplicate alerts, apply explicit filters and rate limits, and save model findings as drafts for an operator. No automatic policy change or active response is part of this phase.

## Rollout order

Phases 3A and the core of 3B are deployed. Complete group-wide verification, then 3C. Start 3D only after the read-only tool audit and investigation quality are verified. Deploy each slice with a service backup, API smoke check, negative permission test, and rollback instructions. Do not use browser automation; ask the operator to review visual behavior in their own session.
