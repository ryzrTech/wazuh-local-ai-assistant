# Reviewed exclusion workflow

Exclusions should be proposed from an investigation and applied only after an administrator reviews the evidence and exact match scope. A model suggestion is never itself an authorization or a validated false-positive finding.

## Default scope

A proposal must name one agent ID, one existing rule ID, and an exact event pattern. It must show recent matching alerts, the original rule, the candidate change, positive and negative test results, expected affected alerts, expiry, and rollback. Broader agent, rule, or pattern scopes require a separate review path with an explicit affected-agent count.

The validator must confirm that the match is evaluated against authenticated Wazuh agent identity at the stage where the rule runs. An `agent.id` field in an indexed alert is not proof that the manager rule engine can use that field during decoding. A global level-zero child rule for one rule ID and a port string would suppress all agents; disabling a rootcheck port check for one agent would suppress every port finding from that check. Neither is an acceptable substitute for the default scope.

## Apply boundary

The chat broker remains read-only. A separate validator should generate the candidate, run Wazuh's native syntax check and positive/negative fixtures, and save a short-lived proposal with the active configuration hash. An administrator applies it through the policy UI. The apply service rechecks the hash and test results, backs up the original, writes atomically, and records the operator, resulting hash, and rollback reference. A negative test must cover the same event on another agent and a different event on the selected agent. Post-apply checks must verify the rule loaded and that new matching events have the expected disposition.

Until the manager can validate agent-specific matching for the target decoder, the UI should offer a draft proposal and a documented manual review rather than an apply button. Installed software, current port snapshots, or a pasted report alone do not prove historical process ownership or justify suppression.
