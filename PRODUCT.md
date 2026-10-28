# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Wazuh operators investigating security events and reviewing detection, agent, and security configuration policies.

## Product Purpose

Provide an in-Dashboard AI workspace that can investigate real Wazuh evidence, explain findings with references, and prepare reviewable configuration proposals.

## Operating Context

The application is an external plugin for Wazuh Dashboard 4.14.9 / OpenSearch Dashboards 2.19.6. It uses the signed-in user's Wazuh and indexer permissions for interactive reads. The model gateway and conversation service run on self-hosted infrastructure.

## Capabilities and Constraints

- Searchable raw events have a requested 30-day retention target.
- Agent and SCA settings are the first complete proposal-and-test area; detection rules, access, and response policies should be visible and added in later workflows.
- The model does not receive unrestricted shell, indexer, or Wazuh administrator access.
- Changes to Wazuh configuration need a separate approval and rollback path.
- Source shared publicly must not contain site identifiers, domains, credentials, or user-specific data.

## Product Principles

- Show the evidence behind every AI finding.
- Make read-only investigation fast; make changes deliberate and reviewable.
- Preserve Wazuh permissions and stability.
