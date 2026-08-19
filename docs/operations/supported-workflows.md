# Supported production workflows

The production web surface is authenticated, capability-gated and API-backed. It supports:

- sign-in, callback, session bootstrap, sign-out and scope switching;
- home summary and durable paginated inventory/workflow reads;
- policy and security-agent create/update/delete plus rollout/configuration where the server capability permits;
- identity member/role and workspace/environment administration;
- API-token create, reveal acknowledgement, rotation and revocation;
- session investigation and revocation;
- audit, compliance, retention and external-flow reads with unavailable provider/export actions honestly disabled;
- scoped finding list/detail, status update and risk acceptance;
- scoped attack-path list/detail and ranked path-local break options.

Red Team, Attack Lab, reports, guardrail prototype controls, tickets, AI explanations, provider/sensor sync, policy simulation/decision history, security-agent execution/approval, exports and deletion jobs are not supported production workflows. They remain capability-hidden until their provider, queue/artifact, authorization and recovery boundaries have deployed evidence.

PostgreSQL schema v9 is the durable product authority. OpenSearch and Neo4j are projections only and cannot authorize or override a PostgreSQL result. The deployment does not fall back to demo fixtures, browser-local product state or in-memory stores.
