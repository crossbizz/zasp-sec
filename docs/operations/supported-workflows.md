# Supported production workflows

The production web surface is authenticated, capability-gated and API-backed. It supports:

- sign-in, callback, session bootstrap, sign-out and scope switching;
- home summary and durable paginated inventory/workflow reads;
- policy and security-agent create/update/delete plus rollout/configuration where the server capability permits;
- identity member/role and workspace/environment administration;
- API-token create, reveal acknowledgement, rotation and revocation;
- session investigation and revocation;
- runtime session timelines and canonical evidence retain precise timestamps plus source-sensor and sandbox identity when the committed evidence contains them; historical or unknown identity stays absent;
- audit, compliance, retention and external-flow reads with unavailable provider/export actions honestly disabled;
- scoped finding list/detail, status update and risk acceptance;
- scoped attack-path list/detail and ranked path-local break options.
- integration authorization, manual synchronization, UTC scheduling, sync history, and independent projection freshness.
- discovered agents without a declaration: Bedrock agents and AgentCore runtimes the AWS control plane lists, and agents inferred from signals (a Lambda function that calls a model, an unlabelled Kubernetes workload, a GitHub repository with an agent manifest or framework, an AI application connected in Okta). Every inventory object shows its provider and how it was found; an agent found without a declaration is unmanaged until it has an owner. None of these collectors has run against a real provider.
- tenant-scoped Red Team definition, run, cancellation, status, and immutable normalized evidence workflows against fresh discovered agent and MCP targets, limited to curated categories and development, test, or staging credentials.

Attack Lab, reports, guardrail prototype controls, AI explanations, exports and deletion jobs are not supported production workflows through the web application. Attack Lab runtime and deployment authority are present, but the route remains capability-hidden until the API-backed product UI and complete provider/queue/artifact/recovery journey have production evidence. Red Team never accepts arbitrary prompts, arbitrary destinations, production environments, production-write credentials, or shell access.

PostgreSQL is the durable product authority at the exact schema selected by the [release phase](production-deployment.md#configure). OpenSearch and Neo4j are projections only and cannot authorize or override a PostgreSQL result. The deployment does not fall back to demo fixtures, browser-local product state or in-memory stores. Runtime session reads stay on target v1 during schema-50 backfill; the query phase selects the independently verified v2 target. A rendered phase or local test result is not live cutover authorization.
