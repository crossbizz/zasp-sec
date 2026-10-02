# Approved addition: outbound Kubernetes inventory collector

Approval was relayed from the user's side conversation
`01a0afd9-f514-7c32-9d0c-1d6244f68ee5` on2026-09-17. That conversation reported
no workspace edits. This is additional scope, not a replacement for any of the
728 original v1.5 microtasks or for the existing direct Kubernetes API option.

All tasks below are **planned**, unshipped and not live-verified. No collector
implementation, deployment, footprint or end-to-end readiness is claimed by
this record. The current existing-test reconciliation batch remains in progress.

## Customer contract

Per cluster, the administrator chooses direct API access with scoped credentials
and an approved network path, or installs an in-cluster collector using Helm or
GitOps manifests. The collector uses least-privilege read-only service-account
RBAC and sends tenant/cluster-scoped inventory outbound over authenticated HTTPS
to Zasp. SaaS does not initiate a connection to that cluster's Kubernetes API in
collector mode. Installation requires customer administrator authorization.

Neither Tetragon nor the enforcement gateway is required for inventory-only
discovery. Inventory, runtime observation and enforcement are separate coverage
choices. A cluster must not require both discovery modes. Heavy risk, graph,
storage and testing workloads remain hosted.

## Additional task ledger

These stable IDs are separate from the original ledger. Every row is planned;
evidence must distinguish component-tested, shipped and live-verified outcomes.

| ID | Required deliverable and acceptance |
| --- | --- |
| KIC-001 | Review current Kubernetes APIs/parsing/schema/normalization and downstream processing. Produce the approved technical design and reuse map; don't treat runtime events as inventory without proving equivalent semantics. |
| KIC-002 | Tenant/cluster-bound inventory ingestion contract with authentication, authorization, limits, validation and cross-tenant refusal tests. |
| KIC-003 | Secure enrollment and trustworthy cluster identity, including administrator authorization and replay/substitution defenses. |
| KIC-004 | Credential issuance, secure storage, rotation, expiry and revocation; no secrets in Helm arguments, shell history, logs or generated public guidance. |
| KIC-005 | Read-only in-cluster inventory collector with documented least-privilege RBAC and reuse of existing Kubernetes interpretation. |
| KIC-006 | Bounded batches, buffering, backpressure and resource limits; measure consumption on representative cluster sizes without invented footprint claims. |
| KIC-007 | Checkpoints, retries, idempotent ingestion and restart recovery under connection loss and process failure. |
| KIC-008 | Reliable full-snapshot completion and deletion semantics; interrupted or partial scans must not falsely delete inventory. |
| KIC-009 | Single-owner/conflict handling for duplicate collectors and direct-mode versus collector-mode ownership, including safe mode transitions. |
| KIC-010 | Helm and GitOps installation, configuration, upgrade and uninstall behavior with compatibility and rollout tests. |
| KIC-011 | Customer setup UI offering either discovery mode, explaining permissions/network paths and generating safe installation guidance. |
| KIC-012 | Connection validation and first-sync onboarding acceptance through actual ingestion and downstream inventory display. |
| KIC-013 | Health, freshness and actionable errors; show inventory/runtime/gateway coverage independently. |
| KIC-014 | Troubleshooting for private clusters, RBAC denial, unavailable egress, expired credentials and interrupted sync. |
| KIC-015 | Tenant/security/permissions/compatibility and full onboarding end-to-end verification, with independent Superpowers review and production/live evidence gates. |
| KIC-016 | Update source-of-truth task lists, technical implementation/design plans, scope/change log, deployment/onboarding docs and status/evidence ledgers; preserve all original IDs and runnable UI/release gates before main pushes. |

## Execution and evidence rules

Use Superpowers design, TDD and independent review with feature-batched
verification. Do not enable this customer option based only on local collector
or parser tests. Record external cluster/deployment/network gates honestly.
Installation on a customer cluster requires that customer's authorization;
approval to implement the product is not permission to modify arbitrary clusters.

Next: complete the active reconciliation checkpoint, then assess existing
Kubernetes surfaces and write the collector design before implementation.
