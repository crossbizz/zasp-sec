# Registered maintenance runtime deployment

The optional `authorizationTemporal.maintenance` object connects the existing
current61/logical78/79/80 hosted profile to the supplementary connector and
approval runtime adapters. It supplies no installation, registration, organization
activation, credential withdrawal, or fleet cutover authority. Omit it until the
actual supplementary catalogs and organization activation have been admitted.
The existing profile and release guards remain required.

The release renderer accepts exactly these fields in this optional object:

| Field | Required authority |
| --- | --- |
| `profile` | Exact selector `registered-dual-maintenance-runtime-v1`. |
| `connectorProfileChecksum` | Exact compiled connector-maintenance checksum from the reviewed application release. |
| `approvalProfileChecksum` | Exact compiled original approval-maintenance checksum from that same release. |
| `activationProfileChecksum` | Exact compiled supplementary approval-activation checksum from that release. |
| `connectorDSNSecret` | Existing Kubernetes Secret containing only the separately registered connector login's `postgres-dsn`. |
| `approvalDSNSecret` | Existing Kubernetes Secret containing only the separately registered approval login's `postgres-dsn`. |
| `connectorKeySecret` | Existing Kubernetes Secret with `seed`: exactly 32 raw bytes matching the registered connector verifier. |
| `approvalKeySecret` | Existing Kubernetes Secret with a different `seed`: exactly 32 raw bytes matching the registered approval verifier. |

Use the approved secret manager and cluster secret delivery mechanism to create
these objects. Never put credential values in release JSON, Helm values, command
arguments, or evidence. All four references must be distinct from one another,
executor/compensation/projector/adapter DSN references, original worker-purpose
keys, runtime-service credentials, and pricing/public-verifier references.
Reference validation cannot establish that the actual secret contents differ;
operator registration and live application admission must verify that separately.
The DSNs must select the same database host/database/TLS authority as the existing
API with distinct registered native principals. Preserve the original outbox
login shared by its original consumers; do not replace or withdraw that SQL role.

Only the API receives the maintenance DSNs and seeds. Its nonroot init container
copies each seed from a read-only projected source to its own regular file on a
memory volume, sets mode 0400, and mounts only that private copy into the API.
The runtime validates file ownership, link count, exact raw size and authority.
Rotating a source Secret requires an API rollout and coordinated verifier
registration; changing the Secret alone does not refresh a running private copy.
The current executor and authorization projector receive the same three profile
pins, without either maintenance DSN or seed. Unrelated workers receive none of
the new settings. Exact compiled/live catalog admission remains mandatory;
format-valid pins do not establish readiness or activate any organization.

Use the existing `renderRelease(release, options)` entrypoint in
`deploy/production/release-contract.mjs` with the full verified release input,
`schemaVersion: 61`, the existing `authorizationTemporal` and `runtimeServices`
objects, and this nested optional object. It validates both input and actual
rendered consumer permissions. Review the generated chart before any deployment.
After copying those same verified options into the secure release values file,
run the existing normal render gates:

```sh
helm lint deploy/staging/product -f deploy/staging/product/values-saas.yaml -f /secure/verified-product-release-values.yaml
helm template zasp deploy/staging/product --namespace agentsec -f deploy/staging/product/values-saas.yaml -f /secure/verified-product-release-values.yaml
```

These commands are render checks. They are not production launch acceptance.
Keep the original rollout requirements in `production-deployment.md`, including
the guarded discovery transition when advancing an older live deployment.

## Installation and activation remain separate gates

The reviewed operator release supplies `up-connector-maintenance-profile`,
`up-approval-maintenance-profile` and `up-approval-activation-profile` through
`agentsec-migrate`. They add supplementary namespaces, preserve the original
source/catalog fingerprints and create no organization activation. Principal and
purpose-key registration must use the original native registration functions
with separate registered roles and seed material; these functions do not make
fleet credential withdrawal safe. This runtime profile intentionally adds no
migration or registration Helm hook and never automatically calls activation SQL.

The current `zasp-controlled-maintenance-cutover` and
`reconcile-and-hold` commands prove only an owned, bounded loopback environment
with an exact held local writer. Their PID/old-token observations do not prove
absence of old writers across a real fleet. `NewDeployment` therefore refuses.
Do not run the controlled commands as a production rollout procedure or broaden
their host restrictions to make a deployment pass.

Production activation remains blocked until a reviewed fleet coordinator can
observe all old writer replicas/processes absent, withdraw their old OpenFGA
credential at the actual service, confirm old-credential refusal and new-credential
full-model access, bind the intended organization/store/model/revision under the
existing lock, activate once, and refresh the composed projection before admitting
API/worker readiness. Retain restart, partial-failure and rollback evidence. A
boolean operator assertion or a copied local receipt cannot supply this proof.

After real activation, verify the public Stytch login/callback and tenant session,
real connector authorize/discovery/sync/revoke, all four approval origins and
signed delivery/settlement, individual permission revocation, cross-tenant denial,
budgets, restart/recovery and audit evidence. The disposable combined-browser
harness and TEST-only Stytch session adapter do not count as these deployed flows.
