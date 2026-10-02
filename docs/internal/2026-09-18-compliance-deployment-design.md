# Deploy the existing compliance56 lifecycle

Status: selected implementation design, not deployment acceptance. The user
authorizes autonomous routine decisions and connected feature-batch testing.
Original M7-08..15 and deployment/release scope remains unchanged. Source
diagnosis: `2026-09-18-compliance-deployment-gap.md`; runtime behavior authority:
`2026-09-18-compliance-production-design.md`.

## Decisions and alternatives

Use the existing release56, API, polling worker and cleanup processes. Add an
explicit worker-registration CLI bridge, dedicated infrastructure declarations,
opt-in chart configuration and exact rendered-resource validation. No migration
SQL or checksum changes are needed. Do not expose fake export success or broaden
the existing audit-export worker's permissions to handle compliance.

A dedicated versioned compliance bucket is required because both services use
`organizations/{org}/workspaces/{workspace}/environments/{environment}/exports/{id}`.
Shared audit storage would mix authority and lifecycle rules. Changing runtime
object keys would require a new persisted-reference compatibility protocol and
is unnecessary for this deployment integration.

Worker registration is explicit, following `up-to-56`. Reuse
`zasp_compliance_register_workers(executor,cleanup,checksum,fingerprint)` through
the bounded CLI interface in `2026-09-18-compliance-registration-brief.md`.
The command does not create login roles, passwords or cloud credentials.
Existing registered discovery API authority already handles compliance reads.

## Opt-in configuration

Extend `renderRelease` options with `complianceExports`. Omission is the only
disabled public-JS form. A present value is a closed plain data object, with
no accessors/symbols/extra keys, synchronously validated and copied before any
async rendering. Its exact keys are:

```text
enabled awsRegion bucket bucketOwner kmsKeyArn
readerRoleArn writerRoleArn cleanupRoleArn
workerDSNSecretArn cleanupDSNSecretArn
workerPrincipal cleanupPrincipal
databaseCIDRs stsCIDRs s3CIDRs
```

`enabled` must be true, `schemaVersion` exactly56 and phase precision-consumers
or precision-intake. Owner must equal the release platform account. Role,
Secrets Manager and KMS ARNs must use the same account and region where
applicable. Bucket uses the runtime's bounded canonical name syntax. Principal
names are distinct bounded lowercase login names and cannot start `zasp_` or
collide with existing database principals. Reader/writer/cleanup IAM roles are
distinct and cannot reuse any predecessor workload identity. The two DSN
references are distinct and cannot reuse predecessor DSN/secret references.
Reject the compliance bucket if it matches an enabled audit export policy
bucket or another existing product evidence bucket.

Network inputs use the current canonical IPv4 CIDR validator, including bounds,
no metadata/loopback ranges, no duplicates or overlap within each list. Values
are explicit operator-supplied references, never raw secrets or discovered
ambient credentials. Chart defaults stay disabled. Direct Helm configuration
must reject malformed enabled authority too; JS validation is not its only gate.

## Storage and IAM

Add opt-in `compliance_exports_enabled` Terraform declarations in
`deploy/staging/compliance_exports.tf`, default false. A separate general-purpose
bucket `zasp-compliance-exports-${md5(var.account_id)}` uses versioning,
BucketOwnerEnforced ownership, all public-access blocks, a dedicated rotating
KMS key and TLS-only bucket policy. No force-destroy or object-lock bypass.
Use SSE-KMS with the exact key and bucket keys, retaining encryption-context
constraints for that bucket and scoped object prefix. The expected owner and
key ARN are exported as non-secret deployment metadata.

IAM roles are keyed reader/writer/cleanup and trusted only for the selected EKS
OIDC provider, audience `sts.amazonaws.com` and respective service accounts:

| Role | Service account | S3 object authority |
| --- | --- | --- |
| reader | agentsec-api | GetObjectVersion only |
| writer | zasp-compliance-export-worker | PutObject, GetObject, GetObjectVersion |
| cleanup | zasp-compliance-cleanup-worker | GetObject, GetObjectVersion, DeleteObjectVersion |

All object resources are the dedicated bucket's scoped export prefix. Writer
PutObject requires exact SSE-KMS headers. No role gets current-key DeleteObject,
bucket mutation, wildcard S3, unrelated queues, AssumeRole, retention bypass or
another worker's DSN. Reader/cleanup KMS access is Decrypt; writer also gets
GenerateDataKey, constrained to S3 service and this bucket/object context.
The runtime uses checksum-mode HEAD; live IAM acceptance must include its real
SDK calls, not infer completeness from a green readiness probe.

Two Secrets Manager entries hold external DSN references only. Terraform does
not set secret versions or passwords. Each worker IAM role can read only its
own DSN with matching Secrets Manager KMS context. Default login names are
`compliance_export_runtime` and `compliance_cleanup_runtime`, distinct from
each other and every predecessor principal. The API reuses its existing API
database connection, never either worker DSN.

Retrieval remains the implemented86400-second database policy. Active cleanup
deletes the exact immutable version only after read leases end and only frees
quota after typed missing-version confirmation. Configure a one-day current
expiration plus one-day noncurrent expiration as storage backstop, with expired
delete-marker cleanup. This is not a24-hour physical-deletion guarantee. AWS
rounds age-based lifecycle eligibility to UTC midnight, and current-version
expiration does not itself erase noncurrent versions. See
[AWS lifecycle rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html)
and [versioned expiration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html).
Object creation follows job creation, so these backstop ages do not precede the
job's retrieval boundary. Unknown/denied cleanup remains charged and visible.

## Chart and runtime bindings

Deploy two replicas each of `zasp-compliance-export-worker` and
`zasp-compliance-cleanup-worker`, using the existing digest-pinned worker image.
Modes are `compliance-export` and `compliance-export-cleanup`; authorities are
`zasp_compliance_worker` and `zasp_compliance_cleanup`. Dedicated CSI-only DSN
mounts populate ZASP_POSTGRES_DSN. Never synchronize these DSNs into Kubernetes
Secrets or expose them to the API/other workers.

Both workers receive common explicit settings: poll1s, lease60s, batch1,
shutdown20s, provider timeout5s, worker ID from metadata.name, region, bucket,
owner, KMS key, their own `ZASP_COMPLIANCE_EXPORT_ROLE_ARN`, and token path
`/var/run/secrets/eks.amazonaws.com/serviceaccount/token`. The projected token
uses STS audience; automount is false. No SQS, planner, connector, gateway,
audit-export, or other runtime authority variables are present.

API receives exactly bucket/owner/KMS/reader role/token compliance settings as
required by its actual loader. No worker-role variable may be present. Reuse
the existing projected web-identity token, with a separately trusted reader
IAM role. Disabled configuration preserves the tested legacy API behavior.

Worker pods use non-root65532, RuntimeDefault seccomp, read-only root filesystem,
no privilege escalation/capabilities/host namespaces/sidecars, CPU request100m
and limit1, memory request128Mi and limit1Gi. Keep shutdown grace >20s and <=300s.
Readiness/health probes use8081 `/readyz` and `/healthz`. Use two-replica PDBs,
topology spread, bounded HPA2..6, internal Services, ServiceMonitors and absent/
not-ready alerts. Probes demonstrate process/dependency readiness, not stored
artifact or cloud configuration acceptance.

NetworkPolicy is additive: exclude these worker labels from the inherited broad
DNS policy, supply their own kube-dns-only53 policy plus explicitly pinned
Postgres5432 and STS/S3 HTTPS443 egress, and monitoring-namespace8081 ingress.
Validate the complete selected policy set, including unnamed broad grants and
malformed selectors. Reject cross-namespace/group RBAC that grants the new
workers permissions. Add the API's explicit storage HTTPS destinations without
giving it a worker's identity. Existing test-reconciler/audit DNS checks must
accept the new exclusions without weakening their own policy validation.

## Rollout and predecessor coexistence

Support56 in both precision phases while keeping48..55 contracts intact and57
unsupported. Default49 compatibility remains unchanged. Extend audit-export
and existing-test reconciler compatibility to56, including schema annotations
and explicit validators. Do not disable those services to make56 render.

The migration job executes, in order: load the existing migration DSN;
`up-to-56`; enabled audit API/worker registration and configuration; enabled
`register-compliance-workers` last. Chain failures with `&&`, using `exec` only
for the final command. No caller-controlled shell fragments. Feed only the two
new principal envs to registration, preserving existing principal inputs.
Job success must include final56 readiness and successful worker binding.
No workers are rollout-ready merely because readiness permits zero bindings.

Confirmed additional runtime gate: `readAuditExportConfigurationState` in
`services/platform/migrations/production_audit_exports.go` accepts only52..55.
All three operational audit commands use it. Extend this operational helper
with exact56 state and compiled56 readiness before/after, preserving historical
upgrade/down readers and rejecting57. Prove the real audit-registration,
audit-configuration, compliance-registration CLI chain under registered migration
authority, including rollback/refusal controls. Render-only tests cannot prove
that this job will execute successfully.

Rendered-resource validation checks exact command/env/roles/DSN mount locations,
authority absence in unrelated resources, both enabled and disabled mode, scope,
resource/probe/network/RBAC constraints and all predecessor combinations.

## Verification and external gates

Focused RED/GREEN during coding; one connected release/render/config suite at
the deployment boundary; one independent spec/quality review of the connected
batch. Preserve separate focused registration proof and reuse unchanged runtime
evidence. No repeated full frontend suite for these non-UI changes; the full
UI/types/lint/build and exact-source CI remain mandatory before publication.

Owned cached Postgres proves real registration and command failures. Rendered
manifest envs must pass the real API/worker configuration loaders, not a second
JavaScript imitation. Negative controls alter role, DSN, permission, bucket,
version, migration ordering, sidecars, network/RBAC, or disabled-mode leakage.
Retain mock/source Terraform results honestly if cached providers are absent.
Do not download providers, apply infrastructure or use live credentials.

Production acceptance still requires authorized account Terraform plan,
provisioned external login/secret values, actual IAM/S3/KMS/versioning/lifecycle
canaries, hosted rollout/CI and approved exact-input advisory evidence. No local
result promotes the component ledger rows by itself.

Rulings: dedicated bucket avoids mixed artifact authority; explicit registration
avoids hidden upgrade side effects; preserve all migration SQL/pins. Costs if
wrong are local declarative/configuration rework and an extra storage resource
at future authorized deployment, not reduced product scope.
