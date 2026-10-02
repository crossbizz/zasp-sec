# B04 original staging tasks: evidence audit

Status: source/evidence audit complete on September 15, 2026. No cloud operation,
test execution, implementation or availability change.

Requirements are the ten B04 rows M1A-01 through M1A-10 in
implementation_batches_v1.5.tsv. Verify their exact deliverables, acceptance and
dependencies against agent_security_platform_Technical_Implementation_Plan_v1.5.md.
Do not replace the original real-AWS/private-endpoint gate with local validation.

Read-only assignment: inspect deploy/staging Terraform/modules, product Helm
configuration, policy tests, runtime pod commands, existing release evidence and
the gate implementation. For each original ID name actual files and tests,
missing product or infrastructure behavior, last evidenced verification and
what would prove its precise acceptance. Distinguish source assertions, mocked
Terraform tests, actual plan output and real deployed pod/provider evidence.

Identify exact approved-deployment prerequisites recorded by the repository:
account/region/profile selection, role trust and permissions, existing resource
identity, private connectivity, image registry/digests and provider configuration.
Missing evidence is not proof of missing access. Do not search credentials,
local kubeconfigs, cloud state, secret stores or user files. Do not contact AWS,
apply Terraform, run kubectl, execute tests or start infrastructure. Billable
deployment is not authorized by this audit. No current cloud liveness claim.

Return a dependency-safe implementation/verification sequence and file ownership
that preserves the active audit-export and Security Agent work. Expose stale or
overbroad gate claims explicitly. Preserve the original six component-only and
four externally blocked classifications unless root separately verifies a change.

Only this report may be edited with apply_patch. No product/Git writes or
subagents. Write a compact per-ID findings table and exact external-gate checklist
below, with source paths and named evidence. Root owns execution decisions and
authoritative status updates.

## Findings

The ten TSV rows match the source plan at lines 1248-1307: M1A-01 depends on
M1-36, then each ID depends on its immediate predecessor. The original queue
contract is also explicit at plan lines 195-203. I kept all six component-only
and four blocked/external classifications. Nothing here grants batch acceptance.

Paths below are repository-relative. "Recorded" means a checked-in account of a
past run, not a fresh run or a reinspection of its temporary log. I read source
and repository evidence only; I did not inspect credentials, kubeconfigs, state,
user files or cloud resources. Missing evidence doesn't prove missing access.

| Original ID / status | Source and named tests | Gap and precise acceptance evidence still needed |
| --- | --- | --- |
| M1A-01 / component-only | `deploy/staging/main.tf`: `aws_vpc.staging`, `aws_subnet.private`; `outputs.tf`: `vpc_id`, `private_subnet_ids`. `app/quality/m1a-m3-foundation-batch-contract.test.ts`: `defines the exact private staging Terraform resources and outputs`. | DNS-enabled VPC and two non-public-IP private subnets exist in source. This is one shared root, not a separately reusable VPC module. No current pinned-revision validation record for this root was found. Original acceptance needs an actual `terraform validate` result and exact subnet outputs; source-string assertions don't supply it. Private runner connectivity and outbound routing remain deployment gates below. |
| M1A-02 / component-only | Same root: `aws_eks_cluster.staging`, `aws_eks_node_group.staging`, EKS/node roles, KMS secret encryption; `outputs.tf`: `cluster_name`, sensitive `cluster_endpoint`. Same foundation test. | Cluster consumes both private subnets and defaults to private API access. But `variables.tf` only forbids public API access when environment is production; staging can set it true. Gate alignment must require false for original private staging acceptance. Current pins are Kubernetes 1.34 and CNI `v1.22.4-eksbuild.3`; the gate fixture's `1.35.5` is synthetic, not cluster evidence. Need current actual validation and output review, then separately approved node/control-plane evidence. |
| M1A-03 / component-only | Root: `aws_s3_bucket.evidence`, public-access block, versioning, KMS encryption with Bucket Keys, lifecycle, rotating `aws_kms_key.staging`, `aws_secretsmanager_secret.product`; outputs name bucket, key and secret ARNs. Foundation test checks resource strings. | Encrypted storage/secret metadata exists; secret values and PostgreSQL principals are explicitly provisioned outside Terraform. Original acceptance needs retained actual plan output showing encryption and every public-access block for the selected staging account/revision. An August 18 plan claim isn't current-plan proof after later root changes. Audit-export secret metadata tests below don't prove deployed values or the whole B04 plan. |
| M1A-04 / component-only | `main.tf` `local.queue_contract`, work/DLQ queues and byQueue redrive-allow policies; `outputs.tf` queue URL maps. Correction: `services/platform/queuedefinition/definitions.go:87-89` now names Red Team, while `app/quality/sqs-queue-definitions-contract.test.ts` checks original-name prose in the design/README, not current definition bytes. Mock-plan tests `audit_export_queue_is_dedicated_and_bounded` and `all_work_and_dead_letter_queues_keep_customer_keys` are in `deploy/staging/tests/session_search_iam.tftest.hcl`. | Original names are `agentsec-background`, `agentsec-runtime-events`, **`agentsec-tests`**, each with a DLQ. Current Terraform and canonical definition both omit the original tests name/schema; current Red Team consumers explicitly require their replacement identity. This is a cross-layer contract mismatch, not merely a missing Terraform entry. Adding an unused original-name queue wouldn't prove workflow compatibility. Preserve shipped Red Team and active audit-exports; reconcile the original contract with explicit consumer/schema evidence before credit. See the correction below. Need actual selected-account plan with original redrive targets, retention/schema settings and output maps. |
| M1A-05 / component-only | `main.tf` `aws_opensearch_domain.events` and its VPC HTTPS SG: OpenSearch 2.19, two subnets/zones, KMS at rest, node encryption and enforced TLS. `deploy/production/release-contract.test.mjs`: `terraform provisions the exact encrypted v15 runtime plane and isolated identities`. `services/platform/inventorysearch/opensearchdriver/driver_test.go`: `TestReadyChecksExactSignedInventoryIndex`, `TestInitializeSchemaCreatesExactMappingAndImmutableMarkerThenReplays`. | Domain and method/path-scoped identity policies exist, but the root has no explicit domain access-policy resource/field; inspect the approved account's effective authorization during the authorized plan/deployment review, don't infer failure or success. Current index/schema initializer receipts are also needed for product readiness. Original acceptance needs actual plan evidence of VPC-only access and encryption; driver doubles and source assertions don't prove it. |
| M1A-06 / component-only | Exact OIDC audience/subject trust and split roles in `main.tf`; `outputs.tf` role/runtime-authority outputs. Foundation test `permits the exact deny-all statement but rejects wildcard grants` and source restrictions; release test `terraform binds each shipped secret consumer to one exact least-privilege IRSA role`; mocked `session_search_exact_method_path_authority` compares actual generated policy action/resource pairs. | Source tests catch selected forbidden strings; they aren't an IAM authorization-denial evaluation. Mocked plan comparisons cover selected roles and paths, not every B04 pod's effective policy union or account boundary. Add a closed per-role original-operation/unrelated-write denial matrix against generated policy JSON and preserve existing roles. Resolve `zasp-staging-*` Terraform defaults versus hardcoded `zasp-production-*` gate/preflight identities. Real STS identity and permitted/denied provider results remain external. Don't manufacture a union role just to make the smoke pass. |
| M1A-07 / blocked/external | `gate.mjs`: `buildStagingDeployment`, `startStagingDeployment`, `inspectStagingDeployment`; `gate.test.mjs`: `staging deployment binds thirty-two deployments and every init/runner/canary identity to one account`. Helm `product/templates/{workloads,runtime,services,ingress,nango,otel-collector}.yaml`; release test `release renders one TLS origin, split ports, private internals, and migration/schema gates`. | There is no live staging launcher/inspector in this boundary: start/inspect are injected functions. Current default hosted chart is 32 deployments plus jobs, not the original four stubs. Later schema phases add workloads; the gate still fixes schema job v49 and 32 deployments. Need an approved staging scope/phase, immutable images, actual selected-cluster rollout/Ready evidence for web/API/worker/event-ingest and observed exclusion of vendor dashboards. Rendering and mocked ready lists don't count. |
| M1A-08 / blocked/external | Driver boundaries exist: S3 `services/platform/agentsec-worker/discovery_artifacts_test.go` `TestProductionDiscoveryArtifactAuthorityUsesExactS3Boundary`; SQS `services/platform/jobqueue/sqsdriver/driver_test.go` `TestPublishBatchSendsExactCanonicalEnvelopesOnceWithoutSDKRetries`; OpenSearch tests above. Health process tests include `TestServeProcessExposesExactHealthEndpoints` in API/worker and `TestServeProductionIngestRunsPrivateAndHealthListenersAndDrains` in `services/event-ingest/production_runtime_test.go`. | The original integrated dependency smoke is absent from `gate.mjs`. `app/quality/m1a-staging-gate-batch-contract.test.ts` explicitly requires `runStagingDependencySmoke`, `throughIRSA`, and `otlpHealthEmitted` to be absent. No replacement real-pod S3/SQS/OpenSearch+OTLP acceptance collector was found. Build the bounded product-pod proof and redacted receipt contract first, then run only after external approval. Prove all three scoped operations, actual projected-token STS authority, private dependency paths and correlated OTLP health evidence. Individual local drivers/readiness do not close this row. |
| M1A-09 / blocked/external | `gate.mjs` `createStagingEvidence`; test `staging evidence is deterministic, credential-free, and gates exact private readiness`. | Closed fields and image sorting reject extra credential fields, but all values are supplied by the caller. No smoke receipt, OTLP observation, deployment provenance binding or same-run image verification is required. It accepts any syntactically valid 40-hex revision and cluster version. Need a redacted reproducible record from M1A-07/08 that binds reviewed Terraform/chart revision, actual cluster identity/version, resolved pod image digests and operation/telemetry receipts. No fabricated run ID or fixture account. |
| M1A-10 / blocked/external | `gate.mjs` `evaluateM1AGate`; same evidence test; `cmd/agentsecctl/release.go` `PreflightInput` / `EvaluatePreflight` checks are another caller-boolean boundary. | Current gate can return ready from `deploymentReady`, `privateEndpoints`, `perWorkloadIAM` all true plus syntactically valid evidence. It never requires dependency results or OTLP. This is an overbroad PASS contract for the original task. Gate must reject missing/failed/mismatched/stale real receipts and consume M1A-07/08/09 evidence from the same authorized run. Only then can the original private real-AWS readiness result be considered. |

### What the recorded runs actually establish

`README.md:323-331` claims Terraform 1.15.8 validation and an offline 34-create
plan, then claims a four-workload boundary with an exact dependency smoke.
`implementation_status_v1.5.md:2959-2964` dates the six component additions to
August 18. The same tracker records a later M8-01 offline 47-addition plan.
Those are historical summaries, not retained current plan output. The root now
has eight work queues and eight DLQs, many split identities and later storage.
Neither 34 nor 47 is a current resource-count assertion.

The newest explicit Terraform evidence I found is the audit-export record,
`docs/internal/2026-09-12-audit-export-evidence.md:1189-1263`: mock-provider plan
runs progressed through 8/8, 9/9 and 16/16 passes (final recorded run 16449).
AWS and TLS provider values are mocked by `session_search_iam.tftest.hcl`.
These are actual Terraform test-plan evaluations of source with fake provider
values. They aren't real-account plans or live permission tests. The record
also gives release regression 49288 at 103/103, followed by later chart checks;
none is a live B04 deployment result. I didn't execute any of them.

`docs/internal/2026-09-11-lineage-release-verification.md` records 42 selected
release/staging tests, later full repository verification and merged-head CI
34612285514. It explicitly withholds deployment claims. Later source edits need
their own verification. No checked-in current B04 real-AWS pod/provider/OTLP
receipt was found in the inspected material.

The tracker text at M1A-08 says an injected smoke boundary exists; current
source contradicts that claim. Its statement that a cluster/role is unavailable
must not be interpreted as a fresh access check. The README's four-workload
description, six queue-resource count and smoke claim are stale too. Root owns
those corrections and the authoritative ledger.

### Before any approved AWS run

These are unverified prerequisites, not findings that access is absent.

- Approval first. Name the isolated non-production account, region, cluster,
  allowed operations, budget, release phase and operator. `release.tfvars` is
  a production offline fixture (`000000000000`, `zasp-production`,
  `offline_validation=true`), not an approved staging input. Terraform defaults
  use staging, `us-west-2`, `zasp-staging`, `10.64.0.0/16` and two named AZs.
  The provider has neither a selected profile/assume-role nor
  `allowed_account_ids`; obtain the approved identity selection and account
  fence through the owner without reading credential material.
- Existing identity inventory: confirm whether each VPC/subnet/cluster, named
  bucket/domain, queue/DLQ, KMS key, secret metadata and IAM/OIDC object is new
  or already owned. Queue names lack an environment suffix; two roots in one
  account/region can collide. Agree state/backend ownership and any import
  decision before a plan or apply. This audit inspected no state.
- The deployment operator needs approved control-plane provisioning and
  `iam:PassRole` authority for the exact EKS/node/Fargate roles, plus Kubernetes
  administration for the selected namespace and required controllers. The root
  doesn't declare operator EKS access entries. Each product pod instead needs
  its own exact OIDC issuer, `aud=sts.amazonaws.com`, service-account subject,
  projected token and bounded S3/SQS/OpenSearch/KMS authority. Confirm effective
  key/resource policies and organization permission boundaries at that time.
- Private reachability. The operator must reach the EKS API and its OIDC TLS
  discovery path; pods need DNS, STS, SQS, KMS, Secrets Manager, S3 and the VPC
  OpenSearch endpoint. The root defines S3 gateway and seven interface endpoint
  types with private DNS, but no NAT/Internet gateway route. Confirm the actual
  bootstrap/controller and registry paths without making EKS public. Copy the
  actual `s3_cidr_snapshot` into reviewed NetworkPolicy values as the operations
  runbook requires. Fixed private/provider CIDRs must match deployed addresses.
- Images and cluster controllers must exist before pod readiness: approved
  registry, nine product digest fields plus pinned Nango/Collector dependencies,
  pull permissions, image attestations, ingress/TLS, CSI Secrets Store with AWS
  provider, and monitoring CRDs/controllers referenced by the chart. Product
  image defaults are empty; `registry.example` test digests aren't artifacts.
  Fixed public dependency image names need a reviewed pull path in the private
  network. Mirroring would require coordinated pin/validator changes.
- For the full current chart, provider setup extends beyond the original
  skeleton: separately provisioned PostgreSQL logins/DSN objects and exact
  migration/schema phase, graph and search initialization, authentication and
  connector references, Nango database/encryption/service keys, and any selected
  Red Team/Attack Lab/Recovery configuration. Values must contain references,
  never secret bytes. Don't activate those systems merely to satisfy a broadened
  staging validator. The minimal-original-scope versus full-chart choice needs
  an explicit owner decision.
- OTLP evidence has its own gate. The Collector default `backend=none` discards
  telemetry through `nop`; the operations runbook says its deployment doesn't
  prove application emission. Select an approved observation/sink and retain
  bounded correlated health evidence from the actual smoke. A remote backend
  needs its exact endpoint, authorization-secret reference and egress CIDRs.

### Safe order and file owners

Root coordinates the next source slice. First reconcile original queue identity,
staging naming and the intended four-stub/current-chart deployment scope; keep
M1-36 and the ten original dependency edges intact. Then implement local denial
tests and receipt/gate binding without claiming cloud acceptance. Obtain fresh
offline validation and selected plan evidence only under a separate authorized
execution step. Account inventory, private connectivity and a reviewed actual
plan come before any billable deployment. Deploy/observe Ready (07), execute the
scoped pod operations and OTLP observation (08), retain provenance (09), then
evaluate the evidence-bound gate (10). Any failure stops that sequence.

File ownership is narrow:

| Owner | Safe scope / coordination constraint |
| --- | --- |
| This audit | Only this report. No source, Git, tests or external actions. |
| Root / staging follow-up | Own `gate.mjs`, gate/preflight tests and any new B04 evidence collector/tests after agreeing the contract. Coordinate `main.tf`, `variables.tf`, `outputs.tf`, chart defaults and release validators before edits; they are shared files. Root alone updates original status/README claims. |
| Active audit-export work | Preserve `audit_exports.tf`, `product/templates/*audit-export*`, dedicated queue/principal policy tests in `session_search_iam.tftest.hcl`, export release fixtures and API/worker wiring. Do not copy an older shared file over these changes or enable `auditExports.enabled` for this audit. |
| Active Security Agent work | Preserve `services/platform/securityagent`, agent-worker planner/runtime changes, Security Agent chart blocks and their IAM policies. M7A-84 review is separate; B04 readiness doesn't award its acceptance. |
| Approved infrastructure/release operator | Own account/profile selection, existing-resource reconciliation, permissions, secret provisioning, private connectivity, image publishing and any actual apply/rollout/smoke. Approval must name the exact run. |

### Queue correction after root's cross-check

My first table incorrectly said `services/platform/queuedefinition` retained the
original three names. It doesn't. Root caught that error; this correction is
based on another read-only source trace, with no tests or provider calls.

There is no `queuedefinition.Tests` exported value or function in current source.
The symbol is `KindTests`, a kind string of `tests`; `Definitions()` returns its
canonical entry with name `agentsec-red-team-tests`, DLQ
`agentsec-red-team-tests-dlq` and schema `agentsec.red-team-tests.v1`.
`definitions_test.go:58-61` and `TestDefinitionsJSONIsExactDeterministicAndFresh`
pin those current names. The field list still requires `test_run_id`, and the
definition version remains 1. A schema/name change is not an alias declaration.

| Boundary | Actual dependency and compatibility consequence |
| --- | --- |
| Original requirement / prose | Source plan lines 195-203, `docs/internal/2026-08-18-m1-33-sqs-queue-definitions-design.md` and the README's SQS proof section still require `agentsec-tests`, its DLQ and `agentsec.tests.v1`. The two relevant tests in `app/quality/sqs-queue-definitions-contract.test.ts` (`binds the exact source task to the selected closed design`, `exposes the exact hermetic and disposable live proof boundary`) read those documents. Their success doesn't compare the current Go definition or runtime wiring with the original names. No waiver was found or granted. |
| Canonical-definition consumer | The repository-wide Go search finds `queuedefinition` imported only by `proofs/localstack-sqs/queue_definitions_proof.go` and its test. `queueDefinitionTargets()` iterates `Definitions()` and requires exactly three definitions; it now provisions the Red Team name/tag in the disposable fixture. Its inventory assertions also derive expected names from the same definitions. `scripts/check-m1-schemas.mjs` tests the definition package, but doesn't connect it to production consumers. Restoring this canonical original entry would change the local proof, not redirect the production worker by itself. |
| A stale negative fixture | `proofs/localstack-sqs/queue_definitions_proof_test.go:126-163`, `TestRunQueueDefinitionsProofReconcilesOnlyAmbiguousPolicyMutation`, still injects `setModes` for `agentsec-tests-dlq`. Current targets use the Red Team DLQ, so those injections miss their target. The applied cases explicitly expect one call under the old name; the definitive/ambiguous-unapplied cases expect an error from the missed injection. Source predicts broken controls/failures here, but I did not run the test. Reconcile the intended original proof boundary before changing these literals merely to make a test pass. |
| Shipped Red Team queue authority | `services/platform/agentsec-worker/runtime_config.go:439-440,507` restricts both outbox and worker to `agentsec-red-team-tests`; `red_team_production.go:32` passes that exact expected queue name into `discovery_queue.go`. `outbox_production.go` selects `outboxQueueAuthority`, then constructs the SQS publisher and checks its queue ARN/redrive. `deploy/production/release-contract.mjs:487` rejects other Red Team queue URLs. Changing only Terraform or the release input to the original name would leave these validators rejecting it. |
| IAM and Helm | `deploy/staging/main.tf` Red Team statements at 1459-1475 bind sends/receives and KMS context to `work["red-team-tests"]`, with the separate Red Team key. `outputs.tf:162` exports that URL; `product/templates/red-team.yaml:117` passes it to both modes through `ZASP_RED_TEAM_QUEUE_URL`. `deploy/production/release-fixture.mjs:68`, release tests, and the current mocked queue inventory pin it too. Do not rename/delete it or collapse its key/roles into the original staging queue. |
| Actual message consumer | Production Red Team doesn't read `queuedefinition.KindTests` or either schema tag. `apiserver/red_team_execution_repository.go:21` retains the DB outbox topic `test-jobs`; `red_team_outbox_runtime.go` validates that topic and creates a `jobqueue.Job` with `Kind: "red-team"`, run ID as `JobID`, scoped payload and authority digest. `jobqueue/queue.go` and `jobqueue/sqsdriver/publish.go` use a version-1 envelope with `job_id` (not the definition's top-level `test_run_id`). `red_team_execution_runtime.go` verifies the run, definition and input digest before work. A queue/tag rename cannot establish wire compatibility with the original seven-field schema. |

Named regression boundaries to preserve are
`TestProductionQueueBindsExactRedTeamQueueAuthority` in `discovery_queue_test.go`,
`TestRedTeamModesRequireSeparateExactQueueDatabaseAndRunnerAuthority` in
`runtime_config_test.go`, and `TestComposeRedTeamRuntimesBindSeparateV25Authorities`
in `production_runtime_test.go`, plus the canonical-definition and disposable
proof tests above. These names map the work; they are not new passing results.

No current production publisher/consumer explicitly targets `agentsec-tests`
or checks `agentsec.tests.v1` in the searched source. The old literals are in
requirements, documentation and the stale proof controls. Keep the original
acceptance open. The safe source decision is to separate preservation of the
original staging/proof contract from the already separate Red Team runtime,
then specify which bounded product workflow will exercise the original queue
and exact schema. If migration or translation is chosen, it needs explicit
message, retry, DLQ, IAM and rollback evidence; don't infer it from the shared
kind string or matching visibility timeout.

Keep B04 unshipped until the original evidence gates are met.

### Root diagnostic execution after the read-only audit

Root subsequently ran only the existing hermetic
`TestRunQueueDefinitionsProofReconcilesOnlyAmbiguousPolicyMutation` to check the
predicted regression. The normal Go1.25.6/offline command exited1 before tests
because this proof module's AWS versions lag its replaced platform module.
`go mod tidy -diff` identified the three version changes without writing files.

Root then copied the existing go.mod/go.sum with apply_patch into the fresh
`/tmp/zasp-queue-diagnostic.xLcrv0` directory and ran from proofs/localstack-sqs:

```text
env GOTOOLCHAIN=local GOPROXY=off /opt/homebrew/bin/go test -mod=mod -modfile=/tmp/zasp-queue-diagnostic.xLcrv0/go.mod -count=1 -run '^TestRunQueueDefinitionsProofReconcilesOnlyAmbiguousPolicyMutation$' .
```

Owned session23272 terminated exit1. All four named subcases failed:
ambiguous-applied and panic-applied observed zero set attempts at the original
DLQ; definitive and ambiguous-unapplied returned a successful result instead
of the expected error. Raw output is retained at
`/tmp/zasp-queue-diagnostic.xLcrv0/focused-red.log`.
Only the temporary modfile dependencies were reconciled; repository module
files and product code are unchanged. No provider, Docker or Kubernetes calls
ran. This confirms a hermetic control regression, not live queue behavior.
