# B05 local runtime original-task audit

Status: source-only audit recorded September 15, 2026. All thirteen IDs remain
component-only. No acceptance or availability change.

Read-only requirements: audit the thirteen B05 original IDs in
implementation_batches_v1.5.tsv against their verbatim source-plan sections:
M0-06/07/08/10, M1-01b, M1-30a/30b/30c/30d/30/31/34/36e.
Name current source, actual named tests, retained execution evidence and exact
missing acceptance per original ID. Distinguish source assertions, injected
clients, emulators, real local cluster/provider operations and live production.
Historical summaries alone are not a current successful run.

Inspect repository files only. Do not execute tests, Docker, Kubernetes,
network requests, provider processes, credential searches or Git writes.
Do not inspect ambient kubeconfigs, cloud state, user files or retained failed
fixture directories. Existing resource ownership is not established by a PID
or pathname in an old report. No deletion, cleanup or restart is authorized.

Only this report may be edited with apply_patch. No product changes, subagents
or availability edits. Preserve all thirteen component-only classifications.
Identify a dependency-compatible grouped implementation sequence and the exact
safe verification setup needed; do not replace original Kubernetes/Cartography/
tenant-separation acceptance with an easier local function test. Preserve the
active export UI and accepted backend/harness work.

Write a compact per-ID findings table, evidence limitations and proposed file
ownership below. Root owns implementation decisions, review and publication.

## Findings

The code exists. Fresh acceptance is a separate question.

I checked the thirteen rows at lines 46-58 of
`docs/internal/implementation_batches_v1.5.tsv` against the original sections
in `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`
(called **Plan** below), then inspected the named source and tests. Test names
below identify available checks; none ran during this audit. Every original
section also has a <=15-minute timebox.

**History** below means the dated row in
`docs/internal/implementation_status_v1.5.md`, not a fresh execution receipt.
Those August rows and the README retain success descriptions. I did not find
a B05 current-checkout run log or machine-readable acceptance receipt in the
inspected repository evidence files. Historical descriptions, expected success
strings, and tests that assert documentation says "Complete" cannot establish
current acceptance.

| ID / original clause | Current source and actual named checks | Retained evidence, exact gap, and scope limit |
| --- | --- | --- |
| **M0-06**, Plan:704. Create LocalStack queue/DLQ; assert batched-message round trip and redrive attributes. Depends on M0-05. | `proofs/localstack-sqs/{proof.go,sdk.go,main.go,run.mjs}` implement queue ownership, exact redrive policies, a two-event scoped envelope, receive/delete, and queue absence. `proof_test.go`: `TestRunProofRoundTripsOneScopedBatchAndCleansInOrder`, `TestRunProofRejectsPolicyAndMessageMismatchesWithCleanup`, `TestDecodeExactJSONRejectsCaseVariantSchemaKeys`; `sdk_test.go`: `TestSDKClientUsesOnlyExplicitLocalIdentity`. | History Aug 13, line 3108, describes a LocalStack SDK pass. Behavioral tests inject a queue client; SDK checks don't establish a current LocalStack round trip. No missing original operation found in inspected source. Missing acceptance: fresh exact queue/DLQ redrive and two-event round-trip results from a newly authorized disposable LocalStack target. Safety setup gap: the root command uses `node --env-file=.env`, and `run.mjs` accepts an existing endpoint without owning the server lifecycle. Do not run that root command or adopt an ambient endpoint. |
| **M0-07**, Plan:710. Exercise S3/KMS/Secrets via AWS SDK; encrypted object and secret round trip. Depends on M0-06. | `proofs/localstack-storage/{proof.go,sdk.go,run.mjs}` implement owned LocalStack, KMS encrypt/decrypt, SSE-KMS S3 content, encrypted secret, and exact cleanup. `proof_test.go`: `TestRunProofCompletesEncryptedStorageLifecycleAndCleanup`, `TestRunProofRejectsWrongEncryptionIdentityAndContent`, `TestRunProofReprovesOwnershipBeforeEveryDestructiveCall`; `sdk_test.go`: `TestSDKUsesPathStyleAndRefusesRedirectsWithoutAmbientConfiguration`. | History Aug 13, line 3109, reports encrypted round trips and absence. Tests use injected storage/provider behavior or controlled HTTP; runner tests emulate Docker responses. No missing original operation found. Acceptance still needs current LocalStack SDK encryption/content/secret results and owned-resource absence. LocalStack encryption behavior isn't AWS KMS policy or tenant authorization proof. Preserve accepted audit-export storage/harness work. |
| **M0-08**, Plan:716. Index one session event in disposable OpenSearch; session/environment query returns it. Depends on M0-07. | `proofs/opensearch-event/{proof.go,http_store.go,run.mjs}` provide a disposable pinned OpenSearch target, strict scoped event mapping, exact result checks and index cleanup. `proof_test.go`: `TestRunProofIndexesOneScopedEventAndRejectsTheOtherOrganization`, `TestRunProofRejectsPrefixCollisionsAndCrossOrganizationLeakage`; `http_store_test.go`: `TestHTTPBackendUsesTheStrictScopedOpenSearchRESTContract`. | History Aug 13, line 3110, reports one A hit and zero B hits. The named orchestration test uses an in-memory backend; REST tests use controlled HTTP. No missing original index/query operation found. Missing fresh acceptance: real disposable OpenSearch session/environment results, preserving the A/B negative check and exact absence. This is separate OpenSearch, not evidence from the S3-only cluster or the AWS OpenSearch Service control-plane client. |
| **M0-10**, Plan:728. Run two Cartography AWS/GitHub fixtures, inspect graph output, retain source IDs/relationships, separate Organizations, no collisions or customer-visible Cartography labels. Depends on M0-09. | `proofs/cartography-scope/{run.mjs,fixture_runner.py,normalizer.mjs,fixtures/org-a.json,fixtures/org-b.json}` run two Cartography/Neo4j fixture pairs; the Python bridge imports actual Cartography schemas/load APIs and queries actual graph output. `normalizer.test.mjs`: `scopes deliberately overlapping raw identities to distinct canonical IDs`, `customer-visible kinds do not expose implementation or provider names`, `merge rejects cross-Organization endpoints`; `fixture_runner_test.py`: `test_load_fixture_invokes_only_the_four_exact_schema_loads`; `run.test.mjs`: `orchestrates two isolated graphs, normalizes exact fixtures, and cleans in reverse dependency order`. | History Aug 14, line 3111, describes eight normalized nodes/four relationships and two fixture runs under a historical delivery waiver. Source covers the fixture clauses; Python unit tests inject `FakeAPI`, and runner tests inject runtime results. Missing fresh acceptance: both actual pinned Cartography schema loads and inspected graph outputs, source-ID collision separation, safe product labels, exact cleanup. **M0-09 is an original dependency, not closed by the fixture test or historical waiver document.** This audit does not grant a waiver, inspect credentials, or infer present cloud access. Root must resolve dependency evidence separately. No AWS/GitHub authorization-parity or shared production graph isolation claim. |
| **M1-01b**, Plan:862. Python security-worker and Node redteam-worker skeletons; each starts a no-op health command. Depends on M1-01a. | `workers/security-python/{pyproject.toml,security_worker/__main__.py}` and `workers/redteam-node/{package.json,health.mjs}` retain exact health entrypoints. Python `tests/test_health.py`: `test_exact_health_output`, `test_invalid_arguments_fail_without_output`, `test_writer_failure_is_contained_by_main`; Node `health.test.mjs`: `writes the exact health result`, `contains writer failure at the process boundary`. | History Aug 15, line 3131, reports both commands and focused tests. No missing original skeleton/health clause found. Current Python command also has later adapter modes; do not remove them to recreate a skeleton. Missing acceptance is a current isolated process launch of each exact health command with expected output/exit status. Function calls and source-string contracts alone don't prove installed entrypoints start. No worker-loop or provider acceptance required by this ID. |
| **M1-30a**, Plan:1072. Kubernetes manifests for four named product stubs; all four pods Ready in local Kubernetes. Depends on M1-29. | `deploy/local/{product-stubs.yaml,Dockerfile,manifests.mjs,run.mjs}` build the four Go commands and validate Deployment/ReplicaSet/Pod/Service/EndpointSlice identity through an owned kind lifecycle. `run.test.mjs`: `validates exactly four Ready product pods and four internal services`, `concrete lifecycle loads all images and proves the exact Ready Kubernetes state`; `manifests.test.mjs`: `defines the exact four real product commands and local images`. | History Aug 16, line 3075, reports real local Kubernetes readiness. Named tests provide crafted provider documents/injected commands, not a current cluster. No missing original manifest/readiness operation found. Missing acceptance: four current built images actually run and become Ready in a newly owned local Kubernetes cluster. Neither Go compilation nor health-handler function tests substitute for this clause. |
| **M1-30b**, Plan:1078. Neo4j service and persistent test volume; graph health reachable only inside cluster. Depends on M1-30a. | `deploy/local/{graph.yaml,graph-manifest.mjs,graph-run.mjs}` provide ClusterIP Neo4j, bound PV/PVC, internal health Job, marker persistence across replacement, and ownership checks. `graph-manifest.test.mjs`: `builds exactly one bound local persistent volume and claim`, `builds only a ClusterIP graph service and one fixed internal health job`; `graph-run.test.mjs`: `normalizes one exact Bound graph lineage with internal health evidence`, `polls delayed provider state and performs the persistence sequence once`. | History Aug 16, line 3074, reports internal health and persistence. Source covers the original service/storage clause. Missing current acceptance: bound storage, actual internal graph health and absence of external service/host exposure in the owned cluster. The PV uses a kind-node `hostPath` with `Retain`; it is not host-application storage or authority to touch an old path. ClusterIP/config checks are not a general network-isolation guarantee outside this fixture. |
| **M1-30c**, Plan:1084. Local OTel Collector with no-egress debug/test sink; test span reaches sink. Depends on M1-30b. | `deploy/local/{observability.yaml,observability-span.yaml,observability-manifest.mjs,observability-run.mjs}` configure only a file exporter and stage a span Job after readiness; runtime reads the sink and compares the exact span. `observability-manifest.test.mjs`: `pins the local-only collector pipeline and one-shot span job`, `parses only one bounded duplicate-safe exact sink record`; `observability-run.test.mjs`: `stages one span Job only after exact core readiness and reads one stable sink artifact`. | History Aug 17, line 3073, reports exact span/file-sink evidence. No missing original configured-sink operation found. Missing current acceptance: the actual Collector receives the span and writes the expected file in Kubernetes. `noEgress: true` is inferred from the allowed Collector configuration, not measured packet blocking; no NetworkPolicy enforcement is established here. Don't claim full cluster no-egress security from that field. |
| **M1-30d**, Plan:1090. LocalStack service and endpoint variables; test S3 call uses LocalStack endpoint. Depends on M1-30c. | `deploy/local/{aws-emulator.yaml,aws-emulator-s3.yaml,aws-emulator-manifest.mjs,aws-emulator-run.mjs}` define S3-only LocalStack, two endpoint variables and an internal `awslocal ... list-buckets` Job. `aws-emulator-manifest.test.mjs`: `pins the S3-only LocalStack server and internal endpoint contract`, `pins one staged S3 endpoint call with synthetic authority and fixed output`; `aws-emulator-run.test.mjs`: `stages exactly one S3 Job after retained LocalStack readiness`. | History Aug 17, line 3072, reports the exact live S3 overlay. No missing original S3/endpoint clause found. Missing current acceptance: actual ready LocalStack plus completed endpoint-bound S3 Job. This command only checks a zero-bucket list response; it doesn't run the product factory, encrypted storage, SQS, KMS, Secrets or OpenSearch. Those aren't extra requirements for M1-30d, and its pass cannot close their IDs. |
| **M1-30**, Plan:1096. One assembled local start target; starts without exposed vendor dashboards. Depends on M1-30d. | `package.json` maps `local:start` to `deploy/local/start.mjs`, which validates six manifests/22 resources and delegates to the existing AWS-emulator lifecycle. `start.test.mjs`: `exposes one immutable assembled target over the exact reviewed lifecycle`, `proves the exact 22-resource assembly has no external vendor-dashboard exposure`, `rejects every external service and host-namespace exposure`. | History Aug 17, line 3071, describes the joined live run and cleanup. No missing original assembly clause found. Missing acceptance: current assembled run with four product pods, graph, Collector and LocalStack healthy and no host/public dashboard exposure. The command is a disposable start/prove/cleanup lifecycle; it doesn't leave a developer environment running. The original task doesn't explicitly require persistence, so that difference alone isn't a source defect. |
| **M1-31**, Plan:1102. Local/CI-only endpoint override in product factory; test points five named clients at LocalStack. Depends on M1-30. | `services/platform/awsclient/factory.go` builds concrete SQS/S3/KMS/Secrets/OpenSearch Service clients, exact local endpoint or numeric-loopback CI endpoint, synthetic credentials and proxy-free bounded transport. `factory_test.go`: `TestNewConstructsAllLocalStackClients`, `TestFiveSDKClientsRouteOneSignedRequestToCIEndpoint`, `TestProductionPreservesOnlyExplicitAuthority`, `TestNewRejectsInvalidEndpointPairsAfterExactlyTwoReads`. | History Aug 17, line 3070, reports five SDK calls to a loopback capture server. Source covers construction and local/CI restriction. **Provider-target evidence gap:** the executable five-call test uses `httptest.NewServer`, not LocalStack; the exact cluster endpoint is checked as configuration. A literal five-client-at-LocalStack acceptance reading still needs a dedicated disposable five-service fixture. Routing-only evidence must stay labeled routing-only; the historical design selected that narrower proof. LocalStack S3-only M1-30d cannot fill this gap. OpenSearch here is AWS's Service control plane, not the M0-08 event index REST API. |
| **M1-34**, Plan:1120. Evidence/export/policy prefixes plus KMS config; builder cannot escape Organization/Workspace prefix. Depends on M1-33. | `services/platform/bucketlayout/layout.go` validates scope and typed IDs, builds fixed class paths, rejects unsafe segments and validates same-account/Region KMS key ARN. `layout_test.go`: `TestLayoutBuildsExactScopedPrefixesAndKeys`, `TestLayoutRejectsInvalidScopeClassReferenceAndCollisions`, `TestNewRejectsInvalidAccountRegionAndKMSIdentity`, `TestExportKeyUsesTheConfiguredLayoutContract`. | History Aug 18, line 3067, reports layout and race tests. No missing original key-builder/config clause found. A fresh focused pass is the acceptance needed for this ID; provider operations aren't required to prove a pure key builder. Prefix separation isn't an authorization check: a valid scope must still come from trusted caller authority. Preserve the later `ExportKey` and accepted export backend behavior. |
| **M1-36e**, Plan:1156. Run local Kubernetes/LocalStack smoke; required local dependencies healthy. Depends on M1-36d. | Existing `deploy/local/start.mjs` is the smoke, with no second wrapper. The Aug 18 smoke design binds `node --test deploy/local/start.test.mjs`, `npm run local:aws-emulator:test`, then `npm run local:start`. `app/quality/m1-local-infrastructure-smoke-contract.test.ts`: `binds the exact source, assembled target, live safety boundary, and successor` reads source/docs and script strings. | History Aug 18, line 3061, reports a 261-second run and absence checks. No missing smoke entrypoint found. **Acceptance is not a source assertion:** current owned-cluster Kubernetes and LocalStack health, fixed successful completion and exact cleanup remain unobserved here. The documentation contract also asserts historical completion text; that isn't dependency health. M1-36d evidence must be reconciled separately. No production availability claim. |

## What the evidence can't say

All thirteen classifications stay **component-only**. This audit made no test,
provider, Docker, Kubernetes, network, credential, ambient-state or Git call.
Only this report changed.

I read the permitted writing-style file at
`/Users/manishmaheshwari/.codex/writing-style.md`; it wasn't in either checkout.
Old retained fixture directories were not inspected. A historical PID, file
path or success sentence supplies no present ownership or cleanup authority.

The material gaps are the fresh execution receipts for actual local-provider
clauses, M1-31's five-client LocalStack evidence versus its capture-server test,
and dependency reconciliation. I did not find an absent original operation in
the other inspected implementations. Don't invent product changes merely
because this audit was forbidden to rerun their tests.

## Order and ownership for a later batch

First, root reconciles original prerequisites outside B05: M0-05 before
M0-06; M0-09 before M0-10; M1-01a before M1-01b; M1-29 before M1-30a;
M1-33 before M1-34; M1-36d before M1-36e. M1-33 itself follows M1-32,
which follows M1-31. A historical exception is not a new acceptance decision.

Then use these small groups, in dependency order:

1. **M0-06 -> M0-07 -> M0-08.** A proof owner handles only these proof
   directories if a newly reviewed run setup needs code changes. The M0-06
   setup needs an owned disposable SQS target without `.env` loading. Keep
   existing queue/storage proof semantics, tenant-negative checks and cleanup.
2. M0-10 can get its own Cartography proof owner after its dependency decision.
   Only `proofs/cartography-scope/` is in that file set. Run the actual pinned
   graph loaders; a normalizer-only pass doesn't satisfy the original task.
3. **Local assembly.** One owner for `deploy/local/` preserves the inheritance
   chain M1-30a -> M1-30b -> M1-30c -> M1-30d -> M1-30. The joined runtime
   already checks each layer. One retained joined run can supply per-ID
   observations without creating six new lifecycle implementations.
4. `workers/security-python/tests/test_health.py` and
   `workers/redteam-node/health.test.mjs` are the small M1-01b verification set;
   entrypoints stay unchanged unless a witnessed failure needs repair.
   M1-31 ownership is `services/platform/awsclient/`, with a separately scoped
   disposable-provider fixture if root selects literal five-service evidence.
   Do not expand the S3-only assembly silently.
5. After M1-33, verify `services/platform/bucketlayout/` for M1-34. M1-36e is
   the final joined smoke after M1-36d, using the same local start entrypoint.

Root owns shared `package.json`, README, status/availability tables, evidence
publication, and integration decisions. Neither this auditor nor a local
proof owner should edit staging files, the active export UI, or accepted
audit-export backend/harness files. Any needed overlap goes back to root first.

## Safe verification setup, not permission to run it

The next executor needs explicit approval for new disposable resources and an
identified isolated Docker engine/test host with no user workloads. No ambient
cluster, cloud account, shared LocalStack instance or old fixture may be adopted.
If that isolation cannot be established without broader inspection, stop and
ask root for a supplied dedicated fixture. Don't scan credentials or kubeconfig.

Use the repository-pinned Node 22.23.1, npm 10.9.8, Python 3.13 and the Go/image
pins from the checked-in manifests. Supply an empty, task-owned HOME and Docker
config, explicit absolute tool PATH, fixed locale, fresh temporary root, and
offline-approved dependency/image caches. Strip cloud, proxy, Docker-context,
kubeconfig and credential variables. A later image download needs its own
approved network scope. The owned runtime generates its own kubeconfig; never
point `kubectl` at an ambient context. The old smoke design's proposed ambient
fingerprint audit is outside this assignment and cannot be copied blindly.

For M0-06, invoke the proof with only a freshly assigned owned loopback endpoint
and synthetic credentials through an approved sanitized process boundary;
do not use `npm run proof:localstack:sqs:run`, which reads `.env`. Its queue
prefix audit doesn't prove ownership of the enclosing server. M0-07 and M0-08
already have disposable runners, and M0-10 has two pinned Cartography/Neo4j
pairs. Those still need the same new-fixture authorization and retained identity.

Run the named focused tests before provider execution. For the cluster group,
the existing verification commands are the start test, AWS-emulator test suite,
then local start; retain intermediate pod/graph/span/S3 observations as well as
the fixed final line:

```text
Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.
```

The outer executor must record exit status, exact checkout identity, command,
runtime/image versions, start/end times, scoped checks, and resource-ownership
receipts. Keep payloads synthetic. Preserve A/B source separation in Cartography
and the OpenSearch negative query; do not replace them with a single-tenant
happy path. M1-31 needs a clear label for capture-server routing versus actual
LocalStack calls. Pure M1-34 tests need no provider fixture.

Finally, prove absence of exactly the resources created by that run using
fresh retained full identity, not names alone. Cleanup needs its own bounded
budget and must not be cut short to meet the original 15-minute task timebox.
Record failure or uncertain cleanup honestly, preserve recovery evidence, and
stop without deleting or restarting anything outside the newly owned fixture.
