# Schema58 export deployment batch

In progress, not accepted or production-enabled. All728 original tasks remain.
This connected batch covers the existing migration CLI, release rendering,
explicit workflow opt-in and same-namespace worker health access. Independent
review follows the connected batch, not every small edit.

## CLI checkpoint

The renderer rejected58, and tracing its migration command found the earlier
CLI gap: up-to-58 was absent. The existing Runner already implements exact58
upgrade/downgrade with installed release validation. The CLI now exposes
up-to-58 and down-from-58, preserving default up target49. Forward58 passes
through57, registers principals and checks zasp_sa_export_readiness with compiled
checksum/fingerprint. Rollback is only from58 and delegates to the existing
retained-history/ACL guarded Runner. This does not advertise workflow readiness.

Tests exercise real command routing with the existing controlled runner/query
boundaries. They check ordered57/58 calls, retry, explicit rollback, wrong source,
old/default/unsupported command rejection, migration errors and each principal
or readiness refusal. They do not execute PostgreSQL migration bodies.

- RED session73424: both new groups fail with invalid release migration command;
  no58 dispatch or registration occurs. Package0.790s, exit1.
- GREEN session30150: both new groups pass, package0.875s, exit0.
- Affected existing run exposed outdated unsupported57 assertions in two tests
  and an unsupported58 assertion in the Attack Lab test. Existing57 is supported;
  unsupported checks now use59. Added57 exact readiness coverage. The existing
  PostgreSQL deployment test's future-version rejection changed58 to59, but that
  PostgreSQL test has not been rerun at this checkpoint.
- Seven affected native race groups session83259 pass, package2.066s, exit0.
  git diff --check on agentsec-migrate passes.

Run from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-migrate -run '^Test(SecurityAgentExports(ExplicitReleaseCommands|ForwardReadiness)|AttackLabExplicitReleaseCommands|ExistingTests(ExplicitReleaseCommands|ReleaseBoundaries)|RegisterForwardReleaseChecksExactSchemaAfterPrincipals|RegisterForwardReleaseStopsOnFailedAuthorityOrReadiness)$' -count=1
```

Source SHA256:

```text
6e0938bd5483bae29c0e096ccac9d33835e3810ecbccc6c16c932077c212acbf services/platform/agentsec-migrate/main.go
f13962437776547cd566e07d4bc3f12454b23a1da07ba89c6f45725bef20ca99 services/platform/agentsec-migrate/security_agent_exports_command_test.go
e779776dcdf0489726f4ec3e33098019de0ae3c8738465bb897fe1c4e1915a33 services/platform/agentsec-migrate/attack_lab_command_test.go
b7506066686a206eb888b69752725e4035d6421f3ee20b40926d01c9bf915a0e services/platform/agentsec-migrate/existing_tests_command_test.go
759fa4c3c9288663e0e441faf2f0079cd0bf9813c6b08776c93ef8a625e393ef services/platform/agentsec-migrate/release_readiness_test.go
0860fe2a49efdecb9e32550626e4e90804cf8e0708f00a97d1f5002dfdc5ff88 services/platform/agentsec-migrate/compliance_deployment_postgres_test.go
```

## Next connected checks

- Actual registered CLI58 chain, coexistence registrations and pinned readiness;
  preserve existing57 proof and explicit downgrade/history checks.
- Renderer session-search/audit/compliance/test/Attack Lab version constraints
  and matching Helm helpers now support58 in the controlled rendering checkpoint
  below. Independent batch review and real registered CLI58 checks remain open.
- Explicit export workflow opt-in and narrow API-to-four-worker health policies
  now have the controlled rendering checkpoint below; actual runtime-loader and
  connected workflow proof remain open.
- Batched rendered mutation tests, actual loader checks and independent review.
- UI build/regression and external publication gates still apply before any push.

No deployment, provider request, commit or push occurred in this checkpoint.

## Renderer coexistence checkpoint

The existing closed version lists and Helm gates now admit58 in both precision
phases. Attack Lab migration selection uses the requested version, its readiness
flag/network remains available at57/58, and its migration-command boundary
requires a complete57/58 token. Default49 and unsupported59 remain unchanged.
Export workflow opt-in is still absent: rendering58 does not enable it.

New export-schema58-rollout.test.mjs renders all16 combinations of optional
audit/test/compliance/Attack Lab configuration in both phases. It checks the
single58 Job, ordered explicit migration/registration calls, API schema58,
absence of export workflow opt-in, and refusal of a mutated57 migration command.
Incompatible phases and unknown59 are refused. These are real Helm-rendered
artifacts with fixture authority values, not deployment or provider evidence.

RED command below on only export-schema58-rollout.test.mjs: all32 supported
cases failed at the release input gate, exit1 (33 failed including parent,
one negative group passed). GREEN session49797 exit0. Affected grouped run
session1764:177 passed,0 failed,13.330s, exit0. Existing future-version tests
now use59; session-search tests had stale57 rejection expectations and now also
use59. Their existing57 positive coverage remains in the affected batch.

```sh
PATH=/opt/homebrew/bin:$PATH /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-reporter=spec deploy/production/export-schema58-rollout.test.mjs deploy/production/session-search-rollout.test.mjs deploy/production/compliance-export-rollout.test.mjs deploy/production/compliance-export-helm.test.mjs deploy/production/audit-export-rollout.test.mjs deploy/production/test-reconciler-rollout.test.mjs deploy/production/attack-lab-reconciler-rollout.test.mjs deploy/production/attack-lab-workflow-readiness.test.mjs
```

git diff --check on deploy/production and the Helm templates exits0. Root owns
renderer/network work; the existing database implementer owns the actual CLI58
PostgreSQL extension and reached Go/migration corrections. Their source paths
do not overlap. The database implementer has not reported acceptance yet.

Renderer checkpoint SHA256, before the remaining network/opt-in work:

```text
b8a9bc8fa2335ff02386d8da61fce9db4e201d5545e7f0a8e190c0c1b4e6cd71 deploy/production/export-schema58-rollout.test.mjs
cc94e7a152d8cd4d0600ca53c020d537e2346a9b6c9a00c87a2edf237f17cad5 deploy/production/session-search-rollout.mjs
27f5d05ff475aa3e36a471392f30522a89ae820c462ceae7cbd792c9d9e35838 deploy/production/audit-export-rollout.mjs
26e4a1f43f94c32da4fa105de304c4c2697ee1e6ad6abf063012f2a376500c6a deploy/production/test-reconciler-rollout.mjs
7646713d739b5a3098a7d1e59ce5e3751881414cbadd915b250ff0c08c0eeb87 deploy/production/compliance-export-rollout.mjs
cd75b0f8b422a7e7c93b4e3d801e135ac0fe6193aceff058488ffd09bea9bf78 deploy/production/attack-lab-reconciler-rollout.mjs
246c12f0abb4f7e47aba5d36dcb80e13c091f316c996fff392138679dbbfbf2a deploy/staging/product/templates/_session-search.tpl
07b9c766661801c6a3e2e026e7328e4a0a0cf588050943bd9655c7eade191697 deploy/staging/product/templates/_compliance-exports.tpl
1fd9a5c2014e05c48f486d11d1dab91b961fe29dd8a474d33668f157e2284cf6 deploy/staging/product/templates/audit-exports.yaml
55d1534ee464aab82113720e4dbb4cf3d2e867d4704ee797148d365edcb36aac deploy/staging/product/templates/test-reconciler.yaml
99df42b5daace4c24fb3623ffc953816ac6c8dc887993466d9ebacc7defc8374 deploy/staging/product/templates/attack-lab-reconciler.yaml
c1a34cf63223c7a294418f07ed24bd2484c0080adaa97d5342f017f6db44a59b deploy/staging/product/templates/attack-lab-workflow-network.yaml
fac74c53613efc720dc25da10cd89679699fa54a051732f21f2df262bfb1a65d deploy/staging/product/templates/workloads.yaml
```

## Explicit opt-in and network checkpoint

The release renderer accepts evidenceExportWorkflow only as literal true or
omitted. True requires schema58 and normalized compliance retrieval config.
Helm gets a closed evidenceExportWorkflow.enabled boolean map, default false.
Enabled renders ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW=enabled on the API
and two same-namespace policies allowing only API-to-four-worker TCP8081 access.
The workers are agentsec-security-agent, agentsec-security-agent-action,
zasp-compliance-export-worker and zasp-compliance-cleanup-worker.

The new export-workflow-readiness validator checks exact policies, flag, services
and workload internal ports. Compliance's additive-policy validator trusts these
two policies only after that check, retaining its rejection of other policies
selecting export workers. Existing monitoring access and provider/DB egress are
unchanged. The flag is refused outside the API. Both Attack Lab-enabled and
disabled configurations are tested. This does not grant SQL workflow capability.

RED: export-workflow-readiness.test.mjs failed both groups at the unknown-option
boundary, exit1. GREEN session8048:28 checks pass,1.630s. Direct Helm coverage
then checked the independent template boundary: closed boolean map, exact58,
control-plane profile, required compliance, no resources while disabled.
Grouped session76526:206 tests pass,0 skipped/failed,14.986s, exit0. Same command
as the renderer batch above with deploy/production/export-workflow-readiness.test.mjs
added. git diff --check on deploy/production and deploy/staging/product passes.

Changed since the renderer hash checkpoint: release-contract.mjs,
compliance-export-rollout.mjs, compliance-export-network.mjs, values.yaml and
workloads.yaml; added export-workflow-readiness.mjs, its test and
templates/export-workflow-network.yaml. The earlier hashes are historical,
not an assertion that these subsequently changed files retain those bytes.

Actual Go loader consumption remains to be added using the existing rendered
fixture pattern in attack-lab-reconciler-runtime.test.mjs and
agentsec-api/attack_lab_deployment_config_test.go. The database implementer reached
real CLI58 errors in Runner.Version and subsequent Attack Lab reconciler
registration; it owns their Go-only corrections and registered rechecks. SQL/pin
is unchanged so far. Independent combined review and production proof are open.

### Reached additive-policy correction and Go loader

The first opt-in tests covered an added broad policy selecting a compliance
worker; compliance's existing policy validator caught it. A new RED selected
agentsec-security-agent instead, and both Attack Lab modes accepted that added
Ingress policy. This was a real coverage and behavior gap, not fixture setup.

The export workflow validator now evaluates Kubernetes label selectors for every
nonempty Ingress policy selecting any of the four workers. It accepts only the
two exact workflow policies, exact task4 monitoring policy, and policy names that
the compliance and Attack Lab validators independently check in the same release
validation. The added agent policy is refused in both modes. Default-deny and
egress-only database/provider policies remain permitted. Focused final workflow
test:32 checks pass, exit0. The nine-file deployment group with this correction
also exits0.

compliance-export-runtime.test.mjs now renders schema58 with compliance and the
workflow opt-in, then gives the untouched manifest to the actual Go API loader.
The Go test checks enabled/disabled/compliance-only/workflow modes, duplicate and
valueFrom refusal, exact compliance authority, partial-config refusal and the
closed workflow value. Synthetic values are limited to CSI secret contents and
metadata.name. Final race run: Node1 pass, Go API2.047s, worker2.417s, no skips or
failures, total7.379s. This is rendered-config/runtime-loader integration, not a
deployed API or live worker probe.

Final opt-in boundary SHA256 before independent review:

```text
a69d3ce16fd699f2399ce8defcf7fd8c9234b739b5d493d21cec39d39caf6157 deploy/production/export-workflow-readiness.mjs
f943b831aec94a982e9eea88502a1f4d7d57abd61bbfb412a725959b14f81158 deploy/production/export-workflow-readiness.test.mjs
b8a9bc8fa2335ff02386d8da61fce9db4e201d5545e7f0a8e190c0c1b4e6cd71 deploy/production/export-schema58-rollout.test.mjs
2e6bfa64a035e871caa1227e954932cc3ab8369541b326ca59534cde45dfe9d7 deploy/production/release-contract.mjs
ff089640311780202de92421e546917aae39890c9118de6a3aa029d8127d31aa deploy/production/compliance-export-rollout.mjs
aa1359326e6033e252f74423e6bafd400d76e8a746ff82b804dd8e4316bec494 deploy/production/compliance-export-network.mjs
4cbb5a088db382163f4e076a105e03275fe7351a407d106504cd9c495265cf99 deploy/production/compliance-export-runtime.test.mjs
79f7a3b84759e6c381bad3dc198c85d23a4c42f5734b8268084f111271d3abc0 deploy/staging/product/templates/export-workflow-network.yaml
844240fe8c7e967a81d9ba569273353467ff4c2475ba9f2de03a7bf168003d2e deploy/staging/product/templates/workloads.yaml
9e40988af19b81e12fd9e84e813a6aebdd730c5337a62bbc0332add55ee273bb deploy/staging/product/values.yaml
b4e7bf4a1db6f5d8e50813fddba3570480562716bfbf8c81b901e7102b8e0db4 services/platform/agentsec-api/compliance_deployment_config_test.go
```

git diff --check on the deployment and touched Go test paths exits0. Actual
registered CLI58 GREEN and its final native batch/report are still owned by the
database implementer; do not infer acceptance until its frozen report arrives.

## Registered CLI58 checkpoint

The frozen [CLI58 report](database/cli58-report.md) records actual offline
PostgreSQL execution. The first RED applied58 but Runner.Version rejected the
post-upgrade state because it recognized at most57. After that Go correction,
the next RED reached Attack Lab operational registration, whose historical
exact57 reader rejected the current58 release. The final implementation keeps
upgrade/downgrade readers exact57 while the operational registration path accepts
only exact57/58 and checks current compiled readiness before and after.

Actual CLI GREEN passes in40.00s: existing56/57 checks, upgrade/retry58,
audit/compliance/Attack Lab coexistence registration, exact58/57/56 readiness,
default/old/59/wrong rollback refusal, both58 drift refusals, empty58 rollback to
exact57 and re-upgrade, and retained-history rollback denial. The corrected
10-group native race batch passes migrations6.323s and agentsec-migrate2.054s.
SQL and fingerprint0d5ce2f2b6a6252ee8bc5e675b2776a5c23c03fb50754f7c46345f8fbae906f3
are unchanged. Root rechecked report/patch/source hashes and the reverse patch.

This closes the local CLI and rendered-runtime deployment component evidence.
Independent combined review is in progress. It still is not a Kubernetes deploy,
live private-service health proof, provider acceptance or production enablement.

## Review fix round: controller-added labels and additive ingress

The independent review found that the earlier `selected` helper evaluated only
fabricated name/part-of labels. An added same-namespace NetworkPolicy with
`podSelector.matchExpressions: [{key: "pod-template-hash", operator: "Exists"}]`,
`policyTypes: ["Ingress"]` and `ingress: [{}]` was therefore accepted even though
it selects Deployment-created protected pods. The compliance secondary selector
check did not reject this mutation either. The partial helper and existing
known-name additive-agent regression were present on entry and were preserved or
corrected in place; no unrelated dirty work was replaced.

The corrected helper conservatively asks whether a selector may select each of
the four protected workers. Only the worker-name identity label, which this
validator pins on each Deployment, proves disjointness. Other labels, including
controller-added labels and unpinned part-of values, remain possibly satisfiable.
Every selector requirement is validated before any disjointness result, so a
fixed-name contradiction cannot hide a malformed later requirement. Validation
closes unknown fields, null/object/array shapes, label keys/values, operator
names, and the required/forbidden expression-value cardinalities. Unknown-label
contradictions are deliberately not used as proof: this can conservatively
reject extra policies and does not attempt general selector satisfiability.

The exact workflow policies, task4 monitoring policy, independently pinned
compliance dependency policies and Attack Lab readiness policy remain trusted
as before. Default-deny and existing egress-only policies remain unchanged.
No changes were made to compliance-export-network.mjs or the Helm templates.

TDD evidence, all from the scoped worktree:

- Initial exact mutation RED (tool chunk bb9af4): both Attack Lab-disabled and
  enabled cases fail with `Missing expected exception`; 30 pass, 3 fail
  including the parent group, exit1, 1.917s. This ran against the pre-fix partial
  helper, not a reconstructed version.
- Expanded selector RED (407aee): 37 pass, 14 fail including both parents,
  exit1, 1.994s. This also exposed unknown matchLabels/In and validation
  short-circuits. Positive fixed-identity disjointness cases passed.
- Focused final GREEN (c5efbf): 53 pass, 0 failed/skipped, exit0, 1.954s.
  Two supplemental trailing-newline malformed-selector cases were already
  rejected by the corrected grammar and passed on their first run.
- Final nine-file deployment group (session65254): 230 pass, 0 failed/skipped,
  exit0, 12.332s. This includes both Attack Lab modes and the predecessor
  coexistence/authority regressions.
- Actual rendered Go loader/race check (session5083): Node1 pass, no failures
  or skips, exit0, 33.896s; API2.011s, worker2.297s. The real API loader accepts
  enabled, disabled, compliance-only and workflow manifests; the real worker
  loader consumes both compliance workers. Go's offline/compiler environment
  remains enforced by go-test-runtime.mjs.

Commands (from the worktree root):

```sh
PATH=/opt/homebrew/bin:$PATH /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-reporter=spec deploy/production/export-workflow-readiness.test.mjs
PATH=/opt/homebrew/bin:$PATH /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-reporter=spec deploy/production/export-schema58-rollout.test.mjs deploy/production/session-search-rollout.test.mjs deploy/production/compliance-export-rollout.test.mjs deploy/production/compliance-export-helm.test.mjs deploy/production/audit-export-rollout.test.mjs deploy/production/test-reconciler-rollout.test.mjs deploy/production/attack-lab-reconciler-rollout.test.mjs deploy/production/attack-lab-workflow-readiness.test.mjs deploy/production/export-workflow-readiness.test.mjs
PATH=/opt/homebrew/bin:$PATH ZASP_GO_BIN=/opt/homebrew/bin/go GOCACHE=/private/tmp/zasp-budget-go-cache /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-reporter=spec deploy/production/compliance-export-runtime.test.mjs
```

Changed source SHA256:

```text
8838722d55d61edc7181d28274472bb376dee3dc475e0d642de60d6cec00c7c1 deploy/production/export-workflow-readiness.mjs
f8b1d39696e7292d6faceadee24a0946a10c935f6399d42a9cf5af3f38784f74 deploy/production/export-workflow-readiness.test.mjs
```

Only these two files and this appended report section were edited in this fix
round. Nothing was staged, committed, pushed or deployed. This is local rendered
release and runtime-loader evidence, not live Kubernetes/CNI enforcement,
private-service health, provider acceptance or production enablement. The fix
applies when the evidence-export workflow is enabled; other standalone policy
validators and disabled-workflow behavior were not expanded. Independent
re-review remains required.
