# Task2 implementation report

Status: DONE_WITH_CONCERNS, local implementation and final affected verification complete. Independent whole-feature acceptance remains with root. Task3 and live deployment gates are pending.

## Scope and frozen source

Task2 extends the accepted local Task1 admission foundation with the dedicated registered settlement runtime and real controller/database/proxy recovery proof. It changes neither published1..56 SQL/pins nor the existing controller/provider implementation. No catalog activation, UI publication, production rollout, staging commit or push occurred. The inherited dirty worktree was preserved.

`blobs.json` records57 task-owned paths, with exact inherited Git blob IDs, final blob IDs and `before/` bytes. A null before ID means the file did not exist when Task2 began, not missing capture. `scoped.patch` is the Task2 delta against those bytes, not a diff against HEAD that would absorb inherited changes. `capture.mjs` never stages files. Root-written review notes are separate evidence, outside this source delta.

- Base HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.
- Patch SHA256: `8c54010a1126138036b8c68abf07a9761300d471cc4ba9125fde1741972efb51`.
- Blob manifest SHA256: `68780934e800f16eedc50b345683a304f315de821294294d21c1dcdc6755f878`.
- Release57 checksum: `c3ad942230e9cf7b924005ba2f6cd71c5cb8b9ce12d7b12ea1e71291ccad59ce`.
- Release57 fingerprint: `9559c712af8fcbe177a7afc9501655f434bbddd53792af431da98dec37ace12d`.
- Release56 checksum remains `f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1`, fingerprint `8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced`.

`release-pins-final.log` records the compiled identities. Published SQL is absent from the scoped delta. The release-cycle test checks actual unused57 downgrade and restored56 readiness. Task1's original evidence and fix1 evidence were not rewritten.

## Implementation and requirements

| Requirement | Implementation and retained proof |
| --- | --- |
| Dedicated narrow database authority | Seven exact `zasp_sa_attack_lab_reconcile_*` interfaces, registered `zasp_security_agent_attack_lab_reconciler`, compiled57 checks, full tenant scope, no direct table/admission-core grant. Registered SQL fixture refuses private link reads and core execution. |
| Renewable bounded ownership | One link per iteration,60s token-hash lease, replacement version/generation on heartbeat,30s operation context and release backoff. Expired/stale/foreign ownership is refused. Scheduler rotates scopes, wraps, re-discovers on restart, cancels and joins before close. |
| Pending until authoritative cleanup | Snapshot joins the exact execution, attempt and cleanup checkpoint. Queued/running/cleanup lag remains pending. Missing/expired Job recovery retains attempt identity and reports Inconclusive after confirmed cleanup, never a new agent execution. |
| Stops retain obligations | Global, environment and action switches, terminal parent, deadline and budget stops invoke the guarded shared cancellation core. Registered API/operator stops are exercised. Parent terminal states do not remove the link or bypass cleanup. Concurrent registered cancellation and stale settlement are observed blocked, then released; stale proof fails. |
| Exact evidence | Read-only pinned artifact version; verify length, SHA256, reference/key, tenant/source/definition/target/execution/attempt/input/sandbox bindings. Strict recursive JSON rejects aliases, duplicates, unknown typed keys, missing fields, null primitives and invalid timestamps. Drift becomes Inconclusive. |
| Safe outcome table | Verified and not_reproduced both become Needs human with distinct bounded explanations, never generic `EvaluateRunOutcome` or remediation. Unknown/mismatch is Inconclusive. Confirmed cancellation plus cleanup is Cancelled. Actual Create403, zero Job and zero proxy execution becomes Failed. |
| Immutable settlement/replay | Preserve snapshot and exact proof bytes; proof digest covers canonical unsigned bytes. One identical retry after lost committed reply, no reread/recomputation. Original dispatch reply is separate from settlement receipt. Exact authorized replay works after lease expiry; changed proof/intent fails. Revoked replay is refused before and after an observed lock wait. |
| Existing controller recovery | Actual registered outbox/repository, production processor, production Kubernetes provider and HTTP API transport, signed runner and TLS proxy with real database resolver. Lost Create while leased permits no authorized egress; lost MarkRunning after commit recovers same UID without Create. No controller correction was needed. |
| Cloud/runtime isolation | Own role, DSN CSI, STS projected identity, versioned Attack Lab S3 reads and matching decrypt only. No SQS, provider/Kubernetes, object writes/deletes or unrelated DSNs. Actual config loader rejects ambient credential/other-worker authority. Readiness checks explicit role and registered SQL; object Get checks its own owner/key/encryption/digest. |
| Deployment/coexistence | Explicit57 in both precision phases, own worker/network/operations templates, exact startup/registration chain, bounded replicas/resources/HPA/PDB/shutdown and private health/metrics. Additive network and direct/group RBAC drift rejected. Default49 and56 controls preserved;58 rejected. |
| Actual command chain | Real CLI boots56, tests56 guards, explicitly boots57, demotes the registered migration session and runs audit/configuration/compliance/own registrations plus replay/drift tests. Existing-test reconciliation uses the baseline registered agent-worker capability; actual registered scope call confirms it still works at57. |

## RED, diagnosis and fixes

`authority-red.log` first reproduced the absent dedicated reconcile-scopes function. `strict-wire-red.log` then reproduced why the shared decoder was unsuitable: SQL timestamps are strings and embedded snapshots are raw JSON. A dedicated decoder resolved that contract without changing the shared Red Team decoder (`strict-wire-green.log`, then actual `connected-wire-green.log`).

`receipt-red.log` reproduced settlement overwriting the original dispatch replay result. A distinct `settlement_result` preserves admission replay, with registered repository replay, changed-intent refusal and exact settlement replay coverage. `action-stop-red.log` reproduced ignored action kill switch; cancellation now locks and checks all three controls before parent/link ownership.

`cli-connected-boundary-1.log` identified the exact first failing operation at57 as `register-compliance-workers`, after up-to57 and all audit operations passed. Only the Go operational registration reader now accepts compiled56 or57 and rechecks current readiness. Historical compliance Up/Down readers remain exact56, and published SQL is unchanged. `cli-connected-green-1.log` and `cli-connected-final.log` prove the actual chain.

Independent security review found a replay authority check before blocking locks but not immediately before receipt return. `settlement-edges-red-2.log` observed that wait, revoked the exact registration grant, released the lock, and reproduced unauthorized receipt return. The same run reproduced actual Create403 stuck pending: existing controller Claim sets started_at before Create, so null started_at was the wrong no-execution condition. New57 settlement now reauthorizes replay after waiting, and recognizes only terminal definite no-sandbox outcomes with no cleanup checkpoint. It does not convert ambiguous Create/GET404 into no-execution proof. `settlement-edges-green-1.log` passes both fixes and concurrent cancellation/settlement coverage.

The initial native RuntimeDispatch failure in `native-feature-race-1.log` was the new cloud clock supplying Local time to an existing UTC contract. The new mode supplies UTC (`native-feature-race-2.log`). No cloud operation was invoked.

Other retained failed logs are explicitly historical: constructor fixture identity mistakes, stale pin calibration, shell quoting, obsolete57-rejection assertions and an unset pinned promtool path. They are not controller defects or live-provider evidence. `deployment-regression-2.log` replaces the obsolete future boundary with58 and uses the already-cached pinned promtool.

## Verification commands and logs

Every `.log` below includes working directory, exact argv, complete raw process output and exit status. `run.mjs` uses unique log names and never overwrites prior evidence. Cross-compiles use local Go1.25.6 with `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache`; native `-run` patterns are exact anchored non-PostgreSQL names, inspected with `-list` first.

| Evidence | Result and scope |
| --- | --- |
| `connected-final-batch.log` | Exit0. Final57 admission, release cycle, dispatch receipt replay, settlement authority/races, and all14 connected runtime scenarios. |
| `settlement-edges-green-1.log` | Exit0. Cancellation-vs-stale-settlement, revoked-after-wait replay, exact expired replay, and actual definite Create403 outcome. |
| `cli-connected-final.log` | Exit0,23.93s. Actual56+57 migration and registered operational CLI chain, existing-test scope compatibility, replay, unsupported58/default/up56 denial and57 drift refusal. |
| `native-affected-race-final.log` | Exit0,23 top-level tests,7.099s. Dedicated runtime/decoder/evidence/config/scheduler and shared existing-test lifecycle/scheduler race checks. |
| `command-race-final.log` | Exit0,2 tests,3.416s. Exact CLI preflight/explicit-release command tests under race detector. |
| `rendered-runtime-1.log` | Exit0. Actual Go worker and registration loaders consume untouched rendered57 coexistence environment, substituting only synthetic DSN and metadata worker ID; default49 lacks the new authority. Both run with race detector. |
| `deployment-regression-2.log` | Exit0,201/201 tests,12.208s. Dedicated57, existing audit/test/compliance deployments, default49,56, future58 boundaries and closed network/RBAC/startup authority. |
| `alerts-green-1.log` | Exit0. Actual rendered new-worker Prometheus rules evaluated with pinned cached promtool3.14.0: healthy, failing/missing scrape/readiness, missing replica and recovery. |
| `release-pins-final.log` | Exit0. Compiled57 identities and preserved56 identities. |
| `source-integrity-final.log` | Exact SHA256 per source file, every final Git blob checked against the manifest, reverse scoped patch check and absence of published1..56 SQL in the delta. |
| `terraform-format-final.log` | Exit0. Format-only check on the two new declarations; no provider evaluation. |

Earlier full connected `connected-feature-batch-1.log` passed all13 original runtime scenarios but overall failed due to a fixture REVOKE issued under the wrong grantor. `settlement-grantor-green.log` fixes the fixture using the actual registration grantor and explicitly proves membership was removed. The final batch supersedes both for final SQL identity.

Owned PostgreSQL runs only in cached `postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba` containers with `--pull=never --network none`, no host ports and read-only source/binaries. Each test joins its PostgreSQL child. Containers use `--rm`; final owned-container check is empty. All launched processes are joined. No host PostgreSQL, provider/network/download or production-release command was run.

## Review and limitations

Superpowers TDD, systematic debugging, review reception and verification-before-completion governed the work. Focused RED/GREEN was followed by one affected feature batch, not full UI tests per edit. Independent review is documented by root in `security-review-1.md` and follow-up notes. The first review identified two material issues; both now have observed RED/GREEN. Reviewed Go files were subsequently gofmt-formatted, and the reviewer reread semantics. No byte-level retained pre-gofmt intermediate snapshot proves formatting-only equivalence; the Task2 start/end bytes are retained exactly.

Local proof is deliberately bounded. Kubernetes HTTP responses, queue/storage and canary forwarding are controlled fixtures; the production transport/parser, processor, registered SQL and signed proxy authority are real. This proves the connected local contract, not a live EKS/Fargate/AWS/provider deployment. Stop parent/deadline/budget state and lease expiry are owner-driven fixture setup; global/environment/action controls use real registered calls. Task3 must supply public API/UI approval/stop acceptance and user-visible detail projection. No production release claim is made.

Terraform is declaration/source coverage only. `terraform fmt` ran on the two new files. Provider plugins are absent; mock tests are checked in but explicitly NOT executed, and no init/plan/apply or provider download occurred. Secret resources declare metadata only; no credentials or secret versions were provisioned. Production activation still requires infrastructure/provider evaluation, approved identities and endpoint snapshots, deployment acceptance and Task3 publication gates.

## Fix1 appended after whole-task review

The rendered pod now sets `eks.amazonaws.com/skip-containers: worker`, preventing automatic IRSA environment injection from conflicting with the dedicated loader. The service-account role for CSI and explicit projected identity remain unchanged; ambient-authority rejection was not relaxed. The actual loader failed under locally modeled admission before the fix, then passed. The affected deployment/rendered-loader batch passed158/158, with both Go loaders under race detection. This is local admission-model coverage, not live EKS proof.

Full commands, RED/GREEN outputs, five-path before/after bytes and concerns are in `../task-2-fix1/report.md`. Fix patch SHA256 is `72b5a16c5703eb3062281bb0e7aabbc67543ec435285da02ffb6550199163329`; fix manifest SHA256 is `8e1728e87ef2d10954c94370c267fe57ebf87463d75c90752d76cd2147224f55`. Original Task2 patch/manifest hashes above remain unchanged. Database/runtime/CLI evidence is reused without rerunning unchanged suites. Task3 remains pending.
