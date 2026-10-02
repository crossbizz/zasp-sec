# Cloud handoff: unfinished full product goal

Status: **LOCAL CHECKPOINT PRESERVED, NOT TRANSFERRED**. Creation of an environment is not proof
that this checkpoint or execution moved. Do not tell the user to close the
laptop until a cloud task confirms the exact remote commit, required files and
runtime/access. Local implementation writers have quiesced. No source repair,
full-suite rerun, provider call or deployment is authorized by this handoff.

## Original goal, unchanged

Complete and verify all 728 original microtasks in
`docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`
without reducing scope. Follow
`docs/internal/2026-09-22-temporal-openfga-design.md` and
`docs/internal/2026-09-22-temporal-openfga-execution-plan.md`. Replace custom
durable orchestration with Temporal OSS and implement OpenFGA authorization
through production APIs/workers, retaining Stytch identity. Preserve
multi-tenancy, PostgreSQL tenant isolation, automatic discovery/sync, security,
approvals, budgets, audit evidence and every original milestone. Retire obsolete
code only after equivalent product behavior is verified.

Implement coherent connected API/worker/authorization/UI batches with grouped
Superpowers TDD and review. Test our integrations/logic/permission model, not
Temporal/OpenFGA internals. Avoid repeated unchanged expensive suites and blind
retries; prepare independent deployment/provider/browser prerequisites with
clear ownership. Keep the UI runnable and connected to real APIs at every
verified main push. Continue autonomously within authorized scope, preserving
other user changes. Push reviewed, verified product batches to main separately;
the WIP checkpoint below is NOT a verified production merge.

Maintain the authoritative `docs/internal/implementation_status_v1.5.md` and
728-row availability/owner TSVs, with implementation/verification links and
production-available/component-only/external distinctions. Historical ledger
counts523/144/61/0missing do not prove the current release is deployed. Latest
validator passed728rows. Completion requires EVERY original requirement,
retired superseded implementations, real deployed Stytch/provider flows and
cross-tenant denial, revocation, approvals, budgets, restart/recovery, audit and
operational readiness. Never treat local fixtures/component tests as live proof
or mark the goal complete while requirements or deployment gates remain.

## Checkpoint and local preservation

Source worktree: `codex/cached-runtime-ship-20260917`, HEAD
6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a. Current fetched main is
8484fba94176071026f711a11fe908a22a02913f, containing side batch9d5c52dd and
template fix7bcde207 (equivalent b8837297; never cherry-pick again).
Use dedicated branch `codex/cloud-handoff-20261001`; do not falsely label its
dirty-source checkpoint verified/production-ready or overwrite main with it.
Reconcile latest main normally in cloud before later verified product pushes.

An alternate index captures explicit source/evidence paths without
changing the active index, branch or dirty source. The root checkout and all
other local worktrees remain untouched. `cloud-handoff-checkpoint-files-2026-10-01.json`
records captured paths/hashes and local-only exclusions. Credentials/environment
files, VCS/cache internals and rebuildable native/compiler outputs are excluded;
none is deleted locally. Required frozen source/review/TDD/capture documents,
the SDD recovery ledgers and archived reference sources remain included. Scan
the exact candidate tree for secrets before any remote upload. No SSH keys,
Codex auth/config, .env/API keys, provider credentials or local Go/PG caches may
be uploaded. The OpenAI key stays local; configure cloud secrets through its
reviewed environment settings if needed, never Git or a task prompt.

Local preservation commit: `1079ff4750f20f0065cfd4f57c76cc5e2e147f14`.
Following metadata records the content-security review; it does not change
application behavior. The origin repository is PUBLIC, verified with the GitHub
API. A branch there is not private. No visibility change is authorized or made.
See `cloud-handoff-security-review-2026-10-01.md` for the exact scanned source
tree, report identities, public-content assessment and remaining transfer gates.

## Exact next work

Active plan: `docs/superpowers/plans/2026-09-29-ordered-current-native379-parity.md`.
Recovery workspace: `.superpowers/sdd/2026-09-29-ordered-current-native379-parity/`.
Tasks1–3 have component evidence; Task4/full native remains incomplete.
Last full native22 result was expected10088/live10050, missing38/changed14,
no accepted complete result. Later source fixes do not imply a passing rerun.

1. Registration QueryJSON diagnostics: read
   `task-4-worker-registration-reference-query-diagnostic-brief.md`. Implementer
   was quiesced BEFORE edits/tests; no diagnostic report or repair exists.
   Only two test-only Go files are authorized. Preserve refusal/cause; add bounded
   statement SHA/native SQLSTATE or error class/closed safe phase, never raw
   SQL/arguments/error detail/DSN/credentials. Group behavioral RED/GREEN, freeze
   full source delta, independently review and rebuild an immutable bundle.
2. Source inventory: full report `task-4-current-build-source-inventory-report.md`
   and full review `task-4-current-build-source-inventory-review.md` are retained.
   Five source changes account for53explicit inputs and156A entries;12affected
   passes retained, but review NEEDS FIXES. Companion tests are added to A's
   file set without traversing imports; replay.test imports/uses descriptor
   SHA c06df5cdc10ac82f10ee8586718f39f775b8604953dd9fb3f57e2a56f1649356,
   absent from A pins/snapshot. Close actual test import graph, add behavioral
   emitted-output/refusal assertions, re-freeze and scoped re-review. Do not
   repeat unchanged private8/full suites or relax computed-import/topology guards.
3. After source approval: produce a separately authorized A successor twice,
   verify complete deterministic bytes, then seed B from ACTUAL verified A.
   Preserve old immutable A/B/95/100 expectations as historical evidence. Upgrade
   native source schema/copier from migration-relative tools/sql to include both
   actual cross-directory apiserver fixtures; synchronize full input/pin closure.
4. Root-equivalent coordinator owns the only PG slot. Reviewed original-source
   reference capture is separate from current target/native acceptance. Read
   source/build reviews, both failed attempts and the full original dispatch
   contract before execution. Substantive private8 Go admission, full native379,
   varied-login/OID portability, connected installed workers and unchanged-limit
   capacity follow. Do not remove production `current_ready() AND false` guards.
5. Resume connected sync→Temporal→OpenFGA-authorized worker→nonempty inventory/
   readback/revocation-before-IO flows, then all remaining security/product/
   browser and real deployed gates. The original728scope is binding.

Registration facts: both source P2 repairs independently approved; actual
immutable build/envelope approved (review1b33cd1b...). Fresh5759inputs/74modules
closure, separate Go1.25.13/CGO0 test binaries and envelope402708a5... are local
macOS evidence. Attempt1 failed PGstartup without LC_ALL and cleanup exit1;
attempt2 added ONLY LC_ALL=C, reached callback but failed generic catalog query
in92.87s, normal pg_ctl/Wait exits0 for pid68696. No reference output exists;
zero PostgreSQL survivors verified. Retained log SHAsbc0b416a.../3aee4701....
Do not repeat a blind fixture; diagnose first. No source guard/cap/expected value
may be weakened to recapture truth. No registration34/native/deployed acceptance.

## Skills and tooling in cloud

Use available Superpowers. If absent, explicitly disclose it and obtain the
official upstream workflow, not an invented substitute. Repository has the
original skill/workflow pointers; local user skill directories are not cloud
runtime authority. Use using-superpowers, grouped TDD/systematic-debugging,
independent review, verification-before-completion and isolated ownership.
No global model/auth configuration changes. Routine commands execute directly
with Node/Go; use an available inexpensive model for routine supervision,
stronger review for tenant/permission/migration authority. No10x claim.

Local Superpowers is a clean checkout of official
`https://github.com/obra/superpowers.git` at
`b36e0829c6d0140e93cfef2ca599b1b07d4a7797`. If cloud skills are absent, disclose
that limitation and obtain/read that official upstream workflow, including
`skills/using-superpowers/SKILL.md` and its `references/codex-tools.md`, before
implementation. Do not upload local Codex configuration or change model routing.
The user requests `writing-style.md`; none was found in the active checkout.
Do not invent its contents.

Fresh local handoff checks: the 728-row ledger validator, direct TypeScript
`tsc --noEmit`, and the five-stage `vinext build` completed successfully. These
checks are local only; cloud must execute its own bounded runtime receipt.
The checkpoint scan covered 2.55GB and flagged3847 findings; the73 new-history
commits flagged8. Neither scanner returned a clean exit. The independent
evidence-bound review classified reported credential-risk clusters and cleared
content upload to the confirmed PUBLIC origin. No scanner rule was disabled;
no blanket fixture/log exemptions were added. Full redacted reports stay local.
The initial hash audit found only `error.log` drift between hashing and staging.
Preserve its scanned final copy, correct that manifest entry, and reverify all
captured files before committing. Do not discard the original local log.

Fresh bounded standalone probe returned HTTP200 for `/` and `/login`; the owned
server stopped and joined on SIGTERM. This is local runnability, not provider,
browser-login or deployed acceptance.

Receiving task's first read-only commands include `git rev-parse HEAD`,
`node scripts/implementation-status-check.mjs`, and a SHA256 comparison of
EVERY `captured` entry in `cloud-handoff-checkpoint-files-2026-10-01.json` against
the actual checkout. The manifest excludes its own digest; the exact Git commit
binds it. Check `deleted` entries are absent and excluded binaries were not
uploaded. Record missing files, byte/hash mismatches, tool/network/access gates
and actual command exits in a cloud receipt; do not start editing the original
source until receipt verification finishes. Then continue the full goal.

Permission portability is a separate gate: the local tree has771 captured
read-only files, and Git preserves executable bits but not their write bits or
directory permissions. The manifest's `permissionEvidence` records observed
local file and ancestor-directory modes. These are historical observations,
not proof of the cloud checkout's immutability, ownership or runtime admission.
Verify bytes first. Prepare separately owned cloud snapshots with reviewed
permissions and Linux runtime bindings before invoking immutable-input routes;
do not chmod the entire working checkout, relabel writable evidence as frozen,
rewrite historical pins, or treat a restored mode as production acceptance.

`scripts/launch-batch.mjs` and its12tests are reviewed local tooling. Release
typecheck/build always run; only unchanged deterministic local checks may reuse
receipts. Artifact/refresh prerequisites are not yet landed on main; generated
artifact authority remains stale here. Do not refresh while owners edit. Side
1244UI/197files,12runner/securityagent-race/affected-API/type/build/HTTP200
evidence is retained history, not fresh cloud/deployment proof. Entire unrelated
API run was stopped296seconds, not passed. Measure accepted comparable flows
before claiming speedups.

## Cloud acceptance gate before local shutdown advice

Upload is also blocked locally. The first reviewed transport commit
`daea775c24ab625653d614ab8b2b1533591ca632` was refused by the installed
`gstack-redact-prepush` hook before upload: its strict Git diff reader has a
64MiB output buffer, and the bounded diagnostic observed more than64MiB for
this checkpoint's added source/evidence. No diff content was printed. The
hook failed closed; no skip flag, hook/config change, alternate upload route
or repeated unchanged push was attempted. A fresh remote-ref check found no
handoff branch. Resolve the hook's capacity safely without weakening credential
checks before retrying; do not describe the checkpoint as remotely available.

The known environment NAME is `zasp-sec`; its exact ID/workspace is not yet
confirmed from this host. Signed-in CLI cloud tasks list is empty and its
environment picker exposes other names, with no zasp-sec match. App handoff tool
explicitly supports no cloud destination and cannot move its calling thread.
Use supported `codex cloud exec --env VERIFIED_ID --branch CHECKPOINT_BRANCH`
once access is established. Do not guess IDs or silently select another project.

The user supplied `codex://threads/6abed32b-fdd0-8191-8ac3-b03b9ba0200c`.
The app read-thread capability reports it is no longer available through dynamic
tools, and no replacement Codex app MCP server is exposed here. A read-only
`codex cloud status` lookup of that UUID returned404 "Invalid task ID".
This URI therefore has not established a cloud environment ID, accessible
receiving task, complete checkpoint or ownership receipt. No task was started.

The receiving cloud task must report:

- Exact Git commit/branch, repository crossbizz/zasp-sec, complete captured path
  count and content-hash comparison to manifest, required plans/ledger/evidence.
- Current environment/runtime readiness from cloud runtime plugin when available,
  network policy enforced/current, actor's GitHub access to checkpoint and later
  authorized pushes; no credential values or environment dumps.
- Actual Node22.23.1, Go1.25.13, PostgreSQL18.3/pgcrypto1.4, installation/download
  access, source build/test tooling, and Superpowers availability/upstream path.
- UI release typecheck/build availability and a bounded affected test check;
  record failures rather than claim a full product acceptance.
- Linux/cloud successor runtime binding needs if OS/arch differs. Darwin/arm64
  executable hashes, /Users paths and /tmp frozen Go bundles are historical,
  not reusable cloud executables. Do not overwrite old pins or assume source
  expected facts are portable; preserve approved behavior and review new runtime
  authorities separately. Continue independent product work where a native gate
  requires a separately reviewed portability step.
- Explicit ACK of checkpoint ownership and continuing the complete goal, with
  all external production gates recorded honestly. Return task ID/URL and its
  evidence before local thread claims execution has transferred.

External prerequisites remain: approved HTTPS origin, real Stytch tenancy and
provider credentials, Temporal/FGA endpoints/store/model/TLS, discovery/provider
services, PostgreSQL DSN/TLS/key access, backups/capacity/rotation. Exact Nexus
annotationsv0.1.0 archive lacks LICENSE; upstream-main MIT is not exact-tag proof.
Do not upload secrets to bridge those gates or treat them as satisfied by this
environment's creation. Checkpoint transfer and product launch are different.
