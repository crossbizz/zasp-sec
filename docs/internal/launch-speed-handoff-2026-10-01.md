# Launch speed handoff, October 1, 2026

The user authorized faster grouped implementation, verified merges, and cheaper
models for routine test supervision. Preserve all 728 requirements and real
deployment acceptance. This handoff does not change task completion status.

## Remote reconciliation: verified batches already landed

The coordinator fetched main and independently checked its ancestry after the
side chat relinquished push ownership. Current remote main is
8484fba94176071026f711a11fe908a22a02913f, which contains side-batch
9d5c52dd32aa641e9f05cf8cfdeb8cd3e83af853 and template fix 7bcde207.
Do not cherry-pick the patch-equivalent b8837297 again. The later token-reveal
batch has its separate `api-token-reveal-merge-status-2026-10-01.md` evidence
on main. Fetch did not merge, rebase, stage or overwrite either dirty checkout.

The side batch's retained fresh results are 1,244 UI tests/197 files,
12 runner tests, securityagent race tests, affected WorkflowHandler API race
tests, UI typecheck/build and local `/` and `/login` HTTP 200. These unchanged
scopes were not rerun for this acknowledgment. The unrelated full API run was
stopped after 296 seconds and is NOT a passing result. Main's
`priority-merge-status-2026-10-01.md` is the merged evidence authority.

Runner artifact/refresh mode remains prerequisite-blocked on main until its
reviewed generators land. Independent reviewed product batches remain eligible
for separate verified pushes; full launch closure is not their merge condition.
Ordered migration-dependent changes still require their coherent dependency
batch. Neither merged component nor tooling evidence establishes deployed
acceptance, model routing, a measured 10x gain or completion of the 728 tasks.
Earlier sections below are historical checkpoints, not claims that these two
runner files or the side batch are still uncommitted.

## Ready tooling

Two new, uncommitted files are in the main repository checkout, outside this
active worktree:

- `/Users/manishmaheshwari/Projects/zasp-sec/scripts/launch-batch.mjs`
- `/Users/manishmaheshwari/Projects/zasp-sec/scripts/launch-batch.test.mjs`

Seven runner tests pass. The runner groups artifact checks, retains logs,
reuses successful deterministic verification only when source/tool/environment
inputs match, includes ignored root environment files and `.superpowers`
evidence, and refuses evidence if inputs change during a check. Release
typecheck/build never reuse receipts. Cached results are local evidence only.

Current integration commands use the reviewed active-worktree copy, not the
original seven-test main-checkout copy. Run with pinned Node22:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/launch-batch.mjs artifacts --root /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917 --run --reuse
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/launch-batch.mjs refresh --root /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917 --run
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/scripts/launch-batch.mjs release --root /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917 --run
```

Without `--run`, commands print the plan. Refresh writes development and
consolidated artifacts, then checks development/consolidated/packet authority.
It does not rewrite reviewed source pins or run PostgreSQL/provider acceptance.
Review and integrate the two tooling files into the active branch when shared
edits are stable. The side chat has not committed, merged, pushed, refreshed
active outputs, or changed chat model settings.

The integration checkpoint below supersedes the original seven-test state.
The main-checkout files remain untouched; use the active-worktree commands above.
Do not run refresh while the precision source/artifact owners are active.

## Merge gate observed

A read/check-only artifact run passed the development check, then failed:
`complete capture output differs services/platform/migrations/ordered_current/consolidated-capture-contract.json`.
Recheck current state before fixing: the main implementation is active. Merge
only after the combined batch review and relevant regression/UI gates pass.

## Recommended execution policy

1. Finish coherent product flows across API, worker, authorization and UI.
   Group acceptance coverage and review once per connected batch.
2. During development, run affected checks that answer a specific question.
   Reuse unchanged deterministic local checks; run full relevant regression
   once after a batch is stable. Do not rerun the same full suite merely to
   produce another report.
3. Run independent deployment/provider preparation and browser acceptance on
   separate owned snapshots. Keep authority generators and ledger edits under
   one owner. Do not interrupt an agent merely because no shell test is active;
   implementation and review can be progressing without a process.
4. Execute tests directly with Node/Go/CI. When AI supervision is needed, use
   an available low-cost model such as GPT-5.4-mini with low reasoning for
   known commands/log summaries; retain stronger review for permission,
   migration-authority and tenant-isolation decisions. The app tool metadata
   lists mini as supported, but the messaging tool currently returns unavailable.
   No cheapest/fastest absolute ranking or model-setting change is established.
5. Keep one authoritative task ledger and update at batch checkpoints.
   Ship coherent verified slices, preserving unrelated changes.

## Validate speed rather than promise 10x

Track elapsed wall time per accepted product flow, verification minutes,
duplicate reruns, repair rounds, model cost, and time blocked on external gates
over the next three comparable batches. Compare with historical batches of
similar scope. Runner tests establish correctness of reuse, not measured launch
acceleration. Tests execute at the same CPU/database speed regardless of the
model supervising them.

If 10% of elapsed time remains irreducible, even removing all other time reaches
only 10x; with finite improvements, the result is below 10x. Model selection
alone cannot prove this target. Focus on eliminating repeated generation/pin
repair cycles, serial waiting, and unshipped integration work while preparing
real-provider gates concurrently. Report measured results and keep any 10x
claim unproven until the comparable-flow data establishes it.

Official model guidance:
https://developers.openai.com/api/docs/models/gpt-5.4-mini

## Main-chat integration checkpoint

The two runner files were copied into the active worktree without changing
generated artifacts or source pins. Twelve local runner tests pass, including
a test-first timing addition: results separate total check `elapsedMs` from
child-process `executionMs`; a reused result reports zero new execution time
and retains the original verification timestamp and log reference. Review found
and test-first repairs addressed mixed batch snapshots, untracked Node preloads,
symlink-directory evidence and failed reruns retaining stale success receipts.
The runner revalidates the complete batch, refuses unsupported preload/link
inputs, keeps unique attempt logs and publishes receipts atomically. Independent
review approved these repairs after a fresh 12/12 test run. This approves only
local runner reuse, not generated artifact correctness or production acceptance.
Nothing has been committed or pushed by this
integration checkpoint. The earlier artifact mismatch has not been rechecked
while the precision implementer owns those outputs.

Per-task timing excludes final batch-wide fingerprint validation; use external
wall-clock start/end timestamps for complete batch overhead. Neither timing
establishes accepted product-flow time. For the next three comparable accepted
flows, record the flow, exact
source revision, start/end timestamps, review verdict, acceptance evidence,
verification minutes, reused checks, duplicate full reruns, repair rounds,
external wait time and model cost when available. Compare equivalent baseline
batches; leave unavailable metrics unknown. No comparable flow has yet been
accepted under the runner, so speedup remains unmeasured.

| Comparable flow batch | Acceptance evidence | Elapsed / verification | Reruns / repairs / external wait / cost |
| --- | --- | --- | --- |
| 1 | Pending | Not measured | Not measured |
| 2 | Pending | Not measured | Not measured |
| 3 | Pending | Not measured | Not measured |

Overhead probe (not an accepted flow): on October 1 the active `.superpowers`
tree occupied approximately 2.8 GB. A no-op check through `runChecks` took
26.535 seconds before refusing concurrent input drift. This establishes a
hashing-cost concern, not stable-batch timing or speedup. Common snapshot
hashing and staged receipt publication are being evaluated; do not narrow
consumed input coverage to improve this number. Product/provider acceptance
and the three comparable-flow measurements remain pending.

Read-only optimization preparation identified repeated full hashing: three
fresh checks perform nine complete scans; three reused checks perform six.
A proposed bounded optimization is one common full-byte snapshot before the
batch and one after, deriving exact per-task/executable keys from that digest
and staging new receipts until final validation. It is not implemented or
approved. Preserve failed fresh-rerun invalidation of the matching prior success
receipt (do not preserve an invalidated success); keep prior logs immutable.
Any optimization also needs explicit log-reference validation and late-failure,
late-drift and reused-result rejection tests. Keep all consumed input coverage;
do not use mtime-only caching or claim this preparation measures speedup.

## Continuation ownership checkpoint

The main goal coordinator reread this handoff and confirmed the active-worktree
copy remains the integration target. Artifact refresh is still held until the
resolver source re-review and remaining reference owners are stable; neither
the original mismatch nor production acceptance is declared closed. The
resolver's grouped admission repair is frozen for independent re-review (46
affected tests reported passing); root owns its next serial PostgreSQL run.
Worker-registration replay preparation proceeds independently, without
generation or target-derived expected hashes. Cross-chat coordination was
attempted, but this host's app thread-list tool reports that it is unavailable;
the shared handoff and authoritative status ledger remain the coordination
record. No chat model settings were changed and no merge or push was performed.

## Latest coordination checkpoint

The coordinator reread the side-chat handoff and retained the reviewed active
worktree runner; the original main-checkout files remain untouched. The existing
12-test runner result is not repeated. The focused resolver PostgreSQL gate and
eight-row remaining-reference source review have subsequently passed; neither is
a full migration or deployed product-flow acceptance.

The higher worker replay is implementing its grouped source tests. Independent
review now checks a chronological dependency-source clarification: retain the
entire original application-callable universe while using only uniquely admitted
pre-wrapper saved originals, never installed target definitions, to reconstruct
the pinned graph. A separate reviewer checks the 34-site registration aggregate
design, including bare PostgreSQL Boolean output versus explicit text casts.
These reviews have disjoint ownership and require no generator or database run.
Artifact refresh, combined regression and release push remain deferred until
source closure is accepted. The three comparable accepted-flow measurements
remain pending; no speedup or production-readiness claim is made.

The proposed two-endpoint fingerprint optimization is now rejected for a mutable
worktree: an input changed before a later task and restored by that task could
escape the two scans, while the existing task-boundary scans refuse it. The
independent report `task-4-launch-runner-optimization-review.md` in the current
SDD directory records the counterexample and alternatives. Keep the current
runner unchanged for this batch. Receipt staging and log-reference validation
are future correctness work, not existing guarantees or measured speedups.

## Separate merge ownership

The user now assigns the side chat exclusive ownership of an isolated merge of
the reviewed runner and its12-test suite onto latest origin/main, with fresh
runner tests and UI typecheck/build. This coordinator will not compete with that
push or modify the side chat's integration worktree. No model or global
configuration change is authorized by this handoff.

Independent verified product changes should land as separate coherent batches;
they need not wait for full launch closure. A read-only reviewer is identifying
the next exact product slice and its dependency/verification boundary, excluding
the runner, in-progress registration harness and generated migration authority.
Each slice still requires review, relevant regression and fresh UI release gates
on its actual integration snapshot. Partial merges do not promote the full728
or deployed acceptance gates. The runner merge is pending, not yet observed here.

The isolated batch has now landed at origin/main
`9d5c52dd32aa641e9f05cf8cfdeb8cd3e83af853`; this coordinator fetched and verified
the remote-tracking SHA and read its priority-merge evidence record. Commit
`7bcde207` is patch-equivalent to `b8837297` and must not be cherry-picked again;
`9d5c52dd` adds the reviewed runner/tests and scoped status record. That record
reports1,244 UI tests,12 runner tests, securityagent race and affected workflow
API race checks, fresh typecheck/build and local root/login HTTP200. The entire
API package run was stopped, not passed. Artifact/refresh mode remains
prerequisite-blocked on main because its generators were excluded. No deployed
acceptance is inferred. Side-chat push ownership is relinquished. Active branch
and dirty files remain untouched; normal branch integration awaits a safe
snapshot, while the next independent product-slice review uses this new main.

The next independent product slice also landed: main is now
`8484fba94176071026f711a11fe908a22a02913f`, confirmed by normal push and
`git ls-remote`. An isolated branch based on9d5c52dd carried only the reviewed
two-file API-token expiry correction and scoped ledger/evidence updates.
Fresh race RED reproduced the defect, affected race GREEN passed3.422s,
exact-environment race controls passed1.616s, all four existing disposable
PostgreSQL regressions passed6.168s without skips, eight affected UI tests
passed, and final stable-snapshot release typecheck/build passed. Independent
security and evidence review approved. No full API, deployed or full728 claim.
The isolated worktree is clean and retained; root and active dirty files remain
preserved. Do not duplicate this correction in later branch reconciliation.

First scoped integration timing observation: Git reflog records the isolated
token-reveal branch created at2026-10-01 11:25:19-0700 and the verified commit
at11:30:49-0700, a330-second interval. This includes transfer, grouped RED/GREEN,
four local PostgreSQL cases, affected UI checks, review and final release checks;
it excludes earlier slice selection and subsequent push/remote confirmation.
It is not a complete deployed-flow timing, comparable three-batch result or
10x measurement. Costs and exact review/verification split remain unmeasured.
