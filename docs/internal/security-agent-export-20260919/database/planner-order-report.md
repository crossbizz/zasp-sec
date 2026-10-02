# Candidate order correction

DONE_WITH_CONCERNS. P2 is fixed and this three-file delta is frozen for scoped re-review. Missing/outstanding planner accounting remains a separate, unwaived all-family production blocker.

Independent review of `planner.patch` found one actionable issue: subset validation rebuilt snapshot order, while the agreed Go/model contract permits a unique exact-tuple subset in candidate order. The earlier `planner-report.md` wording about ordered membership and its reordering-refusal coverage is superseded here. Its bytes and evidence remain unchanged.

Before pin: `4f5dbcc24bcc51b39c3aff1fc019ffed8e15b3e4bd8278367e364c5fc9a1073c`.
After pin: `49c9b2e421d80372470136ede8e9cced66ba34fa19dae1b72e88f6ee0b0cfecb`.

I checked the existing Go candidate validator: it checks each selected tuple's membership without imposing snapshot order. The SQL correction keeps the existing closed selection validator, including kind/ID uniqueness, and uses exact JSONB tuple equality for membership. It does not reconstruct or reorder candidate selection. Plan hashing and durable receipt replay remain unchanged.

Only these files changed relative to the frozen reviewed baseline:

- `services/platform/migrations/sql/fragments/security_agent_export_planner.sql`: replace ordered reconstruction with exact membership.
- The release58 fingerprint in `services/platform/migrations/security_agent_exports_release.go`.
- `services/platform/apiserver/security_agent_export_planner_postgres_test.go`: a real reordered-subset admission/replay test; replace the incorrect reordered-refusal fixture with duplicate-reference refusal.

Before bytes are in `planner-order-before/`; `planner-order.patch` is the scoped correction, not a diff against HEAD. No other SQL or root-owned product file changed.

## Registered proof

Superpowers receiving-code-review and TDD drove the correction. The new test starts with three actual persisted references, captures input, reserves and settles planner usage, then submits reference3 followed by reference1. Against the frozen before pin it fails at real accept with40001, `export planner selection changed`. This is behavioral RED:6.75s, container exit1, owned PostgreSQL pg_ctl/server Wait both exit0. Full command/output: `planner-order-red.log`.

After the minimal SQL edit, release calibration observed the new fingerprint and failed with the expected old compiled-pin mismatch. `planner-order-calibration.log` retains that command/output,5.42s, exit1, clean PostgreSQL join. The compiled pin was then updated.

One affected batch passed on the final pin:

| Group | Result |
| --- | --- |
| PlannerCandidateOrder | PASS6.65s |
| PlannerRefusals | PASS6.10s |
| Release | PASS6.74s |

Container exit0; three owned PostgreSQL lifetimes joined normally, no skips. `planner-order-green.log` is the complete command/output.

CandidateOrder asserts the persisted plan retains the exact candidate array order and clears the parent lease. Identical lost-reply replay returns the same receipt with replayed=true; changing only array order or shortening the selected subset refuses without changed authority. Refusals still covers duplicate selections, wrong parent, empty selection, extra path, borrowed version and the previously corrected authority checks. Release exercises actual registration, drift refusal and up/down/up restoration. Unchanged planner groups were not repeated.

Each run used cached Linux/arm64 PostgreSQL by digest with `--pull=never --network none --read-only --user postgres`, owned tmpfs data and the mounted offline binary. Exact Docker commands are the first line of each log. Compilation before each run exited0 from `services/platform`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

## Frozen hashes

```text
667bc4f5a556d1eac55d4b133a205451794338e8768e96f589dd32908ae5f3db  before planner.sql
e33648e41af5a93fd6ff226eef7da38251bc1febcf4b2c39c26b4241279d3bcb  before release.go
4deae895ff86c7314fa7cffe06c3cd8bed345fa752473c18f85264fae8b66e1e  before planner_test.go
d98e7b87c5a7530400de235a9c19c1a815a95fd0f90b4cfe645e584e9ac0ffc9  after services/platform/migrations/sql/fragments/security_agent_export_planner.sql
03092135441a5daa8cdf3cc173821a67115783b215ba1cbb44bb2f327791e561  after services/platform/migrations/security_agent_exports_release.go
f2cabf76357055501369b0b7f2529550b3466cbdd2f450ffa4fddfcbda5e2643  after services/platform/apiserver/security_agent_export_planner_postgres_test.go
06452e8ebd2932b7a4aa802c994d8f20d0d12d87dcfd94860821961e1ecce368  planner-order.patch
1cf6c410691d7bdc6143988edc0c97f02edc3aa9e14d8b58f554e6104c857b84  planner-order-red.log
a5ad5d80be99b2dbf4378e0319d4c8c1ec29307e9fc572aa07ee91e734e67a1e  planner-order-calibration.log
93539aed9ba95f1339f947de97ac602d7c91c0abea825f918b8678386acad5b6  planner-order-green.log
```

`git apply --reverse --check docs/internal/security-agent-export-20260919/database/planner-order.patch` and `git diff --check` exited0.

No stage, commit, push, host PostgreSQL, new dependency, image pull, external provider/advisory call or subagent occurred. Earlier acceptance limits remain: manual provenance, multi-step admission, definition activation, existing-test dispatch replay, all-family accounting closure, mounted public workflow and production proof are still required. Root owns the scoped re-review.
