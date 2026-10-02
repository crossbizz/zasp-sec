# Fix round1 is ready for review

September 18, 2026. Local fix complete, account acceptance still open.

I pinned four previously implicit settings in `deploy/staging/main.tf`.
For `background`, `runtime-events` and `tests`, DLQs now declare receive wait20,
maximum message size262144 and delay0; work queues declare delay0. Each added
attribute uses `contains(["background", "runtime-events", "tests"], each.key)`
and a `null` false branch. All six other queues keep those attributes unset.
Their existing work polling/size declarations are unchanged.

The fix-only production diff has exactly four added lines. No existing line
changed after formatting. Queue definitions, encryption, redrive, output maps,
consumer references and IAM remain byte-identical to the fix baseline.

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.

## The failure came first

Superpowers TDD drove this round. I added the covering checks before editing
Terraform and observed eight failures for the missing explicit settings; the
five existing tests passed. `fix-1-red.log` retains that exit1 run.

After the four-line fix, the same command passed all13 tests with no skips or
failures. See `fix-1-green.log`. Each new attribute check projects its narrow
source conditional across all nine queue keys, asserting the canonical value
for originals and `null` for the other six. This is limited source-contract
evaluation, not a Terraform plan, generic HCL evaluator or provider-default proof.

Twenty new negative controls reject removing any setting, changing its value,
dropping `tests` from its scope, including `red-team-tests`, and replacing its
`null` branch with0. The seven earlier controls still run. The tests first
accept the real source and confirm every mutation changes it before asserting
rejection.

## Checks and boundaries

Commands ran from the worktree above, all synchronously through exit:

```sh
# RED, then GREEN after the production edit and fmt
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/staging/queue-contract.test.mjs
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform fmt deploy/staging/main.tf
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform fmt -check deploy/staging/main.tf
git diff --check -- deploy/staging/main.tf
git diff --no-index --check /dev/null deploy/staging/queue-contract.test.mjs
```

Formatting and tracked whitespace checks exited0. The untracked-test no-index
check exited1 with empty output, indicating a difference from `/dev/null` and
no whitespace diagnostics. `fix-1-checks.log` records these checks and the exact
byte-preservation assertions. No process remains from this round.

I reused the frozen connected-suite evidence: Node81 passed/1 failed, with the
inherited migration56-versus55 rollout failure still separate and unresolved;
the prior platform and queue-proof Go race suites passed. I didn't rerun those
suites or the UI. No cloud/network operation, downloads, credentials, Terraform
init/validate/plan/apply, staging, commit, push or ledger edit occurred here.
The initial round's checkpoint-traffic uncertainty remains in its frozen report.

## What to review

`fix-1-before.json` contains exact before bytes in base64 and SHA-256 identities.
`fix-1-hashes.json` has before/after identities, all frozen-evidence hashes and
the fix patch hash. Removing only the four new production lines reconstructs
the baseline exactly; removing only the added test block does the same for its
baseline. Initial `scoped.patch`, reports, logs and `package.json` are unchanged.

I reviewed `fix-1.patch`: original-only scope, both conditional branches,
all four values and inherited-byte preservation match the ruling. No further
local defect found. Root's independent re-review is pending.

M1A-04 remains component-only. Actual account plan/redrive/output acceptance,
publication, remaining release gates and exact-SHA UI CI are still unproven.
Review the frozen fix patch next.
