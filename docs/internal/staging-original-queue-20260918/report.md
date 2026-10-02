# The original staging tests queue is restored locally

Status: DONE_WITH_CONCERNS. September 18, 2026.

I added the missing `tests` map entry in `deploy/staging/main.tf`: visibility 900,
maximum receive count 5, schema `agentsec.tests.v1`. That's the entire Terraform
change. A new source-contract regression is included in `staging:gate:test`.

The worktree is `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`,
at HEAD `8733b16f8d939d38a8157dd2519e57fc6f630542`. Inherited edits remain intact.
There was no commit, staging, push, cloud API invocation, provider download,
Terraform init/apply, host database use or frontend edit in this batch.

## What the tests establish

Superpowers TDD produced a real RED before the production edit: the original
`tests` entry was undefined. Four other tests passed in that run. After the
one-line repair, all five tests passed. See `red.log` and `green.log`.

The regression checks all three original queue contracts and all six other
entries, including the distinct `red-team-tests` identity. It checks the shared
queue/DLQ source declarations, names, schema tags, explicit retention and
visibility, queue polling and size, conditional KMS keys, same-key redrive
target, maximum receive count, by-queue redrive allow policy, and both output
maps. The existing Red Team policy stays bound to its own queue and output.

Seven negative controls run within the test file: remove `tests`, change its
visibility, receive count or schema, cross-wire the DLQ, widen redrive to
`allowAll`, or filter `tests` out of the queue output. Each control must reject.
These are source-contract checks. They don't execute Terraform resource
expansion or test AWS behavior.

The connected Node run completed once: **81 passed, 1 failed**, 82 total.
The failure is inherited: `deploy/staging/gate.test.mjs:15` requires latest
migration 55, but `0056_production_compliance.up.sql` is present. Its unchanged
source also lists schema56 as rejected. I didn't change that rollout contract.
The complete failure is retained in `affected-node.log`, not counted as a pass.

Both platform packages (`queuedefinition`, `jobqueue`) passed race tests;
the `proofs/localstack-sqs` Go package also passed its race suite. Logs are
`affected-platform-go.log` and `affected-proof-go.log`. The Node run included
the existing Red Team, runtime, Attack Lab and recovery Terraform source tests,
release rendering, staging preflight and queue-proof runner tests. It did not
start a disposable LocalStack provider run or rerun the UI.

## Commands I ran

Run from the worktree above. The executable for every Node command was
`/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node` (v22.23.1).

```sh
# RED, then the identical command for GREEN after the one-line repair
node --test deploy/staging/queue-contract.test.mjs

# Connected suite, once; exit 1 due only to the inherited migration gate
env CHECKPOINT_DISABLE=1 AWS_EC2_METADATA_DISABLED=true \
  PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/bin:/bin \
  node --test deploy/staging/queue-contract.test.mjs deploy/staging/gate.test.mjs \
  deploy/staging/preflight.test.mjs deploy/production/release-contract.test.mjs \
  proofs/localstack-sqs/queue-definitions-run.test.mjs proofs/localstack-storage/run.test.mjs

env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache \
  /opt/homebrew/bin/go test -C services/platform -race -count=1 ./queuedefinition ./jobqueue
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache \
  /opt/homebrew/bin/go test -C proofs/localstack-sqs -race -count=1 ./...

CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform version -json
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform fmt -check deploy/staging/main.tf
git diff --check -- deploy/staging/main.tf package.json
```

Both formatting/whitespace checks exited 0. Test output was captured with
`set -o pipefail` and `tee` into the named logs. Both spawned test sessions were
joined through exit; no batch-owned process remains.

## The acceptance limit stays open

The cached pinned binary is Terraform 1.15.8 on darwin_arm64. Staging requires
AWS 6.60.0 and TLS 4.3.0. There is no staging `.terraform` directory, the known
cached Terraform data directory is empty, and file searches found no provider
binaries under `/private/tmp`, `~/.terraform.d` or the repository. No mock plan,
validate or account plan was run. The system's separate Terraform 1.16.1 binary
doesn't satisfy the pin.

One tooling caveat: my first cached `terraform version` call did not set
`CHECKPOINT_DISABLE` and printed an update notice. I can't establish whether
that notice used cached data or an outbound checkpoint request. Later calls
disabled checkpoint. This report does not claim the whole turn was proven
network-silent.

The shared DLQ declaration explicitly sets retention 1209600 and visibility 30,
but doesn't set polling, message size or delay. The canonical Go definition
contains polling20, size262144 and delay0. I retained the existing declaration;
cached-provider plan evidence is needed to resolve its implicit defaults. The
work queue also leaves delay implicit. I found no other explicit shared-setting
mismatch that required expanding this one-entry repair.

M1A-04 remains component-only. Account Terraform plan/redrive/output acceptance,
remaining release gates, publication and exact-SHA UI CI are unproven here.
Root owns the availability ledger; I did not edit it.

## Review handoff

`before-main.json` and `before-package.json` contain exact pre-edit bytes in
base64, lengths and SHA-256 hashes. The new test file was absent before this
batch. `hashes.json` records the three after hashes and the scope check.
`scoped.patch` contains only this batch's changes, not the inherited diff.

I compared the current main file after removing the single added entry to its
decoded before bytes, and did the same for the package test-command addition.
Both matched exactly. That comparison preserves every inherited queue, resource,
IAM statement, output and consumer reference outside the added map entry.

Self-review found no queue-scope defect. The source parser assumes the existing
line-oriented HCL layout and does not replace a Terraform parser. Independent
review is pending with root. Review this scoped patch and keep the account-plan
gate open.
