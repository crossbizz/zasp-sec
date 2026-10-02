# Storage is ready for scoped review

Task2 implementation is frozen for independent review. It is local source
evidence only. I did not run a provider plan, mocked Terraform evaluation,
live IAM/S3 calls, or an account acceptance gate.

## What changed

`deploy/staging/compliance_exports.tf` provisions nothing by default. When
enabled, it declares one dedicated versioned bucket, a rotating KMS key,
owner-enforced ownership, all four public-access blocks, TLS denial, SSE-KMS
with bucket keys, and one-day current/noncurrent expiration plus a separate
expired-delete-marker rule. The two lifecycle rules filter `organizations/`;
IAM object grants retain the full tenant export path. S3 lifecycle is a
backstop, not a physical 24-hour deletion guarantee.

Three roles bind reader/writer/cleanup to the selected EKS OIDC provider,
STS audience, and their exact service accounts. The reader gets only
GetObjectVersion. Writer reads and writes require the dedicated bucket path;
PutObject requires both KMS headers. Cleanup gets version reads and
DeleteObjectVersion, with no current-key delete permission. KMS decrypt is
bound to S3 and this bucket/object context. Only the writer can generate
data keys.

The two worker DSN entries contain metadata, never secret versions or
passwords. Each worker role can read its own secret and use the staging key
only with that secret's Secrets Manager context. The output contains the
12 non-network `complianceExports` fields. It invents no CIDRs.

Source checks are labelled as source checks. Four mutation controls remove
versioning, add current-key deletion, broaden the secret reference, and swap
the cleanup service account. All four fail their guard as intended. The
existing staging gate now includes this source test.

`deploy/staging/tests/compliance_exports_iam.tftest.hcl` has six planned runs:
disabled absence, enabled storage/decoded policies/output isolation, and four
invalid-principal cases. These are written but unexecuted. The tests use
mocked ARN outputs; they still need the pinned provider schemas. Secret-version
absence is checked by the source suite, not by evaluating a nonexistent
Terraform resource address.

## RED, then GREEN

All commands ran from:

```text
/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917
```

First I added only the source test, then ran:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/staging/compliance-exports-contract.test.mjs
```

Exit1. All10 tests failed: the opt-in variable, storage resources, identity
map, secret resource, metadata output, mutation baselines and package gate
entry were missing. Those were assertion failures, not import errors.

After adding infrastructure and the one-line package change, that same
command passed10/10. I formatted the new Terraform source:

```sh
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform fmt deploy/staging/compliance_exports.tf
```

After writing the mock fixture, I ran:

```sh
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform fmt deploy/staging/tests/compliance_exports_iam.tftest.hcl
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform fmt -check deploy/staging/compliance_exports.tf deploy/staging/tests/compliance_exports_iam.tftest.hcl
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/staging/compliance-exports-contract.test.mjs
```

All exited0; the source suite passed10/10 again. No production change followed.

The final grouped check was:

```sh
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform version
CHECKPOINT_DISABLE=1 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform fmt -check deploy/staging/compliance_exports.tf deploy/staging/tests/compliance_exports_iam.tftest.hcl
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/staging/compliance-exports-contract.test.mjs
git diff --check -- package.json
shasum -a 256 package.json deploy/staging/compliance_exports.tf deploy/staging/compliance-exports-contract.test.mjs deploy/staging/tests/compliance_exports_iam.tftest.hcl
git status --short -- package.json deploy/staging/compliance_exports.tf deploy/staging/compliance-exports-contract.test.mjs deploy/staging/tests/compliance_exports_iam.tftest.hcl
```

Terraform reported1.15.8 on darwin_arm64. Formatting and package whitespace
checks exited0. Final source result:10 tests,10 passed,0 failed,0 skipped.
The three source/fixture files are new; package.json retains its inherited
dirty changes plus this task's gate entry.

## Frozen files

Before this task, all three new source/fixture paths and this report were
absent. The inherited package SHA-256 was:

```text
287bb54fb5932d63229e34be79aa3343e5a6a4de10ee4a72ad65496f568449c3  package.json
```

After:

```text
f32f1880173537431d4e120f7dfdeecbec64d095634ab356a917677e828ee614  package.json
d9e7d0f951fd663814f3824726e291a4b61329947115847b298f5ebde7db33be  deploy/staging/compliance_exports.tf
6fde71d0b57623e7fcf6eae3278b5b1ef53d499d8ac2232e69f581879aada296  deploy/staging/compliance-exports-contract.test.mjs
14cc32a3554f630977f2df0aaa1e7d588e56e8a76b19db26d5d0f24d9dd5723b  deploy/staging/tests/compliance_exports_iam.tftest.hcl
```

[task.patch](task.patch) captures only this task's three added source/fixture
files and one package line. SHA-256:
`0cbd8809c7cdf9b6bc7b98ae6410dd652de006d7cdebd149c60922cac180b095`.
[inherited-package.patch](inherited-package.patch) retains the package changes
that preceded this task. Reconstructing the original package by removing only
this task's added test path reproduced the before hash exactly. No inherited
package change was lost.

Patch verification used `git apply --check --reverse --unidiff-zero
docs/internal/compliance-storage-20260918/task.patch` and exited0. The first
check omitted `--unidiff-zero` and rejected the zero-context package hunk;
the corrected read-only check accepted every frozen source file. No patch
was applied. The inherited-package patch SHA-256 is
`d7e52b6761f04b770f0bb1df1333910d6ecdc727d8b88626ac9cb087ea1d630d`.

No SQL, chart, Go, UI, migration checksum, or component ledger files changed.
Nothing was staged, committed, pushed, downloaded, initialized, or applied.

## What is still unproved

The permitted cache contains Terraform's binary, license, archive and
checksum list. Its `data` directory has no files, and
`deploy/staging/.terraform/providers` is absent. I checked those paths with
`rg --files -uu`, directory tests, and `ls`; I did not retry provider execution
or run `terraform init`.

`terraform fmt -check` proves parse/format acceptance. It does not prove
provider-schema compatibility, Terraform expression evaluation, IAM policy
effect, or AWS lifecycle behavior. The source checks cannot replace any of
those. The mock file still needs execution with AWS6.60.0 and TLS4.3.0 before
its assertions can be counted as evaluated evidence.

Live acceptance must exercise the actual checksum-mode HEAD SDK calls with
these exact reader/writer/cleanup grants. It must also prove version creation,
encrypted writes, immutable-version reads/deletes, own-secret access and
cross-role denial. Source checks do not prove those cloud outcomes.

Operator-provisioned logins and secret values, authorized account plan,
hosted rollout/CI, and exact-input advisory evidence remain external gates.
No deployment acceptance or ledger promotion is claimed. Independent scoped
storage/authority review is next.
