# Reconciler IAM candidate

Component-only, opt-in and unapplied. No cloud infrastructure or credentials
were provisioned. M7A-21 and original728 availability counts remain unchanged.

## Implementation

`deploy/staging/test-reconciler.tf` adds a disabled-by-default
`test_reconciler_enabled` switch. Its conditional role trusts only the existing
EKS OIDC provider, `system:serviceaccount:agentsec:zasp-test-reconciler`, and STS
audience. The policy allows caller identity, the existing registered worker DSN
secret, bucket readiness, version-specific tenant artifact reads, and exact-key
KMS read/decrypt operations. No planner/target secret, queue or object-write
actions are granted. Secret decryption binds Secrets Manager and the exact DSN;
evidence decryption binds S3, the red-team key and bounded encryption contexts.

The `test_reconciler_deployment_metadata` output is null when disabled and gives
only the role, DSN secret ARN, bucket, owner, key ARN and region when enabled.
It supplies references, not secret values, endpoint snapshots or activation.
The database principal is the existing registered security-agent worker login;
this batch does not provision an additional database login or planner secret.

## Test-first evidence

- Initial empty policy/trust REDd4326c: disabled case passed; five enabled
  authority assertions failed. Implementation GREENa04b49:2 passed.
- Distinct mocked bucket/key/secret resources replaced shared mock ARNs so
  selecting the wrong resource cannot accidentally pass. GREEN4fe9b3:2 passed.
- Metadata REDda0de6: enabled output was null; bound output then passed.
- Grouped run10b4af exposed an invocation error: the older test file requires
  account_id. New reconciler tests passed;10 older cases skipped. The corrected
  command below supplied explicit account/offline settings; GREEN78dd39:13 passed.
- Independent review identified retained-version compatibility: current bucket
  defaults do not prove old versions used bucket-key encryption. New dual-context
  assertion RED9e091a failed against bucket-only policy. The corrected condition
  allows exact bucket ARN or scoped tenant artifact-object ARN, preserving exact
  key and S3 ViaService. Bucket readiness-action resource assertions were added.
- Final grouped GREEN97f342:13 passed,0 failed. Independent follow-up found both
  review findings resolved and no new Critical/Important issues. Source-only
  review is separate from the parent's executed test evidence.
- Terraform validate77a755 passed; final policy was parsed/planned by the final
  grouped mock test. Diff check and ledger validator3ef194 passed.

Reproducible grouped command from `deploy/staging`:

```sh
TF_DATA_DIR=/private/tmp/zasp-reconciler-tf.8wObLE/data CHECKPOINT_DISABLE=1 \
 /private/tmp/zasp-reconciler-tf.8wObLE/bin/terraform test \
 -var=account_id=000000000000 -var=offline_validation=true \
 -filter=tests/test_reconciler_iam.tftest.hcl \
 -filter=tests/session_search_iam.tftest.hcl -no-color
```

The system Terraform was1.16.1, incompatible with the repository pin. Isolated
Terraform1.15.8 was downloaded from HashiCorp and verified against its official
SHA256SUMS: darwin_arm64 archive
`f210110c5698b94d803a7a63cdb0251b5455c150841478808e2bbb343f95ed68`.
Backend-disabled initialization used the existing lockfile read-only and installed
signed AWS6.60.0/TLS4.3.0 providers. Tests use mocked providers and plan commands,
not AWS apply. The existing pinned CI command now includes the new test file.

## Permission rationale and remaining proof

General-purpose versioned object reads and checksum requirements are described
in [AWS HeadObject permissions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).
Bucket-key encryption uses bucket ARN context; older object-key encryption can
use object ARN context. See [AWS bucket-key configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-bucket-key.html).
The candidate supports both within the same evidence storage boundary.

Mocked policy evaluation does not prove effective live permissions, inherited
policies, bucket/key-policy access, checksum retrieval, or retained baseline
readability. Authenticated read-only provider acceptance remains required.
Full schema55 normalization/migration/chart activation, operational monitoring,
registered multi-tenant process restart/reclaim and live rollout remain open.
No commit, push, production promotion or completed-milestone claim in this batch.
