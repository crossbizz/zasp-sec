# Restore the original IAM queue fixture roster

The original staging IAM command passes eleven cases and fails two assertions against published source `4956a862`: its queue-contract and encrypted work/DLQ maps omit the already-configured `tests` queue. This is an expected-roster mismatch, not a demonstrated IAM access denial. The failed receipt is preserved at `/workspace/scratch/staging-iam-policy-union-v1/original-iam-baseline-v1/receipt.json`, SHA256 `97e9aa6899ba74f7c9032776e31d9b44bcf1b1a2d9f9842c9c3901c702c18011`.

The correction adds that existing queue to exactly those two expected maps. It retains exact equality, all previous entries, visibility900, maximum receive5, schema `agentsec.tests.v1`, and the fixed KMS key assertions for both work and dead-letter queues. Production Terraform, roles, policies, queues and trust bindings are unchanged.

The same original command, with pinned Terraform1.15.8 and AWS6.60.0/TLS4.3.0 providers checked against the unchanged lockfile, passes all thirteen cases with zero skips in7.732seconds:

```sh
terraform -chdir=deploy/staging test -filter=tests/session_search_iam.tftest.hcl -filter=tests/test_reconciler_iam.tftest.hcl -var-file=release.tfvars -no-color
```

The corrected receipt is `/workspace/scratch/staging-iam-policy-union-v1/original-iam-corrected-v1/receipt.json`, SHA256 `bc5cea6bd4bb115e0dd492f951b16e31544be0f7a3b3d18450a2cd00d4a52ac8`. Input/tool hashes remain stable and all owned children join. Providers are mocked and the private execution has no AWS credentials or account API calls. These results resolve the two local fixture failures; they do not accept the separate policy-union matrix, deployed IAM, hosted browser or original native/release gates. The original728 scope and all ledger classifications remain unchanged.
