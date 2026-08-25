# Production recovery runbook

Use the tenant recovery API or `agentsecctl recovery`; do not mutate recovery tables, SQS leases, manifests, or temporary resources directly. PostgreSQL schema v27 is authoritative. A recovery hold protects the exact backup LSN while immutable artifacts and the signed manifest are published.

## Inspect

Set only non-secret identifiers in the shell, then inspect the API and workload state:

```sh
agentsecctl recovery list --organization "$ORGANIZATION_ID" --workspace "$WORKSPACE_ID" --environment "$ENVIRONMENT_ID"
agentsecctl recovery get "$RECOVERY_ID" --organization "$ORGANIZATION_ID" --workspace "$WORKSPACE_ID" --environment "$ENVIRONMENT_ID"
kubectl -n agentsec get deploy,pod,pdb,hpa -l zasp.io/recovery-canary=promoted
kubectl -n agentsec get events --sort-by=.lastTimestamp --field-selector type=Warning
aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible RedrivePolicy
```

Never print a DSN, web-identity token, Neon API key, KMS signature, or manifest payload. Use correlation, operation, audit, and receipt IDs when escalating.

## Retry

Retry through the public operation contract with the original idempotency key. The worker validates the durable request digest, operation version, lease, artifact versions, signature, and tenant scope before any side effect. Do not create a second restore for a lost client response. Redrive a DLQ only after the underlying failure is fixed and the exact message schema and operation state are verified.

## Cleanup

Restore success requires deletion of the owned validation Job, namespace resources, and temporary Neon branch. A `cleanup_failed` result is not success. Keep the restore workload running so its fenced cleanup retry can reconcile the operation. Inspect only resources carrying the operation ownership label:

```sh
kubectl get namespace -l zasp.io/recovery-id="$RECOVERY_ID"
kubectl get job,pod,secret,networkpolicy -A -l zasp.io/recovery-id="$RECOVERY_ID"
```

Do not delete an unlabelled namespace, a shared branch, an S3 object version, a queue, or a DLQ. Never use `agentsec-migrate down` as recovery cleanup.

## Escalate

Page immediately when a recovery worker is unavailable, driver readiness is zero, queue age exceeds five minutes, a recovery hold exceeds 15 minutes, work exhausts retries, a lease is lost, or cleanup fails. Freeze new recovery requests, preserve all immutable artifacts and receipts, and capture the reviewed image digest, schema fingerprint, operation version, queue counts, readiness result, and exact owned-resource inventory. Resume only after a same-idempotency retry or a reviewed forward repair proves completion and cleanup.
