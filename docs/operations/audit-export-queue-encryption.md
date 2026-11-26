# Audit export queue encryption

The audit export publisher and consumer share one SQS work queue and its dead-letter queue (DLQ). Terraform in `deploy/staging` defaults both queues to the existing customer-managed KMS key. For SQS-owned encryption, set `audit_export_queue_encryption = "provider-managed"` in the Terraform inputs and set `auditExports.queueEncryption: provider-managed` in Helm. The chart passes `ZASP_AUDIT_EXPORT_QUEUE_ENCRYPTION` to both audit export workers. These settings affect only this queue pair.

| Terraform | Optional Helm selection | Effect |
| --- | --- | --- |
| `aws-kms` (default) | omitted | Existing releases keep their existing queue, redrive and identity checks. |
| `aws-kms` | `aws-kms` | Also check that both queues report a KMS key ARN in the queue's account and region. Terraform pins the specific key. |
| `provider-managed` | `provider-managed` | Check that both queues report SQS-owned encryption and no KMS key ID. |

Install the updated IAM policies before enabling an explicit Helm selection. Each role needs read-only queue attributes on its own DLQ. A mismatch or unavailable probe makes the worker unready before publishing or processing. The S3 evidence bucket, export files, and signing keys retain their own encryption settings. SQS-owned keys avoid customer KMS requests for new queue messages.

## Changing an existing queue

1. Record the work queue and DLQ URLs, KMS key ARN, current settings, outstanding outbox records, and message counts. Pause publishing and processing before changing encryption, and allow in-flight work to settle. Use the normal outbox and redrive procedures for unresolved work.
2. Review the Terraform plan. Apply the change only if it updates the existing queues in place and preserves the original key and decryption grant. SQS does not re-encrypt old messages when the queue encryption setting changes. Keep the old key enabled and available through the longest DLQ/redrive window and any operator-held recovery backlog.
3. Set the matching Helm selection, restart both workloads, and verify readiness. Check both queue attributes independently. Confirm a new audit export completes and an outstanding export can still complete. Resume publishing and monitor backlog and DLQ depth.
4. For rollback, restore the Terraform KMS setting and its publisher data-key permission, then the matching Helm selection. Preserve messages and the original keys. Mismatched selections can briefly hold processing during rollout.

## Cloudflare Queues

Use SQS for the audit export workflow. The dispatcher renews visibility immediately on a received batch and periodically while database-fenced work is in flight. Cloudflare HTTP pull issues a fixed-expiry lease and documents acknowledgment or retry. It exposes no operation to extend that lease in place. Retrying releases the message for redelivery. The durable publisher also requires a broker-issued message ID per entry. Cloudflare's push and batch push responses expose queue metrics and success, without per-entry IDs.

The SQS contract here uses four days of work-queue retention and fourteen days for dead letters. Cloudflare Free fixes retention at 24 hours. Cloudflare's documented maximum message size is 128 KB, including metadata, compared with the current 262,144-byte application bound. A future integration needs a producer receipt design, an execution policy that tolerates non-renewable leases, verified per-message size limits and explicit work/DLQ retention on a qualifying plan.

References: [Amazon SQS encryption attributes](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html), [Amazon SQS key management](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-key-management.html), [Cloudflare HTTP pull](https://developers.cloudflare.com/queues/configuration/pull-consumers/), [Cloudflare producer responses](https://developers.cloudflare.com/api/resources/queues/subresources/messages/methods/bulk_push/), [Cloudflare limits](https://developers.cloudflare.com/queues/platform/limits/).
