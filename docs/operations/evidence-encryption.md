# Discovery and recovery evidence encryption

The discovery collector and recovery worker can write evidence to a versioned Amazon S3 bucket using SSE-S3. This setting applies to the platform's own evidence account. Customer discovery still runs under its existing customer credentials. Compliance exports, audit exports, private archives and runtime raw storage each retain their own encryption policy.

| Worker configuration | New objects | Pinned reads |
| --- | --- | --- |
| Omit `ZASP_EVIDENCE_ENCRYPTION`, or set `aws-kms` | SSE-KMS with the exact `ZASP_EVIDENCE_KMS_KEY_ARN` | The same key |
| `ZASP_EVIDENCE_ENCRYPTION=provider-managed` | SSE-S3 (`AES256`) | SSE-S3, plus historical SSE-KMS versions under the configured key ARN if supplied |

Both modes require the expected AWS account and region, enabled S3 versioning, create-only writes, immutable version IDs and SHA-256 verification against the streamed bytes. Unknown modes fail configuration validation. Each GET checks both the HEAD and GET encryption metadata. A timed-out or conflicting write reconciles only against the requested encryption mode and matching content. A retry that encounters an older KMS object after switching modes fails closed.

## Deployment and cutover

1. Inventory unacknowledged writes. Drain discovery and recovery jobs before changing the bucket's default. Record a known scoped object reference, version and digest for a recovery rehearsal. Confirm that any additional application using this bucket explicitly selects its required encryption.
2. In the existing production Terraform root, set `evidence_encryption = "provider-managed"`. Review the plan for the discovery/recovery bucket before applying in your own deployment process. The plan sets the bucket default to AES256 and adds a deny for incorrectly encrypted writes by those two writer roles. Check for any independently managed bucket policy before adopting Terraform ownership. Retain the existing KMS key for historical reads. The Terraform profile also uses this key for other AWS services.
3. Use the matching Helm settings `discovery.evidenceEncryption` and `recovery.evidenceEncryption` for the two workloads. Terraform supplies both settings. Retain each workload's previous `evidenceKMSKeyArn` to allow exact historical reads. An installation with no KMS evidence history can omit this pin when configuring the runtime directly.
4. Confirm readiness before resuming jobs. Read the pinned historical object and validate its digest. Write a new test artifact, record its immutable version, and verify that a pinned HEAD and GET return AES256 and the expected SHA-256. Run a recovery rehearsal using artifacts from both generations. Evidence signing is configured separately.

Before the first SSE-S3 write, restore the original bucket default and Helm settings to roll back. After SSE-S3 writes exist, preserve the mixed-history reader and keep its historical KMS key accessible. A KMS-only binary rejects SSE-S3 versions. Returning to that binary requires a separately validated evidence migration and signed reference update. Re-encrypting an object creates a new S3 version and cannot preserve a previously signed version ID.

SSE-S3 avoids application KMS encryption requests for new evidence. Select SSE-KMS where customer-managed key policy, revocation or audit requirements demand it. Keep version storage, retrieval, lifecycle and cross-region transfer charges in the cost estimate. [Amazon S3 encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/specifying-s3-encryption.html) · [S3 Bucket Keys and historical encryption contexts](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html)

## R2 compatibility

Use a versioned Amazon S3 bucket for core evidence in this release. R2 supports atomic conditional creation. The current evidence and private archive contracts also pin a provider version for GET, enumerate exact versions for recovery, and in cleanup require a provider-confirmed missing version before releasing accounting. R2's S3 interface does not supply these version operations or AWS owner and KMS metadata. Its bucket locks provide a separate retention mechanism. Moving core evidence requires a provider-tagged reference format, immutable keys, an explicitly stored digest, and a migration for historical records and signed manifests. Changing the S3 endpoint or putting the ETag into the version field would invalidate these guarantees. [R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/) · [Conditional operations](https://developers.cloudflare.com/r2/api/s3/conditional-operations/) · [R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/)
