const first = { schema: "audit-export-policy-v1", policy_id: "pid_52000001-0000-4000-8000-000000000001", bucket: "zasp-production-evidence", expected_bucket_owner: "123456789012", kms_key_arn: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", maximum_export_bytes: 1073741824, maximum_retained_bytes: 10737418240, maximum_inflight: 2, capture_timeout_seconds: 120 };
export function auditExportReleaseFixture() {
  const second = { ...first, policy_id: "pid_52000002-0000-4000-8000-000000000002", maximum_inflight: 3 };
  return {
    enabled: true, awsRegion: "us-west-2", queueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-audit-exports",
    stsCIDRs: ["192.0.2.16/28"], sqsCIDRs: ["192.0.2.32/28"], s3CIDRs: ["198.51.100.0/24"],
    writerRoleArn: "arn:aws:iam::123456789012:role/zasp-production-audit-export-writer",
    publisherRoleArn: "arn:aws:iam::123456789012:role/zasp-production-audit-export-publisher",
    readerRoleArn: "arn:aws:iam::123456789012:role/zasp-production-audit-export-reader",
    workerDSNSecretArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:export-worker-owned",
    outboxDSNSecretArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:export-outbox-owned",
    cursorSecretArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:export-cursor-owned",
    policies: [{ ...first }, second], currentPolicyID: second.policy_id, expectedCurrentPolicyID: first.policy_id,
    workerPrincipal: "zasp_audit_export_worker_runtime", outboxPrincipal: "zasp_audit_export_outbox_runtime",
  };
}
