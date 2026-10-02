// Synthetic authority only. These references are not a deployment approval.
export function complianceExportReleaseFixture() {
  return {
    enabled: true, awsRegion: "us-west-2", bucket: "zasp-compliance-fixture", bucketOwner: "123456789012",
    kmsKeyArn: "arn:aws:kms:us-west-2:123456789012:key/56000000-0000-4000-8000-000000000001",
    readerRoleArn: "arn:aws:iam::123456789012:role/compliance-reader",
    writerRoleArn: "arn:aws:iam::123456789012:role/compliance-writer",
    cleanupRoleArn: "arn:aws:iam::123456789012:role/compliance-cleanup",
    workerDSNSecretArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:compliance-worker-owned",
    cleanupDSNSecretArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:compliance-cleanup-owned",
    workerPrincipal: "compliance_export_runtime", cleanupPrincipal: "compliance_cleanup_runtime",
    databaseCIDRs: ["10.30.0.0/24"], stsCIDRs: ["192.0.2.16/28"], s3CIDRs: ["198.51.100.0/24"],
  };
}
