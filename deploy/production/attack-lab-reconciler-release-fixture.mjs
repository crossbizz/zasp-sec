export function attackLabReconcilerReleaseFixture() {
  return { enabled: true, awsRegion: "us-west-2", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-reconciler",
    databaseSecretArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:postgres-security-agent-attack-lab-reconciler-dsn", workerPrincipal: "attack_lab_reconciler",
    evidenceBucket: "zasp-production-attack-lab-evidence", evidenceOwner: "123456789012", evidenceKMSKeyArn: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
    databaseCIDRs: ["10.30.0.0/24"], stsCIDRs: ["10.31.0.0/28"], s3CIDRs: ["10.32.0.0/28"] };
}
