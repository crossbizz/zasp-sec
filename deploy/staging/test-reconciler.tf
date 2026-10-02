variable "test_reconciler_enabled" {
  description = "Provision the existing-test evidence reader role only after schema55 rollout gates."
  type        = bool
  default     = false
}

output "test_reconciler_deployment_metadata" {
  description = "Non-secret references for the opt-in schema55 reconciler chart."
  value = var.test_reconciler_enabled ? {
    awsRegion         = var.region
    roleArn           = aws_iam_role.test_reconciler[0].arn
    databaseSecretArn = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"].arn
    evidenceBucket    = aws_s3_bucket.red_team_evidence.bucket
    evidenceOwner     = var.account_id
    evidenceKMSKeyArn = aws_kms_key.red_team.arn
  } : null
}

resource "aws_iam_role" "test_reconciler" {
  count = var.test_reconciler_enabled ? 1 : 0
  name  = "${var.cluster_name}-test-reconciler"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Action = "sts:AssumeRoleWithWebIdentity"
    Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
    Condition = { StringEquals = {
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-test-reconciler"
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
    } }
  }] })
}

resource "aws_iam_role_policy" "test_reconciler" {
  count = var.test_reconciler_enabled ? 1 : 0
  name  = "${var.cluster_name}-test-reconciler-evidence-reader"
  role  = aws_iam_role.test_reconciler[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"].arn
      } }
    },
    { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"], Resource = aws_s3_bucket.red_team_evidence.arn },
    { Effect = "Allow", Action = ["s3:GetObjectVersion"], Resource = "${aws_s3_bucket.red_team_evidence.arn}/organizations/*/workspaces/*/environments/*/artifacts/*" },
    {
      # Bucket defaults use bucket keys; retained versions may use object keys.
      # Both remain bound to this key, S3 service and scoped evidence storage.
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.red_team.arn
      Condition = {
        StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        StringLike   = { "kms:EncryptionContext:aws:s3:arn" = [aws_s3_bucket.red_team_evidence.arn, "${aws_s3_bucket.red_team_evidence.arn}/organizations/*/workspaces/*/environments/*/artifacts/*"] }
      }
    },
    { Effect = "Allow", Action = ["kms:DescribeKey"], Resource = aws_kms_key.red_team.arn },
  ] })
}
