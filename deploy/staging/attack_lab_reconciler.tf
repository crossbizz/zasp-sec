variable "attack_lab_reconciler_enabled" {
  description = "Opt-in release57 settlement reader. Does not provision credentials or enable the catalog."
  type        = bool
  default     = false
}

variable "attack_lab_reconciler_database_principal" {
  description = "Separate PostgreSQL login provisioned and registered outside Terraform."
  type        = string
  default     = "attack_lab_reconciler"
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{2,62}$", var.attack_lab_reconciler_database_principal)) && !startswith(var.attack_lab_reconciler_database_principal, "zasp_") && !contains(values(var.database_principals), var.attack_lab_reconciler_database_principal)
    error_message = "The settlement principal must be canonical and separate from all existing worker logins."
  }
}

resource "aws_secretsmanager_secret" "attack_lab_reconciler_dsn" {
  count                   = var.attack_lab_reconciler_enabled ? 1 : 0
  name                    = "${var.cluster_name}/postgres-security-agent-attack-lab-reconciler-dsn"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags                    = { DatabasePrincipal = var.attack_lab_reconciler_database_principal }
}

resource "aws_iam_role" "attack_lab_reconciler" {
  count = var.attack_lab_reconciler_enabled ? 1 : 0
  name  = "${var.cluster_name}-attack-lab-reconciler"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Action = "sts:AssumeRoleWithWebIdentity"
    Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
    Condition = { StringEquals = {
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:security-agent-attack-lab-reconciler"
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
    } }
  }] })
}

resource "aws_iam_role_policy" "attack_lab_reconciler" {
  count = var.attack_lab_reconciler_enabled ? 1 : 0
  name  = "${var.cluster_name}-attack-lab-settlement-reader"
  role  = aws_iam_role.attack_lab_reconciler[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.attack_lab_reconciler_dsn[0].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = {
      "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
      "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.attack_lab_reconciler_dsn[0].arn
    } } },
    { Effect = "Allow", Action = ["s3:GetObjectVersion"], Resource = "${aws_s3_bucket.attack_lab_evidence.arn}/organizations/*/workspaces/*/environments/*/artifacts/*" },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.attack_lab.arn, Condition = {
      StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
      StringLike   = { "kms:EncryptionContext:aws:s3:arn" = [aws_s3_bucket.attack_lab_evidence.arn, "${aws_s3_bucket.attack_lab_evidence.arn}/organizations/*/workspaces/*/environments/*/artifacts/*"] }
    } },
  ] })
}

output "attack_lab_reconciler_deployment_metadata" {
  description = "Non-secret opt-in57 references. Endpoint CIDRs require independently verified snapshots."
  value = var.attack_lab_reconciler_enabled ? {
    awsRegion         = var.region
    roleArn           = aws_iam_role.attack_lab_reconciler[0].arn
    databaseSecretArn = aws_secretsmanager_secret.attack_lab_reconciler_dsn[0].arn
    workerPrincipal   = var.attack_lab_reconciler_database_principal
    evidenceBucket    = aws_s3_bucket.attack_lab_evidence.bucket
    evidenceOwner     = var.account_id
    evidenceKMSKeyArn = aws_kms_key.attack_lab.arn
  } : null
}
