variable "authorization_temporal_enabled" {
  description = "Package the canonical61 logical78/79/80 profile. This does not assert runtime readiness."
  type        = bool
  default     = false
}

variable "temporal_database_principals" {
  description = "Dedicated login names encoded in operator-provisioned DSNs; no credential values."
  type        = object({ executor = string, compensation = string })
  default     = { executor = "zasp_temporal_executor_runtime", compensation = "zasp_temporal_compensation_runtime" }
  validation {
    condition     = var.temporal_database_principals.executor != var.temporal_database_principals.compensation && alltrue([for p in values(var.temporal_database_principals) : can(regex("^[a-z][a-z0-9_]{2,62}$", p))])
    error_message = "Temporal forward and compensation logins must be distinct valid names."
  }
}

locals {
  temporal_authorities = var.authorization_temporal_enabled ? {
    "postgres-temporal-executor-dsn"        = { purpose = "worker-forward", principal = var.temporal_database_principals.executor }
    "postgres-temporal-compensation-dsn"    = { purpose = "captured-compensation", principal = var.temporal_database_principals.compensation }
    "authorization-worker-forward-key"      = { purpose = "worker-forward", principal = "" }
    "authorization-worker-compensation-key" = { purpose = "captured-compensation", principal = "" }
  } : {}
  temporal_worker_mount_secrets = ["postgres-security-agent-worker-dsn", "openrouter-security-agent-api-key", "gateway-policy-signing-private-key", "red-team-adapter-token", "red-team-adapter-tls-certificate"]
  temporal_roles = var.authorization_temporal_enabled ? {
    worker    = { role = "temporal-worker", account = "zasp-security-agent" }
    projector = { role = "authorization-projector", account = "zasp-authorization-projector" }
  } : {}
}

# The operator writes values and synchronizes purpose-specific Kubernetes secrets.
# Terraform records their purpose and database identity, never their bytes.
resource "aws_secretsmanager_secret" "authorization_temporal" {
  for_each                = local.temporal_authorities
  name                    = "${var.cluster_name}/${each.key}"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags                    = { Purpose = each.value.purpose, DatabasePrincipal = each.value.principal }
}

resource "aws_iam_role" "authorization_temporal" {
  for_each = local.temporal_roles
  name     = "${var.cluster_name}-${each.value.role}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = "sts:AssumeRoleWithWebIdentity", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
    Condition = { StringEquals = {
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:${each.value.account}"
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
    } }
  }] })
}

resource "aws_iam_role_policy" "authorization_temporal_projector" {
  count = var.authorization_temporal_enabled ? 1 : 0
  role  = aws_iam_role.authorization_temporal["projector"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-outbox-worker-dsn"].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = {
      "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
      "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["postgres-outbox-worker-dsn"].arn
    } } }
  ] })
}

resource "aws_iam_role_policy" "authorization_temporal_worker" {
  count = var.authorization_temporal_enabled ? 1 : 0
  role  = aws_iam_role.authorization_temporal["worker"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = [for name in local.temporal_worker_mount_secrets : aws_secretsmanager_secret.product[name].arn] },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = {
      "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
      "kms:EncryptionContext:SecretARN" = [for name in local.temporal_worker_mount_secrets : aws_secretsmanager_secret.product[name].arn]
    } } },
    { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"], Resource = aws_s3_bucket.red_team_evidence.arn },
    { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"], Resource = "${aws_s3_bucket.red_team_evidence.arn}/organizations/*/workspaces/*/environments/*/artifacts/*" },
    { Effect = "Allow", Action = ["kms:DescribeKey"], Resource = aws_kms_key.red_team.arn },
    { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = aws_kms_key.red_team.arn, Condition = {
      StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
      StringLike   = { "kms:EncryptionContext:aws:s3:arn" = [aws_s3_bucket.red_team_evidence.arn, "${aws_s3_bucket.red_team_evidence.arn}/organizations/*/workspaces/*/environments/*/artifacts/*"] }
    } }
  ] })
}

resource "aws_iam_role_policy" "authorization_temporal_migration" {
  count = var.authorization_temporal_enabled ? 1 : 0
  role  = aws_iam_role.migration.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = [for name in ["workflow-signing-key", "stytch-project-id", "stytch-organization-id"] : aws_secretsmanager_secret.product[name].arn] }
  ] })
}

output "authorization_temporal_deployment_metadata" {
  description = "Non-secret deployment inputs. Operator-provisioned Kubernetes secret contents must match these registered identities."
  value = var.authorization_temporal_enabled ? {
    profile               = "canonical61-temporal78-authorization79-80-worker-v1"
    canonicalSchema       = 61
    workerRoleArn         = aws_iam_role.authorization_temporal["worker"].arn
    projectorRoleArn      = aws_iam_role.authorization_temporal["projector"].arn
    adapterRoleArn        = aws_iam_role.red_team["adapter"].arn
    executorPrincipal     = var.temporal_database_principals.executor
    compensationPrincipal = var.temporal_database_principals.compensation
    projectorPrincipal    = var.database_principals.outbox_worker
    adapterPrincipal      = var.database_principals.red_team_adapter
    authoritySecrets      = { for name, secret in aws_secretsmanager_secret.authorization_temporal : name => secret.arn }
    projectorDSN          = aws_secretsmanager_secret.product["postgres-outbox-worker-dsn"].arn
    adapterDSN            = aws_secretsmanager_secret.product["postgres-red-team-adapter-dsn"].arn
  } : null
}
