variable "compliance_exports_enabled" {
  description = "Provision dedicated compliance export storage and workload identities after schema56 rollout gates."
  type        = bool
  default     = false
}

variable "compliance_export_database_principals" {
  description = "Distinct compliance LOGIN identities; operators provision credentials outside Terraform."
  type        = object({ worker = string, cleanup = string })
  default     = { worker = "compliance_export_runtime", cleanup = "compliance_cleanup_runtime" }
  validation {
    condition = length(distinct(values(var.compliance_export_database_principals))) == 2 && alltrue([
      for principal in values(var.compliance_export_database_principals) :
      can(regex("^[a-z][a-z0-9_]{2,62}$", principal)) && !startswith(principal, "zasp_") &&
      !contains(values(var.database_principals), principal) &&
      !contains(values(var.audit_export_database_principals), principal)
    ])
    error_message = "Compliance principals must be distinct bounded lowercase LOGIN names, outside the zasp_ namespace and all predecessor principals."
  }
}

locals {
  compliance_export_identities = var.compliance_exports_enabled ? {
    reader  = "agentsec-api"
    writer  = "zasp-compliance-export-worker"
    cleanup = "zasp-compliance-cleanup-worker"
  } : {}
  compliance_export_read_actions = {
    reader  = ["s3:GetObjectVersion"]
    writer  = ["s3:GetObject", "s3:GetObjectVersion"]
    cleanup = ["s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObjectVersion"]
  }
  compliance_export_secrets = var.compliance_exports_enabled ? {
    writer  = { name = "postgres-compliance-export-worker-dsn", principal = var.compliance_export_database_principals.worker }
    cleanup = { name = "postgres-compliance-cleanup-worker-dsn", principal = var.compliance_export_database_principals.cleanup }
  } : {}
}

resource "aws_kms_key" "compliance_exports" {
  count                   = var.compliance_exports_enabled ? 1 : 0
  description             = "Dedicated compliance export object encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "compliance_exports" {
  count  = var.compliance_exports_enabled ? 1 : 0
  bucket = "zasp-compliance-exports-${md5(var.account_id)}"
}

resource "aws_s3_bucket_versioning" "compliance_exports" {
  count  = var.compliance_exports_enabled ? 1 : 0
  bucket = aws_s3_bucket.compliance_exports[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_ownership_controls" "compliance_exports" {
  count  = var.compliance_exports_enabled ? 1 : 0
  bucket = aws_s3_bucket.compliance_exports[0].id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "compliance_exports" {
  count                   = var.compliance_exports_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.compliance_exports[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_exports" {
  count  = var.compliance_exports_enabled ? 1 : 0
  bucket = aws_s3_bucket.compliance_exports[0].id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.compliance_exports[0].arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "compliance_exports" {
  count  = var.compliance_exports_enabled ? 1 : 0
  bucket = aws_s3_bucket.compliance_exports[0].id
  # Storage backstop only. UTC-rounded lifecycle eligibility does not guarantee
  # physical deletion within 24 hours; active cleanup tracks exact versions.
  rule {
    id     = "compliance-export-expiration-backstop"
    status = "Enabled"
    filter { prefix = "organizations/" }
    expiration { days = 1 }
    noncurrent_version_expiration { noncurrent_days = 1 }
  }
  rule {
    id     = "compliance-export-delete-marker-cleanup"
    status = "Enabled"
    filter { prefix = "organizations/" }
    expiration { expired_object_delete_marker = true }
  }
  depends_on = [aws_s3_bucket_versioning.compliance_exports]
}

resource "aws_s3_bucket_policy" "compliance_exports" {
  count  = var.compliance_exports_enabled ? 1 : 0
  bucket = aws_s3_bucket.compliance_exports[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "RequireTLS"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Resource  = [aws_s3_bucket.compliance_exports[0].arn, "${aws_s3_bucket.compliance_exports[0].arn}/*"]
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}

resource "aws_iam_role" "compliance_exports" {
  for_each = local.compliance_export_identities
  name     = "${var.cluster_name}-compliance-export-${each.key}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow"
    Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
    Action    = "sts:AssumeRoleWithWebIdentity"
    Condition = { StringEquals = {
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:${each.value}"
    } }
  }] })
}

resource "aws_iam_role_policy" "compliance_exports" {
  for_each = local.compliance_export_identities
  name     = "${var.cluster_name}-compliance-export-${each.key}"
  role     = aws_iam_role.compliance_exports[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [for statement in compact([
    jsonencode({
      Sid      = "ExportVersions", Effect = "Allow"
      Action   = local.compliance_export_read_actions[each.key]
      Resource = "${aws_s3_bucket.compliance_exports[0].arn}/organizations/*/workspaces/*/environments/*/exports/*"
    }),
    each.key == "writer" ? jsonencode({
      Sid      = "WriteEncryptedExports", Effect = "Allow", Action = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.compliance_exports[0].arn}/organizations/*/workspaces/*/environments/*/exports/*"
      Condition = { StringEquals = {
        "s3:x-amz-server-side-encryption"                = "aws:kms"
        "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.compliance_exports[0].arn
      } }
    }) : null,
    jsonencode({
      Sid      = "ExportKey", Effect = "Allow"
      Action   = concat(["kms:Decrypt"], each.key == "writer" ? ["kms:GenerateDataKey"] : [])
      Resource = aws_kms_key.compliance_exports[0].arn
      # Bucket keys use the bucket context; non-bucket-key objects use the prefix.
      Condition = {
        StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        StringLike   = { "kms:EncryptionContext:aws:s3:arn" = [aws_s3_bucket.compliance_exports[0].arn, "${aws_s3_bucket.compliance_exports[0].arn}/organizations/*/workspaces/*/environments/*/exports/*"] }
      }
    })
  ]) : jsondecode(statement)] })
}

resource "aws_secretsmanager_secret" "compliance_exports" {
  for_each                = local.compliance_export_secrets
  name                    = "${var.cluster_name}/${each.value.name}"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags                    = { DatabasePrincipal = each.value.principal, CredentialClass = "postgres_dsn" }
}

resource "aws_iam_role_policy" "compliance_export_secrets" {
  for_each = local.compliance_export_secrets
  name     = "${var.cluster_name}-${each.value.name}"
  role     = aws_iam_role.compliance_exports[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.compliance_exports[each.key].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = {
      "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
      "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.compliance_exports[each.key].arn
    } } }
  ] })
}

output "compliance_exports_deployment_metadata" {
  description = "Non-secret complianceExports fields only. Operators must supply the three deployment CIDR lists and provision external credentials."
  value = var.compliance_exports_enabled ? {
    enabled             = true
    awsRegion           = var.region
    bucket              = aws_s3_bucket.compliance_exports[0].bucket
    bucketOwner         = var.account_id
    kmsKeyArn           = aws_kms_key.compliance_exports[0].arn
    readerRoleArn       = aws_iam_role.compliance_exports["reader"].arn
    writerRoleArn       = aws_iam_role.compliance_exports["writer"].arn
    cleanupRoleArn      = aws_iam_role.compliance_exports["cleanup"].arn
    workerDSNSecretArn  = aws_secretsmanager_secret.compliance_exports["writer"].arn
    cleanupDSNSecretArn = aws_secretsmanager_secret.compliance_exports["cleanup"].arn
    workerPrincipal     = var.compliance_export_database_principals.worker
    cleanupPrincipal    = var.compliance_export_database_principals.cleanup
  } : null
}
