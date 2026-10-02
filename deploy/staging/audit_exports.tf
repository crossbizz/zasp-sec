locals {
  audit_export_secrets = {
    postgres-audit-export-worker-dsn = { principal = var.audit_export_database_principals.worker, role = aws_iam_role.audit_exports["writer"].id }
    postgres-audit-export-outbox-dsn = { principal = var.audit_export_database_principals.outbox, role = aws_iam_role.audit_exports["publisher"].id }
    audit-export-cursor-signing-key  = { principal = "", role = aws_iam_role.api.id }
  }
  audit_export_roles = {
    reader    = "agentsec-api"
    writer    = "zasp-audit-export-worker"
    publisher = "zasp-audit-export-outbox"
  }
}

variable "audit_export_database_principals" {
  description = "Dedicated export PostgreSQL LOGIN identities; credentials are provisioned outside Terraform."
  type        = object({ worker = string, outbox = string })
  default     = { worker = "zasp_audit_export_worker_runtime", outbox = "zasp_audit_export_outbox_runtime" }
  validation {
    condition = length(distinct(values(var.audit_export_database_principals))) == 2 && alltrue([
      for principal in values(var.audit_export_database_principals) :
      can(regex("^[a-z][a-z0-9_]{2,62}$", principal)) &&
      !contains(values(var.database_principals), principal) &&
      !contains(["zasp_audit_export_worker", "zasp_audit_export_outbox"], principal)
    ])
    error_message = "Export principals must be two distinct bounded LOGIN names, separate from existing principals and fixed capability roles."
  }
}

output "audit_export_deployment_metadata" {
  description = "Export deployment identifiers only; values, policy IDs and activation are provisioned explicitly outside this output."
  value = {
    role_arns               = { for name, role in aws_iam_role.audit_exports : name => role.arn }
    secret_arns             = { for name, secret in aws_secretsmanager_secret.audit_exports : name => secret.arn }
    database_principals     = var.audit_export_database_principals
    queue_url               = aws_sqs_queue.work["audit-exports"].id
    bucket                  = aws_s3_bucket.evidence.bucket
    expected_bucket_owner   = var.account_id
    kms_key_arn             = aws_kms_key.staging.arn
    web_identity_token_file = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
  }
}

resource "aws_secretsmanager_secret" "audit_exports" {
  for_each                = local.audit_export_secrets
  name                    = "${var.cluster_name}/${each.key}"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags                    = each.value.principal == "" ? { CredentialClass = "audit_export_cursor_signing_key" } : { DatabasePrincipal = each.value.principal, CredentialClass = "postgres_dsn" }
}

resource "aws_iam_role_policy" "audit_export_secrets" {
  for_each = local.audit_export_secrets
  name     = "${var.cluster_name}-${each.key}"
  role     = each.value.role
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.audit_exports[each.key].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = {
      "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
      "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.audit_exports[each.key].arn
    } } }
  ] })
}

resource "aws_iam_role" "audit_exports" {
  for_each = local.audit_export_roles
  name     = "${var.cluster_name}-audit-export-${each.key}"
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

resource "aws_iam_role_policy" "audit_exports" {
  for_each = local.audit_export_roles
  name     = "${var.cluster_name}-audit-export-${each.key}"
  role     = aws_iam_role.audit_exports[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [for statement in compact([
    each.key != "publisher" ? jsonencode({
      Sid      = "ReadExportVersions", Effect = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = "${aws_s3_bucket.evidence.arn}/organizations/*/workspaces/*/environments/*/exports/*"
    }) : null,
    each.key == "writer" ? jsonencode({
      Sid      = "WriteEncryptedExports", Effect = "Allow", Action = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.evidence.arn}/organizations/*/workspaces/*/environments/*/exports/*"
      Condition = { StringEquals = {
        "s3:x-amz-server-side-encryption"                = "aws:kms"
        "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.staging.arn
      } }
    }) : null,
    each.key != "publisher" ? jsonencode({
      Sid      = "ExportBucketKey", Effect = "Allow"
      Action   = concat(["kms:Decrypt"], each.key == "writer" ? ["kms:GenerateDataKey"] : [])
      Resource = aws_kms_key.staging.arn
      # S3 Bucket Keys use the bucket ARN, not an object ARN, as context.
      Condition = { StringEquals = {
        "kms:ViaService"                   = "s3.${var.region}.amazonaws.com"
        "kms:EncryptionContext:aws:s3:arn" = aws_s3_bucket.evidence.arn
      } }
    }) : null,
    each.key != "reader" ? jsonencode({
      Sid      = "ExportQueue", Effect = "Allow"
      Action   = concat(["sqs:GetQueueAttributes"], each.key == "writer" ? ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"] : ["sqs:SendMessage"])
      Resource = aws_sqs_queue.work["audit-exports"].arn
    }) : null,
    each.key != "reader" ? jsonencode({
      Sid      = "ExportQueueKey", Effect = "Allow"
      Action   = concat(["kms:Decrypt"], each.key == "publisher" ? ["kms:GenerateDataKey"] : [])
      Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
        "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["audit-exports"].arn
      } }
    }) : null
  ]) : jsondecode(statement)] })
}
