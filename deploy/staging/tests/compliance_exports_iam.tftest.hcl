# These assertions require the pinned AWS/TLS provider schemas, even when mocked.
# They are not a live IAM acceptance test. Secret-version absence is also checked
# by compliance-exports-contract.test.mjs; Terraform creates metadata only here.
mock_provider "aws" {
  override_during = plan
  mock_resource "aws_eks_cluster" {
    defaults = { identity = [{ oidc = [{ issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/compliance-test" }] }] }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111" }
  }
}
mock_provider "tls" {
  override_during = plan
  mock_data "tls_certificate" {
    defaults = { certificates = [{ sha1_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }] }
  }
}
override_resource {
  target          = aws_iam_openid_connect_provider.eks
  override_during = plan
  values = {
    arn = "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/compliance-test"
    url = "https://oidc.eks.us-west-2.amazonaws.com/id/compliance-test"
  }
}

variables {
  account_id         = "000000000000"
  offline_validation = true
}

run "disabled_by_default" {
  command = plan
  assert {
    condition     = output.compliance_exports_deployment_metadata == null
    error_message = "Disabled compliance exports must not publish active deployment metadata."
  }
  assert {
    condition = alltrue([
      length(aws_kms_key.compliance_exports) == 0,
      length(aws_s3_bucket.compliance_exports) == 0,
      length(aws_s3_bucket_versioning.compliance_exports) == 0,
      length(aws_s3_bucket_ownership_controls.compliance_exports) == 0,
      length(aws_s3_bucket_public_access_block.compliance_exports) == 0,
      length(aws_s3_bucket_server_side_encryption_configuration.compliance_exports) == 0,
      length(aws_s3_bucket_lifecycle_configuration.compliance_exports) == 0,
      length(aws_s3_bucket_policy.compliance_exports) == 0,
      length(aws_iam_role.compliance_exports) == 0,
      length(aws_iam_role_policy.compliance_exports) == 0,
      length(aws_secretsmanager_secret.compliance_exports) == 0,
      length(aws_iam_role_policy.compliance_export_secrets) == 0,
    ])
    error_message = "Every compliance resource must remain absent unless explicitly enabled."
  }
}

run "isolated_versioned_exports" {
  command = plan
  variables { compliance_exports_enabled = true }

  override_resource {
    target          = aws_s3_bucket.compliance_exports[0]
    override_during = plan
    values          = { arn = "arn:aws:s3:::compliance-exports-test", id = "compliance-exports-test" }
  }
  override_resource {
    target          = aws_kms_key.compliance_exports[0]
    override_during = plan
    values          = { arn = "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222" }
  }
  override_resource {
    target          = aws_secretsmanager_secret.compliance_exports["writer"]
    override_during = plan
    values          = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:compliance-worker-AAAAAA" }
  }
  override_resource {
    target          = aws_secretsmanager_secret.compliance_exports["cleanup"]
    override_during = plan
    values          = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:compliance-cleanup-BBBBBB" }
  }
  override_resource {
    target          = aws_iam_role.compliance_exports["reader"]
    override_during = plan
    values          = { arn = "arn:aws:iam::000000000000:role/compliance-reader", id = "compliance-reader" }
  }
  override_resource {
    target          = aws_iam_role.compliance_exports["writer"]
    override_during = plan
    values          = { arn = "arn:aws:iam::000000000000:role/compliance-writer", id = "compliance-writer" }
  }
  override_resource {
    target          = aws_iam_role.compliance_exports["cleanup"]
    override_during = plan
    values          = { arn = "arn:aws:iam::000000000000:role/compliance-cleanup", id = "compliance-cleanup" }
  }

  assert {
    condition     = aws_s3_bucket.compliance_exports[0].bucket == "zasp-compliance-exports-${md5("000000000000")}" && aws_s3_bucket.compliance_exports[0].bucket != aws_s3_bucket.evidence.bucket && aws_s3_bucket.compliance_exports[0].bucket != aws_s3_bucket.red_team_evidence.bucket && !aws_s3_bucket.compliance_exports[0].force_destroy
    error_message = "Compliance storage must use its dedicated canonical bucket and must not force-delete objects."
  }
  assert {
    condition     = aws_s3_bucket_versioning.compliance_exports[0].versioning_configuration[0].status == "Enabled" && aws_s3_bucket_versioning.compliance_exports[0].bucket == aws_s3_bucket.compliance_exports[0].id
    error_message = "Compliance objects require immutable versions in the dedicated bucket."
  }
  assert {
    condition = (
      one(aws_s3_bucket_ownership_controls.compliance_exports[0].rule).object_ownership == "BucketOwnerEnforced" &&
      aws_s3_bucket_public_access_block.compliance_exports[0].block_public_acls &&
      aws_s3_bucket_public_access_block.compliance_exports[0].block_public_policy &&
      aws_s3_bucket_public_access_block.compliance_exports[0].ignore_public_acls &&
      aws_s3_bucket_public_access_block.compliance_exports[0].restrict_public_buckets &&
      aws_s3_bucket_public_access_block.compliance_exports[0].bucket == aws_s3_bucket.compliance_exports[0].id &&
      aws_s3_bucket_ownership_controls.compliance_exports[0].bucket == aws_s3_bucket.compliance_exports[0].id
    )
    error_message = "The compliance bucket must enforce owner-only ownership and block every public-access path."
  }
  assert {
    condition = (
      length(aws_s3_bucket_server_side_encryption_configuration.compliance_exports[0].rule) == 1 &&
      one(aws_s3_bucket_server_side_encryption_configuration.compliance_exports[0].rule).bucket_key_enabled &&
      one(one(aws_s3_bucket_server_side_encryption_configuration.compliance_exports[0].rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms" &&
      one(one(aws_s3_bucket_server_side_encryption_configuration.compliance_exports[0].rule).apply_server_side_encryption_by_default).kms_master_key_id == "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222" &&
      aws_s3_bucket_server_side_encryption_configuration.compliance_exports[0].bucket == aws_s3_bucket.compliance_exports[0].id &&
      aws_kms_key.compliance_exports[0].enable_key_rotation && aws_kms_key.compliance_exports[0].deletion_window_in_days == 30
    )
    error_message = "SSE-KMS must use the dedicated rotating key and bucket keys."
  }
  assert {
    condition = (
      length(aws_s3_bucket_lifecycle_configuration.compliance_exports[0].rule) == 2 &&
      aws_s3_bucket_lifecycle_configuration.compliance_exports[0].bucket == aws_s3_bucket.compliance_exports[0].id &&
      alltrue([for r in aws_s3_bucket_lifecycle_configuration.compliance_exports[0].rule : r.status == "Enabled" && one(r.filter).prefix == "organizations/"]) &&
      length([for r in aws_s3_bucket_lifecycle_configuration.compliance_exports[0].rule : r if try(one(r.expiration).days == 1 && one(r.noncurrent_version_expiration).noncurrent_days == 1, false)]) == 1 &&
      length([for r in aws_s3_bucket_lifecycle_configuration.compliance_exports[0].rule : r if try(one(r.expiration).expired_object_delete_marker == true && length(r.noncurrent_version_expiration) == 0, false)]) == 1
    )
    error_message = "Current/noncurrent one-day expiration and separate expired-marker cleanup are required as a storage backstop, not a physical 24-hour deletion guarantee."
  }
  assert {
    condition = aws_s3_bucket_policy.compliance_exports[0].bucket == aws_s3_bucket.compliance_exports[0].id && jsonencode(jsondecode(aws_s3_bucket_policy.compliance_exports[0].policy)) == jsonencode({
      Version = "2012-10-17", Statement = [{
        Sid       = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*"
        Resource  = ["arn:aws:s3:::compliance-exports-test", "arn:aws:s3:::compliance-exports-test/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }]
    })
    error_message = "The bucket policy must deny all plaintext transport without adding access grants."
  }
  assert {
    condition = (
      toset(keys(aws_iam_role.compliance_exports)) == toset(["reader", "writer", "cleanup"]) &&
      toset(keys(aws_iam_role_policy.compliance_exports)) == toset(["reader", "writer", "cleanup"]) &&
      length(distinct([for role in aws_iam_role.compliance_exports : role.name])) == 3 &&
      alltrue([for name, role in aws_iam_role.compliance_exports : role.name == "zasp-staging-compliance-export-${name}" && jsonencode(jsondecode(role.assume_role_policy)) == jsonencode({
        Version = "2012-10-17", Statement = [{
          Effect    = "Allow", Action = "sts:AssumeRoleWithWebIdentity"
          Principal = { Federated = "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/compliance-test" }
          Condition = { StringEquals = {
            "oidc.eks.us-west-2.amazonaws.com/id/compliance-test:aud" = "sts.amazonaws.com"
            "oidc.eks.us-west-2.amazonaws.com/id/compliance-test:sub" = "system:serviceaccount:agentsec:${ { reader = "agentsec-api", writer = "zasp-compliance-export-worker", cleanup = "zasp-compliance-cleanup-worker" }[name]}"
          } }
        }]
      })])
    )
    error_message = "Exactly three distinct roles must trust only their service account, STS audience, and EKS OIDC provider."
  }
  assert {
    condition = alltrue([for name, policy in aws_iam_role_policy.compliance_exports :
      policy.role == aws_iam_role.compliance_exports[name].id &&
      length(jsondecode(policy.policy).Statement) == (name == "writer" ? 3 : 2) &&
      alltrue([for s in jsondecode(policy.policy).Statement : s.Effect == "Allow"]) &&
      toset(flatten([for s in jsondecode(policy.policy).Statement : s.Action])) == toset({
        reader  = ["s3:GetObjectVersion", "kms:Decrypt"]
        writer  = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "kms:Decrypt", "kms:GenerateDataKey"]
        cleanup = ["s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObjectVersion", "kms:Decrypt"]
      }[name]) &&
      alltrue([for s in jsondecode(policy.policy).Statement : s.Resource == "arn:aws:s3:::compliance-exports-test/organizations/*/workspaces/*/environments/*/exports/*" if anytrue([for action in s.Action : startswith(action, "s3:")])]) &&
      length([for s in jsondecode(policy.policy).Statement : s if contains(s.Action, "kms:Decrypt") && jsonencode(s) == jsonencode({
        Sid    = "ExportKey", Effect = "Allow", Resource = "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222"
        Action = name == "writer" ? ["kms:Decrypt", "kms:GenerateDataKey"] : ["kms:Decrypt"]
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.us-west-2.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:aws:s3:arn" = ["arn:aws:s3:::compliance-exports-test", "arn:aws:s3:::compliance-exports-test/organizations/*/workspaces/*/environments/*/exports/*"] }
        }
      })]) == 1
    ])
    error_message = "Each role must retain its exact object/KMS actions, dedicated object prefix, key and encryption contexts; no current-key deletion, queues or other authority."
  }
  assert {
    condition = length([for s in jsondecode(aws_iam_role_policy.compliance_exports["writer"].policy).Statement : s if contains(s.Action, "s3:PutObject") && jsonencode(s.Condition) == jsonencode({
      StringEquals = {
        "s3:x-amz-server-side-encryption"                = "aws:kms"
        "s3:x-amz-server-side-encryption-aws-kms-key-id" = "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222"
      }
    })]) == 1
    error_message = "Writer PutObject requires both exact encryption headers."
  }
  assert {
    condition = (
      toset(keys(aws_secretsmanager_secret.compliance_exports)) == toset(["writer", "cleanup"]) &&
      toset(keys(aws_iam_role_policy.compliance_export_secrets)) == toset(["writer", "cleanup"]) &&
      alltrue([for name, secret in aws_secretsmanager_secret.compliance_exports :
        secret.name == { writer = "zasp-staging/postgres-compliance-export-worker-dsn", cleanup = "zasp-staging/postgres-compliance-cleanup-worker-dsn" }[name] &&
        secret.kms_key_id == "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111" &&
        secret.recovery_window_in_days == 30 && secret.tags.CredentialClass == "postgres_dsn" &&
        secret.tags.DatabasePrincipal == { writer = "compliance_export_runtime", cleanup = "compliance_cleanup_runtime" }[name]
      ]) &&
      alltrue([for name, policy in aws_iam_role_policy.compliance_export_secrets : policy.role == aws_iam_role.compliance_exports[name].id && jsonencode(jsondecode(policy.policy)) == jsonencode({
        Version = "2012-10-17", Statement = [
          { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.compliance_exports[name].arn },
          { Effect = "Allow", Action = ["kms:Decrypt"], Resource = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111", Condition = { StringEquals = {
            "kms:ViaService"                  = "secretsmanager.us-west-2.amazonaws.com"
            "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.compliance_exports[name].arn
          } } }
        ]
      })])
    )
    error_message = "Only the two worker roles may read their own DSN metadata reference and decrypt its matching Secrets Manager context."
  }
  assert {
    condition = jsonencode(output.compliance_exports_deployment_metadata) == jsonencode({
      enabled             = true
      awsRegion           = "us-west-2"
      bucket              = "zasp-compliance-exports-${md5("000000000000")}"
      bucketOwner         = "000000000000"
      kmsKeyArn           = "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222"
      readerRoleArn       = "arn:aws:iam::000000000000:role/compliance-reader"
      writerRoleArn       = "arn:aws:iam::000000000000:role/compliance-writer"
      cleanupRoleArn      = "arn:aws:iam::000000000000:role/compliance-cleanup"
      workerDSNSecretArn  = "arn:aws:secretsmanager:us-west-2:000000000000:secret:compliance-worker-AAAAAA"
      cleanupDSNSecretArn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:compliance-cleanup-BBBBBB"
      workerPrincipal     = "compliance_export_runtime"
      cleanupPrincipal    = "compliance_cleanup_runtime"
    })
    error_message = "Deployment metadata must contain exactly the non-network complianceExports fields, without credential values or invented CIDRs."
  }
}

run "reject_duplicate_principals" {
  command = plan
  variables { compliance_export_database_principals = { worker = "compliance_same", cleanup = "compliance_same" } }
  expect_failures = [var.compliance_export_database_principals]
}

run "reject_capability_namespace" {
  command = plan
  variables { compliance_export_database_principals = { worker = "zasp_compliance_worker", cleanup = "compliance_cleanup_runtime" } }
  expect_failures = [var.compliance_export_database_principals]
}

run "reject_malformed_principal" {
  command = plan
  variables { compliance_export_database_principals = { worker = "Compliance Worker", cleanup = "compliance_cleanup_runtime" } }
  expect_failures = [var.compliance_export_database_principals]
}

run "reject_audit_principal_collision" {
  command = plan
  variables {
    audit_export_database_principals = { worker = "compliance_export_runtime", outbox = "audit_outbox_runtime" }
  }
  expect_failures = [var.compliance_export_database_principals]
}
