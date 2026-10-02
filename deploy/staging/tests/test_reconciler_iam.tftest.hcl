mock_provider "aws" {
  override_during = plan
  mock_resource "aws_eks_cluster" {
    defaults = { identity = [{ oidc = [{ issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/reconciler-test" }] }] }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::unrelated-evidence" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111" }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:unrelated-secret" }
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
  values          = { arn = "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/reconciler-test" }
}

variables {
  account_id         = "000000000000"
  offline_validation = true
}

override_resource {
  target          = aws_s3_bucket.red_team_evidence
  override_during = plan
  values          = { arn = "arn:aws:s3:::reconciler-evidence" }
}
override_resource {
  target          = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"]
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:worker-dsn" }
}
override_resource {
  target          = aws_kms_key.red_team
  override_during = plan
  values          = { arn = "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222" }
}

override_resource {
  target          = aws_iam_role.test_reconciler[0]
  override_during = plan
  values          = { arn = "arn:aws:iam::000000000000:role/zasp-staging-test-reconciler", id = "zasp-staging-test-reconciler" }
}

run "disabled_by_default" {
  command = plan
  assert {
    condition     = output.test_reconciler_deployment_metadata == null
    error_message = "Disabled reconciler must not publish active deployment metadata."
  }
  assert {
    condition     = length(aws_iam_role.test_reconciler) == 0 && length(aws_iam_role_policy.test_reconciler) == 0
    error_message = "Reconciler IAM must remain opt-in."
  }
}

run "registered_evidence_reader" {
  command = plan
  variables { test_reconciler_enabled = true }
  assert {
    condition     = try(output.test_reconciler_deployment_metadata.databaseSecretArn == "arn:aws:secretsmanager:us-west-2:000000000000:secret:worker-dsn" && output.test_reconciler_deployment_metadata.evidenceKMSKeyArn == "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222" && output.test_reconciler_deployment_metadata.evidenceOwner == "000000000000" && output.test_reconciler_deployment_metadata.awsRegion == "us-west-2" && output.test_reconciler_deployment_metadata.roleArn == aws_iam_role.test_reconciler[0].arn && output.test_reconciler_deployment_metadata.evidenceBucket == aws_s3_bucket.red_team_evidence.bucket, false)
    error_message = "Enabled metadata must bind the chart to provisioned non-secret references."
  }
  assert {
    condition     = length(jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement) == 7 && alltrue([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s.Effect == "Allow" && (contains(s.Action, "sts:GetCallerIdentity") || s.Resource != "*")])
    error_message = "No additional policy statement or wildcard data resource is allowed."
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s.Resource == "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222" if contains(s.Action, "kms:DescribeKey") || try(s.Condition.StringEquals["kms:ViaService"], "") == "s3.us-west-2.amazonaws.com"])
    error_message = "Evidence KMS operations must use the red-team key, not another application key."
  }
  assert {
    condition     = length([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s if contains(s.Action, "kms:Decrypt") && s.Resource == "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111" && try(s.Condition.StringEquals["kms:ViaService"], "") == "secretsmanager.us-west-2.amazonaws.com" && try(s.Condition.StringEquals["kms:EncryptionContext:SecretARN"], "") == "arn:aws:secretsmanager:us-west-2:000000000000:secret:worker-dsn"]) == 1
    error_message = "DSN decrypt must use the exact staging key, secret ARN and Secrets Manager service."
  }
  assert {
    condition     = length(jsondecode(aws_iam_role.test_reconciler[0].assume_role_policy).Statement) == 1 && alltrue([for s in jsondecode(aws_iam_role.test_reconciler[0].assume_role_policy).Statement : s.Principal.Federated == "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/reconciler-test"])
    error_message = "Only the provisioned EKS OIDC provider may assume this role."
  }
  assert {
    condition = toset(flatten([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s.Action])) == toset([
      "sts:GetCallerIdentity", "secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "kms:Decrypt", "kms:DescribeKey",
      "s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetObjectVersion"
    ])
    error_message = "Only identity, exact DSN, bucket readiness, versioned artifact reads and KMS reads are allowed."
  }
  assert {
    condition     = length([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s if contains(s.Action, "s3:GetObjectVersion") && s.Resource == "arn:aws:s3:::reconciler-evidence/organizations/*/workspaces/*/environments/*/artifacts/*"]) == 1
    error_message = "Artifact reads must be scoped to versioned tenant artifact paths."
  }
  assert {
    condition     = length([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s if contains(s.Action, "secretsmanager:GetSecretValue") && s.Resource == "arn:aws:secretsmanager:us-west-2:000000000000:secret:worker-dsn"]) == 1
    error_message = "Only the existing registered worker DSN metadata is readable; no planner or target credentials."
  }
  assert {
    condition     = length([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s if contains(s.Action, "kms:Decrypt") && try(s.Condition.StringEquals["kms:ViaService"], "") == "s3.us-west-2.amazonaws.com" && try(toset(s.Condition.StringLike["kms:EncryptionContext:aws:s3:arn"]) == toset(["arn:aws:s3:::reconciler-evidence", "arn:aws:s3:::reconciler-evidence/organizations/*/workspaces/*/environments/*/artifacts/*"]), false)]) == 1
    error_message = "Decrypt must support bucket-key and retained artifact-object contexts, with exact S3 service and bounded paths."
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_iam_role_policy.test_reconciler[0].policy).Statement : s.Resource == "arn:aws:s3:::reconciler-evidence" if contains(s.Action, "s3:ListBucket") || contains(s.Action, "s3:GetBucketVersioning") || contains(s.Action, "s3:GetEncryptionConfiguration")])
    error_message = "Every bucket readiness action must bind the provisioned evidence bucket."
  }
  assert {
    condition     = length([for s in jsondecode(aws_iam_role.test_reconciler[0].assume_role_policy).Statement : s if s.Action == "sts:AssumeRoleWithWebIdentity" && try(s.Condition.StringEquals["oidc.eks.us-west-2.amazonaws.com/id/reconciler-test:sub"], "") == "system:serviceaccount:agentsec:zasp-test-reconciler" && try(s.Condition.StringEquals["oidc.eks.us-west-2.amazonaws.com/id/reconciler-test:aud"], "") == "sts.amazonaws.com"]) == 1
    error_message = "Trust must bind the reconciler service account and STS audience."
  }
}
