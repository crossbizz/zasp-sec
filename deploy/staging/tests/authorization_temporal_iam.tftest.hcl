mock_provider "aws" {
  override_during = plan
  mock_resource "aws_eks_cluster" {
    defaults = { identity = [{ oidc = [{ issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/temporal-test" }] }] }
  }
  mock_resource "aws_s3_bucket" { defaults = { arn = "arn:aws:s3:::evidence" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111" } }
  mock_resource "aws_secretsmanager_secret" { defaults = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:authority" } }
}
mock_provider "tls" {
  override_during = plan
  mock_data "tls_certificate" { defaults = { certificates = [{ sha1_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }] } }
}
override_resource {
  target          = aws_iam_openid_connect_provider.eks
  override_during = plan
  values          = { arn = "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/temporal-test" }
}
variables {
  account_id         = "000000000000"
  offline_validation = true
}
run "disabled_default" {
  command = plan
  assert {
    condition     = output.authorization_temporal_deployment_metadata == null
    error_message = "Current profile must be opt-in."
  }
}
run "purpose_bound_roles" {
  command = plan
  variables { authorization_temporal_enabled = true }
  assert {
    condition     = jsondecode(aws_iam_role.authorization_temporal["worker"].assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.us-west-2.amazonaws.com/id/temporal-test:sub"] == "system:serviceaccount:agentsec:zasp-security-agent"
    error_message = "Worker IAM must bind the actual security-agent service account."
  }
  assert {
    condition     = jsondecode(aws_iam_role.authorization_temporal["projector"].assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.us-west-2.amazonaws.com/id/temporal-test:sub"] == "system:serviceaccount:agentsec:zasp-authorization-projector"
    error_message = "Projection IAM must bind its CronJob account."
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_iam_role_policy.authorization_temporal_projector[0].policy).Statement : alltrue([for a in s.Action : !startswith(a, "s3:") && !startswith(a, "sqs:") && !startswith(a, "sts:")])])
    error_message = "Projector only reads its mounted database secret; it must not gain provider/artifact/queue authority."
  }
  assert {
    condition     = anytrue([for s in jsondecode(aws_iam_role_policy.authorization_temporal_worker[0].policy).Statement : contains(s.Action, "s3:PutObject")]) && alltrue([for s in jsondecode(aws_iam_role_policy.authorization_temporal_worker[0].policy).Statement : !contains(s.Action, "sqs:ReceiveMessage")])
    error_message = "Temporal executor needs artifact writes, not ownership of retained SQS consumers."
  }
  assert {
    condition     = aws_secretsmanager_secret.authorization_temporal["postgres-temporal-executor-dsn"].tags.DatabasePrincipal != aws_secretsmanager_secret.authorization_temporal["postgres-temporal-compensation-dsn"].tags.DatabasePrincipal
    error_message = "Forward and captured compensation DSNs must remain distinct."
  }
}
