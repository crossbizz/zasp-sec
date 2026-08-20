output "vpc_id" {
  value = aws_vpc.staging.id
}
output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}
output "cluster_name" {
  value = aws_eks_cluster.staging.name
}
output "cluster_endpoint" {
  value     = aws_eks_cluster.staging.endpoint
  sensitive = true
}
output "bucket_name" {
  value = aws_s3_bucket.evidence.bucket
}
output "kms_key_arn" {
  value = aws_kms_key.staging.arn
}
output "secret_arns" {
  value = { for key, secret in aws_secretsmanager_secret.product : key => secret.arn }
}
output "database_principals" {
  description = "Non-secret stable PostgreSQL identities registered by the migration job."
  value       = local.database_principals
}
output "queue_urls" {
  value = { for key, queue in aws_sqs_queue.work : key => queue.id }
}
output "dead_letter_queue_urls" {
  value = { for key, queue in aws_sqs_queue.dead_letter : key => queue.id }
}
output "opensearch_endpoint" {
  value     = aws_opensearch_domain.events.endpoint
  sensitive = true
}
output "api_role_arn" {
  value = aws_iam_role.api.arn
}
output "connector_role_arn" {
  description = "Explicit web-identity role assumed only by the API connector runtime."
  value       = aws_iam_role.api_connectors.arn
}
output "connector_kms_key_arn" {
  description = "Dedicated KMS key for connector OAuth and provider credential records."
  value       = aws_kms_key.connector_oauth.arn
}
output "connector_secret_prefix" {
  description = "Reference-only OAuth secret namespace; secret values are never Terraform outputs."
  value       = local.connector_secret_prefix
}
output "connector_runtime_config" {
  description = "Non-secret, reference-only API connector runtime configuration."
  value = {
    ZASP_CONNECTOR_AWS_REGION              = var.region
    ZASP_CONNECTOR_ROLE_ARN                = aws_iam_role.api_connectors.arn
    ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    ZASP_CONNECTOR_KMS_KEY_ARN             = aws_kms_key.connector_oauth.arn
    ZASP_CONNECTOR_SECRET_PREFIX           = local.connector_secret_prefix
    ZASP_AWS_CUSTOMER_ROLE_PREFIXES        = jsonencode(sort(tolist(var.aws_reference_role_prefixes)))
    ZASP_AWS_CUSTOMER_ROLE_ARNS            = jsonencode(sort(tolist(var.aws_reference_role_arns)))
    ZASP_KUBERNETES_EGRESS_CIDRS           = join(",", var.kubernetes_connector_egress_cidrs)
    ZASP_GITHUB_CLIENT_ID                  = var.connector_client_ids.github
    ZASP_GITHUB_CLIENT_SECRET_REFERENCE    = "ref:github/client-secret"
    ZASP_GITHUB_APP_ID                     = var.github_app_id
    ZASP_GITHUB_PRIVATE_KEY_REFERENCE      = "ref:github/app-private-key"
    ZASP_OKTA_CLIENT_ID                    = var.connector_client_ids.okta
    ZASP_OKTA_CLIENT_SECRET_REFERENCE      = "ref:okta/client-secret"
  }
}
output "connector_reference_secret_arns" {
  description = "Reference-only secret metadata ARNs; values are provisioned outside Terraform."
  value       = { for key, secret in aws_secretsmanager_secret.connector_reference : key => secret.arn }
}
output "migration_role_arn" {
  value = aws_iam_role.migration.arn
}

output "worker_role_arn" {
  value = aws_iam_role.worker.arn
}
output "scheduler_role_arn" {
  value = aws_iam_role.scheduler.arn
}
output "canary_secret_sync_role_arn" {
  value = aws_iam_role.canary_secret_sync.arn
}
output "attack_lab_security_group_id" {
  value = aws_security_group.attack_lab.id
}
output "attack_lab_fargate_profile_arn" {
  value = aws_eks_fargate_profile.attack_lab.arn
}
