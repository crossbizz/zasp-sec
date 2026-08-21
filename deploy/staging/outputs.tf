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
    ZASP_FINDING_TICKET_EGRESS_CIDRS       = join(",", var.finding_ticket_egress_cidrs)
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
output "discovery_runtime_config" {
  description = "Non-secret production discovery authority and immutable implementation fence."
  value = {
    ZASP_DISCOVERY_QUEUE_URL                    = aws_sqs_queue.work["discovery-jobs"].id
    ZASP_AWS_REGION                             = var.region
    ZASP_EVIDENCE_BUCKET                        = aws_s3_bucket.evidence.bucket
    ZASP_EVIDENCE_BUCKET_OWNER                  = var.account_id
    ZASP_EVIDENCE_KMS_KEY_ARN                   = aws_kms_key.staging.arn
    ZASP_DISCOVERY_ROLE_ARN                     = aws_iam_role.worker.arn
    ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE      = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    ZASP_DISCOVERY_SECRET_PREFIX                = local.connector_secret_root
    ZASP_DISCOVERY_AWS_COLLECTOR_VERSION        = var.discovery_implementation_versions.aws_collector
    ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION = var.discovery_implementation_versions.kubernetes_collector
    ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION     = var.discovery_implementation_versions.github_collector
    ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION       = var.discovery_implementation_versions.okta_collector
    ZASP_DISCOVERY_PARSER_VERSION               = var.discovery_implementation_versions.parser
    ZASP_DISCOVERY_TOOL_VERSION                 = var.discovery_implementation_versions.tool
    ZASP_KUBERNETES_EGRESS_CIDRS                = join(",", var.kubernetes_connector_egress_cidrs)
    ZASP_GITHUB_APP_ID                          = var.github_app_id
    ZASP_GITHUB_PRIVATE_KEY_REFERENCE           = "ref:github/app-private-key"
    ZASP_OKTA_CLIENT_ID                         = var.connector_client_ids.okta
    ZASP_OKTA_CLIENT_SECRET_REFERENCE           = "ref:okta/client-secret"
    ZASP_PROVIDER_TIMEOUT                       = "5s"
    ZASP_DISCOVERY_READINESS_TIMEOUT            = "5s"
  }
}
output "scheduler_role_arn" {
  value = aws_iam_role.scheduler.arn
}
output "outbox_role_arn" {
  value = aws_iam_role.outbox.arn
}
output "outbox_runtime_config" {
  description = "Non-secret, explicit discovery outbox publication authority."
  value = {
    ZASP_AWS_REGION                     = var.region
    ZASP_DISCOVERY_QUEUE_URL            = aws_sqs_queue.work["discovery-jobs"].id
    ZASP_OUTBOX_ROLE_ARN                = aws_iam_role.outbox.arn
    ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
  }
}
output "projection_search_role_arn" {
  value = aws_iam_role.projection_search.arn
}
output "projection_search_init_authority" {
  description = "Exact one-shot OpenSearch mapping and immutable schema-marker authority."
  value = {
    ZASP_AWS_REGION                              = var.region
    ZASP_PROJECTION_INIT_ROLE_ARN                = aws_iam_role.projection_search_init.arn
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    ZASP_PROJECTION_INIT_TIMEOUT                 = "20s"
    ZASP_OPENSEARCH_ENDPOINT                     = "https://${aws_opensearch_domain.events.endpoint}"
    ZASP_OPENSEARCH_INDEX                        = "zasp-inventory-v1"
  }
}
output "projection_search_runtime_config" {
  description = "Non-secret, explicit production search projection authority."
  value = {
    ZASP_AWS_REGION                         = var.region
    ZASP_PROJECTION_ROLE_ARN                = aws_iam_role.projection_search.arn
    ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    ZASP_OPENSEARCH_ENDPOINT                = "https://${aws_opensearch_domain.events.endpoint}"
    ZASP_OPENSEARCH_INDEX                   = "zasp-inventory-v1"
  }
}
output "projection_risk_role_arn" {
  value = aws_iam_role.projection_risk.arn
}
output "projection_graph_role_arn" {
  value = aws_iam_role.projection_graph.arn
}
output "projection_graph_runtime_config" {
  description = "Non-secret graph projection authority; the Neo4j credential remains reference-only."
  value = {
    ZASP_AWS_REGION                         = var.region
    ZASP_PROJECTION_ROLE_ARN                = aws_iam_role.projection_graph.arn
    ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    ZASP_PROJECTION_SECRET_PREFIX           = local.projection_secret_root
    ZASP_NEO4J_URI                          = var.neo4j_endpoint
    ZASP_NEO4J_CREDENTIAL_REFERENCE         = "ref:neo4j/auth/runtime"
    ZASP_NEO4J_EXPECTED_PRINCIPAL           = "zasp_projection_runtime"
    ZASP_NEO4J_EXPECTED_ROLE                = "publisher"
    ZASP_NEO4J_ENDPOINT_CIDR                = var.neo4j_endpoint_cidr
  }
}
output "projection_graph_init_authority" {
  description = "Reference-only one-shot Neo4j constraint authority; no credential value is exported."
  value = {
    ZASP_AWS_REGION                              = var.region
    ZASP_PROJECTION_INIT_ROLE_ARN                = aws_iam_role.projection_graph_init.arn
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    ZASP_PROJECTION_INIT_TIMEOUT                 = "20s"
    ZASP_PROJECTION_SECRET_PREFIX                = local.projection_secret_root
    ZASP_NEO4J_URI                               = var.neo4j_endpoint
    ZASP_NEO4J_SCHEMA_CREDENTIAL_REFERENCE       = "ref:neo4j/auth/schema"
    credential_secret_arn                        = aws_secretsmanager_secret.neo4j_projection_schema.arn
  }
}
output "runtime_release_authority" {
  description = "Non-secret immutable Task 6 queue, object, index, and per-workload identity authority."
  value = {
    aws_region               = var.region
    queue_url                = aws_sqs_queue.work["runtime-events"].id
    raw_bucket               = aws_s3_bucket.runtime_raw.bucket
    raw_bucket_owner         = var.account_id
    raw_kms_key_arn          = aws_kms_key.runtime_raw.arn
    opensearch_endpoint      = "https://${aws_opensearch_domain.events.endpoint}"
    opensearch_index         = "zasp-runtime-events-v1"
    web_identity_token_file  = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    ingest_role_arn          = aws_iam_role.runtime["ingest"].arn
    gateway_control_role_arn = aws_iam_role.runtime["gateway_control"].arn
    outbox_role_arn          = aws_iam_role.runtime["outbox"].arn
    coordinator_role_arn     = aws_iam_role.runtime["coordinator"].arn
    archive_role_arn         = aws_iam_role.runtime["archive"].arn
    index_role_arn           = aws_iam_role.runtime["index"].arn
    correlation_role_arn     = aws_iam_role.runtime["correlation"].arn
    projection_role_arn      = aws_iam_role.runtime["projection"].arn
    complete_role_arn        = aws_iam_role.runtime["complete"].arn
  }
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
