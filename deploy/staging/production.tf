# Production additions for a deployment on the baseline schema.
#
# Everything in this file that creates a resource is opt-in and defaults to off,
# so the closed staging source profile (tests/iam_policy_union.tftest.hcl) is
# unchanged. deploy/production/example.tfvars turns the production options on.
# Nothing here has been applied to an AWS account.
# See docs/operations/production-aws-runbook.md.

variable "schema_install" {
  description = "Which product schema the deployment runs. baseline: agentsec-migrate install-baseline, whose operator role (zasp_operator) and service logins (zasp_svc_*) have fixed names; database_principals and temporal_database_principals are then ignored. chain: the historical migration chain, which takes its login names from those two variables."
  type        = string
  default     = "baseline"
  validation {
    condition     = contains(["baseline", "chain"], var.schema_install)
    error_message = "schema_install must be baseline or chain."
  }
}

variable "public_subnet_cidrs" {
  description = "Owner decision. Two public subnet CIDRs inside vpc_cidr, disjoint from the private and Attack Lab subnets, or an empty list. Two CIDRs create an internet gateway, two public subnets tagged for internet-facing load balancers, one NAT gateway in the first availability zone and a default route for the private subnets. An empty list keeps the VPC without any internet path: the product then cannot reach Neon, Stytch, OpenRouter, GitHub, Okta, customer Kubernetes APIs or public image registries, and nothing can reach its ingress from the internet."
  type        = list(string)
  default     = []
  validation {
    condition     = contains([0, 2], length(var.public_subnet_cidrs)) && length(distinct(var.public_subnet_cidrs)) == length(var.public_subnet_cidrs) && alltrue([for cidr in var.public_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "public_subnet_cidrs must be empty or two distinct IPv4 CIDRs."
  }
}

variable "vpc_cni_network_policy_enabled" {
  description = "Owner decision. true turns on the VPC CNI network policy agent, so the chart's NetworkPolicy objects are enforced. They are CIDR allow-lists: every provider address (Neon, Stytch, OpenRouter, GitHub, Okta, AWS endpoints) must then be listed correctly in the Helm values or the workload loses that connection. false leaves the policies unenforced."
  type        = bool
  default     = false
}

variable "create_opensearch_service_linked_role" {
  description = "Create AWSServiceRoleForAmazonOpenSearchService. A VPC OpenSearch domain cannot be created in an account that lacks it. Set true in an account that has never had an OpenSearch domain; false if the role already exists (creating it twice fails)."
  type        = bool
  default     = false
}

variable "ecr_repositories_enabled" {
  description = "Create one private, immutable-tag ECR repository per product image (zasp/<name>)."
  type        = bool
  default     = false
}

variable "route53_zone_id" {
  description = "Owner decision. Public Route 53 hosted zone ID that contains the product host name, or empty. When set, an IAM role for cert-manager (service account cert-manager/cert-manager) is created that may answer DNS-01 challenges in that zone only. Leave empty when the TLS certificate is supplied another way."
  type        = string
  default     = ""
  validation {
    condition     = var.route53_zone_id == "" || can(regex("^Z[A-Z0-9]{4,31}$", var.route53_zone_id))
    error_message = "route53_zone_id must be empty or a Route 53 hosted zone ID."
  }
}

variable "runtime_services_rds_enabled" {
  description = "Owner decision. true creates one private, encrypted RDS PostgreSQL instance for the databases Temporal (temporal, temporal_visibility), OpenFGA (openfga) and Nango (nango) need; its master password is generated and kept in Secrets Manager. false means those four databases are provided elsewhere (for example as separate databases on Neon). The product database is never created here."
  type        = bool
  default     = false
}

variable "runtime_services_rds_instance_class" {
  description = "Instance class of the optional runtime-services RDS instance."
  type        = string
  default     = "db.t4g.medium"
}

variable "runtime_services_rds_multi_az" {
  description = "Whether the optional runtime-services RDS instance has a standby in the second availability zone."
  type        = bool
  default     = true
}

locals {
  # Fixed by services/platform/migrations/baseline; the Helm chart's
  # databasePrincipals defaults carry the same names.
  baseline_database_principals = {
    migration                    = "zasp_operator"
    api                          = "zasp_svc_api"
    security_agent_api           = "zasp_svc_security_agent_api"
    security_agent_worker        = "zasp_svc_security_agent_worker"
    security_agent_action_worker = "zasp_svc_security_agent_action"
    policy_deployment_worker     = "zasp_svc_policy_deployment"
    discovery_worker             = "zasp_svc_discovery"
    runtime_ingest               = "zasp_svc_ingest"
    runtime_worker               = "zasp_svc_runtime"
    outbox_worker                = "zasp_svc_outbox"
    recovery_outbox_worker       = "zasp_svc_recovery_outbox"
    recovery_worker              = "zasp_svc_recovery"
    red_team_outbox_worker       = "zasp_svc_red_team_outbox"
    red_team_worker              = "zasp_svc_red_team_worker"
    red_team_adapter             = "zasp_svc_red_team_adapter"
    attack_lab_controller        = "zasp_svc_attack_lab_controller"
    attack_lab_outbox            = "zasp_svc_attack_lab_outbox"
    attack_lab_proxy             = "zasp_svc_attack_lab_proxy"
    runtime_gateway              = "zasp_svc_gateway"
    discovery_scheduler          = "zasp_svc_scheduler"
    projection_risk              = "zasp_svc_projection_risk"
    projection_graph             = "zasp_svc_projection_graph"
    projection_search            = "zasp_svc_projection_search"
    runtime_coordinator          = "zasp_svc_coordinator"
    runtime_archive              = "zasp_svc_archive"
    runtime_index                = "zasp_svc_index"
    runtime_correlation          = "zasp_svc_correlation"
    runtime_projection           = "zasp_svc_runtime_projection"
    gateway_control              = "zasp_svc_gateway_control"
  }
  baseline_temporal_database_principals = {
    executor     = "zasp_svc_temporal_executor"
    compensation = "zasp_svc_temporal_compensation"
  }
  baseline_approval_maintenance_principal = "zasp_svc_approval_maintenance"
  baseline_schema                         = var.schema_install == "baseline"
  temporal_database_principals            = local.baseline_schema ? local.baseline_temporal_database_principals : var.temporal_database_principals

  public_egress_enabled = length(var.public_subnet_cidrs) == 2
  ecr_repository_names = var.ecr_repositories_enabled ? toset([
    "web", "agentsec-api", "agentsec-worker", "attack-lab-runner", "red-team-worker",
    "event-ingest", "gateway-control", "runtime-gateway", "sensor-agent",
  ]) : toset([])
  oidc_issuer = replace(aws_iam_openid_connect_provider.eks.url, "https://", "")
}

# ---- Internet path: public subnets, internet gateway, one NAT gateway -------

resource "aws_internet_gateway" "public" {
  count  = local.public_egress_enabled ? 1 : 0
  vpc_id = aws_vpc.staging.id
  tags   = { Name = "${var.cluster_name}-public" }
}

resource "aws_subnet" "public" {
  count                   = local.public_egress_enabled ? 2 : 0
  vpc_id                  = aws_vpc.staging.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false
  tags = {
    Name                                        = "${var.cluster_name}-public-${count.index + 1}"
    "kubernetes.io/role/elb"                    = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

resource "aws_route_table" "public" {
  count  = local.public_egress_enabled ? 1 : 0
  vpc_id = aws_vpc.staging.id
  tags   = { Name = "${var.cluster_name}-public" }
}

resource "aws_route" "public_internet" {
  count                  = local.public_egress_enabled ? 1 : 0
  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.public[0].id
}

resource "aws_route_table_association" "public" {
  count          = local.public_egress_enabled ? 2 : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_eip" "nat" {
  count  = local.public_egress_enabled ? 1 : 0
  domain = "vpc"
  tags   = { Name = "${var.cluster_name}-nat" }
}

resource "aws_nat_gateway" "egress" {
  count         = local.public_egress_enabled ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${var.cluster_name}-egress" }
  depends_on    = [aws_internet_gateway.public]
}

# The private product subnets use the VPC main route table (as the S3 gateway
# endpoint does). The isolated Attack Lab route table gets no default route.
resource "aws_route" "private_egress" {
  count                  = local.public_egress_enabled ? 1 : 0
  route_table_id         = aws_vpc.staging.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.egress[0].id
}

# ---- OpenSearch service-linked role ------------------------------------------

resource "aws_iam_service_linked_role" "opensearch" {
  count            = var.create_opensearch_service_linked_role ? 1 : 0
  aws_service_name = "opensearchservice.amazonaws.com"
}

# ---- Image repositories ------------------------------------------------------

resource "aws_ecr_repository" "product" {
  for_each             = local.ecr_repository_names
  name                 = "zasp/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.staging.arn
  }
}

# ---- cert-manager DNS-01 identity -------------------------------------------

resource "aws_iam_role" "cert_manager" {
  count = var.route53_zone_id == "" ? 0 : 1
  name  = "${var.cluster_name}-cert-manager"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${local.oidc_issuer}:aud" = "sts.amazonaws.com"
        "${local.oidc_issuer}:sub" = "system:serviceaccount:cert-manager:cert-manager"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "cert_manager" {
  count = var.route53_zone_id == "" ? 0 : 1
  name  = "${var.cluster_name}-cert-manager-dns01"
  role  = aws_iam_role.cert_manager[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["route53:GetChange"], Resource = "arn:${local.partition}:route53:::change/*" },
    { Effect = "Allow", Action = ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"], Resource = "arn:${local.partition}:route53:::hostedzone/${var.route53_zone_id}" },
    { Effect = "Allow", Action = ["route53:ListHostedZonesByName"], Resource = "*" },
  ] })
}

# ---- Optional database instance for Temporal, OpenFGA and Nango -------------

resource "aws_db_subnet_group" "runtime_services" {
  count      = var.runtime_services_rds_enabled ? 1 : 0
  name       = "${var.cluster_name}-runtime-services"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "runtime_services_rds" {
  count       = var.runtime_services_rds_enabled ? 1 : 0
  name_prefix = "${var.cluster_name}-runtime-services-db-"
  description = "PostgreSQL for Temporal, OpenFGA and Nango from the product VPC"
  vpc_id      = aws_vpc.staging.id
  ingress {
    description = "PostgreSQL from the product VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.staging.cidr_block]
  }
}

resource "aws_db_instance" "runtime_services" {
  count                         = var.runtime_services_rds_enabled ? 1 : 0
  identifier                    = "${var.cluster_name}-runtime-services"
  engine                        = "postgres"
  engine_version                = "17"
  instance_class                = var.runtime_services_rds_instance_class
  allocated_storage             = 50
  max_allocated_storage         = 200
  storage_type                  = "gp3"
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.staging.arn
  db_name                       = "postgres"
  username                      = "zasp_runtime_admin"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.staging.arn
  db_subnet_group_name          = aws_db_subnet_group.runtime_services[0].name
  vpc_security_group_ids        = [aws_security_group.runtime_services_rds[0].id]
  publicly_accessible           = false
  multi_az                      = var.runtime_services_rds_multi_az
  backup_retention_period       = 7
  deletion_protection           = true
  skip_final_snapshot           = false
  final_snapshot_identifier     = "${var.cluster_name}-runtime-services-final"
  auto_minor_version_upgrade    = true
  copy_tags_to_snapshot         = true
}

# ---- Outputs -----------------------------------------------------------------

output "schema_install" {
  value = var.schema_install
}

output "temporal_database_principals" {
  description = "Login names the Temporal executor and compensation DSNs must use."
  value       = local.temporal_database_principals
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "nat_public_ip" {
  description = "The single address all product egress leaves from (for a Neon IP allow-list); null without public subnets."
  value       = local.public_egress_enabled ? aws_eip.nat[0].public_ip : null
}

output "ecr_repository_urls" {
  value = { for name, repository in aws_ecr_repository.product : name => repository.repository_url }
}

output "cert_manager_role_arn" {
  value = var.route53_zone_id == "" ? null : aws_iam_role.cert_manager[0].arn
}

output "runtime_services_rds" {
  description = "Endpoint and master-credential secret of the optional Temporal/OpenFGA/Nango database instance."
  value = var.runtime_services_rds_enabled ? {
    address           = aws_db_instance.runtime_services[0].address
    port              = aws_db_instance.runtime_services[0].port
    master_username   = aws_db_instance.runtime_services[0].username
    master_secret_arn = aws_db_instance.runtime_services[0].master_user_secret[0].secret_arn
  } : null
}

output "postgres_dsn_secret_logins" {
  description = "Secrets Manager name of each service DSN and the PostgreSQL login that DSN must use. The operator DSN (postgres-migration-dsn) is not listed: it is the zasp_operator role."
  value = merge(
    { for name, login in local.postgres_secret_principals : aws_secretsmanager_secret.product[name].name => login if name != "postgres-migration-dsn" },
    { for name, authority in merge(local.temporal_authorities, local.approval_maintenance_authorities) : aws_secretsmanager_secret.authorization_temporal[name].name => authority.principal if authority.principal != "" },
  )
}

output "operator_secret_names" {
  description = "Every Secrets Manager entry Terraform creates empty. Each needs a value before the workload that mounts it can start. Names only."
  value = sort(concat(
    [for secret in aws_secretsmanager_secret.product : secret.name],
    [for secret in aws_secretsmanager_secret.authorization_temporal : secret.name],
    [for secret in aws_secretsmanager_secret.connector_provider : secret.name],
    [for secret in aws_secretsmanager_secret.connector_reference : secret.name],
    [
      aws_secretsmanager_secret.neo4j_projection_runtime.name,
      aws_secretsmanager_secret.neo4j_projection_schema.name,
      aws_secretsmanager_secret.recovery_neon_api.name,
      aws_secretsmanager_secret.red_team_readiness_target.name,
    ],
  ))
}

# Helm values that are fully determined by this Terraform root. Write it to a
# file and pass it to Helm before the operator's own values:
#   terraform output -json helm_values > values-terraform.json
#   helm upgrade --install ... -f values-terraform.json -f values-production.yaml
# It holds names, ARNs, URLs and CIDRs only, never a secret value.
output "helm_values" {
  description = "Non-secret Helm values for deploy/staging/product derived from this root."
  value = {
    global = { trustedProxyCIDRs = [var.vpc_cidr] }
    network = {
      s3CIDRs        = sort(aws_vpc_endpoint.s3.cidr_blocks)
      opensearchCIDR = var.vpc_cidr
      neo4jCIDR      = var.neo4j_endpoint_cidr
      connectorEgressCIDRs = {
        kubernetes = var.kubernetes_connector_egress_cidrs
        # Empty while the optional provider is disabled.
        microsoft  = var.discovery_optional_providers.microsoft_egress_cidrs
        azure      = var.discovery_optional_providers.azure_egress_cidrs
        salesforce = var.discovery_optional_providers.salesforce_egress_cidrs
      }
      findingTicketEgressCIDRs = var.finding_ticket_egress_cidrs
    }
    serviceAccounts = {
      api                   = { roleArn = aws_iam_role.api.arn }
      migration             = { roleArn = aws_iam_role.migration.arn }
      worker                = { roleArn = aws_iam_role.worker.arn }
      scheduler             = { roleArn = aws_iam_role.scheduler.arn }
      securityAgent         = { roleArn = var.authorization_temporal_enabled ? aws_iam_role.authorization_temporal["worker"].arn : aws_iam_role.security_agent_worker.arn }
      securityAgentAction   = { roleArn = aws_iam_role.security_agent_action_worker.arn }
      policyDeployment      = { roleArn = aws_iam_role.policy_deployment_worker.arn }
      projectionRisk        = { roleArn = aws_iam_role.projection_risk.arn }
      projectionGraph       = { roleArn = aws_iam_role.projection_graph.arn }
      projectionGraphInit   = { roleArn = aws_iam_role.projection_graph_init.arn }
      projectionSearch      = { roleArn = aws_iam_role.projection_search.arn }
      projectionSearchInit  = { roleArn = aws_iam_role.projection_search_init.arn }
      outbox                = { roleArn = aws_iam_role.outbox.arn }
      recoveryBackupOutbox  = { roleArn = aws_iam_role.recovery["recovery_backup_outbox"].arn }
      recoveryRestoreOutbox = { roleArn = aws_iam_role.recovery["recovery_restore_outbox"].arn }
      recoveryBackup        = { roleArn = aws_iam_role.recovery["recovery_backup"].arn }
      recoveryRestore       = { roleArn = aws_iam_role.recovery["recovery_restore"].arn }
      redTeamOutbox         = { roleArn = aws_iam_role.red_team["outbox"].arn }
      redTeamWorker         = { roleArn = aws_iam_role.red_team["worker"].arn }
      redTeamAdapter        = { roleArn = aws_iam_role.red_team["adapter"].arn }
      attackLabController   = { roleArn = aws_iam_role.attack_lab["controller"].arn }
      attackLabOutbox       = { roleArn = aws_iam_role.attack_lab["outbox"].arn }
      attackLabProxy        = { roleArn = aws_iam_role.attack_lab["proxy"].arn }
      runtimeIngest         = { roleArn = aws_iam_role.runtime["ingest"].arn }
      gatewayControl        = { roleArn = aws_iam_role.runtime["gateway_control"].arn }
      runtimeOutbox         = { roleArn = aws_iam_role.runtime["outbox"].arn }
      runtimeCoordinator    = { roleArn = aws_iam_role.runtime["coordinator"].arn }
      runtimeArchive        = { roleArn = aws_iam_role.runtime["archive"].arn }
      runtimeIndex          = { roleArn = aws_iam_role.runtime["index"].arn }
      runtimeCorrelation    = { roleArn = aws_iam_role.runtime["correlation"].arn }
      runtimeProjection     = { roleArn = aws_iam_role.runtime["projection"].arn }
      runtimeComplete       = { roleArn = aws_iam_role.runtime["complete"].arn }
      canarySecretSync      = { roleArn = aws_iam_role.canary_secret_sync.arn }
    }
    secrets = {
      region                                     = var.region
      apiPostgresDSNObjectName                   = aws_secretsmanager_secret.product["postgres-api-dsn"].name
      securityAgentAPIPostgresDSNObjectName      = aws_secretsmanager_secret.product["postgres-security-agent-api-dsn"].name
      securityAgentWorkerPostgresDSNObjectName   = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"].name
      securityAgentPlannerTokenObjectName        = aws_secretsmanager_secret.product["openrouter-security-agent-api-key"].name
      securityAgentActionPostgresDSNObjectName   = aws_secretsmanager_secret.product["postgres-security-agent-action-worker-dsn"].name
      policyDeploymentPostgresDSNObjectName      = aws_secretsmanager_secret.product["postgres-policy-deployment-worker-dsn"].name
      gatewaySigningPrivateKeyObjectName         = aws_secretsmanager_secret.product["gateway-policy-signing-private-key"].name
      migrationPostgresDSNObjectName             = aws_secretsmanager_secret.product["postgres-migration-dsn"].name
      workerPostgresDSNObjectName                = aws_secretsmanager_secret.product["postgres-worker-dsn"].name
      schedulerPostgresDSNObjectName             = aws_secretsmanager_secret.product["postgres-scheduler-dsn"].name
      projectionRiskPostgresDSNObjectName        = aws_secretsmanager_secret.product["postgres-projection-risk-dsn"].name
      projectionGraphPostgresDSNObjectName       = aws_secretsmanager_secret.product["postgres-projection-graph-dsn"].name
      projectionSearchPostgresDSNObjectName      = aws_secretsmanager_secret.product["postgres-projection-search-dsn"].name
      outboxPostgresDSNObjectName                = aws_secretsmanager_secret.product["postgres-outbox-worker-dsn"].name
      recoveryBackupOutboxPostgresDSNObjectName  = aws_secretsmanager_secret.product["postgres-recovery-outbox-worker-dsn"].name
      recoveryRestoreOutboxPostgresDSNObjectName = aws_secretsmanager_secret.product["postgres-recovery-outbox-worker-dsn"].name
      recoveryBackupPostgresDSNObjectName        = aws_secretsmanager_secret.product["postgres-recovery-worker-dsn"].name
      recoveryRestorePostgresDSNObjectName       = aws_secretsmanager_secret.product["postgres-recovery-worker-dsn"].name
      redTeamOutboxPostgresDSNObjectName         = aws_secretsmanager_secret.product["postgres-red-team-outbox-dsn"].name
      redTeamWorkerPostgresDSNObjectName         = aws_secretsmanager_secret.product["postgres-red-team-worker-dsn"].name
      redTeamAdapterPostgresDSNObjectName        = aws_secretsmanager_secret.product["postgres-red-team-adapter-dsn"].name
      redTeamAdapterTokenObjectName              = aws_secretsmanager_secret.product["red-team-adapter-token"].name
      redTeamAdapterTLSCertificateObjectName     = aws_secretsmanager_secret.product["red-team-adapter-tls-certificate"].name
      redTeamAdapterTLSPrivateKeyObjectName      = aws_secretsmanager_secret.product["red-team-adapter-tls-private-key"].name
      attackLabControllerPostgresDSNObjectName   = aws_secretsmanager_secret.product["postgres-attack-lab-controller-dsn"].name
      attackLabOutboxPostgresDSNObjectName       = aws_secretsmanager_secret.product["postgres-attack-lab-outbox-dsn"].name
      attackLabProxyPostgresDSNObjectName        = aws_secretsmanager_secret.product["postgres-attack-lab-proxy-dsn"].name
      attackLabSigningKeyObjectName              = aws_secretsmanager_secret.product["attack-lab-egress-signing-key"].name
      attackLabProxyTLSCertificateObjectName     = aws_secretsmanager_secret.product["attack-lab-proxy-tls-certificate"].name
      attackLabProxyTLSPrivateKeyObjectName      = aws_secretsmanager_secret.product["attack-lab-proxy-tls-private-key"].name
      runtimeIngestPostgresDSNObjectName         = aws_secretsmanager_secret.product["postgres-runtime-ingest-dsn"].name
      runtimeCoordinatorPostgresDSNObjectName    = aws_secretsmanager_secret.product["postgres-runtime-coordinator-dsn"].name
      runtimeArchivePostgresDSNObjectName        = aws_secretsmanager_secret.product["postgres-runtime-archive-dsn"].name
      runtimeIndexPostgresDSNObjectName          = aws_secretsmanager_secret.product["postgres-runtime-index-dsn"].name
      runtimeCorrelationPostgresDSNObjectName    = aws_secretsmanager_secret.product["postgres-runtime-correlation-dsn"].name
      runtimeProjectionPostgresDSNObjectName     = aws_secretsmanager_secret.product["postgres-runtime-projection-dsn"].name
      gatewayControlPostgresDSNObjectName        = aws_secretsmanager_secret.product["postgres-gateway-control-dsn"].name
      stytchProjectIDObjectName                  = aws_secretsmanager_secret.product["stytch-project-id"].name
      stytchSecretObjectName                     = aws_secretsmanager_secret.product["stytch-secret"].name
      stytchWebhookSecretObjectName              = aws_secretsmanager_secret.product["stytch-webhook-secret"].name
      stytchPublicTokenObjectName                = aws_secretsmanager_secret.product["stytch-public-token"].name
      stytchOrganizationIDObjectName             = aws_secretsmanager_secret.product["stytch-organization-id"].name
      workflowSigningKeyObjectName               = aws_secretsmanager_secret.product["workflow-signing-key"].name
      tokenRevealKeyObjectName                   = aws_secretsmanager_secret.product["token-reveal-key"].name
      canaryReadTokenObjectName                  = aws_secretsmanager_secret.product["canary-read-token"].name
    }
    connectors = {
      awsRegion                   = var.region
      roleArn                     = aws_iam_role.api_connectors.arn
      awsCustomerRolePrefixes     = sort(tolist(var.aws_reference_role_prefixes))
      awsCustomerRoleARNs         = sort(tolist(var.aws_reference_role_arns))
      kmsKeyArn                   = aws_kms_key.connector_oauth.arn
      secretPrefix                = local.connector_secret_prefix
      githubClientID              = var.connector_client_ids.github
      githubClientSecretReference = "ref:github/client-secret"
      githubAppID                 = var.github_app_id
      githubPrivateKeyReference   = "ref:github/app-private-key"
      oktaClientID                = var.connector_client_ids.okta
      oktaClientSecretReference   = "ref:okta/client-secret"
    }
    discovery = {
      parserVersion              = var.discovery_implementation_versions.parser
      toolVersion                = var.discovery_implementation_versions.tool
      awsCollectorVersion        = var.discovery_implementation_versions.aws_collector
      kubernetesCollectorVersion = var.discovery_implementation_versions.kubernetes_collector
      githubCollectorVersion     = var.discovery_implementation_versions.github_collector
      oktaCollectorVersion       = var.discovery_implementation_versions.okta_collector
      # Empty keeps the optional provider disabled.
      microsoftCollectorVersion  = var.discovery_optional_providers.microsoft_collector
      microsoftAzure             = var.discovery_optional_providers.microsoft_azure
      salesforceCollectorVersion = var.discovery_optional_providers.salesforce_collector
      saasCollectorVersion       = var.discovery_optional_providers.saas_collector
      awsRegion                  = var.region
      queueURL                   = aws_sqs_queue.work["discovery-jobs"].id
      roleArn                    = aws_iam_role.worker.arn
      secretPrefix               = local.connector_secret_root
      evidenceBucket             = aws_s3_bucket.evidence.bucket
      evidenceBucketOwner        = var.account_id
      evidenceKMSKeyArn          = aws_kms_key.staging.arn
      githubAppID                = var.github_app_id
      githubPrivateKeyReference  = "ref:github/app-private-key"
      oktaClientID               = var.connector_client_ids.okta
      oktaClientSecretReference  = "ref:okta/client-secret"
    }
    outbox = {
      awsRegion = var.region
      queueURL  = aws_sqs_queue.work["discovery-jobs"].id
      roleArn   = aws_iam_role.outbox.arn
    }
    projectionRisk = { roleArn = aws_iam_role.projection_risk.arn }
    projectionGraph = {
      awsRegion                 = var.region
      endpoint                  = var.neo4j_endpoint
      credentialReference       = "ref:neo4j/auth/runtime"
      schemaCredentialReference = "ref:neo4j/auth/schema"
      secretPrefix              = local.projection_secret_root
      roleArn                   = aws_iam_role.projection_graph.arn
      initRoleArn               = aws_iam_role.projection_graph_init.arn
      expectedPrincipal         = "zasp_projection_runtime"
      expectedRole              = "publisher"
    }
    projectionSearch = {
      awsRegion   = var.region
      endpoint    = "https://${aws_opensearch_domain.events.endpoint}"
      index       = "zasp-inventory-v1"
      roleArn     = aws_iam_role.projection_search.arn
      initRoleArn = aws_iam_role.projection_search_init.arn
    }
    recovery = {
      awsRegion            = var.region
      backupQueueURL       = aws_sqs_queue.work["recovery-backup-jobs"].id
      restoreQueueURL      = aws_sqs_queue.work["recovery-restore-jobs"].id
      evidenceBucket       = aws_s3_bucket.evidence.bucket
      evidenceBucketOwner  = var.account_id
      evidenceKMSKeyArn    = aws_kms_key.staging.arn
      signingKMSKeyArn     = aws_kms_key.recovery_signing.arn
      backupOutboxRoleArn  = aws_iam_role.recovery["recovery_backup_outbox"].arn
      restoreOutboxRoleArn = aws_iam_role.recovery["recovery_restore_outbox"].arn
      backupRoleArn        = aws_iam_role.recovery["recovery_backup"].arn
      restoreRoleArn       = aws_iam_role.recovery["recovery_restore"].arn
      neonSecretReference  = "ref:neon/project-api-key"
    }
    redTeam = {
      awsRegion                    = var.region
      queueURL                     = aws_sqs_queue.work["red-team-tests"].id
      evidenceBucket               = aws_s3_bucket.red_team_evidence.bucket
      evidenceBucketOwner          = var.account_id
      evidenceKMSKeyArn            = aws_kms_key.red_team.arn
      outboxRoleArn                = aws_iam_role.red_team["outbox"].arn
      workerRoleArn                = aws_iam_role.red_team["worker"].arn
      adapterRoleArn               = aws_iam_role.red_team["adapter"].arn
      targetEndpoint               = "https://agentsec-red-team-adapter.agentsec.svc.cluster.local/v1/evaluate"
      readinessCredentialReference = "ref:red-team/readiness-0001"
    }
    attackLab = {
      runnerTestRoleArn            = aws_iam_role.attack_lab_runner_test.arn
      awsRegion                    = var.region
      queueURL                     = aws_sqs_queue.work["attack-lab-jobs"].id
      evidenceBucket               = aws_s3_bucket.attack_lab_evidence.bucket
      evidenceBucketOwner          = var.account_id
      evidenceKMSKeyArn            = aws_kms_key.attack_lab.arn
      controllerRoleArn            = aws_iam_role.attack_lab["controller"].arn
      outboxRoleArn                = aws_iam_role.attack_lab["outbox"].arn
      proxyRoleArn                 = aws_iam_role.attack_lab["proxy"].arn
      securityGroupID              = aws_security_group.attack_lab.id
      proxySecurityGroupID         = aws_security_group.attack_lab_proxy.id
      targetAllowedCIDRs           = sort(tolist(var.attack_lab_target_egress_cidrs))
      readinessCredentialReference = "ref:red-team/readiness-0001"
    }
    runtime = {
      awsRegion             = var.region
      queueURL              = aws_sqs_queue.work["runtime-events"].id
      rawBucket             = aws_s3_bucket.runtime_raw.bucket
      rawBucketOwner        = var.account_id
      rawKMSKeyArn          = aws_kms_key.runtime_raw.arn
      openSearchEndpoint    = "https://${aws_opensearch_domain.events.endpoint}"
      openSearchIndex       = "zasp-runtime-events-v1"
      eventIngestRoleArn    = aws_iam_role.runtime["ingest"].arn
      gatewayControlRoleArn = aws_iam_role.runtime["gateway_control"].arn
      outboxRoleArn         = aws_iam_role.runtime["outbox"].arn
      coordinatorRoleArn    = aws_iam_role.runtime["coordinator"].arn
      archiveRoleArn        = aws_iam_role.runtime["archive"].arn
      indexRoleArn          = aws_iam_role.runtime["index"].arn
      correlationRoleArn    = aws_iam_role.runtime["correlation"].arn
      projectionRoleArn     = aws_iam_role.runtime["projection"].arn
      completeRoleArn       = aws_iam_role.runtime["complete"].arn
    }
    # Empty, not null, when the profile is off: a null would delete the chart's
    # authorizationTemporal defaults.
    authorizationTemporal = { for key, role in {
      workerRoleArn    = try(aws_iam_role.authorization_temporal["worker"].arn, "")
      projectorRoleArn = try(aws_iam_role.authorization_temporal["projector"].arn, "")
      adapterRoleArn   = aws_iam_role.red_team["adapter"].arn
    } : key => role if var.authorization_temporal_enabled }
  }
}
