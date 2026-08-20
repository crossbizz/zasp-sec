provider "aws" {
  region                      = var.region
  access_key                  = var.offline_validation ? "offline" : null
  secret_key                  = var.offline_validation ? "offline" : null
  skip_credentials_validation = var.offline_validation
  skip_metadata_api_check     = var.offline_validation
  skip_region_validation      = var.offline_validation
  skip_requesting_account_id  = var.offline_validation

  default_tags {
    tags = merge({
      Product     = "zasp"
      Environment = var.environment
      ManagedBy   = "terraform"
    }, var.tags)
  }
}

locals {
  database_principals = {
    migration           = var.database_principals.migration
    api                 = var.database_principals.api
    discovery_worker    = var.database_principals.discovery_worker
    runtime_ingest      = var.database_principals.runtime_ingest
    runtime_worker      = var.database_principals.runtime_worker
    outbox_worker       = var.database_principals.outbox_worker
    runtime_gateway     = var.database_principals.runtime_gateway
    discovery_scheduler = var.database_principals.discovery_scheduler
    projection_risk     = var.database_principals.projection_risk
    projection_graph    = var.database_principals.projection_graph
    projection_search   = var.database_principals.projection_search
  }
  postgres_secret_principals = {
    postgres-api-dsn               = local.database_principals.api
    postgres-worker-dsn            = local.database_principals.discovery_worker
    postgres-migration-dsn         = local.database_principals.migration
    postgres-runtime-ingest-dsn    = local.database_principals.runtime_ingest
    postgres-runtime-worker-dsn    = local.database_principals.runtime_worker
    postgres-outbox-worker-dsn     = local.database_principals.outbox_worker
    postgres-runtime-gateway-dsn   = local.database_principals.runtime_gateway
    postgres-scheduler-dsn         = local.database_principals.discovery_scheduler
    postgres-projection-risk-dsn   = local.database_principals.projection_risk
    postgres-projection-graph-dsn  = local.database_principals.projection_graph
    postgres-projection-search-dsn = local.database_principals.projection_search
  }
  api_secret_names = toset([
    "postgres-api-dsn",
    "stytch-project-id",
    "stytch-secret",
    "stytch-public-token",
    "stytch-organization-id",
    "workflow-signing-key",
    "token-reveal-key",
  ])
  queue_contract = {
    background       = { visibility = 300, schema = "agentsec.background.v1" }
    "discovery-jobs" = { visibility = 30, schema = "agentsec.discovery-jobs.v1" }
    runtime-events   = { visibility = 120, schema = "agentsec.runtime-events.v1" }
    tests            = { visibility = 900, schema = "agentsec.tests.v1" }
  }
  connector_secret_root   = "${var.cluster_name}/connectors"
  connector_secret_prefix = "${local.connector_secret_root}/oauth"
  connector_provider_secret_names = {
    github_client_secret = {
      name             = "${local.connector_secret_root}/github/client-secret"
      credential_class = "github_oauth_client_secret"
    }
    github_app_private_key = {
      name             = "${local.connector_secret_root}/github/app-private-key"
      credential_class = "github_app_private_key"
    }
    okta_client_secret = {
      name             = "${local.connector_secret_root}/okta/client-secret"
      credential_class = "okta_oauth_client_secret"
    }
  }
  connector_reference_secret_names = {
    aws_external_id = {
      name             = "${local.connector_secret_root}/aws/external-id/${var.connector_reference_ids.aws_external_id}"
      credential_class = "aws_external_id_reference"
    }
    kubernetes_connection = {
      name             = "${local.connector_secret_root}/kubernetes/connection/${var.connector_reference_ids.kubernetes_connection}"
      credential_class = "kubernetes_connection_descriptor"
    }
    kubernetes_ca = {
      name             = "${local.connector_secret_root}/kubernetes/ca/${var.connector_reference_ids.kubernetes_ca}"
      credential_class = "kubernetes_ca_reference"
    }
    kubernetes_credential = {
      name             = "${local.connector_secret_root}/kubernetes/credential/${var.connector_reference_ids.kubernetes_credential}"
      credential_class = "kubernetes_credential_reference"
    }
  }
  bucket_name = "zasp-product-data-${md5(var.account_id)}"
  partition   = startswith(var.region, "cn-") ? "aws-cn" : startswith(var.region, "us-gov-") ? "aws-us-gov" : "aws"
}

resource "aws_vpc" "staging" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.cluster_name}-vpc" }
}

resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id                  = aws_vpc.staging.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name                                        = "${var.cluster_name}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb"           = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "staging" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = var.endpoint_public_access
  }

  encryption_config {
    provider { key_arn = aws_kms_key.staging.arn }
    resources = ["secrets"]
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

resource "aws_iam_role" "eks_nodes" {
  name = "${var.cluster_name}-nodes"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_nodes" {
  for_each = toset([
    "AmazonEC2ContainerRegistryReadOnly",
    "AmazonEKS_CNI_Policy",
    "AmazonEKSWorkerNodePolicy",
  ])
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/${each.value}"
}

resource "aws_eks_node_group" "staging" {
  cluster_name    = aws_eks_cluster.staging.name
  node_group_name = "product"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = aws_subnet.private[*].id
  capacity_type   = "ON_DEMAND"
  instance_types  = var.node_instance_types

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config { max_unavailable = 1 }
  depends_on = [aws_iam_role_policy_attachment.eks_nodes]
}

resource "aws_kms_key" "staging" {
  description             = "ZASP staging evidence, queue, secret, and cluster encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "staging" {
  name          = "alias/${var.cluster_name}"
  target_key_id = aws_kms_key.staging.key_id
}

resource "aws_kms_key" "connector_oauth" {
  description             = "ZASP API connector OAuth and provider secret encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "connector_oauth" {
  name          = "alias/${var.cluster_name}-connector-oauth"
  target_key_id = aws_kms_key.connector_oauth.key_id
}

resource "aws_s3_bucket" "evidence" {
  bucket = local.bucket_name
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.staging.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "organization-evidence-retention"
    status = "Enabled"
    filter { prefix = "organizations/" }
    noncurrent_version_expiration { noncurrent_days = var.evidence_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_secretsmanager_secret" "product" {
  for_each = toset([
    "postgres-api-dsn",
    "postgres-worker-dsn",
    "postgres-migration-dsn",
    "postgres-runtime-ingest-dsn",
    "postgres-runtime-worker-dsn",
    "postgres-outbox-worker-dsn",
    "postgres-runtime-gateway-dsn",
    "postgres-scheduler-dsn",
    "postgres-projection-risk-dsn",
    "postgres-projection-graph-dsn",
    "postgres-projection-search-dsn",
    "stytch-project-id",
    "stytch-secret",
    "stytch-public-token",
    "stytch-organization-id",
    "workflow-signing-key",
    "token-reveal-key",
    "canary-read-token",
  ])

  name                    = "${var.cluster_name}/${each.key}"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags = contains(keys(local.postgres_secret_principals), each.key) ? {
    DatabasePrincipal = local.postgres_secret_principals[each.key]
  } : {}
}

resource "aws_secretsmanager_secret" "connector_provider" {
  for_each = local.connector_provider_secret_names

  name                    = each.value.name
  kms_key_id              = aws_kms_key.connector_oauth.arn
  recovery_window_in_days = 30
  tags                    = { CredentialClass = each.value.credential_class }
}

resource "aws_secretsmanager_secret" "connector_reference" {
  for_each = local.connector_reference_secret_names

  name                    = each.value.name
  kms_key_id              = aws_kms_key.connector_oauth.arn
  recovery_window_in_days = 30
  tags                    = { CredentialClass = each.value.credential_class }
}

resource "aws_sqs_queue" "dead_letter" {
  for_each = local.queue_contract

  name                       = "agentsec-${each.key}-dlq"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 30
  kms_master_key_id          = aws_kms_key.staging.arn
  sqs_managed_sse_enabled    = false
  tags                       = { Schema = each.value.schema }
}

resource "aws_sqs_queue" "work" {
  for_each = local.queue_contract

  name                       = "agentsec-${each.key}"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = each.value.visibility
  receive_wait_time_seconds  = 20
  max_message_size           = 262144
  kms_master_key_id          = aws_kms_key.staging.arn
  sqs_managed_sse_enabled    = false
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter[each.key].arn
    maxReceiveCount     = 5
  })
  tags = { Schema = each.value.schema }
}

resource "aws_sqs_queue_redrive_allow_policy" "dead_letter" {
  for_each  = local.queue_contract
  queue_url = aws_sqs_queue.dead_letter[each.key].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.work[each.key].arn]
  })
}

resource "aws_security_group" "opensearch" {
  name_prefix = "${var.cluster_name}-opensearch-"
  description = "Private OpenSearch access from the staging VPC"
  vpc_id      = aws_vpc.staging.id

  ingress {
    description = "HTTPS from staging VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.staging.cidr_block]
  }
}

resource "aws_opensearch_domain" "events" {
  domain_name    = "${var.cluster_name}-events"
  engine_version = "OpenSearch_2.19"

  cluster_config {
    instance_type          = var.opensearch_instance_type
    instance_count         = var.opensearch_instance_count
    zone_awareness_enabled = true
    zone_awareness_config { availability_zone_count = 2 }
  }
  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.opensearch_volume_size
  }
  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.staging.arn
  }
  node_to_node_encryption { enabled = true }
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  vpc_options {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.opensearch.id]
  }
}

data "tls_certificate" "eks" {
  url = aws_eks_cluster.staging.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.staging.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
}

resource "aws_iam_role" "api" {
  name = "${var.cluster_name}-api"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:agentsec-api"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "api" {
  name = "${var.cluster_name}-api-secrets"
  role = aws_iam_role.api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = [for name in local.api_secret_names : aws_secretsmanager_secret.product[name].arn] },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } }
    ]
  })
}

resource "aws_iam_role" "api_connectors" {
  name = "${var.cluster_name}-api-connectors"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:agentsec-api"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "api_connectors" {
  name = "${var.cluster_name}-api-connector-secrets"
  role = aws_iam_role.api_connectors.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [for secret in aws_secretsmanager_secret.connector_provider : secret.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = [for secret in aws_secretsmanager_secret.connector_reference : secret.arn]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DeleteSecret",
        ]
        Resource = [
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_prefix}/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/github/effect-manifest/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/github/effect-outcome/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/github/revoked-installation/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/effect-manifest/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/effect-access/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/effect-outcome/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/refresh/*",
          "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/revoked-refresh/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = var.aws_reference_role_arns
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.connector_oauth.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
          ArnLike = {
            "kms:EncryptionContext:SecretARN" = [
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_prefix}/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/github/effect-manifest/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/github/effect-outcome/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/github/revoked-installation/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/effect-manifest/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/effect-access/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/effect-outcome/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/refresh/*",
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/revoked-refresh/*",
            ]
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.connector_oauth.arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
            "kms:EncryptionContext:SecretARN" = concat([for secret in aws_secretsmanager_secret.connector_provider : secret.arn], [for secret in aws_secretsmanager_secret.connector_reference : secret.arn])
          }
        }
      },
    ]
  })
}

resource "aws_iam_role" "worker" {
  name = "${var.cluster_name}-discovery-worker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-discovery-worker"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "worker" {
  name = "${var.cluster_name}-discovery-worker-secret"
  role = aws_iam_role.worker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-worker-dsn"].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } },
  ] })
}

resource "aws_iam_role" "scheduler" {
  name = "${var.cluster_name}-discovery-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-discovery-scheduler"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "${var.cluster_name}-discovery-scheduler-secret"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-scheduler-dsn"].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } },
  ] })
}

resource "aws_iam_role" "outbox" {
  name = "${var.cluster_name}-outbox"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-outbox-publisher"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "outbox" {
  name = "${var.cluster_name}-outbox"
  role = aws_iam_role.outbox.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-outbox-worker-dsn"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["postgres-outbox-worker-dsn"].arn
      } }
    },
    { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.work["discovery-jobs"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                          = "sqs.${var.region}.amazonaws.com"
        "kms:EncryptionContext:aws:sqs:queue-arn" = aws_sqs_queue.work["discovery-jobs"].arn
      } }
    },
  ] })
}

resource "aws_iam_role" "projection_search" {
  name = "${var.cluster_name}-projection-search"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-projection-search"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "projection_search" {
  name = "${var.cluster_name}-projection-search"
  role = aws_iam_role.projection_search.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-projection-search-dsn"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["postgres-projection-search-dsn"].arn
      } }
    },
    { Effect = "Allow", Action = ["es:ESHttpGet", "es:ESHttpPost", "es:ESHttpPut"], Resource = "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/*" },
  ] })
}

resource "aws_iam_role" "migration" {
  name = "${var.cluster_name}-migration"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:agentsec-migration"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "migration" {
  name = "${var.cluster_name}-migration-secret"
  role = aws_iam_role.migration.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-migration-dsn"].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } },
  ] })
}

resource "aws_iam_role" "canary_secret_sync" {
  name = "${var.cluster_name}-canary-secret-sync"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:agentsec-canary-secret-sync"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "canary_secret_sync" {
  name = "${var.cluster_name}-canary-secret"
  role = aws_iam_role.canary_secret_sync.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["canary-read-token"].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } },
  ] })
}

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.cluster_name}-endpoints-"
  description = "Private AWS service endpoints from the product VPC"
  vpc_id      = aws_vpc.staging.id
  ingress {
    description = "TLS from the private product VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.staging.cidr_block]
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.staging.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint" "private_services" {
  for_each            = toset(["ecr.api", "ecr.dkr", "logs", "secretsmanager", "sqs", "sts"])
  vpc_id              = aws_vpc.staging.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

resource "aws_iam_role" "attack_lab_pod" {
  name = "${var.cluster_name}-attack-lab-pod"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "eks-fargate-pods.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "attack_lab_pod" {
  role       = aws_iam_role.attack_lab_pod.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}

resource "aws_eks_fargate_profile" "attack_lab" {
  cluster_name           = aws_eks_cluster.staging.name
  fargate_profile_name   = "attack-lab"
  pod_execution_role_arn = aws_iam_role.attack_lab_pod.arn
  subnet_ids             = aws_subnet.private[*].id
  selector {
    namespace = var.attack_lab_namespace
    labels    = { "zasp.io/execution" = "attack-lab" }
  }
  depends_on = [aws_iam_role_policy_attachment.attack_lab_pod]
}

resource "aws_security_group" "attack_lab" {
  name_prefix = "${var.cluster_name}-attack-lab-"
  description = "Bounded egress for Attack Lab Fargate pods"
  vpc_id      = aws_vpc.staging.id
  egress {
    description = "TLS to approved private endpoints and product proxy"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.staging.cidr_block]
  }
}
