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
    migration                    = var.database_principals.migration
    api                          = var.database_principals.api
    security_agent_api           = var.database_principals.security_agent_api
    security_agent_worker        = var.database_principals.security_agent_worker
    security_agent_action_worker = var.database_principals.security_agent_action_worker
    discovery_worker             = var.database_principals.discovery_worker
    runtime_ingest               = var.database_principals.runtime_ingest
    runtime_worker               = var.database_principals.runtime_worker
    outbox_worker                = var.database_principals.outbox_worker
    recovery_outbox_worker       = var.database_principals.recovery_outbox_worker
    recovery_worker              = var.database_principals.recovery_worker
    red_team_outbox_worker       = var.database_principals.red_team_outbox_worker
    red_team_worker              = var.database_principals.red_team_worker
    red_team_adapter             = var.database_principals.red_team_adapter
    attack_lab_controller        = var.database_principals.attack_lab_controller
    attack_lab_outbox            = var.database_principals.attack_lab_outbox
    attack_lab_proxy             = var.database_principals.attack_lab_proxy
    runtime_gateway              = var.database_principals.runtime_gateway
    discovery_scheduler          = var.database_principals.discovery_scheduler
    projection_risk              = var.database_principals.projection_risk
    projection_graph             = var.database_principals.projection_graph
    projection_search            = var.database_principals.projection_search
    runtime_coordinator          = var.database_principals.runtime_coordinator
    runtime_archive              = var.database_principals.runtime_archive
    runtime_index                = var.database_principals.runtime_index
    runtime_correlation          = var.database_principals.runtime_correlation
    runtime_projection           = var.database_principals.runtime_projection
    gateway_control              = var.database_principals.gateway_control
  }
  postgres_secret_principals = {
    postgres-api-dsn                          = local.database_principals.api
    postgres-security-agent-api-dsn           = local.database_principals.security_agent_api
    postgres-security-agent-worker-dsn        = local.database_principals.security_agent_worker
    postgres-security-agent-action-worker-dsn = local.database_principals.security_agent_action_worker
    postgres-worker-dsn                       = local.database_principals.discovery_worker
    postgres-migration-dsn                    = local.database_principals.migration
    postgres-runtime-ingest-dsn               = local.database_principals.runtime_ingest
    postgres-runtime-worker-dsn               = local.database_principals.runtime_worker
    postgres-outbox-worker-dsn                = local.database_principals.outbox_worker
    postgres-recovery-outbox-worker-dsn       = local.database_principals.recovery_outbox_worker
    postgres-recovery-worker-dsn              = local.database_principals.recovery_worker
    postgres-red-team-outbox-dsn              = local.database_principals.red_team_outbox_worker
    postgres-red-team-worker-dsn              = local.database_principals.red_team_worker
    postgres-red-team-adapter-dsn             = local.database_principals.red_team_adapter
    postgres-attack-lab-controller-dsn        = local.database_principals.attack_lab_controller
    postgres-attack-lab-outbox-dsn            = local.database_principals.attack_lab_outbox
    postgres-attack-lab-proxy-dsn             = local.database_principals.attack_lab_proxy
    postgres-runtime-gateway-dsn              = local.database_principals.runtime_gateway
    postgres-scheduler-dsn                    = local.database_principals.discovery_scheduler
    postgres-projection-risk-dsn              = local.database_principals.projection_risk
    postgres-projection-graph-dsn             = local.database_principals.projection_graph
    postgres-projection-search-dsn            = local.database_principals.projection_search
    postgres-runtime-coordinator-dsn          = local.database_principals.runtime_coordinator
    postgres-runtime-archive-dsn              = local.database_principals.runtime_archive
    postgres-runtime-index-dsn                = local.database_principals.runtime_index
    postgres-runtime-correlation-dsn          = local.database_principals.runtime_correlation
    postgres-runtime-projection-dsn           = local.database_principals.runtime_projection
    postgres-gateway-control-dsn              = local.database_principals.gateway_control
  }
  api_secret_names = toset([
    "postgres-api-dsn",
    "postgres-security-agent-api-dsn",
    "stytch-project-id",
    "stytch-secret",
    "stytch-webhook-secret",
    "stytch-public-token",
    "stytch-organization-id",
    "workflow-signing-key",
    "token-reveal-key",
  ])
  queue_contract = {
    background              = { visibility = 300, max_receive = 5, schema = "agentsec.background.v1" }
    "discovery-jobs"        = { visibility = 30, max_receive = 5, schema = "agentsec.discovery-jobs.v1" }
    runtime-events          = { visibility = 120, max_receive = 5, schema = "agentsec.runtime-events.v1" }
    "red-team-tests"        = { visibility = 900, max_receive = 5, schema = "agentsec.red-team-tests.v1" }
    "attack-lab-jobs"       = { visibility = 60, max_receive = 5, schema = "agentsec.attack-lab-jobs.v1" }
    "recovery-backup-jobs"  = { visibility = 30, max_receive = 100, schema = "agentsec.recovery-backup-jobs.v1" }
    "recovery-restore-jobs" = { visibility = 30, max_receive = 100, schema = "agentsec.recovery-restore-jobs.v1" }
  }
  runtime_irsa_contract = {
    ingest          = { role_name = "runtime-ingest", principal = "system:serviceaccount:agentsec:zasp-runtime-ingest", database_secret = "postgres-runtime-ingest-dsn" }
    gateway_control = { role_name = "gateway-control", principal = "system:serviceaccount:agentsec:zasp-gateway-control", database_secret = "postgres-gateway-control-dsn" }
    outbox          = { role_name = "runtime-outbox", principal = "system:serviceaccount:agentsec:zasp-runtime-outbox", database_secret = "postgres-outbox-worker-dsn" }
    coordinator     = { role_name = "runtime-coordinator", principal = "system:serviceaccount:agentsec:zasp-runtime-coordinator", database_secret = "postgres-runtime-coordinator-dsn" }
    archive         = { role_name = "runtime-archive", principal = "system:serviceaccount:agentsec:zasp-runtime-archive", database_secret = "postgres-runtime-archive-dsn" }
    index           = { role_name = "runtime-index", principal = "system:serviceaccount:agentsec:zasp-runtime-index", database_secret = "postgres-runtime-index-dsn" }
    correlation     = { role_name = "runtime-correlation", principal = "system:serviceaccount:agentsec:zasp-runtime-correlation", database_secret = "postgres-runtime-correlation-dsn" }
    projection      = { role_name = "runtime-projection", principal = "system:serviceaccount:agentsec:zasp-runtime-projection", database_secret = "postgres-runtime-projection-dsn" }
    complete        = { role_name = "runtime-complete", principal = "system:serviceaccount:agentsec:zasp-runtime-complete", database_secret = "postgres-runtime-coordinator-dsn" }
  }
  red_team_irsa_contract = {
    outbox  = { role_name = "red-team-outbox", principal = "system:serviceaccount:agentsec:zasp-red-team-outbox", database_secret = "postgres-red-team-outbox-dsn" }
    worker  = { role_name = "red-team-worker", principal = "system:serviceaccount:agentsec:zasp-red-team-worker", database_secret = "postgres-red-team-worker-dsn" }
    adapter = { role_name = "red-team-adapter", principal = "system:serviceaccount:agentsec:zasp-red-team-adapter", database_secret = "postgres-red-team-adapter-dsn" }
  }
  red_team_mount_secrets = {
    outbox  = ["postgres-red-team-outbox-dsn"]
    worker  = ["postgres-red-team-worker-dsn", "red-team-adapter-token"]
    adapter = ["postgres-red-team-adapter-dsn", "red-team-adapter-token", "red-team-adapter-tls-certificate", "red-team-adapter-tls-private-key"]
  }
  attack_lab_irsa_contract = {
    controller = { role_name = "attack-lab-controller", principal = "system:serviceaccount:agentsec:zasp-attack-lab-controller", database_secret = "postgres-attack-lab-controller-dsn" }
    outbox     = { role_name = "attack-lab-outbox", principal = "system:serviceaccount:agentsec:zasp-attack-lab-outbox", database_secret = "postgres-attack-lab-outbox-dsn" }
    proxy      = { role_name = "attack-lab-proxy", principal = "system:serviceaccount:agentsec:zasp-attack-lab-proxy", database_secret = "postgres-attack-lab-proxy-dsn" }
  }
  attack_lab_mount_secrets = {
    controller = ["postgres-attack-lab-controller-dsn", "attack-lab-egress-signing-key"]
    outbox     = ["postgres-attack-lab-outbox-dsn"]
    proxy      = ["postgres-attack-lab-proxy-dsn", "attack-lab-egress-signing-key", "attack-lab-proxy-tls-certificate", "attack-lab-proxy-tls-private-key"]
  }
  recovery_irsa_contract = {
    recovery_backup_outbox  = { role_name = "recovery-backup-outbox", principal = "system:serviceaccount:agentsec:zasp-recovery-backup-outbox", database_secret = "postgres-recovery-outbox-worker-dsn", queue = "recovery-backup-jobs", operation = "outbox" }
    recovery_restore_outbox = { role_name = "recovery-restore-outbox", principal = "system:serviceaccount:agentsec:zasp-recovery-restore-outbox", database_secret = "postgres-recovery-outbox-worker-dsn", queue = "recovery-restore-jobs", operation = "outbox" }
    recovery_backup         = { role_name = "recovery-backup", principal = "system:serviceaccount:agentsec:zasp-recovery-backup", database_secret = "postgres-recovery-worker-dsn", queue = "recovery-backup-jobs", operation = "backup" }
    recovery_restore        = { role_name = "recovery-restore", principal = "system:serviceaccount:agentsec:zasp-recovery-restore", database_secret = "postgres-recovery-worker-dsn", queue = "recovery-restore-jobs", operation = "restore" }
  }
  connector_secret_root   = "${var.cluster_name}/connectors"
  connector_secret_prefix = "${local.connector_secret_root}/oauth"
  projection_secret_root  = "${var.cluster_name}/projection"
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
  bucket_name             = "zasp-product-data-${md5(var.account_id)}"
  runtime_raw_bucket_name = "zasp-runtime-raw-${md5(var.account_id)}"
  red_team_bucket_name    = "zasp-red-team-evidence-${md5(var.account_id)}"
  attack_lab_bucket_name  = "zasp-attack-lab-evidence-${md5(var.account_id)}"
  partition               = startswith(var.region, "cn-") ? "aws-cn" : startswith(var.region, "us-gov-") ? "aws-us-gov" : "aws"
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

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSVPCResourceController"
}

resource "aws_eks_cluster" "staging" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.eks_kubernetes_version

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

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.staging.name
  addon_name                  = "vpc-cni"
  addon_version               = var.vpc_cni_addon_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  configuration_values = jsonencode({ env = {
    ENABLE_POD_ENI                    = "true"
    POD_SECURITY_GROUP_ENFORCING_MODE = "strict"
  } })
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

resource "aws_kms_key" "runtime_raw" {
  description             = "ZASP immutable runtime raw objects and stage receipts"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "runtime_raw" {
  name          = "alias/${var.cluster_name}-runtime-raw"
  target_key_id = aws_kms_key.runtime_raw.key_id
}

resource "aws_kms_key" "red_team" {
  description             = "ZASP immutable tenant Red Team evidence, queue, and target credentials"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "red_team" {
  name          = "alias/${var.cluster_name}-red-team"
  target_key_id = aws_kms_key.red_team.key_id
}

resource "aws_kms_key" "attack_lab" {
  description             = "ZASP isolated Attack Lab queue, evidence, and proxy credentials"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "attack_lab" {
  name          = "alias/${var.cluster_name}-attack-lab"
  target_key_id = aws_kms_key.attack_lab.key_id
}

resource "aws_kms_key" "recovery_signing" {
  description              = "ZASP recovery manifest signing and verification"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
}

resource "aws_kms_alias" "recovery_signing" {
  name          = "alias/${var.cluster_name}-recovery-signing"
  target_key_id = aws_kms_key.recovery_signing.key_id
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

resource "aws_s3_bucket" "runtime_raw" {
  bucket = local.runtime_raw_bucket_name
}

resource "aws_s3_bucket" "red_team_evidence" {
  bucket = local.red_team_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "red_team_evidence" {
  bucket = aws_s3_bucket.red_team_evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "red_team_evidence" {
  bucket                  = aws_s3_bucket.red_team_evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "red_team_evidence" {
  bucket = aws_s3_bucket.red_team_evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "red_team_evidence" {
  bucket = aws_s3_bucket.red_team_evidence.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.red_team.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "red_team_evidence" {
  bucket = aws_s3_bucket.red_team_evidence.id
  rule {
    id     = "tenant-red-team-evidence-retention"
    status = "Enabled"
    filter { prefix = "organizations/" }
    noncurrent_version_expiration { noncurrent_days = var.evidence_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_policy" "red_team_evidence" {
  bucket = aws_s3_bucket.red_team_evidence.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.red_team_evidence.arn, "${aws_s3_bucket.red_team_evidence.arn}/*"], Condition = { Bool = { "aws:SecureTransport" = "false" } } },
    { Sid = "DenyUnencryptedWrites", Effect = "Deny", Principal = "*", Action = "s3:PutObject", Resource = "${aws_s3_bucket.red_team_evidence.arn}/organizations/*", Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } } },
    { Sid = "DenyWrongKey", Effect = "Deny", Principal = "*", Action = "s3:PutObject", Resource = "${aws_s3_bucket.red_team_evidence.arn}/organizations/*", Condition = { ArnNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.red_team.arn } } },
  ] })
}

resource "aws_s3_bucket" "attack_lab_evidence" {
  bucket = local.attack_lab_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "attack_lab_evidence" {
  bucket = aws_s3_bucket.attack_lab_evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "attack_lab_evidence" {
  bucket                  = aws_s3_bucket.attack_lab_evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "attack_lab_evidence" {
  bucket = aws_s3_bucket.attack_lab_evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "attack_lab_evidence" {
  bucket = aws_s3_bucket.attack_lab_evidence.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.attack_lab.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "attack_lab_evidence" {
  bucket = aws_s3_bucket.attack_lab_evidence.id
  rule {
    id     = "tenant-attack-lab-evidence-retention"
    status = "Enabled"
    filter { prefix = "organizations/" }
    noncurrent_version_expiration { noncurrent_days = var.evidence_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_policy" "attack_lab_evidence" {
  bucket = aws_s3_bucket.attack_lab_evidence.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.attack_lab_evidence.arn, "${aws_s3_bucket.attack_lab_evidence.arn}/*"], Condition = { Bool = { "aws:SecureTransport" = "false" } } },
    { Sid = "DenyUnencryptedWrites", Effect = "Deny", Principal = "*", Action = "s3:PutObject", Resource = "${aws_s3_bucket.attack_lab_evidence.arn}/organizations/*", Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } } },
    { Sid = "DenyWrongKey", Effect = "Deny", Principal = "*", Action = "s3:PutObject", Resource = "${aws_s3_bucket.attack_lab_evidence.arn}/organizations/*", Condition = { ArnNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.attack_lab.arn } } },
  ] })
}

resource "aws_s3_bucket_ownership_controls" "runtime_raw" {
  bucket = aws_s3_bucket.runtime_raw.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "runtime_raw" {
  bucket                  = aws_s3_bucket.runtime_raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "runtime_raw" {
  bucket = aws_s3_bucket.runtime_raw.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "runtime_raw" {
  bucket = aws_s3_bucket.runtime_raw.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.runtime_raw.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "runtime_raw" {
  bucket = aws_s3_bucket.runtime_raw.id
  rule {
    id     = "runtime-version-retention"
    status = "Enabled"
    filter { prefix = "runtime/v15/" }
    noncurrent_version_expiration { noncurrent_days = var.evidence_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_policy" "runtime_raw" {
  bucket = aws_s3_bucket.runtime_raw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.runtime_raw.arn, "${aws_s3_bucket.runtime_raw.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyUnencryptedRuntimeWrites"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.runtime_raw.arn}/runtime/v15/*"
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
      },
      {
        Sid       = "DenyWrongRuntimeKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.runtime_raw.arn}/runtime/v15/*"
        Condition = { ArnNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.runtime_raw.arn } }
      },
    ]
  })
}

resource "aws_secretsmanager_secret" "product" {
  for_each = toset([
    "postgres-api-dsn",
    "postgres-security-agent-api-dsn",
    "postgres-security-agent-worker-dsn",
    "postgres-security-agent-action-worker-dsn",
    "postgres-worker-dsn",
    "postgres-migration-dsn",
    "postgres-runtime-ingest-dsn",
    "postgres-runtime-worker-dsn",
    "postgres-outbox-worker-dsn",
    "postgres-recovery-outbox-worker-dsn",
    "postgres-recovery-worker-dsn",
    "postgres-red-team-outbox-dsn",
    "postgres-red-team-worker-dsn",
    "postgres-red-team-adapter-dsn",
    "postgres-runtime-gateway-dsn",
    "postgres-scheduler-dsn",
    "postgres-projection-risk-dsn",
    "postgres-projection-graph-dsn",
    "postgres-projection-search-dsn",
    "postgres-runtime-coordinator-dsn",
    "postgres-runtime-archive-dsn",
    "postgres-runtime-index-dsn",
    "postgres-runtime-correlation-dsn",
    "postgres-runtime-projection-dsn",
    "postgres-gateway-control-dsn",
    "stytch-project-id",
    "stytch-secret",
    "stytch-webhook-secret",
    "stytch-public-token",
    "stytch-organization-id",
    "workflow-signing-key",
    "token-reveal-key",
    "canary-read-token",
    "gateway-policy-signing-private-key",
    "red-team-adapter-token",
    "red-team-adapter-tls-certificate",
    "red-team-adapter-tls-private-key",
    "postgres-attack-lab-controller-dsn",
    "postgres-attack-lab-outbox-dsn",
    "postgres-attack-lab-proxy-dsn",
    "attack-lab-egress-signing-key",
    "attack-lab-proxy-tls-certificate",
    "attack-lab-proxy-tls-private-key",
  ])

  name                    = "${var.cluster_name}/${each.key}"
  kms_key_id              = startswith(each.key, "attack-lab-") || startswith(each.key, "postgres-attack-lab-") ? aws_kms_key.attack_lab.arn : aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags = contains(keys(local.postgres_secret_principals), each.key) ? {
    DatabasePrincipal = local.postgres_secret_principals[each.key]
  } : {}
}

resource "aws_secretsmanager_secret" "red_team_readiness_target" {
  name                    = "zasp/red-team/targets/readiness-0001"
  kms_key_id              = aws_kms_key.red_team.arn
  recovery_window_in_days = 30
  tags                    = { CredentialClass = "red_team_target", Authority = "red-team-adapter" }
}

resource "aws_secretsmanager_secret" "recovery_neon_api" {
  name                    = "zasp-recovery/neon/project-api-key"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags                    = { CredentialClass = "neon_project_api_key", Authority = "recovery-restore" }
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

resource "aws_secretsmanager_secret" "neo4j_projection_runtime" {
  name                    = "${local.projection_secret_root}/neo4j/auth/runtime"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags                    = { CredentialClass = "neo4j_projection_runtime_basic", ExpectedPrincipal = "zasp_projection_runtime", ExpectedRole = "publisher" }
}

resource "aws_secretsmanager_secret" "neo4j_projection_schema" {
  name                    = "${local.projection_secret_root}/neo4j/auth/schema"
  kms_key_id              = aws_kms_key.staging.arn
  recovery_window_in_days = 30
  tags                    = { CredentialClass = "neo4j_projection_schema_basic", Authority = "projection-graph-init" }
}

resource "aws_sqs_queue" "dead_letter" {
  for_each = local.queue_contract

  name                       = "agentsec-${each.key}-dlq"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 30
  kms_master_key_id          = each.key == "red-team-tests" ? aws_kms_key.red_team.arn : each.key == "attack-lab-jobs" ? aws_kms_key.attack_lab.arn : aws_kms_key.staging.arn
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
  kms_master_key_id          = each.key == "red-team-tests" ? aws_kms_key.red_team.arn : each.key == "attack-lab-jobs" ? aws_kms_key.attack_lab.arn : aws_kms_key.staging.arn
  sqs_managed_sse_enabled    = false
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter[each.key].arn
    maxReceiveCount     = each.value.max_receive
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

resource "aws_iam_role" "runtime" {
  for_each = local.runtime_irsa_contract

  name = "${var.cluster_name}-${each.value.role_name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = each.value.principal
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "runtime" {
  for_each = local.runtime_irsa_contract
  name     = "${var.cluster_name}-${each.value.role_name}-exact"
  role     = aws_iam_role.runtime[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [for statement in compact([
      jsonencode({
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.product[each.value.database_secret].arn
      }),
      jsonencode({
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.staging.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product[each.value.database_secret].arn }
        }
      }),
      each.key == "gateway_control" ? null : jsonencode({ Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" }),
      each.key == "outbox" ? jsonencode({
        Effect   = "Allow"
        Action   = ["sqs:SendMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.work["runtime-events"].arn
      }) : null,
      each.key == "outbox" ? jsonencode({
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.staging.arn
        Condition = { StringEquals = {
          "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
          "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["runtime-events"].arn
        } }
      }) : null,
      each.key == "coordinator" ? jsonencode({
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.work["runtime-events"].arn
      }) : null,
      each.key == "coordinator" ? jsonencode({
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.staging.arn
        Condition = { StringEquals = {
          "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
          "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["runtime-events"].arn
        } }
      }) : null,
      contains(["ingest", "archive", "index", "correlation", "projection", "complete"], each.key) ? jsonencode({
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"]
        Resource = aws_s3_bucket.runtime_raw.arn
      }) : null,
      contains(["ingest", "archive", "index", "correlation", "projection", "complete"], each.key) ? jsonencode({
        Effect   = "Allow"
        Action   = compact(["s3:GetObject", each.key == "archive" ? null : "s3:PutObject"])
        Resource = "${aws_s3_bucket.runtime_raw.arn}/runtime/v15/*"
      }) : null,
      contains(["ingest", "archive", "index", "correlation", "projection", "complete"], each.key) ? jsonencode({
        Effect   = "Allow"
        Action   = compact(["kms:Decrypt", each.key == "archive" ? null : "kms:GenerateDataKey"])
        Resource = aws_kms_key.runtime_raw.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.runtime_raw.arn}/*" }
        }
      }) : null,
      contains(["ingest", "archive", "index", "correlation", "projection", "complete"], each.key) ? jsonencode({
        Effect   = "Allow"
        Action   = ["kms:DescribeKey"]
        Resource = aws_kms_key.runtime_raw.arn
      }) : null,
      each.key == "index" ? jsonencode({
        Effect   = "Allow"
        Action   = ["es:ESHttpGet", "es:ESHttpPost", "es:ESHttpPut"]
        Resource = "${aws_opensearch_domain.events.arn}/zasp-runtime-events-v1/*"
      }) : null,
      each.key == "correlation" ? jsonencode({
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.neo4j_projection_runtime.arn
      }) : null,
      each.key == "correlation" ? jsonencode({
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.staging.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.neo4j_projection_runtime.arn }
        }
      }) : null,
    ]) : jsondecode(statement)]
  })
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
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = ["arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/webhook/*"]
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
              "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/webhook/*",
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
  name = "${var.cluster_name}-discovery-worker"
  role = aws_iam_role.worker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-worker-dsn"].arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = concat([
      aws_secretsmanager_secret.connector_provider["github_app_private_key"].arn,
      aws_secretsmanager_secret.connector_provider["okta_client_secret"].arn,
    ], [for secret in aws_secretsmanager_secret.connector_reference : secret.arn]) },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = ["arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/refresh/*"] },
    {
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = aws_kms_key.connector_oauth.arn
      Condition = { StringEquals = {
        "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = concat([
          aws_secretsmanager_secret.connector_provider["github_app_private_key"].arn,
          aws_secretsmanager_secret.connector_provider["okta_client_secret"].arn,
        ], [for secret in aws_secretsmanager_secret.connector_reference : secret.arn])
      } }
    },
    {
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = aws_kms_key.connector_oauth.arn
      Condition = {
        StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        StringLike   = { "kms:EncryptionContext:SecretARN" = "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/okta/refresh/*" }
      }
    },
    { Effect = "Allow", Action = ["sts:AssumeRole"], Resource = var.aws_reference_role_arns },
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
    { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work["discovery-jobs"].arn },
    {
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"]
      Resource = aws_s3_bucket.evidence.arn
    },
    { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"], Resource = "${aws_s3_bucket.evidence.arn}/organizations/*" },
    {
      Effect   = "Allow"
      Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
      Resource = aws_kms_key.staging.arn
      Condition = {
        StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        StringLike   = { "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.evidence.arn}/organizations/*" }
      }
    },
    {
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
        "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["discovery-jobs"].arn
      } }
    },
    { Effect = "Allow", Action = ["kms:DescribeKey"], Resource = aws_kms_key.staging.arn },
  ] })
}

resource "aws_iam_role" "security_agent_worker" {
  name = "${var.cluster_name}-security-agent-worker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-security-agent"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "security_agent_worker" {
  name = "${var.cluster_name}-security-agent-worker-secret"
  role = aws_iam_role.security_agent_worker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"].arn
      } }
    },
  ] })
}

resource "aws_iam_role" "security_agent_action_worker" {
  name = "${var.cluster_name}-security-agent-action-worker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-security-agent-action"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "security_agent_action_worker" {
  name = "${var.cluster_name}-security-agent-action-worker-secrets"
  role = aws_iam_role.security_agent_action_worker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.product["postgres-security-agent-action-worker-dsn"].arn, aws_secretsmanager_secret.product["gateway-policy-signing-private-key"].arn] },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["postgres-security-agent-action-worker-dsn"].arn
      } }
    },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["gateway-policy-signing-private-key"].arn
      } }
    },
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
    { Effect = "Allow", Action = ["sqs:SendMessage", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work["discovery-jobs"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
        "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["discovery-jobs"].arn
      } }
    },
  ] })
}

resource "aws_iam_role" "recovery" {
  for_each = local.recovery_irsa_contract
  name     = "${var.cluster_name}-${each.value.role_name}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
    Condition = { StringEquals = {
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = each.value.principal
    } }
  }] })
}

resource "aws_iam_role_policy" "recovery" {
  for_each = local.recovery_irsa_contract
  name     = "${var.cluster_name}-${each.value.role_name}-exact"
  role     = aws_iam_role.recovery[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([
    {
      Effect   = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
      Resource = aws_secretsmanager_secret.product[each.value.database_secret].arn
    },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product[each.value.database_secret].arn
      } }
    },
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
    ], jsondecode(each.value.operation == "outbox" ? jsonencode([
      { Effect = "Allow", Action = ["sqs:SendMessage", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work[each.value.queue].arn },
      {
        Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.staging.arn
        Condition = { StringEquals = {
          "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
          "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work[each.value.queue].arn
        } }
      },
      ]) : jsonencode([
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work[each.value.queue].arn },
      {
        Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
        Condition = { StringEquals = {
          "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
          "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work[each.value.queue].arn
        } }
      },
      { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"], Resource = aws_s3_bucket.evidence.arn },
      { Effect = "Allow", Action = concat(["s3:GetObject"], each.value.operation == "backup" ? ["s3:PutObject"] : []), Resource = "${aws_s3_bucket.evidence.arn}/organizations/*" },
      {
        Effect = "Allow", Action = concat(["kms:Decrypt"], each.value.operation == "backup" ? ["kms:GenerateDataKey"] : []), Resource = aws_kms_key.staging.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.evidence.arn}/*" }
        }
      },
      { Effect = "Allow", Action = ["kms:DescribeKey", each.value.operation == "backup" ? "kms:Sign" : "kms:Verify"], Resource = aws_kms_key.recovery_signing.arn },
      ])), jsondecode(each.value.operation == "restore" ? jsonencode([
      { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.recovery_neon_api.arn },
      {
        Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
        Condition = { StringEquals = {
          "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
          "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.recovery_neon_api.arn
        } }
      },
  ]) : "[]")) })
}

resource "aws_iam_role" "red_team" {
  for_each = local.red_team_irsa_contract
  name     = "${var.cluster_name}-${each.value.role_name}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
    Condition = { StringEquals = {
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = each.value.principal
    } }
  }] })
}

resource "aws_iam_role_policy" "red_team" {
  for_each = local.red_team_irsa_contract
  name     = "${var.cluster_name}-${each.value.role_name}-exact"
  role     = aws_iam_role.red_team[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat(
    [{
      Effect   = "Allow"
      Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
      Resource = [for name in local.red_team_mount_secrets[each.key] : aws_secretsmanager_secret.product[name].arn]
      }, {
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = aws_kms_key.staging.arn
      Condition = {
        StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        StringLike   = { "kms:EncryptionContext:SecretARN" = [for name in local.red_team_mount_secrets[each.key] : aws_secretsmanager_secret.product[name].arn] }
      }
      }, {
      Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*"
    }],
    [for statement in [{
      Effect = "Allow", Action = ["sqs:SendMessage", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work["red-team-tests"].arn
      }, {
      Effect    = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.red_team.arn
      Condition = { StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com", "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["red-team-tests"].arn } }
    }] : statement if each.key == "outbox"],
    [for statement in [{
      Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work["red-team-tests"].arn
      }, {
      Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"], Resource = aws_s3_bucket.red_team_evidence.arn
      }, {
      Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"], Resource = "${aws_s3_bucket.red_team_evidence.arn}/organizations/*"
      }, {
      Effect    = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = aws_kms_key.red_team.arn
      Condition = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.red_team_evidence.arn}/organizations/*" } }
      }, {
      Effect    = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.red_team.arn
      Condition = { StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com", "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["red-team-tests"].arn } }
      }, {
      Effect = "Allow", Action = ["kms:DescribeKey"], Resource = aws_kms_key.red_team.arn
    }] : statement if each.key == "worker"],
    [for statement in [{
      Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:zasp/red-team/targets/*"
      }, {
      Effect    = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.red_team.arn
      Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }, StringLike = { "kms:EncryptionContext:SecretARN" = "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:zasp/red-team/targets/*" } }
    }] : statement if each.key == "adapter"]
  ) })
}

resource "aws_iam_role" "attack_lab" {
  for_each = local.attack_lab_irsa_contract
  name     = "${var.cluster_name}-${each.value.role_name}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
    Condition = { StringEquals = {
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
      "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = each.value.principal
    } }
  }] })
}

resource "aws_iam_role_policy" "attack_lab" {
  for_each = local.attack_lab_irsa_contract
  name     = "${var.cluster_name}-${each.value.role_name}-exact"
  role     = aws_iam_role.attack_lab[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat(
    [{
      Effect   = "Allow"
      Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
      Resource = [for name in local.attack_lab_mount_secrets[each.key] : aws_secretsmanager_secret.product[name].arn]
      }, {
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = aws_kms_key.attack_lab.arn
      Condition = {
        StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        StringLike   = { "kms:EncryptionContext:SecretARN" = [for name in local.attack_lab_mount_secrets[each.key] : aws_secretsmanager_secret.product[name].arn] }
      }
      }, {
      Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*"
    }],
    [for statement in [{
      Effect = "Allow", Action = ["sqs:SendMessage", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work["attack-lab-jobs"].arn
      }, {
      Effect    = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.attack_lab.arn
      Condition = { StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com", "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["attack-lab-jobs"].arn } }
    }] : statement if each.key == "outbox"],
    [for statement in [{
      Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.work["attack-lab-jobs"].arn
      }, {
      Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"], Resource = aws_s3_bucket.attack_lab_evidence.arn
      }, {
      Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"], Resource = "${aws_s3_bucket.attack_lab_evidence.arn}/organizations/*"
      }, {
      Effect    = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = aws_kms_key.attack_lab.arn
      Condition = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.attack_lab_evidence.arn}/organizations/*" } }
      }, {
      Effect    = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.attack_lab.arn
      Condition = { StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com", "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["attack-lab-jobs"].arn } }
      }, {
      Effect = "Allow", Action = ["kms:DescribeKey"], Resource = aws_kms_key.attack_lab.arn
    }] : statement if each.key == "controller"],
    [for statement in [{
      Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:zasp/red-team/targets/*"
      }, {
      Effect    = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.red_team.arn
      Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }, StringLike = { "kms:EncryptionContext:SecretARN" = "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:zasp/red-team/targets/*" } }
    }] : statement if each.key == "proxy"]
  ) })
}

resource "aws_iam_role" "projection_risk" {
  name = "${var.cluster_name}-projection-risk"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-projection-risk"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "projection_risk" {
  name = "${var.cluster_name}-projection-risk"
  role = aws_iam_role.projection_risk.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.product["postgres-projection-risk-dsn"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.product["postgres-projection-risk-dsn"].arn
      } }
    },
  ] })
}

resource "aws_iam_role" "projection_graph" {
  name = "${var.cluster_name}-projection-graph"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-projection-graph"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "projection_graph" {
  name = "${var.cluster_name}-projection-graph"
  role = aws_iam_role.projection_graph.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.product["postgres-projection-graph-dsn"].arn, aws_secretsmanager_secret.neo4j_projection_runtime.arn] },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = [aws_secretsmanager_secret.product["postgres-projection-graph-dsn"].arn, aws_secretsmanager_secret.neo4j_projection_runtime.arn]
      } }
    },
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
  ] })
}

resource "aws_iam_role" "projection_graph_init" {
  name = "${var.cluster_name}-projection-graph-init"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:agentsec-projection-graph-init"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "projection_graph_init" {
  name = "${var.cluster_name}-projection-graph-init"
  role = aws_iam_role.projection_graph_init.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.neo4j_projection_schema.arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.neo4j_projection_schema.arn
      } }
    },
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
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
    { Effect = "Allow", Action = ["es:ESHttpGet"], Resource = [
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_mapping",
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_doc/_zasp_schema_v1",
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_doc/active_*",
    ] },
    { Effect = "Allow", Action = ["es:ESHttpPost"], Resource = [
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_bulk",
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_mget",
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_search",
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_delete_by_query",
    ] },
    { Effect = "Allow", Action = ["es:ESHttpPut"], Resource = "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_doc/active_*" },
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
  ] })
}

resource "aws_iam_role" "projection_search_init" {
  name = "${var.cluster_name}-projection-search-init"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:agentsec-projection-search-init"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "projection_search_init" {
  name = "${var.cluster_name}-projection-search-init"
  role = aws_iam_role.projection_search_init.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["es:ESHttpGet"], Resource = [
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_mapping",
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_doc/_zasp_schema_v1",
    ] },
    { Effect = "Allow", Action = ["es:ESHttpPut"], Resource = [
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1",
      "${aws_opensearch_domain.events.arn}/zasp-inventory-v1/_doc/_zasp_schema_v1",
    ] },
    { Effect = "Allow", Action = ["sts:GetCallerIdentity"], Resource = "*" },
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

resource "aws_security_group" "attack_lab_ecr_endpoints" {
  name_prefix = "${var.cluster_name}-attack-lab-ecr-endpoints-"
  description = "Image-pull-only ECR endpoints for isolated Attack Lab runners"
  vpc_id      = aws_vpc.staging.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.staging.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.staging.main_route_table_id]
}

resource "aws_vpc_endpoint" "private_services" {
  for_each          = toset(["ecr.api", "ecr.dkr", "kms", "logs", "secretsmanager", "sqs", "sts"])
  vpc_id            = aws_vpc.staging.id
  service_name      = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.private[*].id
  security_group_ids = contains(["ecr.api", "ecr.dkr"], each.value) ? [
    aws_security_group.vpc_endpoints.id,
    aws_security_group.attack_lab_ecr_endpoints.id,
  ] : [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

resource "aws_iam_role" "attack_lab_pod" {
  name = "${var.cluster_name}-attack-lab-pod"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Service = "eks-fargate-pods.amazonaws.com" }, Action = "sts:AssumeRole"
      Condition = {
        ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:eks:${var.region}:${var.account_id}:fargateprofile/${var.cluster_name}/*" }
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
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
  depends_on = [
    aws_eks_addon.vpc_cni,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller,
    aws_iam_role_policy_attachment.attack_lab_pod,
  ]
}

resource "aws_security_group" "attack_lab" {
  name_prefix = "${var.cluster_name}-attack-lab-"
  description = "Proxy-only egress for isolated Attack Lab Fargate runners"
  vpc_id      = aws_vpc.staging.id
}

resource "aws_security_group" "attack_lab_proxy" {
  name_prefix = "${var.cluster_name}-attack-lab-proxy-"
  description = "Bounded target and dependency egress for the Attack Lab proxy"
  vpc_id      = aws_vpc.staging.id
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_ecr_runner" {
  security_group_id            = aws_security_group.attack_lab_ecr_endpoints.id
  referenced_security_group_id = aws_security_group.attack_lab.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_runner_proxy" {
  security_group_id            = aws_security_group.attack_lab.id
  referenced_security_group_id = aws_security_group.attack_lab_proxy.id
  ip_protocol                  = "tcp"
  from_port                    = 8443
  to_port                      = 8443
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_runner_ecr" {
  security_group_id            = aws_security_group.attack_lab.id
  referenced_security_group_id = aws_security_group.attack_lab_ecr_endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_runner_s3" {
  security_group_id = aws_security_group.attack_lab.id
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_runner_control_plane" {
  security_group_id            = aws_security_group.attack_lab.id
  referenced_security_group_id = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_control_plane_runner" {
  security_group_id            = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.attack_lab.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_runner_kubelet" {
  security_group_id            = aws_security_group.attack_lab.id
  referenced_security_group_id = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 10250
  to_port                      = 10250
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_proxy_runner" {
  security_group_id            = aws_security_group.attack_lab_proxy.id
  referenced_security_group_id = aws_security_group.attack_lab.id
  ip_protocol                  = "tcp"
  from_port                    = 8443
  to_port                      = 8443
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_proxy_internal" {
  security_group_id            = aws_security_group.attack_lab_proxy.id
  referenced_security_group_id = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 8081
  to_port                      = 8081
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_runner_dns_udp" {
  security_group_id            = aws_security_group.attack_lab.id
  referenced_security_group_id = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "udp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_runner_dns_tcp" {
  security_group_id            = aws_security_group.attack_lab.id
  referenced_security_group_id = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_proxy_dns_udp" {
  security_group_id            = aws_security_group.attack_lab_proxy.id
  referenced_security_group_id = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "udp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_proxy_dns_tcp" {
  security_group_id            = aws_security_group.attack_lab_proxy.id
  referenced_security_group_id = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_dns_runner_udp" {
  security_group_id            = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.attack_lab.id
  ip_protocol                  = "udp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_dns_runner_tcp" {
  security_group_id            = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.attack_lab.id
  ip_protocol                  = "tcp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_dns_proxy_udp" {
  security_group_id            = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.attack_lab_proxy.id
  ip_protocol                  = "udp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_ingress_rule" "attack_lab_dns_proxy_tcp" {
  security_group_id            = aws_eks_cluster.staging.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.attack_lab_proxy.id
  ip_protocol                  = "tcp"
  from_port                    = 53
  to_port                      = 53
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_proxy_endpoints" {
  security_group_id            = aws_security_group.attack_lab_proxy.id
  referenced_security_group_id = aws_security_group.vpc_endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_proxy_targets" {
  for_each          = toset(var.attack_lab_target_egress_cidrs)
  security_group_id = aws_security_group.attack_lab_proxy.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "attack_lab_proxy_database" {
  for_each          = toset(var.attack_lab_database_egress_cidrs)
  security_group_id = aws_security_group.attack_lab_proxy.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
}
