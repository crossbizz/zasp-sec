variable "region" {
  description = "AWS region for the shared non-production staging environment."
  type        = string
  default     = "us-west-2"

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.region))
    error_message = "region must be one canonical AWS region."
  }
}

variable "cluster_name" {
  description = "Product-owned staging EKS cluster name."
  type        = string
  default     = "zasp-staging"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,39}$", var.cluster_name))
    error_message = "cluster_name must be a bounded DNS label."
  }
}

variable "vpc_cidr" {
  description = "Private staging VPC CIDR."
  type        = string
  default     = "10.64.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "Two private staging subnet CIDRs."
  type        = list(string)
  default     = ["10.64.0.0/20", "10.64.16.0/20"]

  validation {
    condition     = length(var.private_subnet_cidrs) == 2 && length(distinct(var.private_subnet_cidrs)) == 2
    error_message = "exactly two distinct private subnets are required."
  }
}

variable "tags" {
  description = "Additional non-sensitive resource tags."
  type        = map(string)
  default     = {}
}

variable "account_id" {
  description = "Twelve-digit staging account ID used to bind global resource names and policies."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be exactly twelve digits."
  }
}

variable "availability_zones" {
  description = "Two availability zones in the selected region."
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b"]

  validation {
    condition     = length(var.availability_zones) == 2 && length(distinct(var.availability_zones)) == 2 && alltrue([for zone in var.availability_zones : startswith(zone, var.region)])
    error_message = "availability_zones must contain two distinct zones in region."
  }
}

variable "offline_validation" {
  description = "Disable provider account calls only for the committed offline plan verification."
  type        = bool
  default     = false
}

variable "environment" {
  description = "Deployment environment for the shared staging/release root."
  type        = string
  default     = "staging"
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "database_principals" {
  description = "Stable PostgreSQL login names provisioned outside Terraform; credentials may rotate, identities must not."
  type = object({
    migration             = string
    api                   = string
    security_agent_api    = string
    security_agent_worker = string
    discovery_worker      = string
    runtime_ingest        = string
    runtime_worker        = string
    outbox_worker         = string
    runtime_gateway       = string
    discovery_scheduler   = string
    projection_risk       = string
    projection_graph      = string
    projection_search     = string
    runtime_coordinator   = string
    runtime_archive       = string
    runtime_index         = string
    runtime_correlation   = string
    runtime_projection    = string
    gateway_control       = string
  })
  default = {
    migration             = "zasp_migration"
    api                   = "zasp_api_runtime"
    security_agent_api    = "zasp_security_agent_api_runtime"
    security_agent_worker = "zasp_security_agent_worker_runtime"
    discovery_worker      = "zasp_discovery_runtime"
    runtime_ingest        = "zasp_ingest_runtime"
    runtime_worker        = "zasp_runtime_worker_runtime"
    outbox_worker         = "zasp_outbox_runtime"
    runtime_gateway       = "zasp_gateway_runtime"
    discovery_scheduler   = "zasp_scheduler_runtime"
    projection_risk       = "zasp_projection_risk_runtime"
    projection_graph      = "zasp_projection_graph_runtime"
    projection_search     = "zasp_projection_search_runtime"
    runtime_coordinator   = "zasp_runtime_coordinator_runtime"
    runtime_archive       = "zasp_runtime_archive_runtime"
    runtime_index         = "zasp_runtime_index_runtime"
    runtime_correlation   = "zasp_runtime_correlation_runtime"
    runtime_projection    = "zasp_runtime_projection_runtime"
    gateway_control       = "zasp_gateway_control_runtime"
  }

  validation {
    condition = length(distinct(values(var.database_principals))) == 19 && alltrue([
      for principal in values(var.database_principals) : can(regex("^[a-z][a-z0-9_]{2,62}$", principal))
    ])
    error_message = "database_principals must contain nineteen distinct bounded PostgreSQL login names."
  }
}

variable "connector_client_ids" {
  description = "Non-secret first-party OAuth client identifiers; client credentials are populated out of band in the connector secret namespace."
  type = object({
    github = string
    okta   = string
  })
  default = {
    github = "Iv1.0000000000000000"
    okta   = "0oa0000000000000000"
  }

  validation {
    condition     = can(regex("^Iv1\\.[A-Za-z0-9]{16}$", var.connector_client_ids.github)) && can(regex("^0oa[A-Za-z0-9]{16}$", var.connector_client_ids.okta))
    error_message = "connector_client_ids must contain canonical non-secret GitHub and Okta client identifiers."
  }
}

variable "github_app_id" {
  description = "Non-secret numeric GitHub App identifier used to mint bounded App JWTs."
  type        = string
  default     = "123456"
  validation {
    condition     = can(regex("^[1-9][0-9]{0,15}$", var.github_app_id))
    error_message = "github_app_id must be a canonical positive numeric GitHub App identifier."
  }
}

variable "discovery_implementation_versions" {
  description = "Immutable production implementation identities fenced against every hydrated discovery job."
  type = object({
    parser               = string
    tool                 = string
    aws_collector        = string
    kubernetes_collector = string
    github_collector     = string
    okta_collector       = string
  })
  default = {
    parser               = "inventory-parser-2026.08.20"
    tool                 = "collector-tool-2026.08.20"
    aws_collector        = "aws-collector-2026.08.20"
    kubernetes_collector = "kubernetes-collector-2026.08.20"
    github_collector     = "github-collector-2026.08.20"
    okta_collector       = "okta-collector-2026.08.20"
  }
  validation {
    condition = alltrue([
      for version in values(var.discovery_implementation_versions) : can(regex("^[a-z][a-z0-9_.-]{1,63}$", version)) && !contains(["parser-v1", "tool-v1"], version)
    ])
    error_message = "discovery_implementation_versions must contain six exact bounded release identities."
  }
}

variable "neo4j_endpoint" {
  description = "Verified-TLS production Neo4j endpoint; credentials are resolved by reference at runtime."
  type        = string
  default     = "neo4j+s://neo4j.internal.example:7687"
  validation {
    condition     = can(regex("^neo4j\\+s://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9]):7687$", var.neo4j_endpoint))
    error_message = "neo4j_endpoint must be one canonical neo4j+s DNS endpoint on port 7687."
  }
}

variable "neo4j_endpoint_cidr" {
  description = "Canonical private CIDR containing every resolved Neo4j endpoint address."
  type        = string
  default     = "10.55.0.0/24"
  validation {
    condition     = can(cidrhost(var.neo4j_endpoint_cidr, 0)) && "${cidrhost(var.neo4j_endpoint_cidr, 0)}/${split("/", var.neo4j_endpoint_cidr)[1]}" == var.neo4j_endpoint_cidr && var.neo4j_endpoint_cidr != "0.0.0.0/0" && var.neo4j_endpoint_cidr != "::/0"
    error_message = "neo4j_endpoint_cidr must be one canonical non-global CIDR."
  }
}

variable "aws_reference_role_prefixes" {
  description = "Canonical customer role path prefixes accepted by the AWS reference authorization runtime across configured accounts."
  type        = set(string)
  default     = ["arn:aws:iam::111111111111:role/zasp-reference/"]
  validation {
    condition = length(var.aws_reference_role_prefixes) >= 1 && length(var.aws_reference_role_prefixes) <= 64 && alltrue([
      for prefix in var.aws_reference_role_prefixes : can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,120}/$", prefix)) && !strcontains(prefix, "*")
    ])
    error_message = "aws_reference_role_prefixes must contain one to 64 exact wildcard-free customer role path prefixes."
  }
}

variable "aws_reference_role_arns" {
  description = "Exact customer roles the connector runtime may assume for read-only reference authorization."
  type        = set(string)
  default     = ["arn:aws:iam::111111111111:role/zasp-reference/customer-0001"]
  validation {
    condition = length(var.aws_reference_role_arns) >= 1 && length(var.aws_reference_role_arns) <= 64 && alltrue([
      for role in var.aws_reference_role_arns : anytrue([for prefix in var.aws_reference_role_prefixes : startswith(role, prefix) && role != prefix]) && !strcontains(role, "*") && can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$", role))
    ])
    error_message = "aws_reference_role_arns must contain one to 64 exact wildcard-free roles beneath the configured customer prefixes."
  }
}

variable "connector_reference_ids" {
  description = "Opaque identifiers for pre-provisioned reference-only AWS and Kubernetes secret metadata."
  type = object({
    aws_external_id       = string
    kubernetes_connection = string
    kubernetes_ca         = string
    kubernetes_credential = string
  })
  default = {
    aws_external_id       = "customer-0001"
    kubernetes_connection = "customer-0001"
    kubernetes_ca         = "customer-0001"
    kubernetes_credential = "customer-0001"
  }
  validation {
    condition     = alltrue([for identifier in values(var.connector_reference_ids) : can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$", identifier))])
    error_message = "connector_reference_ids must contain four bounded opaque identifiers."
  }
}

variable "kubernetes_connector_egress_cidrs" {
  description = "Exact canonical customer Kubernetes API CIDRs admitted by both the runtime dialer and NetworkPolicy."
  type        = list(string)
  default     = ["203.0.113.0/28"]
  validation {
    condition = length(var.kubernetes_connector_egress_cidrs) >= 1 && length(var.kubernetes_connector_egress_cidrs) <= 16 && length(distinct(var.kubernetes_connector_egress_cidrs)) == length(var.kubernetes_connector_egress_cidrs) && alltrue([
      for cidr in var.kubernetes_connector_egress_cidrs : can(cidrhost(cidr, 0)) && "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}" == cidr && cidr != "0.0.0.0/0" && cidr != "::/0"
    ])
    error_message = "kubernetes_connector_egress_cidrs must contain one to 16 distinct canonical non-global CIDRs."
  }
}

variable "finding_ticket_egress_cidrs" {
  description = "Exact canonical public webhook CIDRs admitted by both the ticket dialer and API NetworkPolicy."
  type        = list(string)
  default     = ["192.0.2.64/28"]
  validation {
    condition = length(var.finding_ticket_egress_cidrs) >= 1 && length(var.finding_ticket_egress_cidrs) <= 16 && length(distinct(var.finding_ticket_egress_cidrs)) == length(var.finding_ticket_egress_cidrs) && alltrue([
      for cidr in var.finding_ticket_egress_cidrs : can(cidrhost(cidr, 0)) && "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}" == cidr && tonumber(split("/", cidr)[1]) >= 16 && !can(regex("^(?:0|10|127|169\\.254|172\\.(?:1[6-9]|2[0-9]|3[01])|192\\.168|22[4-9]|23[0-9]|24[0-9]|25[0-5])\\.", cidr))
    ])
    error_message = "finding_ticket_egress_cidrs must contain one to 16 distinct canonical public IPv4 CIDRs at /16 or narrower."
  }
}

variable "endpoint_public_access" {
  description = "Whether the EKS API has a public endpoint; production must remain false."
  type        = bool
  default     = false
  validation {
    condition     = var.environment != "production" || !var.endpoint_public_access
    error_message = "production EKS API access must remain private."
  }
}

variable "node_desired_size" {
  type    = number
  default = 1
}
variable "node_min_size" {
  type    = number
  default = 1
}
variable "node_max_size" {
  type    = number
  default = 2
}
variable "node_instance_types" {
  type    = list(string)
  default = ["m7i.large"]
}
variable "opensearch_instance_type" {
  type    = string
  default = "t3.small.search"
}
variable "opensearch_instance_count" {
  type    = number
  default = 2
}
variable "opensearch_volume_size" {
  type    = number
  default = 20
}
variable "evidence_retention_days" {
  type    = number
  default = 90
}
variable "attack_lab_namespace" {
  type    = string
  default = "zasp-attack-lab"
}
