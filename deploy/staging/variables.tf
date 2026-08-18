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
