# Production variables for the Terraform root in deploy/staging.
# Copy to a private file outside the repository, replace every REPLACE value and
# pass it with -var-file. This file holds no secret: Terraform creates empty
# Secrets Manager entries and the operator fills them afterwards.
# See docs/operations/production-aws-runbook.md. Not applied to any account.

environment = "production"
region      = "us-west-2"    # Decision D1. availability_zones must be in it.
account_id  = "000000000000" # REPLACE: the twelve-digit AWS account ID.

# The release contract and the Helm examples assume this exact name: role names
# are <cluster_name>-<workload> and secret names are <cluster_name>/<name>.
cluster_name           = "zasp-production"
eks_kubernetes_version = "1.34"
vpc_cni_addon_version  = "v1.22.4-eksbuild.3"

vpc_cidr             = "10.80.0.0/16"
availability_zones   = ["us-west-2a", "us-west-2b"]
private_subnet_cidrs = ["10.80.0.0/20", "10.80.16.0/20"]
# The Attack Lab subnets default to 10.80.32.0/20 and 10.80.48.0/20.

# Decision D3: internet path. Two CIDRs create public subnets, an internet
# gateway and one NAT gateway. Without them the product cannot reach Neon,
# Stytch or OpenRouter and has no internet-facing load balancer.
public_subnet_cidrs = ["10.80.64.0/24", "10.80.65.0/24"]

# Production requires a private EKS API endpoint. kubectl and helm must run
# from inside the VPC (runbook, step 3).
endpoint_public_access = false

# Decision D4: sizing. The chart renders 33 Deployments, most with 2 replicas.
node_desired_size   = 6
node_min_size       = 6
node_max_size       = 10
node_instance_types = ["m7i.xlarge"]

# Two availability zones need an even number of data nodes.
opensearch_instance_type  = "r7g.large.search"
opensearch_instance_count = 2
opensearch_volume_size    = 100
evidence_retention_days   = 365

# Baseline schema: fixed login names (zasp_operator, zasp_svc_*).
schema_install = "baseline"
# The baseline requires the named profile: runtime services, worker keys,
# the permission projector and the approval-maintenance entries.
authorization_temporal_enabled = true

# Set true only in an account that has never had an OpenSearch domain.
create_opensearch_service_linked_role = true
ecr_repositories_enabled              = true

# Decision D6: NetworkPolicy enforcement. See the runbook before setting true.
vpc_cni_network_policy_enabled = false

# Decision D5: TLS. A public hosted zone ID lets cert-manager issue the
# certificate with DNS-01. Leave empty to supply the certificate yourself.
route53_zone_id = "" # REPLACE or leave empty, for example "Z0123456789ABCDEFGHIJ".

# Decision D7: databases for Temporal, OpenFGA and Nango.
runtime_services_rds_enabled        = true
runtime_services_rds_instance_class = "db.t4g.medium"
runtime_services_rds_multi_az       = true

# Decision D8: graph store. A verified-TLS Neo4j endpoint must exist; Terraform
# does not create one. The CIDR must contain every address the host resolves to.
neo4j_endpoint      = "neo4j+s://neo4j.internal.example:7687" # REPLACE
neo4j_endpoint_cidr = "10.55.0.0/24"                          # REPLACE

# Connector identifiers (not secrets). The API and the discovery worker refuse
# to start without syntactically valid values, even if GitHub and Okta
# connectors are not used yet. REPLACE with the real GitHub App and Okta
# application when they exist.
connector_client_ids = {
  github = "Iv1.0000000000000000"
  okta   = "0oa0000000000000000"
}
github_app_id = "123456"

# Customer AWS accounts. The API and the discovery worker may assume exactly
# these roles, each under an allowed path prefix. Adding a customer account
# means adding its role here and applying again. REPLACE.
aws_reference_role_prefixes = ["arn:aws:iam::111111111111:role/zasp-reference/"]
aws_reference_role_arns     = ["arn:aws:iam::111111111111:role/zasp-reference/customer-0001"]
connector_reference_ids = {
  aws_external_id       = "customer-0001"
  kubernetes_connection = "customer-0001"
  kubernetes_ca         = "customer-0001"
  kubernetes_credential = "customer-0001"
}

# Fixed destination snapshots. REPLACE with the real addresses.
kubernetes_connector_egress_cidrs = ["203.0.113.0/28"]
finding_ticket_egress_cidrs       = ["192.0.2.64/28"]
attack_lab_target_egress_cidrs    = ["203.0.113.0/28"]
# Private addresses the Attack Lab proxy reaches the product database on.
# Neon is not inside the VPC; see "Known gaps" in the runbook.
attack_lab_database_egress_cidrs = ["10.30.0.0/24"]

tags = {
  Owner = "REPLACE"
}
