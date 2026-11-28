# One fixed, offline source profile. These mock identities are never deployed.
mock_provider "aws" {
 override_during = plan
 mock_resource "aws_eks_cluster" { defaults = { identity = [{ oidc = [{ issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/staging-union" }] }] } }
}
mock_provider "tls" {
 override_during = plan
 mock_data "tls_certificate" { defaults = { certificates = [{ sha1_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }] } }
}
variables {
 account_id = "000000000000"
 offline_validation = true
 authorization_temporal_enabled = false
 compliance_exports_enabled = false
 test_reconciler_enabled = false
 attack_lab_reconciler_enabled = false
}

override_resource {
 target = aws_iam_openid_connect_provider.eks
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/staging-union"}
}

override_resource {
 target = aws_iam_policy.attack_lab_runner_test_boundary
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:policy/zasp-staging-attack-lab-runner-test-boundary", "id": "arn:aws:iam::000000000000:policy/zasp-staging-attack-lab-runner-test-boundary"}
}

override_resource {
 target = aws_iam_role.api
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-api", "id": "zasp-staging-api"}
}

override_resource {
 target = aws_iam_role.api_connectors
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-api-connectors", "id": "zasp-staging-api-connectors"}
}

override_resource {
 target = aws_iam_role.attack_lab["controller"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-controller", "id": "zasp-staging-attack-lab-controller"}
}

override_resource {
 target = aws_iam_role.attack_lab["outbox"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-outbox", "id": "zasp-staging-attack-lab-outbox"}
}

override_resource {
 target = aws_iam_role.attack_lab["proxy"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-proxy", "id": "zasp-staging-attack-lab-proxy"}
}

override_resource {
 target = aws_iam_role.attack_lab_pod
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-pod", "id": "zasp-staging-attack-lab-pod"}
}

override_resource {
 target = aws_iam_role.attack_lab_runner_test
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-runner-test", "id": "zasp-staging-attack-lab-runner-test"}
}

override_resource {
 target = aws_iam_role.audit_exports["publisher"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-audit-export-publisher", "id": "zasp-staging-audit-export-publisher"}
}

override_resource {
 target = aws_iam_role.audit_exports["reader"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-audit-export-reader", "id": "zasp-staging-audit-export-reader"}
}

override_resource {
 target = aws_iam_role.audit_exports["writer"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-audit-export-writer", "id": "zasp-staging-audit-export-writer"}
}

override_resource {
 target = aws_iam_role.canary_secret_sync
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-canary-secret-sync", "id": "zasp-staging-canary-secret-sync"}
}

override_resource {
 target = aws_iam_role.eks_cluster
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-cluster", "id": "zasp-staging-cluster"}
}

override_resource {
 target = aws_iam_role.eks_nodes
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-nodes", "id": "zasp-staging-nodes"}
}

override_resource {
 target = aws_iam_role.migration
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-migration", "id": "zasp-staging-migration"}
}

override_resource {
 target = aws_iam_role.outbox
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-outbox", "id": "zasp-staging-outbox"}
}

override_resource {
 target = aws_iam_role.policy_deployment_worker
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-policy-deployment-worker", "id": "zasp-staging-policy-deployment-worker"}
}

override_resource {
 target = aws_iam_role.projection_graph
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-graph", "id": "zasp-staging-projection-graph"}
}

override_resource {
 target = aws_iam_role.projection_graph_init
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-graph-init", "id": "zasp-staging-projection-graph-init"}
}

override_resource {
 target = aws_iam_role.projection_risk
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-risk", "id": "zasp-staging-projection-risk"}
}

override_resource {
 target = aws_iam_role.projection_search
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-search", "id": "zasp-staging-projection-search"}
}

override_resource {
 target = aws_iam_role.projection_search_init
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-search-init", "id": "zasp-staging-projection-search-init"}
}

override_resource {
 target = aws_iam_role.recovery["recovery_backup"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-backup", "id": "zasp-staging-recovery-backup"}
}

override_resource {
 target = aws_iam_role.recovery["recovery_backup_outbox"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-backup-outbox", "id": "zasp-staging-recovery-backup-outbox"}
}

override_resource {
 target = aws_iam_role.recovery["recovery_restore"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-restore", "id": "zasp-staging-recovery-restore"}
}

override_resource {
 target = aws_iam_role.recovery["recovery_restore_outbox"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-restore-outbox", "id": "zasp-staging-recovery-restore-outbox"}
}

override_resource {
 target = aws_iam_role.red_team["adapter"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-red-team-adapter", "id": "zasp-staging-red-team-adapter"}
}

override_resource {
 target = aws_iam_role.red_team["outbox"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-red-team-outbox", "id": "zasp-staging-red-team-outbox"}
}

override_resource {
 target = aws_iam_role.red_team["worker"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-red-team-worker", "id": "zasp-staging-red-team-worker"}
}

override_resource {
 target = aws_iam_role.runtime["archive"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-archive", "id": "zasp-staging-runtime-archive"}
}

override_resource {
 target = aws_iam_role.runtime["complete"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-complete", "id": "zasp-staging-runtime-complete"}
}

override_resource {
 target = aws_iam_role.runtime["coordinator"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-coordinator", "id": "zasp-staging-runtime-coordinator"}
}

override_resource {
 target = aws_iam_role.runtime["correlation"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-correlation", "id": "zasp-staging-runtime-correlation"}
}

override_resource {
 target = aws_iam_role.runtime["gateway_control"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-gateway-control", "id": "zasp-staging-gateway-control"}
}

override_resource {
 target = aws_iam_role.runtime["index"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-index", "id": "zasp-staging-runtime-index"}
}

override_resource {
 target = aws_iam_role.runtime["ingest"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-ingest", "id": "zasp-staging-runtime-ingest"}
}

override_resource {
 target = aws_iam_role.runtime["outbox"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-outbox", "id": "zasp-staging-runtime-outbox"}
}

override_resource {
 target = aws_iam_role.runtime["projection"]
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-projection", "id": "zasp-staging-runtime-projection"}
}

override_resource {
 target = aws_iam_role.scheduler
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-discovery-scheduler", "id": "zasp-staging-discovery-scheduler"}
}

override_resource {
 target = aws_iam_role.security_agent_action_worker
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-security-agent-action-worker", "id": "zasp-staging-security-agent-action-worker"}
}

override_resource {
 target = aws_iam_role.security_agent_worker
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-security-agent-worker", "id": "zasp-staging-security-agent-worker"}
}

override_resource {
 target = aws_iam_role.worker
 override_during = plan
 values = {"arn": "arn:aws:iam::000000000000:role/zasp-staging-discovery-worker", "id": "zasp-staging-discovery-worker"}
}

override_resource {
 target = aws_kms_key.attack_lab
 override_during = plan
 values = {"arn": "arn:aws:kms:us-west-2:000000000000:key/19b5c7c4-bd0f-43c1-8997-00d89c60de3c", "id": "19b5c7c4-bd0f-43c1-8997-00d89c60de3c"}
}

override_resource {
 target = aws_kms_key.connector_oauth
 override_during = plan
 values = {"arn": "arn:aws:kms:us-west-2:000000000000:key/63500a26-5cc2-ab1e-0e23-d07574fc6f55", "id": "63500a26-5cc2-ab1e-0e23-d07574fc6f55"}
}

override_resource {
 target = aws_kms_key.recovery_signing
 override_during = plan
 values = {"arn": "arn:aws:kms:us-west-2:000000000000:key/10befce7-852e-cf7c-e6cc-e5a05dd4a230", "id": "10befce7-852e-cf7c-e6cc-e5a05dd4a230"}
}

override_resource {
 target = aws_kms_key.red_team
 override_during = plan
 values = {"arn": "arn:aws:kms:us-west-2:000000000000:key/2d07a082-d7d9-37bd-2e7a-903b1c558b15", "id": "2d07a082-d7d9-37bd-2e7a-903b1c558b15"}
}

override_resource {
 target = aws_kms_key.runtime_raw
 override_during = plan
 values = {"arn": "arn:aws:kms:us-west-2:000000000000:key/c225b472-d20b-912e-bc20-91ff5159034e", "id": "c225b472-d20b-912e-bc20-91ff5159034e"}
}

override_resource {
 target = aws_kms_key.staging
 override_during = plan
 values = {"arn": "arn:aws:kms:us-west-2:000000000000:key/c824037f-f668-5b41-f364-7e25f1707b38", "id": "c824037f-f668-5b41-f364-7e25f1707b38"}
}

override_resource {
 target = aws_opensearch_domain.events
 override_during = plan
 values = {"arn": "arn:aws:es:us-west-2:000000000000:domain/zasp-staging-events", "endpoint": "zasp-staging-events.us-west-2.es.amazonaws.com"}
}

override_resource {
 target = aws_s3_bucket.attack_lab_evidence
 override_during = plan
 values = {"arn": "arn:aws:s3:::zasp-attack-lab-evidence-35b9ab5a36f3234dd26db357fd4a0dc1", "id": "zasp-attack-lab-evidence-35b9ab5a36f3234dd26db357fd4a0dc1"}
}

override_resource {
 target = aws_s3_bucket.evidence
 override_during = plan
 values = {"arn": "arn:aws:s3:::zasp-product-data-35b9ab5a36f3234dd26db357fd4a0dc1", "id": "zasp-product-data-35b9ab5a36f3234dd26db357fd4a0dc1"}
}

override_resource {
 target = aws_s3_bucket.red_team_evidence
 override_during = plan
 values = {"arn": "arn:aws:s3:::zasp-red-team-evidence-35b9ab5a36f3234dd26db357fd4a0dc1", "id": "zasp-red-team-evidence-35b9ab5a36f3234dd26db357fd4a0dc1"}
}

override_resource {
 target = aws_s3_bucket.runtime_raw
 override_during = plan
 values = {"arn": "arn:aws:s3:::zasp-runtime-raw-35b9ab5a36f3234dd26db357fd4a0dc1", "id": "zasp-runtime-raw-35b9ab5a36f3234dd26db357fd4a0dc1"}
}

override_resource {
 target = aws_secretsmanager_secret.audit_exports["audit-export-cursor-signing-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/audit-export-cursor-signing-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/audit-export-cursor-signing-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.audit_exports["postgres-audit-export-outbox-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-outbox-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-outbox-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.audit_exports["postgres-audit-export-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.connector_provider["github_app_private_key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/app-private-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/app-private-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.connector_provider["github_client_secret"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/client-secret-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/client-secret-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.connector_provider["okta_client_secret"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/okta/client-secret-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/okta/client-secret-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.connector_reference["aws_external_id"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/aws/external-id/customer-0001-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/aws/external-id/customer-0001-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.connector_reference["kubernetes_ca"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/ca/customer-0001-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/ca/customer-0001-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.connector_reference["kubernetes_connection"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/connection/customer-0001-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/connection/customer-0001-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.connector_reference["kubernetes_credential"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/credential/customer-0001-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/credential/customer-0001-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.neo4j_projection_runtime
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/runtime-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/runtime-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.neo4j_projection_schema
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/schema-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/schema-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["attack-lab-egress-signing-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-egress-signing-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-egress-signing-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["attack-lab-proxy-tls-certificate"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-certificate-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-certificate-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["attack-lab-proxy-tls-private-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-private-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-private-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["canary-read-token"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/canary-read-token-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/canary-read-token-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["gateway-policy-signing-private-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/gateway-policy-signing-private-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/gateway-policy-signing-private-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["openrouter-security-agent-api-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/openrouter-security-agent-api-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/openrouter-security-agent-api-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-api-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-api-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-api-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-attack-lab-controller-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-controller-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-controller-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-attack-lab-outbox-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-outbox-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-outbox-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-attack-lab-proxy-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-proxy-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-proxy-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-gateway-control-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-gateway-control-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-gateway-control-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-migration-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-migration-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-migration-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-outbox-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-outbox-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-outbox-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-policy-deployment-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-policy-deployment-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-policy-deployment-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-projection-graph-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-graph-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-graph-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-projection-risk-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-risk-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-risk-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-projection-search-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-search-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-search-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-recovery-outbox-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-outbox-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-outbox-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-recovery-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-red-team-adapter-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-adapter-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-adapter-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-red-team-outbox-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-outbox-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-outbox-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-red-team-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-archive-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-archive-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-archive-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-coordinator-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-coordinator-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-coordinator-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-correlation-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-correlation-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-correlation-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-gateway-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-gateway-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-gateway-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-index-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-index-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-index-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-ingest-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-ingest-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-ingest-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-projection-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-projection-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-projection-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-runtime-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-scheduler-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-scheduler-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-scheduler-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-security-agent-action-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-action-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-action-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-security-agent-api-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-api-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-api-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-security-agent-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["postgres-worker-dsn"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-worker-dsn-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-worker-dsn-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["red-team-adapter-tls-certificate"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-certificate-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-certificate-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["red-team-adapter-tls-private-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-private-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-private-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["red-team-adapter-token"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-token-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-token-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["stytch-organization-id"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-organization-id-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-organization-id-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["stytch-project-id"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-project-id-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-project-id-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["stytch-public-token"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-public-token-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-public-token-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["stytch-secret"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-secret-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-secret-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["stytch-webhook-secret"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-webhook-secret-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-webhook-secret-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["token-reveal-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/token-reveal-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/token-reveal-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.product["workflow-signing-key"]
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/workflow-signing-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/workflow-signing-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.recovery_neon_api
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-recovery/neon/project-api-key-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-recovery/neon/project-api-key-mock00"}
}

override_resource {
 target = aws_secretsmanager_secret.red_team_readiness_target
 override_during = plan
 values = {"arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp/red-team/targets/readiness-0001-mock00", "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp/red-team/targets/readiness-0001-mock00"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["attack-lab-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-attack-lab-jobs-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-attack-lab-jobs-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["audit-exports"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-audit-exports-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-audit-exports-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["background"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-background-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-background-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["discovery-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-discovery-jobs-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-discovery-jobs-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["recovery-backup-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-backup-jobs-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-backup-jobs-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["recovery-restore-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-restore-jobs-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-restore-jobs-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["red-team-tests"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-red-team-tests-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-red-team-tests-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["runtime-events"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-runtime-events-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-runtime-events-dlq"}
}

override_resource {
 target = aws_sqs_queue.dead_letter["tests"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-tests-dlq", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-tests-dlq"}
}

override_resource {
 target = aws_sqs_queue.work["attack-lab-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-attack-lab-jobs", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-attack-lab-jobs"}
}

override_resource {
 target = aws_sqs_queue.work["audit-exports"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-audit-exports", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-audit-exports"}
}

override_resource {
 target = aws_sqs_queue.work["background"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-background", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-background"}
}

override_resource {
 target = aws_sqs_queue.work["discovery-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-discovery-jobs", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-discovery-jobs"}
}

override_resource {
 target = aws_sqs_queue.work["recovery-backup-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-backup-jobs", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-backup-jobs"}
}

override_resource {
 target = aws_sqs_queue.work["recovery-restore-jobs"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-restore-jobs", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-restore-jobs"}
}

override_resource {
 target = aws_sqs_queue.work["red-team-tests"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-red-team-tests", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-red-team-tests"}
}

override_resource {
 target = aws_sqs_queue.work["runtime-events"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-runtime-events", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-runtime-events"}
}

override_resource {
 target = aws_sqs_queue.work["tests"]
 override_during = plan
 values = {"arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-tests", "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-tests"}
}

run "closed_default_workload_policy_union" {
 command = plan
 assert {
  condition = length(aws_iam_role.runtime) == 9 && length(aws_iam_role.recovery) == 4 && length(aws_iam_role.red_team) == 3 && length(aws_iam_role.attack_lab) == 3 && length(aws_iam_role.audit_exports) == 3 && length(aws_iam_role.authorization_temporal) == 0 && length(aws_iam_role.compliance_exports) == 0 && length(aws_iam_role.test_reconciler) == 0 && length(aws_iam_role.attack_lab_reconciler) == 0
  error_message = "The fixed default workload profile requires its exact role split and no optional roles."
 }
}
