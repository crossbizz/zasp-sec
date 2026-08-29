package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadWorkerRuntimeConfigRequiresExactModeAuthority(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		"ZASP_WORKER_MODE":              "scheduler",
		"ZASP_POSTGRES_DSN":             "postgres://scheduler@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY":       "zasp_discovery_scheduler",
		"ZASP_WORKER_ID":                "scheduler-01",
		"ZASP_POLL_INTERVAL":            "250ms",
		"ZASP_LEASE_DURATION":           "30s",
		"ZASP_BATCH_SIZE":               "8",
		"ZASP_SHUTDOWN_TIMEOUT":         "20s",
		"ZASP_DISCOVERY_PARSER_VERSION": "inventory-parser-2026.08.20",
		"ZASP_DISCOVERY_TOOL_VERSION":   "collector-tool-2026.08.20",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil {
		t.Fatalf("loadWorkerRuntimeConfig() error = %v", err)
	}
	if config.Mode != workerModeScheduler || config.DatabaseAuthority != "zasp_discovery_scheduler" || config.LeaseDuration != 30*time.Second {
		t.Fatalf("config = %#v", config)
	}

	for name, mutate := range map[string]func(map[string]string){
		"union authority": func(values map[string]string) { values["ZASP_DATABASE_AUTHORITY"] = "zasp_projection_worker" },
		"missing dsn":     func(values map[string]string) { delete(values, "ZASP_POSTGRES_DSN") },
		"unknown mode":    func(values map[string]string) { values["ZASP_WORKER_MODE"] = "all" },
		"oversized batch": func(values map[string]string) { values["ZASP_BATCH_SIZE"] = "65" },
		"unsafe lease":    func(values map[string]string) { values["ZASP_LEASE_DURATION"] = "3s" },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error = %v, want errWorkerConfiguration", err)
			}
		})
	}
}

func TestAttackLabOutboxModeRequiresExactQueueAndPrincipalAuthority(t *testing.T) {
	values := map[string]string{
		"ZASP_WORKER_MODE": "attack-lab-outbox", "ZASP_POSTGRES_DSN": "postgres://attack_lab_outbox@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_attack_lab_outbox_worker", "ZASP_WORKER_ID": "attack-lab-outbox-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_ATTACK_LAB_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-attack-lab-jobs", "ZASP_AWS_REGION": "us-west-2",
		"ZASP_OUTBOX_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-attack-lab-outbox", "ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.Mode != workerModeAttackLabOutbox || config.AttackLabQueueURL != values["ZASP_ATTACK_LAB_QUEUE_URL"] {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"foreign authority": func(input map[string]string) { input["ZASP_DATABASE_AUTHORITY"] = "zasp_red_team_outbox_worker" },
		"wrong queue": func(input map[string]string) {
			input["ZASP_ATTACK_LAB_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-red-team-tests"
		},
		"cross account role": func(input map[string]string) {
			input["ZASP_OUTBOX_ROLE_ARN"] = "arn:aws:iam::210987654321:role/zasp-production-attack-lab-outbox"
		},
		"ambient token": func(input map[string]string) { delete(input, "ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE") },
	} {
		t.Run(name, func(t *testing.T) {
			drift := cloneStringMap(values)
			mutate(drift)
			if _, err := loadWorkerRuntimeConfig(mapLookup(drift)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("drift accepted: %v", err)
			}
		})
	}
}

func TestAttackLabControllerModeRequiresExactSandboxAndCloudAuthority(t *testing.T) {
	values := validAttackLabControllerRuntimeEnvironment()
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.Mode != workerModeAttackLabController || config.AttackLabNamespace != "zasp-attack-lab" || config.AttackLabOperationTimeout != 10*time.Second {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"foreign authority": func(input map[string]string) { input["ZASP_DATABASE_AUTHORITY"] = "zasp_discovery_worker" },
		"queue drift": func(input map[string]string) {
			input["ZASP_ATTACK_LAB_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-red-team-tests"
		},
		"namespace drift":        func(input map[string]string) { input["ZASP_ATTACK_LAB_NAMESPACE"] = "default" },
		"foreign security group": func(input map[string]string) { input["ZASP_ATTACK_LAB_SECURITY_GROUP_ID"] = "sg-not-valid" },
		"mutable image": func(input map[string]string) {
			input["ZASP_ATTACK_LAB_RUNNER_IMAGE"] = "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner:latest"
		},
		"cross account image": func(input map[string]string) {
			input["ZASP_ATTACK_LAB_RUNNER_IMAGE"] = "210987654321.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64)
		},
		"public proxy": func(input map[string]string) {
			input["ZASP_ATTACK_LAB_PROXY_ENDPOINT"] = "https://proxy.example.com/v1/egress"
		},
		"ambient kube token": func(input map[string]string) {
			delete(input, "ZASP_ATTACK_LAB_KUBERNETES_TOKEN_FILE")
		},
		"unbounded timeout": func(input map[string]string) { input["ZASP_ATTACK_LAB_OPERATION_TIMEOUT"] = "31s" },
	} {
		t.Run(name, func(t *testing.T) {
			drift := cloneStringMap(values)
			mutate(drift)
			if _, err := loadWorkerRuntimeConfig(mapLookup(drift)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("drift accepted: %v", err)
			}
		})
	}
}

func validAttackLabControllerRuntimeEnvironment() map[string]string {
	return map[string]string{
		"ZASP_WORKER_MODE": "attack-lab-controller", "ZASP_POSTGRES_DSN": "postgres://attack_lab_controller@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_attack_lab_controller", "ZASP_WORKER_ID": "attack-lab-controller-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "5", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_ATTACK_LAB_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-attack-lab-jobs", "ZASP_AWS_REGION": "us-west-2",
		"ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012", "ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_ATTACK_LAB_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-attack-lab-controller", "ZASP_ATTACK_LAB_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_ATTACK_LAB_NAMESPACE": "zasp-attack-lab", "ZASP_ATTACK_LAB_RUNNER_SERVICE_ACCOUNT": "agentsec-attack-lab-runner",
		"ZASP_ATTACK_LAB_SECURITY_GROUP_ID":   "sg-1234abcd",
		"ZASP_ATTACK_LAB_RUNNER_IMAGE":        "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64),
		"ZASP_ATTACK_LAB_KUBERNETES_ENDPOINT": "https://kubernetes.default.svc", "ZASP_ATTACK_LAB_KUBERNETES_TOKEN_FILE": "/var/run/secrets/kubernetes.io/serviceaccount/token", "ZASP_ATTACK_LAB_KUBERNETES_CA_FILE": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		"ZASP_ATTACK_LAB_PROXY_ENDPOINT": "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", "ZASP_ATTACK_LAB_PROXY_CA_FILE": "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", "ZASP_ATTACK_LAB_EGRESS_SIGNING_KEY_FILE": "/var/run/secrets/zasp-attack-lab/egress-signing-key",
		"ZASP_ATTACK_LAB_OPERATION_TIMEOUT": "10s",
	}
}

func TestSecurityAgentWorkerModeRequiresOnlyV18WorkerAuthority(t *testing.T) {
	values := map[string]string{
		"ZASP_WORKER_MODE": "security-agent", "ZASP_POSTGRES_DSN": "postgres://security_agent@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_security_agent_worker", "ZASP_WORKER_ID": "security-agent-worker-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.Mode != workerModeSecurityAgent || config.DatabaseAuthority != "zasp_security_agent_worker" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	values["ZASP_DATABASE_AUTHORITY"] = "zasp_discovery_worker"
	if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
		t.Fatalf("foreign authority error=%v", err)
	}
}

func TestSecurityAgentActionModeRequiresSeparateDatabaseAndSigningAuthority(t *testing.T) {
	values := map[string]string{
		"ZASP_WORKER_MODE": "security-agent-action", "ZASP_POSTGRES_DSN": "postgres://security_agent_action@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_security_agent_action_worker", "ZASP_WORKER_ID": "security-agent-action-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_GATEWAY_SIGNING_KEY_ID": "gateway-key-01", "ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE": "/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.Mode != workerModeSecurityAgentAction || config.DatabaseAuthority != "zasp_security_agent_action_worker" || config.GatewaySigningKeyID != "gateway-key-01" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for key, value := range map[string]string{"ZASP_DATABASE_AUTHORITY": "zasp_security_agent_worker", "ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE": "/tmp/key", "ZASP_GATEWAY_SIGNING_KEY_ID": "short"} {
		drift := cloneStringMap(values)
		drift[key] = value
		if _, err := loadWorkerRuntimeConfig(mapLookup(drift)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%s drift accepted: %v", key, err)
		}
	}
}

func TestPolicyDeploymentModeRequiresDedicatedDatabaseAndSigningAuthority(t *testing.T) {
	values := map[string]string{
		"ZASP_WORKER_MODE": "policy-deployment", "ZASP_POSTGRES_DSN": "postgres://policy_deployment@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_policy_deployment_worker", "ZASP_WORKER_ID": "policy-deployment-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_GATEWAY_SIGNING_KEY_ID": "gateway-key-01", "ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE": "/var/run/secrets/zasp-policy-deployment/gateway-signing-private-key",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.Mode != workerMode("policy-deployment") || config.DatabaseAuthority != "zasp_policy_deployment_worker" || config.GatewaySigningKeyID != "gateway-key-01" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for key, value := range map[string]string{"ZASP_DATABASE_AUTHORITY": "zasp_security_agent_action_worker", "ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE": "/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key", "ZASP_GATEWAY_SIGNING_KEY_ID": "short"} {
		drift := cloneStringMap(values)
		drift[key] = value
		if _, err := loadWorkerRuntimeConfig(mapLookup(drift)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%s drift accepted: %v", key, err)
		}
	}
}

func TestProjectionModesRequireKindSpecificAuthority(t *testing.T) {
	t.Parallel()

	for mode, authority := range map[string]string{
		"projection-risk": "zasp_projection_risk_worker", "projection-graph": "zasp_projection_graph_worker", "projection-search": "zasp_projection_search_worker",
	} {
		values := map[string]string{
			"ZASP_WORKER_MODE": mode, "ZASP_POSTGRES_DSN": "postgres://projection@postgres.internal/zasp?sslmode=verify-full",
			"ZASP_DATABASE_AUTHORITY": authority, "ZASP_WORKER_ID": mode + "-01",
			"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
			"ZASP_OPENSEARCH_ENDPOINT": "https://vpc-zasp.us-west-2.es.amazonaws.com", "ZASP_OPENSEARCH_INDEX": "zasp-inventory-v1",
			"ZASP_NEO4J_URI": "neo4j+s://neo4j.internal.example:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/auth/production",
			"ZASP_NEO4J_EXPECTED_PRINCIPAL": "zasp-graph-worker", "ZASP_NEO4J_EXPECTED_ROLE": "zasp_projection_graph",
			"ZASP_AWS_REGION": "us-west-2", "ZASP_PROJECTION_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-projection",
			"ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_PROJECTION_SECRET_PREFIX": "zasp-production/projection",
		}
		config, err := loadWorkerRuntimeConfig(mapLookup(values))
		if err != nil {
			t.Fatalf("%s config error = %v", mode, err)
		}
		if config.ProjectionKind == "" {
			t.Fatalf("%s omitted projection kind", mode)
		}
	}
}

func TestProjectionInitModesRequireDistinctOneShotAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_AWS_REGION": "us-west-2", "ZASP_PROJECTION_INIT_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-projection-init",
		"ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_PROJECTION_INIT_TIMEOUT": "20s",
		"ZASP_OPENSEARCH_ENDPOINT": "https://vpc-zasp.us-west-2.es.amazonaws.com", "ZASP_OPENSEARCH_INDEX": "zasp-inventory-v1",
		"ZASP_PROJECTION_SECRET_PREFIX": "zasp-production/projection", "ZASP_NEO4J_URI": "neo4j+s://neo4j.internal.example:7687", "ZASP_NEO4J_SCHEMA_CREDENTIAL_REFERENCE": "ref:neo4j/auth/schema-production",
	}
	for _, mode := range []string{"projection-search-init", "projection-graph-init"} {
		values := cloneStringMap(base)
		values["ZASP_WORKER_MODE"] = mode
		config, err := loadProjectionInitConfig(mapLookup(values))
		if err != nil || string(config.Mode) != mode || config.PostgresDSN != "" || config.ProjectionRoleARN != values["ZASP_PROJECTION_INIT_ROLE_ARN"] || config.LeaseDuration != 20*time.Second {
			t.Fatalf("%s config=%#v error=%v", mode, config, err)
		}
	}
	for _, missing := range []string{"ZASP_PROJECTION_INIT_ROLE_ARN", "ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE", "ZASP_PROJECTION_INIT_TIMEOUT"} {
		values := cloneStringMap(base)
		values["ZASP_WORKER_MODE"] = "projection-search-init"
		delete(values, missing)
		if _, err := loadProjectionInitConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("missing %s error=%v", missing, err)
		}
	}
}

func TestWorkerRuntimeConfigRequiresOnlyModeOwnedDependencies(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		"ZASP_POSTGRES_DSN": "postgres://worker@postgres.internal/zasp?sslmode=verify-full", "ZASP_WORKER_ID": "worker-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_DISCOVERY_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs",
		"ZASP_AWS_REGION":          "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012",
		"ZASP_OUTBOX_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-outbox", "ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_EVIDENCE_KMS_KEY_ARN":     "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_DISCOVERY_PARSER_VERSION": "parser-v1", "ZASP_DISCOVERY_TOOL_VERSION": "tool-v1",
		"ZASP_DISCOVERY_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-discovery-worker", "ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_DISCOVERY_SECRET_PREFIX": "zasp-production/connectors", "ZASP_DISCOVERY_AWS_COLLECTOR_VERSION": "aws-collector-v1", "ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION": "kubernetes-collector-v1",
		"ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION": "github-collector-v1", "ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION": "okta-collector-v1", "ZASP_KUBERNETES_EGRESS_CIDRS": "203.0.113.0/24",
		"ZASP_GITHUB_APP_ID": "123456", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE": "ref:github/app-private-key-0001", "ZASP_OKTA_CLIENT_ID": "0oa1234567890abcdef", "ZASP_OKTA_CLIENT_SECRET_REFERENCE": "ref:okta/client-secret-0001",
		"ZASP_PROVIDER_TIMEOUT": "5s", "ZASP_DISCOVERY_READINESS_TIMEOUT": "5s",
		"ZASP_OPENSEARCH_ENDPOINT": "https://vpc-zasp.us-west-2.es.amazonaws.com", "ZASP_OPENSEARCH_INDEX": "zasp-inventory-v1",
		"ZASP_NEO4J_URI": "neo4j+s://neo4j.internal.example:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/auth/production",
		"ZASP_NEO4J_EXPECTED_PRINCIPAL": "zasp-graph-worker", "ZASP_NEO4J_EXPECTED_ROLE": "zasp_projection_graph",
		"ZASP_PROJECTION_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-projection", "ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_PROJECTION_SECRET_PREFIX": "zasp-production/projection",
	}
	for _, test := range []struct {
		mode, authority string
		remove          string
	}{
		{"outbox", "zasp_outbox_worker", "ZASP_DISCOVERY_QUEUE_URL"},
		{"discovery", "zasp_discovery_worker", "ZASP_EVIDENCE_BUCKET"},
		{"projection-search", "zasp_projection_search_worker", "ZASP_OPENSEARCH_ENDPOINT"},
		{"projection-graph", "zasp_projection_graph_worker", "ZASP_NEO4J_URI"},
	} {
		values := cloneStringMap(base)
		values["ZASP_WORKER_MODE"], values["ZASP_DATABASE_AUTHORITY"] = test.mode, test.authority
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); err != nil {
			t.Fatalf("%s config rejected: %v", test.mode, err)
		}
		delete(values, test.remove)
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%s missing %s error = %v", test.mode, test.remove, err)
		}
	}
}

func TestDiscoveryRuntimeRequiresExactProviderQueueAndCloudAuthority(t *testing.T) {
	t.Parallel()
	base := validDiscoveryRuntimeEnvironment()
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil {
		t.Fatalf("valid discovery config error = %v", err)
	}
	if config.DiscoveryRoleARN != base["ZASP_DISCOVERY_ROLE_ARN"] || config.AWSCollectorVersion != "aws-collector-v1" || len(config.KubernetesEgressCIDRs) != 1 || config.ProviderTimeout != 5*time.Second {
		t.Fatalf("config=%#v", config)
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing role":           func(values map[string]string) { delete(values, "ZASP_DISCOVERY_ROLE_ARN") },
		"ambient token":          func(values map[string]string) { delete(values, "ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE") },
		"oauth secret namespace": func(values map[string]string) { values["ZASP_DISCOVERY_SECRET_PREFIX"] += "/oauth" },
		"queue region drift":     func(values map[string]string) { values["ZASP_AWS_REGION"] = "us-east-1" },
		"queue account drift": func(values map[string]string) {
			values["ZASP_DISCOVERY_ROLE_ARN"] = "arn:aws:iam::210987654321:role/zasp-production-discovery-worker"
		},
		"kms account drift": func(values map[string]string) {
			values["ZASP_EVIDENCE_KMS_KEY_ARN"] = "arn:aws:kms:us-west-2:210987654321:key/11111111-1111-4111-8111-111111111111"
		},
		"unbounded kubernetes": func(values map[string]string) { values["ZASP_KUBERNETES_EGRESS_CIDRS"] = "0.0.0.0/0" },
		"collector drift":      func(values map[string]string) { delete(values, "ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION") },
		"foreign github reference": func(values map[string]string) {
			values["ZASP_GITHUB_PRIVATE_KEY_REFERENCE"] = "ref:okta/app-private-key-0001"
		},
		"foreign okta reference": func(values map[string]string) {
			values["ZASP_OKTA_CLIENT_SECRET_REFERENCE"] = "ref:github/client-secret-0001"
		},
		"provider timeout":          func(values map[string]string) { values["ZASP_PROVIDER_TIMEOUT"] = "31s" },
		"oversized discovery batch": func(values map[string]string) { values["ZASP_BATCH_SIZE"] = "11" },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func validDiscoveryRuntimeEnvironment() map[string]string {
	return map[string]string{
		"ZASP_WORKER_MODE": "discovery", "ZASP_POSTGRES_DSN": "postgres://discovery@postgres.internal/zasp?sslmode=verify-full", "ZASP_DATABASE_AUTHORITY": "zasp_discovery_worker", "ZASP_WORKER_ID": "discovery-01",
		"ZASP_POLL_INTERVAL": "1s", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "15s",
		"ZASP_DISCOVERY_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs", "ZASP_AWS_REGION": "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012",
		"ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", "ZASP_DISCOVERY_PARSER_VERSION": "inventory-parser-2026.08.20", "ZASP_DISCOVERY_TOOL_VERSION": "collector-tool-2026.08.20",
		"ZASP_DISCOVERY_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-discovery-worker", "ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_DISCOVERY_SECRET_PREFIX": "zasp-production/connectors",
		"ZASP_DISCOVERY_AWS_COLLECTOR_VERSION": "aws-collector-v1", "ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION": "kubernetes-collector-v1", "ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION": "github-collector-v1", "ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION": "okta-collector-v1",
		"ZASP_KUBERNETES_EGRESS_CIDRS": "203.0.113.0/24", "ZASP_GITHUB_APP_ID": "123456", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE": "ref:github/app-private-key-0001", "ZASP_OKTA_CLIENT_ID": "0oa1234567890abcdef", "ZASP_OKTA_CLIENT_SECRET_REFERENCE": "ref:okta/client-secret-0001",
		"ZASP_PROVIDER_TIMEOUT": "5s", "ZASP_DISCOVERY_READINESS_TIMEOUT": "5s",
	}
}

func TestOutboxRuntimeRejectsAmbientOrDriftedQueueAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "outbox", "ZASP_POSTGRES_DSN": "postgres://outbox@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_outbox_worker", "ZASP_WORKER_ID": "outbox-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_DISCOVERY_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs", "ZASP_AWS_REGION": "us-west-2",
		"ZASP_OUTBOX_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-outbox", "ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
	if _, err := loadWorkerRuntimeConfig(mapLookup(base)); err != nil {
		t.Fatalf("valid outbox config error = %v", err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing role":  func(values map[string]string) { delete(values, "ZASP_OUTBOX_ROLE_ARN") },
		"ambient token": func(values map[string]string) { delete(values, "ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE") },
		"region drift":  func(values map[string]string) { values["ZASP_AWS_REGION"] = "us-east-1" },
		"account drift": func(values map[string]string) {
			values["ZASP_OUTBOX_ROLE_ARN"] = "arn:aws:iam::210987654321:role/zasp-production-outbox"
		},
		"wrong queue": func(values map[string]string) {
			values["ZASP_DISCOVERY_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/runtime-events"
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error = %v, want errWorkerConfiguration", err)
			}
		})
	}
}

func TestRecoveryModesRequireSeparateExactQueueArtifactAndSigningAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_POSTGRES_DSN": "postgres://recovery@postgres.internal/zasp?sslmode=verify-full", "ZASP_WORKER_ID": "recovery-worker-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_RECOVERY_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-recovery",
		"ZASP_RECOVERY_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_RECOVERY_QUEUE_URL":               "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-recovery-backup-jobs",
		"ZASP_RECOVERY_OUTBOX_TOPIC":            "recovery-backup-jobs", "ZASP_RECOVERY_OPERATION_KIND": "backup",
		"ZASP_EVIDENCE_BUCKET": "zasp-production-recovery", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012",
		"ZASP_EVIDENCE_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_RECOVERY_SIGNING_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/22222222-2222-4222-8222-222222222222",
		"ZASP_RECOVERY_NEON_PROJECT_ID":     "silent-moon-12345678", "ZASP_RECOVERY_NEON_BRANCH_ID": "br-production-main",
	}
	for mode, authority := range map[string]string{"recovery-outbox": "zasp_recovery_outbox_worker", "recovery": "zasp_recovery_worker"} {
		values := cloneStringMap(base)
		values["ZASP_WORKER_MODE"], values["ZASP_DATABASE_AUTHORITY"] = mode, authority
		if mode == "recovery-outbox" {
			delete(values, "ZASP_RECOVERY_OPERATION_KIND")
			delete(values, "ZASP_EVIDENCE_BUCKET")
			delete(values, "ZASP_EVIDENCE_BUCKET_OWNER")
			delete(values, "ZASP_EVIDENCE_KMS_KEY_ARN")
			delete(values, "ZASP_RECOVERY_SIGNING_KMS_KEY_ARN")
			delete(values, "ZASP_RECOVERY_NEON_PROJECT_ID")
			delete(values, "ZASP_RECOVERY_NEON_BRANCH_ID")
		} else {
			delete(values, "ZASP_RECOVERY_OUTBOX_TOPIC")
		}
		config, err := loadWorkerRuntimeConfig(mapLookup(values))
		if err != nil || config.Mode != workerMode(mode) || config.DatabaseAuthority != authority {
			t.Fatalf("mode=%s config=%#v error=%v", mode, config, err)
		}
	}
	restore := cloneStringMap(base)
	restore["ZASP_WORKER_MODE"], restore["ZASP_DATABASE_AUTHORITY"], restore["ZASP_RECOVERY_OPERATION_KIND"] = "recovery", "zasp_recovery_worker", "restore"
	restore["ZASP_RECOVERY_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-recovery-restore-jobs"
	restore["ZASP_POSTGRES_DSN"] = "postgres://recovery@ep-main.us-west-2.aws.neon.tech/zasp?sslmode=verify-full"
	delete(restore, "ZASP_RECOVERY_OUTBOX_TOPIC")
	restore["ZASP_RECOVERY_NEON_SECRET_REFERENCE"] = "ref:neon/project-api-key"
	restore["ZASP_RECOVERY_KUBERNETES_ENDPOINT"] = "https://kubernetes.default.svc"
	restore["ZASP_RECOVERY_KUBERNETES_TOKEN_FILE"] = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	restore["ZASP_RECOVERY_KUBERNETES_CA_FILE"] = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	restore["ZASP_RECOVERY_RUNNER_IMAGE"] = "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/agentsec-worker@sha256:" + strings.Repeat("a", 64)
	restore["ZASP_RECOVERY_RUNNER_SERVICE_ACCOUNT"] = "agentsec-recovery-runner"
	restore["ZASP_RECOVERY_NEON_EGRESS_CIDRS"] = "10.24.8.0/24"
	if config, err := loadWorkerRuntimeConfig(mapLookup(restore)); err != nil || config.RecoveryOperationKind != "restore" || len(config.RecoveryNeonEgressCIDRs) != 1 {
		t.Fatalf("restore config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"non neon database": func(values map[string]string) {
			values["ZASP_POSTGRES_DSN"] = "postgres://recovery@postgres.internal/zasp?sslmode=verify-full"
		},
		"loopback network": func(values map[string]string) { values["ZASP_RECOVERY_NEON_EGRESS_CIDRS"] = "127.0.0.0/24" },
	} {
		values := cloneStringMap(restore)
		mutate(values)
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	for name, mutate := range map[string]func(map[string]string){
		"same kms key": func(values map[string]string) {
			values["ZASP_RECOVERY_SIGNING_KMS_KEY_ARN"] = values["ZASP_EVIDENCE_KMS_KEY_ARN"]
		},
		"foreign role": func(values map[string]string) {
			values["ZASP_RECOVERY_ROLE_ARN"] = "arn:aws:iam::210987654321:role/zasp-production-recovery"
		},
		"source branch omitted":     func(values map[string]string) { delete(values, "ZASP_RECOVERY_NEON_BRANCH_ID") },
		"queue omitted from worker": func(values map[string]string) { delete(values, "ZASP_RECOVERY_QUEUE_URL") },
	} {
		values := cloneStringMap(base)
		values["ZASP_WORKER_MODE"], values["ZASP_DATABASE_AUTHORITY"] = "recovery", "zasp_recovery_worker"
		delete(values, "ZASP_RECOVERY_OUTBOX_TOPIC")
		mutate(values)
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
}

func TestRuntimeOutboxRequiresDistinctExactQueueAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-outbox", "ZASP_POSTGRES_DSN": "postgres://runtime_outbox@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_outbox_worker", "ZASP_WORKER_ID": "runtime-outbox-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_RUNTIME_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events", "ZASP_AWS_REGION": "us-west-2",
		"ZASP_OUTBOX_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox", "ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.Mode != workerModeRuntimeOutbox || config.RuntimeQueueURL != base["ZASP_RUNTIME_QUEUE_URL"] {
		t.Fatalf("runtime outbox config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"discovery queue": func(values map[string]string) {
			values["ZASP_DISCOVERY_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs"
		},
		"wrong name": func(values map[string]string) {
			values["ZASP_RUNTIME_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs"
		},
		"wrong account": func(values map[string]string) {
			values["ZASP_OUTBOX_ROLE_ARN"] = "arn:aws:iam::210987654321:role/zasp-production-runtime-outbox"
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRedTeamModesRequireSeparateExactQueueDatabaseAndRunnerAuthority(t *testing.T) {
	base := map[string]string{
		"ZASP_POSTGRES_DSN": "postgres://red_team@postgres.internal/zasp?sslmode=verify-full", "ZASP_WORKER_ID": "red-team-worker-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_RED_TEAM_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-red-team-tests", "ZASP_AWS_REGION": "us-west-2",
		"ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012", "ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_RED_TEAM_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-red-team", "ZASP_RED_TEAM_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_RED_TEAM_TARGET_ENDPOINT": "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate", "ZASP_RED_TEAM_TARGET_TOKEN_FILE": "/var/run/secrets/zasp-red-team/adapter-token", "ZASP_RED_TEAM_TARGET_CA_FILE": "/var/run/secrets/zasp-red-team/adapter-ca.crt", "ZASP_RED_TEAM_RUNNER_TIMEOUT": "10m",
	}
	worker := cloneStringMap(base)
	worker["ZASP_WORKER_MODE"], worker["ZASP_DATABASE_AUTHORITY"] = "red-team", "zasp_red_team_worker"
	if config, err := loadWorkerRuntimeConfig(mapLookup(worker)); err != nil || config.Mode != workerModeRedTeam || config.RedTeamRunnerTimeout != 10*time.Minute {
		t.Fatalf("worker config=%#v err=%v", config, err)
	}
	outbox := cloneStringMap(base)
	outbox["ZASP_WORKER_MODE"], outbox["ZASP_DATABASE_AUTHORITY"] = "red-team-outbox", "zasp_red_team_outbox_worker"
	outbox["ZASP_OUTBOX_ROLE_ARN"], outbox["ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE"] = "arn:aws:iam::123456789012:role/zasp-production-red-team-outbox", "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	delete(outbox, "ZASP_RED_TEAM_ROLE_ARN")
	delete(outbox, "ZASP_RED_TEAM_WEB_IDENTITY_TOKEN_FILE")
	delete(outbox, "ZASP_RED_TEAM_TARGET_ENDPOINT")
	delete(outbox, "ZASP_RED_TEAM_TARGET_TOKEN_FILE")
	delete(outbox, "ZASP_RED_TEAM_TARGET_CA_FILE")
	delete(outbox, "ZASP_RED_TEAM_RUNNER_TIMEOUT")
	delete(outbox, "ZASP_EVIDENCE_BUCKET")
	delete(outbox, "ZASP_EVIDENCE_BUCKET_OWNER")
	delete(outbox, "ZASP_EVIDENCE_KMS_KEY_ARN")
	if config, err := loadWorkerRuntimeConfig(mapLookup(outbox)); err != nil || config.Mode != workerModeRedTeamOutbox {
		t.Fatalf("outbox config=%#v err=%v", config, err)
	}
	for key, value := range map[string]string{
		"ZASP_DATABASE_AUTHORITY": "zasp_discovery_worker", "ZASP_RED_TEAM_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs",
		"ZASP_RED_TEAM_TARGET_ENDPOINT": "https://example.com/v1/evaluate", "ZASP_RED_TEAM_TARGET_TOKEN_FILE": "/tmp/token", "ZASP_RED_TEAM_TARGET_CA_FILE": "/tmp/ca.crt", "ZASP_RED_TEAM_RUNNER_TIMEOUT": "16m",
	} {
		drift := cloneStringMap(worker)
		drift[key] = value
		if _, err := loadWorkerRuntimeConfig(mapLookup(drift)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%s drift accepted: %v", key, err)
		}
	}
}

func TestRuntimeCoordinatorRequiresDistinctConsumerAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-coordinator", "ZASP_POSTGRES_DSN": "postgres://runtime_coordinator@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_coordinator", "ZASP_WORKER_ID": "runtime-coordinator-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_RUNTIME_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events", "ZASP_AWS_REGION": "us-west-2",
		"ZASP_RUNTIME_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-coordinator", "ZASP_RUNTIME_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.Mode != workerModeRuntimeCoordinator || config.RuntimeRoleARN != base["ZASP_RUNTIME_ROLE_ARN"] {
		t.Fatalf("runtime coordinator config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"publisher role": func(values map[string]string) { values["ZASP_OUTBOX_ROLE_ARN"] = values["ZASP_RUNTIME_ROLE_ARN"] },
		"discovery queue": func(values map[string]string) {
			values["ZASP_DISCOVERY_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs"
		},
		"wrong queue": func(values map[string]string) {
			values["ZASP_RUNTIME_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs"
		},
		"wrong account": func(values map[string]string) {
			values["ZASP_RUNTIME_ROLE_ARN"] = "arn:aws:iam::210987654321:role/zasp-production-runtime-coordinator"
		},
		"ambient token": func(values map[string]string) { delete(values, "ZASP_RUNTIME_WEB_IDENTITY_TOKEN_FILE") },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRuntimeArchiveRequiresNonUnionEvidenceAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-archive", "ZASP_POSTGRES_DSN": "postgres://runtime_archive@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_archive_worker", "ZASP_WORKER_ID": "runtime-archive-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012", "ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_RUNTIME_STAGE_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-archive", "ZASP_RUNTIME_STAGE_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_RUNTIME_STAGE_VERSION": "runtime-archive-v1",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.Mode != workerModeRuntimeArchive || config.RuntimeStageVersion != "runtime-archive-v1" {
		t.Fatalf("runtime archive config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"wrong version":  func(values map[string]string) { values["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-archive-v2" },
		"publisher role": func(values map[string]string) { values["ZASP_OUTBOX_ROLE_ARN"] = values["ZASP_RUNTIME_STAGE_ROLE_ARN"] },
		"wrong account":  func(values map[string]string) { values["ZASP_EVIDENCE_BUCKET_OWNER"] = "210987654321" },
		"kms region": func(values map[string]string) {
			values["ZASP_EVIDENCE_KMS_KEY_ARN"] = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
		},
		"ambient token": func(values map[string]string) { delete(values, "ZASP_RUNTIME_STAGE_WEB_IDENTITY_TOKEN_FILE") },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRuntimeIndexRequiresSeparateEvidenceAndSearchAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-index", "ZASP_POSTGRES_DSN": "postgres://runtime_index@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_index_worker", "ZASP_WORKER_ID": "runtime-index-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012", "ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_RUNTIME_STAGE_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-index", "ZASP_RUNTIME_STAGE_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_RUNTIME_STAGE_VERSION": "runtime-index-v1",
		"ZASP_OPENSEARCH_ENDPOINT": "https://vpc-zasp.us-west-2.es.amazonaws.com", "ZASP_OPENSEARCH_INDEX": "zasp-runtime-events-v1",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.Mode != workerModeRuntimeIndex || config.RuntimeStageVersion != "runtime-index-v1" {
		t.Fatalf("runtime index config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"archive version":  func(values map[string]string) { values["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-archive-v1" },
		"inventory index":  func(values map[string]string) { values["ZASP_OPENSEARCH_INDEX"] = "zasp-inventory-v1" },
		"foreign endpoint": func(values map[string]string) { values["ZASP_OPENSEARCH_ENDPOINT"] = "https://example.com" },
		"projection role": func(values map[string]string) {
			values["ZASP_PROJECTION_ROLE_ARN"] = values["ZASP_RUNTIME_STAGE_ROLE_ARN"]
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRuntimeCorrelationRequiresEvidenceAndGraphAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-correlation", "ZASP_POSTGRES_DSN": "postgres://runtime_correlation@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_correlation_worker", "ZASP_WORKER_ID": "runtime-correlation-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012", "ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_RUNTIME_STAGE_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-correlation", "ZASP_RUNTIME_STAGE_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_RUNTIME_STAGE_VERSION": "runtime-correlation-v1",
		"ZASP_PROJECTION_SECRET_PREFIX": "zasp-production/projection", "ZASP_NEO4J_URI": "neo4j+s://graph.example.com:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/auth/runtime", "ZASP_NEO4J_EXPECTED_PRINCIPAL": "zasp_projection_runtime", "ZASP_NEO4J_EXPECTED_ROLE": "publisher",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.Mode != workerModeRuntimeCorrelation || config.RuntimeStageVersion != "runtime-correlation-v1" {
		t.Fatalf("runtime correlation config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"index version": func(values map[string]string) { values["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-index-v1" },
		"search authority": func(values map[string]string) {
			values["ZASP_OPENSEARCH_ENDPOINT"] = "https://vpc-zasp.us-west-2.es.amazonaws.com"
		},
		"projection role": func(values map[string]string) {
			values["ZASP_PROJECTION_ROLE_ARN"] = values["ZASP_RUNTIME_STAGE_ROLE_ARN"]
		},
		"missing graph": func(values map[string]string) { delete(values, "ZASP_NEO4J_URI") },
		"admin graph role": func(values map[string]string) {
			values["ZASP_NEO4J_EXPECTED_ROLE"] = "Admin"
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRuntimeProjectionRequiresSeparateEvidenceAndRiskGraphAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-projection", "ZASP_POSTGRES_DSN": "postgres://runtime_projection@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_projection_worker", "ZASP_WORKER_ID": "runtime-projection-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012", "ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_RUNTIME_STAGE_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-projection", "ZASP_RUNTIME_STAGE_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_RUNTIME_STAGE_VERSION": "runtime-projection-v1",
		"ZASP_PROJECTION_SECRET_PREFIX": "zasp-production/projection", "ZASP_NEO4J_URI": "neo4j+s://graph.example.com:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/auth/runtime", "ZASP_NEO4J_EXPECTED_PRINCIPAL": "zasp_projection_runtime", "ZASP_NEO4J_EXPECTED_ROLE": "publisher",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.Mode != workerModeRuntimeProjection || config.RuntimeStageVersion != "runtime-projection-v1" {
		t.Fatalf("runtime projection config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"correlation version": func(values map[string]string) { values["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-correlation-v1" },
		"search authority": func(values map[string]string) {
			values["ZASP_OPENSEARCH_ENDPOINT"] = "https://vpc-zasp.us-west-2.es.amazonaws.com"
		},
		"projection union": func(values map[string]string) {
			values["ZASP_PROJECTION_ROLE_ARN"] = values["ZASP_RUNTIME_STAGE_ROLE_ARN"]
		},
		"missing graph":     func(values map[string]string) { delete(values, "ZASP_NEO4J_URI") },
		"foreign graph ref": func(values map[string]string) { values["ZASP_NEO4J_CREDENTIAL_REFERENCE"] = "ref:neo4j/schema/runtime" },
		"foreign account":   func(values map[string]string) { values["ZASP_EVIDENCE_BUCKET_OWNER"] = "210987654321" },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRuntimeCompleteUsesCoordinatorDatabaseAuthorityWithoutQueueUnion(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-complete", "ZASP_POSTGRES_DSN": "postgres://runtime_complete@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_coordinator", "ZASP_WORKER_ID": "runtime-complete-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012", "ZASP_EVIDENCE_KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_RUNTIME_STAGE_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-complete", "ZASP_RUNTIME_STAGE_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_RUNTIME_STAGE_VERSION": "runtime-complete-v1",
	}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.Mode != workerModeRuntimeComplete || config.DatabaseAuthority != "zasp_runtime_coordinator" || config.RuntimeQueueURL != "" {
		t.Fatalf("runtime complete config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"projection version": func(values map[string]string) { values["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-projection-v1" },
		"queue union": func(values map[string]string) {
			values["ZASP_RUNTIME_QUEUE_URL"] = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events"
		},
		"coordinator role": func(values map[string]string) {
			values["ZASP_RUNTIME_ROLE_ARN"] = values["ZASP_RUNTIME_STAGE_ROLE_ARN"]
		},
		"wrong db authority": func(values map[string]string) { values["ZASP_DATABASE_AUTHORITY"] = "zasp_runtime_projection_worker" },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProjectionRuntimeRejectsAmbientOrDriftedProductionAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "projection-search", "ZASP_POSTGRES_DSN": "postgres://projection@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_projection_search_worker", "ZASP_WORKER_ID": "projection-search-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_PROJECTION_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-projection-search",
		"ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_PROJECTION_SECRET_PREFIX": "zasp-production/projection",
		"ZASP_OPENSEARCH_ENDPOINT": "https://vpc-zasp.us-west-2.es.amazonaws.com", "ZASP_OPENSEARCH_INDEX": "zasp-inventory-v1",
	}
	if _, err := loadWorkerRuntimeConfig(mapLookup(base)); err != nil {
		t.Fatalf("valid projection search config error = %v", err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing explicit role": func(values map[string]string) { delete(values, "ZASP_PROJECTION_ROLE_ARN") },
		"ambient token file":    func(values map[string]string) { values["ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE"] = "" },
		"wrong index":           func(values map[string]string) { values["ZASP_OPENSEARCH_INDEX"] = "other-index" },
		"endpoint region drift": func(values map[string]string) {
			values["ZASP_OPENSEARCH_ENDPOINT"] = "https://vpc-zasp.us-east-1.es.amazonaws.com"
		},
		"endpoint query": func(values map[string]string) { values["ZASP_OPENSEARCH_ENDPOINT"] += "?credential=escape" },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneStringMap(base)
			mutate(values)
			if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("error = %v, want errWorkerConfiguration", err)
			}
		})
	}
}

func TestGraphProjectionConfigRejectsAmbiguousSecretPaths(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ZASP_WORKER_MODE": "projection-graph", "ZASP_POSTGRES_DSN": "postgres://projection@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_projection_graph_worker", "ZASP_WORKER_ID": "projection-graph-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_AWS_REGION": "us-west-2", "ZASP_PROJECTION_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-projection-graph",
		"ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_PROJECTION_SECRET_PREFIX": "zasp-production/projection",
		"ZASP_NEO4J_URI": "neo4j+s://neo4j.internal.example:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/auth/production",
		"ZASP_NEO4J_EXPECTED_PRINCIPAL": "zasp-graph-worker", "ZASP_NEO4J_EXPECTED_ROLE": "zasp_projection_graph",
	}
	if _, err := loadWorkerRuntimeConfig(mapLookup(base)); err != nil {
		t.Fatalf("valid graph config error = %v", err)
	}
	for _, hostile := range []struct{ key, value string }{
		{"ZASP_PROJECTION_SECRET_PREFIX", "zasp-production/../projection"},
		{"ZASP_PROJECTION_SECRET_PREFIX", "zasp-production//projection"},
		{"ZASP_NEO4J_CREDENTIAL_REFERENCE", "ref:neo4j/auth/production/other"},
	} {
		values := cloneStringMap(base)
		values[hostile.key] = hostile.value
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%s=%q error = %v", hostile.key, hostile.value, err)
		}
	}
}

func mapLookup(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func cloneStringMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}
