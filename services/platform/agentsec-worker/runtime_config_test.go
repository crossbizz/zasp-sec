package main

import (
	"errors"
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
