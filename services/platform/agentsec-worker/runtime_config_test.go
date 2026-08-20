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
			"ZASP_NEO4J_URI": "neo4j+s://neo4j.internal.example:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/production",
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

func TestWorkerRuntimeConfigRequiresOnlyModeOwnedDependencies(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		"ZASP_POSTGRES_DSN": "postgres://worker@postgres.internal/zasp?sslmode=verify-full", "ZASP_WORKER_ID": "worker-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_DISCOVERY_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/zasp-background",
		"ZASP_AWS_REGION":          "us-west-2", "ZASP_EVIDENCE_BUCKET": "zasp-production-evidence", "ZASP_EVIDENCE_BUCKET_OWNER": "123456789012",
		"ZASP_EVIDENCE_KMS_KEY_ARN":     "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_DISCOVERY_PARSER_VERSION": "parser-v1", "ZASP_DISCOVERY_TOOL_VERSION": "tool-v1",
		"ZASP_OPENSEARCH_ENDPOINT": "https://vpc-zasp.us-west-2.es.amazonaws.com", "ZASP_OPENSEARCH_INDEX": "zasp-inventory-v1",
		"ZASP_NEO4J_URI": "neo4j+s://neo4j.internal.example:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/production",
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
		"ZASP_NEO4J_URI": "neo4j+s://neo4j.internal.example:7687", "ZASP_NEO4J_CREDENTIAL_REFERENCE": "ref:neo4j/production",
	}
	if _, err := loadWorkerRuntimeConfig(mapLookup(base)); err != nil {
		t.Fatalf("valid graph config error = %v", err)
	}
	for _, hostile := range []struct{ key, value string }{
		{"ZASP_PROJECTION_SECRET_PREFIX", "zasp-production/../projection"},
		{"ZASP_PROJECTION_SECRET_PREFIX", "zasp-production//projection"},
		{"ZASP_NEO4J_CREDENTIAL_REFERENCE", "ref:neo4j/production/other"},
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
