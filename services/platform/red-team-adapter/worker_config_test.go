package main

import (
	"context"
	"encoding/json"
	"testing"
)

func workerAdapterEnvironment() map[string]string {
	return map[string]string{
		"ZASP_DATABASE_URL": "postgres://adapter_login@postgres.internal:5432/zasp?sslmode=verify-full", "ZASP_DATABASE_AUTHORITY": "zasp_red_team_adapter", "ZASP_AWS_REGION": "us-west-2", "ZASP_RED_TEAM_ADAPTER_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-red-team-adapter", "ZASP_RED_TEAM_ADAPTER_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_RED_TEAM_READINESS_CREDENTIAL_REFERENCE": "ref:red-team/readiness-0001", "ZASP_RED_TEAM_ALLOWED_TARGET_CIDRS": "203.0.113.0/24", "ZASP_RED_TEAM_ADAPTER_TOKEN_FILE": "/var/run/secrets/zasp/red-team-adapter/token", "ZASP_RED_TEAM_ADAPTER_TLS_CERT_FILE": "/var/run/secrets/zasp/red-team-adapter-tls/tls.crt", "ZASP_RED_TEAM_ADAPTER_TLS_KEY_FILE": "/var/run/secrets/zasp/red-team-adapter-tls/tls.key", "ZASP_RED_TEAM_ADAPTER_REQUEST_TIMEOUT": "10s", "ZASP_RED_TEAM_ADAPTER_SHUTDOWN_TIMEOUT": "10s",
		"ZASP_RUNTIME_SERVICES_ENABLED": "true", "ZASP_ENVIRONMENT": "production", "ZASP_RUNTIME_SERVICES_TIMEOUT": "5s", "ZASP_OPENFGA_URL": "https://openfga.zasp-system.svc.cluster.local:8080", "ZASP_OPENFGA_STORE_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "ZASP_OPENFGA_MODEL_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAW", "ZASP_OPENFGA_TOKEN_FILE": "/var/run/secrets/zasp/openfga/token", "ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN": "postgres://compensation_login@postgres.internal:5432/zasp?sslmode=verify-full", "ZASP_AUTHORIZATION_WORKER_KEY_FILE": "/var/run/secrets/zasp/worker/forward", "ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE": "/var/run/secrets/zasp/worker/compensation"}
}

func TestWorkerAdapterConfigurationSeparatesPurposeAndHasNoTemporalInput(t *testing.T) {
	values := workerAdapterEnvironment()
	c, err := loadRuntimeConfig(func(k string) string { return values[k] })
	if err != nil || !c.Authorization.Enabled || c.Authorization.TemporalAddress != "" || c.CompensationDatabaseURL == c.DatabaseURL || c.WorkerKeyFile == c.CompensationKeyFile {
		t.Fatal("valid independent adapter configuration", err)
	}
	for _, field := range []string{"ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN", "ZASP_AUTHORIZATION_WORKER_KEY_FILE", "ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE", "ZASP_OPENFGA_MODEL_ID", "ZASP_OPENFGA_TOKEN_FILE"} {
		bad := workerAdapterEnvironment()
		delete(bad, field)
		if _, err := loadRuntimeConfig(func(k string) string { return bad[k] }); err == nil {
			t.Fatal("partial adapter configuration accepted", field)
		}
	}
	for _, change := range []func(map[string]string){func(v map[string]string) { v["ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN"] = v["ZASP_DATABASE_URL"] }, func(v map[string]string) {
		v["ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE"] = v["ZASP_AUTHORIZATION_WORKER_KEY_FILE"]
	}, func(v map[string]string) { v["ZASP_AUTHORIZATION_WORKER_KEY_FILE"] = "relative" }, func(v map[string]string) { v["ZASP_RUNTIME_SERVICES_ENABLED"] = "false" }, func(v map[string]string) {
		v["ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN"] = "postgres://compensation_login@other.internal/zasp?sslmode=verify-full"
	}} {
		bad := workerAdapterEnvironment()
		change(bad)
		if _, err := loadRuntimeConfig(func(k string) string { return bad[k] }); err == nil {
			t.Fatal("mixed adapter authority accepted")
		}
	}
}

type workerAdapterProbe func(context.Context, string, ...any) (json.RawMessage, error)

func (f workerAdapterProbe) QueryJSON(c context.Context, s string, a ...any) (json.RawMessage, error) {
	return f(c, s, a...)
}
func TestWorkerAdapterPartialProfileCannotEnterComposition(t *testing.T) {
	for _, value := range []string{"false", "null", "{}", ""} {
		calls := 0
		db := workerAdapterProbe(func(_ context.Context, s string, _ ...any) (json.RawMessage, error) {
			calls++
			if s == `SELECT to_jsonb(to_regnamespace('zasp_authorization80_worker') IS NOT NULL)` {
				return json.RawMessage(`true`), nil
			}
			if s == `SELECT to_jsonb(zasp_authorization80_worker.runtime_ready())` {
				return json.RawMessage(value), nil
			}
			t.Fatal("unguarded legacy/native query", s)
			return nil, nil
		})
		if _, err := adapterProductionProfile(context.Background(), db, true); err == nil || calls != 2 {
			t.Fatal("partial profile enabled", value, calls)
		}
	}
}
