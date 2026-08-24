package main

import (
	"testing"
)

func TestRuntimeConfigRequiresExactLeastPrivilegeAuthorityAndFixedFiles(t *testing.T) {
	values := map[string]string{
		"ZASP_DATABASE_URL":                             "postgres://zasp_red_team_adapter_login@postgres.internal:5432/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY":                       "zasp_red_team_adapter",
		"ZASP_AWS_REGION":                               "us-west-2",
		"ZASP_RED_TEAM_ADAPTER_ROLE_ARN":                "arn:aws:iam::123456789012:role/zasp-red-team-adapter",
		"ZASP_RED_TEAM_ADAPTER_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_RED_TEAM_READINESS_CREDENTIAL_REFERENCE":  "ref:red-team/readiness-0001",
		"ZASP_RED_TEAM_ALLOWED_TARGET_CIDRS":            "203.0.113.0/24,2001:db8:1234::/48",
		"ZASP_RED_TEAM_ADAPTER_TOKEN_FILE":              "/var/run/secrets/zasp/red-team-adapter/token",
		"ZASP_RED_TEAM_ADAPTER_TLS_CERT_FILE":           "/var/run/secrets/zasp/red-team-adapter-tls/tls.crt",
		"ZASP_RED_TEAM_ADAPTER_TLS_KEY_FILE":            "/var/run/secrets/zasp/red-team-adapter-tls/tls.key",
		"ZASP_RED_TEAM_ADAPTER_REQUEST_TIMEOUT":         "5s",
		"ZASP_RED_TEAM_ADAPTER_SHUTDOWN_TIMEOUT":        "10s",
	}
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || !validRuntimeConfig(config) || len(config.AllowedTargetCIDRs) != 2 {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"shared worker authority": func(candidate map[string]string) { candidate["ZASP_DATABASE_AUTHORITY"] = "zasp_red_team_worker" },
		"plaintext database": func(candidate map[string]string) {
			candidate["ZASP_DATABASE_URL"] = "postgres://zasp_red_team_adapter_login@postgres.internal/zasp?sslmode=disable"
		},
		"ambient role":      func(candidate map[string]string) { candidate["ZASP_RED_TEAM_ADAPTER_ROLE_ARN"] = "" },
		"broad target CIDR": func(candidate map[string]string) { candidate["ZASP_RED_TEAM_ALLOWED_TARGET_CIDRS"] = "0.0.0.0/0" },
		"movable token":     func(candidate map[string]string) { candidate["ZASP_RED_TEAM_ADAPTER_TOKEN_FILE"] = "/tmp/token" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]string, len(values))
			for key, value := range values {
				candidate[key] = value
			}
			mutate(candidate)
			if _, err := loadRuntimeConfig(func(key string) string { return candidate[key] }); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
