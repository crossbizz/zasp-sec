package main

import "testing"

func TestRuntimeConfigRequiresExactProxyAuthorityCIDRsAndPinnedFiles(t *testing.T) {
	values := validProxyEnvironment()
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || config.DatabaseAuthority != "zasp_attack_lab_proxy" || config.AWS.RoleSessionName != "zasp-attack-lab-proxy" || len(config.AllowedTargetCIDRs) != 2 {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"plaintext database": func(candidate map[string]string) {
			candidate["ZASP_DATABASE_URL"] = "postgres://proxy@postgres.internal/zasp?sslmode=disable"
		},
		"controller database": func(candidate map[string]string) { candidate["ZASP_DATABASE_AUTHORITY"] = "zasp_attack_lab_controller" },
		"world CIDR":          func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_ALLOWED_TARGET_CIDRS"] = "0.0.0.0/0" },
		"movable key":         func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_EGRESS_SIGNING_KEY_FILE"] = "/tmp/key" },
		"plaintext listener":  func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_PROXY_TLS_CERT_FILE"] = "" },
		"ambient AWS":         func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_PROXY_ROLE_ARN"] = "" },
		"foreign secret": func(candidate map[string]string) {
			candidate["ZASP_ATTACK_LAB_READINESS_CREDENTIAL_REFERENCE"] = "ref:github/installation/123456"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneProxyEnvironment(values)
			mutate(candidate)
			if _, err := loadRuntimeConfig(func(key string) string { return candidate[key] }); err == nil {
				t.Fatal("invalid proxy configuration accepted")
			}
		})
	}
}

func validProxyEnvironment() map[string]string {
	return map[string]string{
		"ZASP_DATABASE_URL":                              "postgres://zasp_attack_lab_proxy_login@postgres.internal:5432/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY":                        "zasp_attack_lab_proxy",
		"ZASP_ATTACK_LAB_ALLOWED_TARGET_CIDRS":           "203.0.113.0/24,2001:db8:1234::/48",
		"ZASP_ATTACK_LAB_EGRESS_SIGNING_KEY_FILE":        "/var/run/secrets/zasp-attack-lab/egress-signing-key",
		"ZASP_ATTACK_LAB_PROXY_TLS_CERT_FILE":            "/var/run/secrets/zasp-attack-lab-proxy-tls/tls.crt",
		"ZASP_ATTACK_LAB_PROXY_TLS_KEY_FILE":             "/var/run/secrets/zasp-attack-lab-proxy-tls/tls.key",
		"ZASP_ATTACK_LAB_PROXY_REQUEST_TIMEOUT":          "5s",
		"ZASP_ATTACK_LAB_PROXY_SHUTDOWN_TIMEOUT":         "10s",
		"ZASP_AWS_REGION":                                "us-west-2",
		"ZASP_ATTACK_LAB_PROXY_ROLE_ARN":                 "arn:aws:iam::123456789012:role/zasp-attack-lab-proxy",
		"ZASP_ATTACK_LAB_PROXY_WEB_IDENTITY_TOKEN_FILE":  "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_ATTACK_LAB_READINESS_CREDENTIAL_REFERENCE": "ref:red-team/readiness-0001",
	}
}

func cloneProxyEnvironment(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
