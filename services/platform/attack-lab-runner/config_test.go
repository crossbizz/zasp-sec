package main

import "testing"

func TestRuntimeConfigRequiresExactInjectedRunAndProxyAuthority(t *testing.T) {
	values := validRunnerEnvironment()
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || config.Runner.RunID != values["ZASP_ATTACK_LAB_RUN_ID"] || len(config.Runner.ExpectedSideEffects) != 1 {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing test role": func(candidate map[string]string) { delete(candidate, "AWS_ROLE_ARN") },
		"product role": func(candidate map[string]string) {
			candidate["AWS_ROLE_ARN"] = "arn:aws:iam::123456789012:role/zasp-production-discovery-worker"
		},
		"metadata fallback":      func(candidate map[string]string) { candidate["AWS_EC2_METADATA_DISABLED"] = "false" },
		"movable identity token": func(candidate map[string]string) { candidate["AWS_WEB_IDENTITY_TOKEN_FILE"] = "/tmp/token" },
		"static credentials":     func(candidate map[string]string) { candidate["AWS_ACCESS_KEY_ID"] = "fixture-not-a-key" },
		"container credentials": func(candidate map[string]string) {
			candidate["AWS_CONTAINER_CREDENTIALS_FULL_URI"] = "http://169.254.170.2/credentials"
		},
		"credential profile": func(candidate map[string]string) { candidate["AWS_PROFILE"] = "product-worker" },
		"foreign proxy": func(candidate map[string]string) {
			candidate["ZASP_ATTACK_LAB_EGRESS_PROXY"] = "https://evil.example/v1/egress"
		},
		"movable CA":     func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_EGRESS_PROXY_CA_FILE"] = "/tmp/ca" },
		"missing token":  func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_EGRESS_TOKEN"] = "" },
		"invalid digest": func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_INPUT_DIGEST"] = "00" },
		"long timeout":   func(candidate map[string]string) { candidate["ZASP_ATTACK_LAB_REQUEST_TIMEOUT"] = "31s" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneRunnerEnvironment(values)
			mutate(candidate)
			if _, err := loadRuntimeConfig(func(key string) string { return candidate[key] }); err == nil {
				t.Fatal("invalid runner configuration accepted")
			}
		})
	}
}

func validRunnerEnvironment() map[string]string {
	return map[string]string{
		"AWS_ROLE_ARN":                "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test",
		"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"AWS_REGION":                  "us-west-2", "AWS_STS_REGIONAL_ENDPOINTS": "regional", "AWS_EC2_METADATA_DISABLED": "true",
		"ZASP_ATTACK_LAB_ORGANIZATION_ID":       "pid_7d100010-0000-4000-8000-000000000010",
		"ZASP_ATTACK_LAB_WORKSPACE_ID":          "pid_7d100011-0000-4000-8000-000000000011",
		"ZASP_ATTACK_LAB_ENVIRONMENT_ID":        "pid_7d100012-0000-4000-8000-000000000012",
		"ZASP_ATTACK_LAB_RUN_ID":                "pid_7e300001-0000-4000-8000-000000000001",
		"ZASP_ATTACK_LAB_DESTINATION":           "adapter.customer.example",
		"ZASP_ATTACK_LAB_SUCCESS_CRITERION":     "Observe exact canary touch",
		"ZASP_ATTACK_LAB_EXPECTED_SIDE_EFFECTS": `["one bounded canary mutation"]`,
		"ZASP_ATTACK_LAB_INPUT_DIGEST":          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"ZASP_ATTACK_LAB_EGRESS_PROXY":          "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress",
		"ZASP_ATTACK_LAB_EGRESS_PROXY_CA_FILE":  "/var/run/secrets/zasp-attack-lab/proxy-ca.crt",
		"ZASP_ATTACK_LAB_EGRESS_TOKEN":          "signed.capability.production",
		"ZASP_ATTACK_LAB_REQUEST_TIMEOUT":       "30s",
		"ZASP_ATTACK_LAB_TERMINATION_PATH":      "/dev/termination-log",
	}
}

func cloneRunnerEnvironment(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
