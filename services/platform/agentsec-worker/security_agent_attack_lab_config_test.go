package main

import "testing"

func attackLabReconcilerEnvironment() map[string]string {
	env := existingTestRuntimeEnvironment()
	env["ZASP_WORKER_MODE"] = "security-agent-attack-lab-reconciler"
	env["ZASP_DATABASE_AUTHORITY"] = "zasp_security_agent_attack_lab_reconciler"
	env["ZASP_ATTACK_LAB_RECONCILER_ROLE_ARN"] = env["ZASP_TEST_RECONCILER_ROLE_ARN"]
	env["ZASP_ATTACK_LAB_RECONCILER_WEB_IDENTITY_TOKEN_FILE"] = env["ZASP_TEST_RECONCILER_WEB_IDENTITY_TOKEN_FILE"]
	delete(env, "ZASP_TEST_RECONCILER_ROLE_ARN")
	delete(env, "ZASP_TEST_RECONCILER_WEB_IDENTITY_TOKEN_FILE")
	return env
}

// Rejecting the dedicated mode or accepting unrelated credentials breaks its
// deployment boundary. Exercise the actual environment loader.
func TestAttackLabReconcilerConfigIsolation(t *testing.T) {
	env := attackLabReconcilerEnvironment()
	if _, err := loadWorkerRuntimeConfig(mapLookup(env)); err != nil {
		t.Fatalf("dedicated57 mode missing: %v", err)
	}
	for _, key := range []string{"ZASP_TEST_RECONCILER_ROLE_ARN", "ZASP_ATTACK_LAB_QUEUE_URL", "ZASP_ATTACK_LAB_KUBERNETES_TOKEN_FILE", "ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE", "AWS_ACCESS_KEY_ID", "AWS_PROFILE"} {
		t.Run(key, func(t *testing.T) {
			e := attackLabReconcilerEnvironment()
			e[key] = "foreign-authority"
			if _, err := loadWorkerRuntimeConfig(mapLookup(e)); err == nil {
				t.Fatal("accepted mixed authority")
			}
		})
	}
	for _, pair := range [][2]string{{"ZASP_DATABASE_AUTHORITY", "zasp_security_agent_worker"}, {"ZASP_BATCH_SIZE", "2"}, {"ZASP_LEASE_DURATION", "30s"}} {
		e := attackLabReconcilerEnvironment()
		e[pair[0]] = pair[1]
		if _, err := loadWorkerRuntimeConfig(mapLookup(e)); err == nil {
			t.Fatalf("accepted %s=%s", pair[0], pair[1])
		}
	}
}
