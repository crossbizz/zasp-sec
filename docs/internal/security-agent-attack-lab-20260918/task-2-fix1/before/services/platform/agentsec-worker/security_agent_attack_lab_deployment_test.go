package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestAttackLabDeploymentRenderedWorkerConfig(t *testing.T) {
	path := os.Getenv("ZASP_ATTACK_LAB_RENDERED_FIXTURE")
	if path == "" {
		t.Skip("owned rendered manifest fixture required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string][]struct {
		Kind     string
		Metadata struct{ Name string }
		Spec     struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Env []struct {
							Name      string
							Value     string
							ValueFrom *struct{ FieldRef struct{ FieldPath string } }
						}
					}
				}
			}
		}
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range fixtures["enabled"] {
		if r.Kind != "Deployment" || r.Metadata.Name != "security-agent-attack-lab-reconciler" {
			continue
		}
		count++
		if len(r.Spec.Template.Spec.Containers) != 1 {
			t.Fatal("container count")
		}
		values := map[string]string{}
		for _, e := range r.Spec.Template.Spec.Containers[0].Env {
			if _, ok := values[e.Name]; ok {
				t.Fatal("duplicate env")
			}
			values[e.Name] = e.Value
			if e.ValueFrom != nil {
				if e.Name != "ZASP_WORKER_ID" || e.ValueFrom.FieldRef.FieldPath != "metadata.name" {
					t.Fatal("unapproved field substitution")
				}
				values[e.Name] = "attack-lab-reconciler-fixture"
			}
		}
		values["ZASP_POSTGRES_DSN"] = "postgres://attack_lab_reconciler@db.internal/zasp?sslmode=verify-full"
		c, err := loadWorkerRuntimeConfig(mapLookup(values))
		if err != nil || c.Mode != workerModeAttackLabReconciler || c.DatabaseAuthority != "zasp_security_agent_attack_lab_reconciler" || c.BatchSize != 1 || c.LeaseDuration != time.Minute {
			t.Fatalf("actual rendered loader rejected: %v", err)
		}
		for _, k := range []string{"ZASP_ATTACK_LAB_QUEUE_URL", "ZASP_TEST_RECONCILER_ROLE_ARN", "AWS_ROLE_ARN"} {
			v := map[string]string{}
			for name, value := range values {
				v[name] = value
			}
			v[k] = "foreign"
			if _, err := loadWorkerRuntimeConfig(mapLookup(v)); err == nil {
				t.Fatalf("rendered authority mixed via%s", k)
			}
		}
	}
	if count != 1 {
		t.Fatal("exact settlement workload required", count)
	}
	for _, r := range fixtures["disabled"] {
		if r.Metadata.Name == "security-agent-attack-lab-reconciler" {
			t.Fatal("default49 enabled57 workload")
		}
	}
	t.Log("real worker loader consumed untouched rendered env; only metadata.name and synthetic DSN substituted")
}
