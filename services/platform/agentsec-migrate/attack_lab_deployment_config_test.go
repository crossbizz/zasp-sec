package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAttackLabDeploymentRenderedMigrationConfig(t *testing.T) {
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
							Name  string
							Value string
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
		if r.Kind != "Job" || r.Metadata.Name != "agentsec-schema-v57" {
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
		}
		principal, err := loadAttackLabReconcilerRegistration(func(k string) string { return values[k] })
		if err != nil || principal != "attack_lab_reconciler" {
			t.Fatalf("rendered registration: %s %v", principal, err)
		}
		if _, _, err := loadComplianceWorkerRegistration(func(k string) string { return values[k] }); err != nil {
			t.Fatal("57 lost compliance registration", err)
		}
		if _, _, err := loadAuditExportWorkerRegistration(func(k string) string { return values[k] }); err != nil {
			t.Fatal("57 lost audit registration", err)
		}
	}
	if count != 1 {
		t.Fatal("exact57 migration required", count)
	}
	t.Log("real registration loaders consumed actual coexistence57 env")
}
