package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestComplianceDeploymentRenderedWorkerConfig(t *testing.T) {
	path := os.Getenv("ZASP_COMPLIANCE_RENDERED_FIXTURE")
	if path == "" {
		t.Skip("requires the owned rendered manifest fixture")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string][]struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Env []struct {
							Name      string `json:"name"`
							Value     string `json:"value"`
							ValueFrom *struct {
								FieldRef struct {
									FieldPath string `json:"fieldPath"`
								} `json:"fieldRef"`
							} `json:"valueFrom"`
						} `json:"env"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, resource := range fixtures["enabled"] {
		name := resource.Metadata.Name
		if resource.Kind != "Deployment" || (name != "zasp-compliance-export-worker" && name != "zasp-compliance-cleanup-worker") {
			continue
		}
		count++
		t.Run(name, func(t *testing.T) {
			if len(resource.Spec.Template.Spec.Containers) != 1 {
				t.Fatal("worker container count")
			}
			values := map[string]string{}
			for _, e := range resource.Spec.Template.Spec.Containers[0].Env {
				if _, duplicate := values[e.Name]; duplicate {
					t.Fatal("duplicate environment")
				}
				values[e.Name] = e.Value
				if e.ValueFrom != nil {
					if e.Name != "ZASP_WORKER_ID" || e.ValueFrom.FieldRef.FieldPath != "metadata.name" {
						t.Fatal("unexpected field substitution")
					}
					values[e.Name] = name + "-fixture"
				}
			}
			principal, role, authority := "compliance_export_runtime", "compliance-writer", "zasp_compliance_worker"
			if name == "zasp-compliance-cleanup-worker" {
				principal, role, authority = "compliance_cleanup_runtime", "compliance-cleanup", "zasp_compliance_cleanup"
			}
			// The only worker secret substitution. No live DSN is read.
			values["ZASP_POSTGRES_DSN"] = "postgres://" + principal + "@db.internal/zasp?sslmode=verify-full"
			load := func() (workerRuntimeConfig, error) { return loadWorkerRuntimeConfig(mapLookup(values)) }
			config, err := load()
			if err != nil || config.ComplianceExports == nil || config.ComplianceExports.RoleARN != "arn:aws:iam::123456789012:role/"+role || config.LeaseDuration != time.Minute {
				t.Fatalf("rendered worker configuration: %v", err)
			}
			values["ZASP_DATABASE_AUTHORITY"] = "zasp_audit_export_worker"
			if _, err := load(); err == nil {
				t.Fatal("swapped database authority accepted")
			}
			values["ZASP_DATABASE_AUTHORITY"] = authority
			delete(values, "ZASP_COMPLIANCE_EXPORT_ROLE_ARN")
			if _, err := load(); err == nil {
				t.Fatal("partial worker configuration accepted")
			}
			t.Log("real worker loader accepted untouched rendered env; synthetic DSN and metadata.name only")
		})
	}
	if count != 2 {
		t.Fatal("both compliance workers required", count)
	}
}
