package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Only mounted secret values are synthetic. Every plain environment value below
// is decoded from Helm output by the Node deployment-boundary test.
func TestComplianceDeploymentRenderedAPIConfig(t *testing.T) {
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
							Name      string          `json:"name"`
							Value     string          `json:"value"`
							ValueFrom json.RawMessage `json:"valueFrom"`
						} `json:"env"`
						Args []string `json:"args"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"enabled", "disabled", "complianceOnly", "workflow"} {
		t.Run(mode, func(t *testing.T) {
			found := false
			for _, resource := range fixtures[mode] {
				if resource.Kind != "Deployment" || resource.Metadata.Name != "agentsec-api" {
					continue
				}
				found = true
				if len(resource.Spec.Template.Spec.Containers) != 1 {
					t.Fatal("API container count")
				}
				container := resource.Spec.Template.Spec.Containers[0]
				values := map[string]string{}
				for _, e := range container.Env {
					if len(e.ValueFrom) != 0 {
						t.Fatal("unexpected API field substitution")
					}
					if _, duplicate := values[e.Name]; duplicate {
						t.Fatal("duplicate environment")
					}
					values[e.Name] = e.Value
				}
				mounted := map[string]string{
					"POSTGRES_DSN":                "postgres://zasp_api_runtime@db.internal/zasp?sslmode=verify-full",
					"SECURITY_AGENT_POSTGRES_DSN": "postgres://zasp_security_agent_api_runtime@db.internal/zasp?sslmode=verify-full",
					"STYTCH_PROJECT_ID":           "project-live-local", "STYTCH_SECRET": "secret-live-local",
					"STYTCH_WEBHOOK_SECRET": "whsec_MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=",
					"STYTCH_PUBLIC_TOKEN":   "public-token-live-local", "STYTCH_ORGANIZATION_ID": "organization-live-local",
					"WORKFLOW_SIGNING_KEY": "0123456789abcdef0123456789abcdef", "TOKEN_REVEAL_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
					"AUDIT_EXPORT_CURSOR_SIGNING_KEY": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg",
				}
				for _, line := range strings.Split(strings.Join(container.Args, "\n"), "\n") {
					if !strings.HasPrefix(line, "export ZASP_") {
						continue
					}
					name, _, ok := strings.Cut(strings.TrimPrefix(line, "export ZASP_"), "=")
					value, known := mounted[name]
					if !ok || !known || strings.HasPrefix(name, "COMPLIANCE_") {
						t.Fatal("unrecognized mounted secret")
					}
					values["ZASP_"+name] = value
				}
				load := func() (RuntimeConfig, error) {
					return loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { v, ok := values[k]; return v, ok })
				}
				config, err := load()
				if err != nil || (config.ComplianceExports != nil) != (mode != "disabled") {
					t.Fatalf("rendered %s API configuration: %v", mode, err)
				}
				if (config.AuditExports != nil) != (mode == "enabled") {
					t.Fatal("rendered audit opt-in changed")
				}
				if (config.EvidenceExportWorkflow == "enabled") != (mode == "workflow") {
					t.Fatal("rendered export workflow opt-in changed")
				}
				if mode != "disabled" {
					if config.ComplianceExports.Bucket != "zasp-compliance-fixture" || config.ComplianceExports.ReaderRoleARN != "arn:aws:iam::123456789012:role/compliance-reader" {
						t.Fatal("manifest compliance authority changed")
					}
					original := values["ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN"]
					values["ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN"] = values["ZASP_CONNECTOR_ROLE_ARN"]
					if _, err := load(); err == nil {
						t.Fatal("swapped reader role accepted")
					}
					values["ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN"] = original
					for key, value := range values {
						if strings.HasPrefix(key, "ZASP_COMPLIANCE_EXPORT_") {
							delete(values, key)
							if _, err := load(); err == nil {
								t.Fatal("partial compliance accepted", key)
							}
							values[key] = value
						}
					}
					if mode == "workflow" {
						values["ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW"] = "https://arbitrary.invalid"
						if _, err := load(); err == nil {
							t.Fatal("rendered runtime accepted arbitrary export readiness override")
						}
					}
				}
				t.Log("real API loader accepted untouched rendered env; synthetic CSI values only:", mode)
			}
			if !found {
				t.Fatal("API deployment absent")
			}
		})
	}
}
