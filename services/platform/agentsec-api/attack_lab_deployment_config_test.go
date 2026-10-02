package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Plain values come from the exact Helm output. Only CSI-mounted secret
// contents use inert fixtures; no secret or external provider is accessed.
func TestAttackLabDeploymentRenderedAPIConfig(t *testing.T) {
	path := os.Getenv("ZASP_ATTACK_LAB_RENDERED_FIXTURE")
	if path == "" {
		t.Skip("owned rendered fixture required")
	}
	raw, err := os.ReadFile(path)
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
							Name, Value string
							ValueFrom   json.RawMessage
						}
						Args []string
					}
				}
			}
		}
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("invalid rendered resources")
	}
	for _, mode := range []string{"enabled", "disabled"} {
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
				for _, entry := range container.Env {
					if len(entry.ValueFrom) != 0 {
						t.Fatal("unexpected substitution")
					}
					if _, exists := values[entry.Name]; exists {
						t.Fatal("duplicate env")
					}
					values[entry.Name] = entry.Value
				}
				mounted := map[string]string{"POSTGRES_DSN": "postgres://zasp_api_runtime@db.internal/zasp?sslmode=verify-full", "SECURITY_AGENT_POSTGRES_DSN": "postgres://zasp_security_agent_api_runtime@db.internal/zasp?sslmode=verify-full", "STYTCH_PROJECT_ID": "project-live-local", "STYTCH_SECRET": "secret-live-local", "STYTCH_WEBHOOK_SECRET": "whsec_MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=", "STYTCH_PUBLIC_TOKEN": "public-token-live-local", "STYTCH_ORGANIZATION_ID": "organization-live-local", "WORKFLOW_SIGNING_KEY": "0123456789abcdef0123456789abcdef", "TOKEN_REVEAL_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", "AUDIT_EXPORT_CURSOR_SIGNING_KEY": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg"}
				for _, line := range strings.Split(strings.Join(container.Args, "\n"), "\n") {
					if !strings.HasPrefix(line, "export ZASP_") {
						continue
					}
					name, _, ok := strings.Cut(strings.TrimPrefix(line, "export ZASP_"), "=")
					value, known := mounted[name]
					if !ok || !known {
						t.Fatal("unrecognized mounted secret")
					}
					values["ZASP_"+name] = value
				}
				load := func() (RuntimeConfig, error) {
					return loadRuntimeConfigFromEnvironment(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
				}
				config, err := load()
				if err != nil || (config.AttackLabWorkflow == "enabled") != (mode == "enabled") {
					t.Fatalf("rendered API readiness mode=%s error=%v", mode, err)
				}
				if mode == "enabled" {
					values["ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW"] = "https://arbitrary.invalid"
					if _, err := load(); err == nil {
						t.Fatal("rendered runtime accepted arbitrary readiness override")
					}
				}
			}
			if !found {
				t.Fatal("rendered API missing")
			}
		})
	}
}
