package main

import (
	"encoding/json"
	"os"
	"strings"
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
		Metadata struct {
			Name        string
			Annotations map[string]string
		}
		Spec struct {
			Template struct {
				Metadata struct{ Annotations map[string]string }
				Spec     struct {
					Containers []struct {
						Name string
						Env  []struct {
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
	var serviceAccountRole string
	for _, r := range fixtures["enabled"] {
		if r.Kind == "ServiceAccount" && r.Metadata.Name == "security-agent-attack-lab-reconciler" {
			serviceAccountRole = r.Metadata.Annotations["eks.amazonaws.com/role-arn"]
		}
	}
	if serviceAccountRole == "" {
		t.Fatal("CSI service account role missing")
	}
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
		admitted := attackLabIRSAAdmissionEnvironment(values, serviceAccountRole, r.Spec.Template.Metadata.Annotations, r.Spec.Template.Spec.Containers[0].Name)
		c, err := loadWorkerRuntimeConfig(mapLookup(admitted))
		if err != nil || c.Mode != workerModeAttackLabReconciler || c.DatabaseAuthority != "zasp_security_agent_attack_lab_reconciler" || c.BatchSize != 1 || c.LeaseDuration != time.Minute {
			t.Fatalf("actual rendered loader rejected after modeled IRSA admission: %v", err)
		}
		if c.AttackLabReconcilerRoleARN != serviceAccountRole || c.AttackLabReconcilerTokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" {
			t.Fatal("explicit identity changed after admission")
		}
		for _, annotation := range []map[string]string{nil, {"eks.amazonaws.com/skip-containers": "other-container"}} {
			if _, err := loadWorkerRuntimeConfig(mapLookup(attackLabIRSAAdmissionEnvironment(values, serviceAccountRole, annotation, "worker"))); err == nil {
				t.Fatal("ambient admission authority accepted when worker is not skipped")
			}
		}
		for _, k := range []string{"ZASP_ATTACK_LAB_QUEUE_URL", "ZASP_TEST_RECONCILER_ROLE_ARN", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
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
	t.Log("real worker loader consumed rendered pod after locally modeled IRSA admission; metadata.name and synthetic DSN substituted; ambient injection still rejected")
}

// Model only the documented IRSA environment boundary, not a live webhook.
// https://github.com/aws/amazon-eks-pod-identity-webhook#eks-walkthrough
// A role-annotated service account injects these variables unless the Pod's
// comma-separated skip-containers annotation names the container.
func attackLabIRSAAdmissionEnvironment(values map[string]string, role string, annotations map[string]string, container string) map[string]string {
	admitted := make(map[string]string, len(values)+2)
	for k, v := range values {
		admitted[k] = v
	}
	for _, skip := range strings.Split(annotations["eks.amazonaws.com/skip-containers"], ",") {
		if skip == container {
			return admitted
		}
	}
	if role != "" {
		admitted["AWS_ROLE_ARN"] = role
		admitted["AWS_WEB_IDENTITY_TOKEN_FILE"] = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	}
	return admitted
}
