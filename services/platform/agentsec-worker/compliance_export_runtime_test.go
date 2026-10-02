package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"strings"
	"testing"
	"time"
)

func complianceRuntimeEnvironment() map[string]string {
	return map[string]string{
		"ZASP_WORKER_MODE": "compliance-export", "ZASP_POSTGRES_DSN": "postgres://compliance_executor@postgres.internal/zasp?sslmode=verify-full", "ZASP_DATABASE_AUTHORITY": "zasp_compliance_worker", "ZASP_WORKER_ID": "compliance-worker-1", "ZASP_POLL_INTERVAL": "100ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "2", "ZASP_SHUTDOWN_TIMEOUT": "10s", "ZASP_PROVIDER_TIMEOUT": "5s", "ZASP_AWS_REGION": "us-east-1",
		"ZASP_COMPLIANCE_EXPORT_BUCKET": "zasp-compliance-exports", "ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER": "123456789012", "ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001", "ZASP_COMPLIANCE_EXPORT_ROLE_ARN": "arn:aws:iam::123456789012:role/compliance-export-worker", "ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
}

func complianceRuntimeLease(t *testing.T) complianceExportLease {
	t.Helper()
	o, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	w, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	e, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	s, _ := domain.NewScope(o, w, e)
	return complianceExportLease{Scope: s, ExportID: "pid_10000004-0000-4000-8000-000000000004", WorkerID: "worker-1", Token: strings.Repeat("a", 64), Lane: "execute", Attempt: 1, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}
}
func complianceSnapshotFixture(t *testing.T, l complianceExportLease) json.RawMessage {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"mapping_revision": "product-evidence-v1", "snapshot_at": "2026-09-18T00:00:00Z", "organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(), "controls": []any{map[string]any{"framework": "soc2_security", "control_id": "soc2_security-policies", "label": "Policy definitions", "required_sources": []string{"policy"}, "maximum_age_seconds": 86400, "records": []any{map[string]any{"source_kind": "policy", "source_id": "policy-safe", "source_version": 7, "source_family": "policy", "source_time": "2026-09-17T01:00:00Z", "source_valid": true, "metadata": map[string]string{"verification": "definition_only"}}}}}})
	return raw
}
func TestComplianceRuntimeRendersFrozenSnapshot(t *testing.T) {
	l := complianceRuntimeLease(t)
	raw := complianceSnapshotFixture(t, l)
	p, err := renderComplianceExportPackage(context.Background(), l, raw)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		JSON    json.RawMessage `json:"json"`
		CSV     string          `json:"csv"`
		Human   string          `json:"human"`
	}
	if json.Unmarshal(p.Bytes, &envelope) != nil || envelope.Version != 1 || envelope.ID != l.ExportID || !strings.Contains(string(envelope.JSON), `"freshness":"fresh"`) || !strings.Contains(string(envelope.JSON), `"source_version":7`) || !strings.Contains(envelope.Human, "definition_only") {
		t.Fatalf("bad frozen package %s", p.Bytes)
	}
	for _, bad := range []string{strings.Replace(string(raw), "definition_only", strings.Repeat("x", 1025), 1), strings.Replace(string(raw), `"verification":"definition_only"`, `"raw_prompt":"secret"`, 1), strings.Replace(string(raw), `"source_valid":true`, `"source_valid":false`, 1), strings.Replace(string(raw), `"source_version":7`, `"source_version":0`, 1)} {
		if _, err = renderComplianceExportPackage(context.Background(), l, []byte(bad)); err == nil {
			t.Fatal("invalid captured source accepted")
		}
	}
	stale := strings.Replace(string(raw), "2026-09-17T01:00:00Z", "2026-09-16T00:00:00Z", 1)
	p, err = renderComplianceExportPackage(context.Background(), l, []byte(stale))
	if err != nil || !strings.Contains(string(p.Bytes), `"freshness":"stale"`) {
		t.Fatalf("source age lost %s %v", p.Bytes, err)
	}
	missing := strings.Replace(string(raw), `"required_sources":["policy"]`, `"required_sources":["policy","test"]`, 1)
	p, err = renderComplianceExportPackage(context.Background(), l, []byte(missing))
	if err != nil || !strings.Contains(string(p.Bytes), `"freshness":"missing"`) {
		t.Fatalf("missing category ignored %s %v", p.Bytes, err)
	}
}

func TestComplianceRuntimeCandidatesRejectUnsafeWire(t *testing.T) {
	db := &complianceDatabaseFixture{body: json.RawMessage(`{"items":[]}`)}
	a := newPostgresComplianceExportAuthority(db)
	if err := a.Ready(context.Background(), "execute"); err != nil {
		t.Fatal(err)
	}
	l := complianceRuntimeLease(t)
	raw, _ := json.Marshal(map[string]any{"items": []any{map[string]string{"organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(), "export_id": l.ExportID}}})
	db.body = raw
	items, err := a.Candidates(context.Background(), "execute", 1)
	if err != nil || len(items) != 1 || items[0].Scope != l.Scope {
		t.Fatalf("candidate %v %v", items, err)
	}
	for _, body := range []string{`{"items":[],"foreign":true}`, `{"items":[{"organization_id":"foreign"}]}`, `{"items":null}`} {
		db.body = json.RawMessage(body)
		if _, err = a.Candidates(context.Background(), "execute", 1); err == nil {
			t.Fatal("unsafe candidates accepted")
		}
	}
}

// Removing mode installation or accepting mixed authority must fail this test.
func TestComplianceRuntimeConfiguration(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		env := complianceRuntimeEnvironment()
		if cleanup {
			env["ZASP_WORKER_MODE"] = "compliance-export-cleanup"
			env["ZASP_DATABASE_AUTHORITY"] = "zasp_compliance_cleanup"
			env["ZASP_POSTGRES_DSN"] = "postgres://compliance_cleaner@postgres.internal/zasp?sslmode=verify-full"
			env["ZASP_COMPLIANCE_EXPORT_ROLE_ARN"] = "arn:aws:iam::123456789012:role/compliance-export-cleanup"
		}
		if _, err := loadWorkerRuntimeConfig(mapLookup(env)); err != nil {
			t.Fatalf("dedicated mode rejected: %v", err)
		}
		for key, value := range map[string]string{"ZASP_DATABASE_AUTHORITY": "zasp_audit_export_worker", "ZASP_LEASE_DURATION": "90s", "ZASP_PROVIDER_TIMEOUT": "0s", "ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER": "foreign", "ZASP_AUDIT_EXPORT_QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/123456789012/audit", "ZASP_RUNTIME_ROLE_ARN": "arn:aws:iam::123456789012:role/runtime"} {
			bad := cloneStringMap(env)
			bad[key] = value
			if _, err := loadWorkerRuntimeConfig(mapLookup(bad)); err == nil {
				t.Fatalf("accepted mixed/invalid %s", key)
			}
		}
	}
}
