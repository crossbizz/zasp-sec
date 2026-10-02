package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

type agentExportRuntimeDatabase struct {
	complianceRuntimeDatabase
	available bool
	probeErr  error
	reads     int
}

func (d *agentExportRuntimeDatabase) SecurityAgentExportsAvailable(context.Context) (bool, error) {
	return d.available, d.probeErr
}

func (d *agentExportRuntimeDatabase) QueryJSON(ctx context.Context, q string, a ...any) (json.RawMessage, error) {
	if strings.HasPrefix(q, "SELECT public.zasp_sa_export_get(") {
		d.reads++
		return json.RawMessage(`{"export_id":"pid_20000001-0000-4000-8000-000000000001","state":"pending","phase":"queued","failure_code":null,"created_at":"2026-09-19T00:00:00Z","retrieval_expires_at":"2026-09-20T00:00:00Z","mapping_revision":"security-agent-run-evidence-v1","snapshot_at":null,"cleanup_state":"retained","selection":[{"source_kind":"finding","source_id":"pid_20000004-0000-4000-8000-000000000004","source_version":7,"association_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"artifact":null}`), nil
	}
	return d.complianceRuntimeDatabase.QueryJSON(ctx, q, a...)
}

// Missing mounting, use of the general API role, or ignored catalog drift must fail.
func TestSecurityAgentExportAPIProductionComposition(t *testing.T) {
	t.Setenv("HOSTNAME", "agent-export-runtime-test")
	for _, mode := range []string{"installed", "absent", "drift", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			v := complianceAPIEnvironment()
			c, err := loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { s, ok := v[k]; return s, ok })
			if err != nil {
				t.Fatal(err)
			}
			if mode == "disabled" {
				c.ComplianceExports = nil
			}
			ordinary := &complianceRuntimeDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "view_audit", "view_compliance"}}}
			agent := &agentExportRuntimeDatabase{complianceRuntimeDatabase: *ordinary, available: mode != "absent"}
			if mode == "drift" {
				agent.probeErr = errors.New("installed release drift")
			}
			deps, err := composeRuntimeDependenciesWithTelemetry(context.Background(), c, ordinary, agent, auditFactoryProvider(), newAuditExportStorageClients, newComplianceStorageResources, &complianceTelemetryCapture{})
			defer func() {
				for _, closer := range deps.Closers {
					_ = closer.Close()
				}
			}()
			if mode == "drift" {
				if err == nil || deps.ProductHandler != nil {
					t.Fatal("installed export drift mounted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			deps.ProductHandler.ServeHTTP(w, publicPageRuntimeRequest(c, "/api/v1/security-agent-runs/pid_20000002-0000-4000-8000-000000000002/steps/pid_20000003-0000-4000-8000-000000000003/export"))
			if mode != "installed" {
				if w.Code != 404 || agent.reads != 0 {
					t.Fatalf("unavailable export route: %d reads=%d", w.Code, agent.reads)
				}
				return
			}
			if w.Code != 200 || agent.reads != 1 || !strings.Contains(w.Body.String(), `"state":"pending"`) {
				t.Fatalf("export status: %d %s reads=%d", w.Code, w.Body, agent.reads)
			}
			agent.available = false
			if deps.ReadinessCheck(context.Background()) == nil {
				t.Fatal("removed export release remained ready")
			}
		})
	}
}
