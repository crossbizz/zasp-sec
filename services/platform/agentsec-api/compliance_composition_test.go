package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type complianceTelemetryCapture struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (c *complianceTelemetryCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.Write(p)
}

func (c *complianceTelemetryCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.String()
}

type complianceRuntimeDatabase struct {
	auditExportRuntimeDatabase
	deny bool
}

func (d *complianceRuntimeDatabase) QueryJSON(ctx context.Context, q string, a ...any) (json.RawMessage, error) {
	if strings.Contains(q, "FROM zasp_compliance_evidence AS evidence JOIN") {
		return json.RawMessage(`{"items":[{"control":{"id":"legacy-control","framework":"SOC 2","name":"Legacy seed","evidence_ids":["legacy-evidence"],"fresh_until":"2020-01-02T00:00:00Z"},"freshness":"stale","evidence":[{"id":"legacy-evidence","asset_id":"legacy-asset","source":"runtime","at":"2020-01-01T00:00:00Z"}]}]}`), nil
	}
	if strings.Contains(q, "FROM zasp_compliance_controls AS control") {
		return json.RawMessage(`{"items":[{"id":"legacy-control","framework":"SOC 2","name":"Legacy seed","evidence_ids":[],"fresh_until":"2020-01-02T00:00:00Z"}]}`), nil
	}
	if q == `SELECT to_jsonb(public.zasp_compliance_api_ready($1,$2))` && d.deny {
		return json.RawMessage(`false`), nil
	}
	if strings.HasPrefix(q, `SELECT public.zasp_compliance_read(`) {
		record := `{"id":"policy-live","asset":"policy-live","source":"policy","timestamp":"2026-09-18T00:00:00Z","organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","target":{"source_kind":"policy","source_id":"policy-live","source_version":1},"freshness":"fresh","metadata":{"verification":"definition_only"}}`
		if a[5] == "getEvidence" {
			return json.RawMessage(record), nil
		}
		if a[5] == "listControls" {
			framework := "soc2_security"
			if strings.Contains(string(a[6].(json.RawMessage)), "hipaa") {
				framework = "hipaa"
			}
			record = `{"framework":"` + framework + `","control_id":"` + framework + `-policies","label":"Policy definitions","required_sources":["policy"],"maximum_age_seconds":86400,"freshness":"fresh","fresh_until":"2026-09-19T00:00:00Z"}`
		}
		return json.RawMessage(`{"mapping_revision":"product-evidence-v1","collected_at":"2026-09-18T00:00:00Z","items":[` + record + `],"next_cursor":null}`), nil
	}
	return d.auditExportRuntimeDatabase.QueryJSON(ctx, q, a...)
}
func TestComplianceAPIProductionComposition(t *testing.T) {
	t.Setenv("HOSTNAME", "compliance-runtime-test")
	for _, mode := range []string{"installed", "disabled", "absent", "unregistered"} {
		t.Run(mode, func(t *testing.T) {
			v := complianceAPIEnvironment()
			if mode == "absent" {
				for key := range v {
					if strings.HasPrefix(key, "ZASP_COMPLIANCE_EXPORT_") {
						delete(v, key)
					}
				}
			}
			c, err := loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { s, ok := v[k]; return s, ok })
			if err != nil {
				t.Fatal(err)
			}
			if mode == "disabled" {
				c.ComplianceExports = nil
			}
			db := &complianceRuntimeDatabase{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view", "view_audit", "view_compliance"}}, deny: mode == "unregistered"}
			capture := &complianceTelemetryCapture{}
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("composition telemetry:\n%s", capture.String())
				}
			})
			deps, err := composeRuntimeDependenciesWithTelemetry(context.Background(), c, db, db, auditFactoryProvider(), newAuditExportStorageClients, newComplianceStorageResources, capture)
			if capture.String() == "" {
				t.Fatal("composition spans were not captured")
			}
			defer func() {
				for _, closer := range deps.Closers {
					_ = closer.Close()
				}
			}()
			if mode == "unregistered" {
				if err == nil || deps.ProductHandler != nil {
					t.Fatal("unregistered compliance mounted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			req := publicPageRuntimeRequest(c, "/api/v1/compliance/evidence/policy/policy-live?source_version=1")
			w := httptest.NewRecorder()
			deps.ProductHandler.ServeHTTP(w, req)
			if !strings.Contains(capture.String(), `"event":"http_request"`) {
				t.Fatal("request telemetry was not captured")
			}
			if mode == "disabled" || mode == "absent" {
				if w.Code != 404 {
					t.Fatalf("disabled route %d", w.Code)
				}
				legacy := httptest.NewRecorder()
				deps.ProductHandler.ServeHTTP(legacy, publicPageRuntimeRequest(c, "/api/v1/compliance/controls"))
				if legacy.Code != 200 || !strings.Contains(legacy.Body.String(), `"id":"legacy-control"`) || strings.Contains(legacy.Body.String(), `"freshness"`) {
					t.Fatalf("disabled legacy compatibility %d %s", legacy.Code, legacy.Body)
				}
				for _, query := range []string{"?limit=100", "?limit=100&framework=soc2_security"} {
					page := httptest.NewRecorder()
					deps.ProductHandler.ServeHTTP(page, publicPageRuntimeRequest(c, "/api/v1/compliance/evidence"+query))
					if strings.Contains(query, "framework") {
						if page.Code != 400 {
							t.Fatalf("legacy accepted unsupported framework: %d %s", page.Code, page.Body)
						}
						continue
					}
					if page.Code != 200 || !strings.Contains(page.Body.String(), `"id":"legacy-evidence"`) || strings.Contains(page.Body.String(), `"target"`) {
						t.Fatalf("legacy evidence: %d %s", page.Code, page.Body)
					}
				}
				return
			}
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"source_id":"policy-live"`) {
				t.Fatalf("production route %d %s", w.Code, w.Body)
			}
			for _, route := range []string{"/api/v1/compliance/controls?limit=100", "/api/v1/compliance/evidence?limit=100&framework=soc2_security", "/api/v1/compliance/evidence?limit=100&framework=hipaa"} {
				page := httptest.NewRecorder()
				deps.ProductHandler.ServeHTTP(page, publicPageRuntimeRequest(c, route))
				if page.Code != 200 || !strings.Contains(page.Body.String(), `"freshness":"fresh"`) {
					t.Fatalf("installed current signal: %s %d %s", route, page.Code, page.Body)
				}
			}
			found := false
			for _, s := range deps.Stores {
				if s.Name == "aws-s3-compliance-exports" && s.Durable {
					found = true
				}
			}
			if !found {
				t.Fatal("missing read storage dependency")
			}
			db.deny = true
			if deps.ReadinessCheck(context.Background()) == nil {
				t.Fatal("readiness ignored revoked registration")
			}
		})
	}
}
