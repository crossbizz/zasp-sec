package admincontrol

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRetentionExternalFlowsSystemHealthAndHTTP(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	worker := NewRetentionWorker()
	remaining, audit, err := worker.Apply(context.Background(), []RetainedRecord{{ID: "fresh", Class: "event", CreatedAt: now.Add(-24 * time.Hour)}, {ID: "expired", Class: "evidence", CreatedAt: now.Add(-40 * 24 * time.Hour)}}, RetentionPolicy{EnvironmentID: "environment-1", RetentionDays: 30, ChangedBy: "principal-1"}, now)
	if err != nil || len(remaining) != 1 || remaining[0].ID != "fresh" || audit.DeletedIDs[0] != "expired" {
		t.Fatalf("remaining=%+v audit=%+v err=%v", remaining, audit, err)
	}

	flows := NewExternalFlowStore([]ExternalFlow{{ID: "identity", Required: true, Categories: []string{"identity_metadata"}, Enabled: true, Health: "healthy"}, {ID: "database", Required: true, Categories: []string{"identity_metadata"}, Enabled: true, Health: "healthy"}, {ID: "analytics", Required: false, Categories: []string{"product_usage"}, Enabled: true, Health: "healthy"}})
	if err := flows.Update(context.Background(), ExternalFlow{ID: "identity", Required: true, Categories: []string{"identity_metadata"}, Enabled: false, Health: "healthy"}); err == nil {
		t.Fatal("disabled required flow")
	}
	if err := flows.Update(context.Background(), ExternalFlow{ID: "analytics", Categories: []string{"raw_security_evidence"}, Enabled: true, Health: "healthy"}); err == nil {
		t.Fatal("enabled prohibited category")
	}
	if err := flows.Update(context.Background(), ExternalFlow{ID: "analytics", Categories: []string{"product_usage"}, Enabled: false, Health: "degraded"}); err != nil {
		t.Fatal(err)
	}
	if audits := flows.Audits(); len(audits) != 1 || audits[0].FlowID != "analytics" {
		t.Fatalf("audits=%+v", audits)
	}

	probes := NewSystemProbes("v1.0.0", []ComponentProbe{{ID: "database", Required: true, State: "healthy", FreshAt: now}, {ID: "remote-telemetry", Required: false, State: "degraded", FreshAt: now}})
	status, err := probes.Status(context.Background(), now)
	if err != nil || !status.SecurityPlaneHealthy || !status.OptionalDegraded {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	probes = NewSystemProbes("v1.0.0", []ComponentProbe{{ID: "database", Required: true, State: "degraded", FreshAt: now}})
	status, _ = probes.Status(context.Background(), now)
	if status.SecurityPlaneHealthy {
		t.Fatal("required degradation reported healthy")
	}

	flows = NewExternalFlowStore([]ExternalFlow{{ID: "identity", Required: true, Categories: []string{"identity_metadata"}, Enabled: true, Health: "healthy"}, {ID: "database", Required: true, Categories: []string{"identity_metadata"}, Enabled: true, Health: "healthy"}, {ID: "analytics", Categories: []string{"product_usage"}, Enabled: true, Health: "healthy"}})
	handler, err := NewHTTPHandler(flows, NewSystemProbes("v1.0.0", []ComponentProbe{{ID: "database", Required: true, State: "healthy", FreshAt: now}}), func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer allowed" })
	if err != nil {
		t.Fatal(err)
	}
	handler.clock = func() time.Time { return now }
	for _, tc := range []struct{ method, path, body string }{{"GET", "/api/v1/settings/external-data-flows", ""}, {"PATCH", "/api/v1/settings/external-data-flows", "{\"id\":\"analytics\",\"required\":false,\"categories\":[\"product_usage\"],\"enabled\":false,\"health\":\"degraded\"}"}, {"GET", "/api/v1/system/status", ""}, {"GET", "/api/v1/system/components", ""}, {"GET", "/api/v1/system/version", ""}} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("Authorization", "Bearer allowed")
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code < 200 || rec.Code >= 300 {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	if denied.Code != http.StatusForbidden || !bytes.Contains(denied.Body.Bytes(), []byte("admin_control_rejected")) {
		t.Fatalf("status=%d body=%s", denied.Code, denied.Body.String())
	}
}
