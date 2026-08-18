package sessioncontrol

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPHandlerPublishesBoundedAuthorizedRoutes(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	projector := NewProjector()
	_, err := projector.Project(context.Background(), "session-1", "agent-1", "principal-1", []SessionEvent{{ID: "event-1", SessionID: "session-1", Class: "tool", Label: "shell", EvidenceID: "evidence-1", Source: "runtime", Confidence: ConfidenceExact, At: now}})
	if err != nil {
		t.Fatal(err)
	}
	controls := []ComplianceControl{{ID: "control-1", Framework: "SOC 2", Name: "Security", EvidenceIDs: []string{"evidence-1"}, FreshUntil: now.Add(time.Hour)}}
	data := NewDataControlStore()
	if err := data.Update(context.Background(), DataControls{EnvironmentID: "environment-1", EnvironmentClass: "production", CollectionMode: "metadata_only", RetentionDays: 30, DeletionEnabled: true}); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHTTPHandler(projector, controls, []EvidenceRecord{{ID: "evidence-1", AssetID: "asset-1", Source: "runtime", At: now}}, data, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer allowed" })
	if err != nil {
		t.Fatal(err)
	}
	handler.clock = func() time.Time { return now }
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{{"GET", "/api/v1/sessions", "", 200}, {"GET", "/api/v1/sessions/session-1", "", 200}, {"GET", "/api/v1/sessions/session-1/events", "", 200}, {"GET", "/api/v1/compliance/controls", "", 200}, {"GET", "/api/v1/compliance/evidence", "", 200}, {"POST", "/api/v1/compliance/exports", "{\"id\":\"export-1\"}", 201}, {"GET", "/api/v1/compliance/exports/export-1", "", 200}, {"GET", "/api/v1/settings/data-controls", "", 200}, {"PATCH", "/api/v1/settings/data-controls", "{\"environment_id\":\"environment-1\",\"environment_class\":\"production\",\"collection_mode\":\"metadata_only\",\"retention_days\":60,\"deletion_enabled\":true}", 200}} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("Authorization", "Bearer allowed")
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	record := httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	if record.Code != http.StatusForbidden || !bytes.Contains(record.Body.Bytes(), []byte("session_control_rejected")) {
		t.Fatalf("status=%d body=%s", record.Code, record.Body.String())
	}
	hostile := httptest.NewRequest(http.MethodGet, "/api/v1/sessions?raw=*", nil)
	hostile.Header.Set("Authorization", "Bearer allowed")
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, hostile)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("hostile query status=%d", rejected.Code)
	}
}
