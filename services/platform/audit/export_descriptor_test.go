package audit

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const exportDescriptorQueuedFixture = `{"id":"pid_76000001-0000-4000-8000-000000000001","organization_id":"pid_76000002-0000-4000-8000-000000000002","workspace_id":"pid_76000003-0000-4000-8000-000000000003","environment_id":"pid_76000004-0000-4000-8000-000000000004","created_at":"2026-09-12T10:00:00.000000Z","audit_correlation_id":"pid_76000005-0000-4000-8000-000000000005","status":"queued","event_count":null}`

func TestExportDescriptorDecodesEveryPublicState(t *testing.T) {
	for _, status := range []string{"queued", "processing", "failed", "ready"} {
		body := strings.Replace(exportDescriptorQueuedFixture, `"queued"`, `"`+status+`"`, 1)
		if status == "failed" {
			body = strings.TrimSuffix(body, "}") + `,"failure_code":"execution_failed"}`
		}
		if status == "ready" {
			body = strings.Replace(body, `"event_count":null`, `"event_count":1,"captured_at":"2026-09-12T10:00:01.000000Z","chunk_count":1,"chunk_bytes":1000,"manifest_sha256":"`+strings.Repeat("a", 64)+`"`, 1)
		}
		got, err := DecodeExportDescriptor([]byte(body))
		if err != nil || got.Status != status || got.ID != "pid_76000001-0000-4000-8000-000000000001" || got.CreatedAt != "2026-09-12T10:00:00.000000Z" {
			t.Fatalf("public state %s rejected: %v", status, err)
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var original, roundtrip any
		if json.Unmarshal([]byte(body), &original) != nil || json.Unmarshal(encoded, &roundtrip) != nil || !reflect.DeepEqual(original, roundtrip) {
			t.Fatal("descriptor fields changed on roundtrip")
		}
		// JSONB may reorder fields; the shared decoder must not require wire canonicalization.
		ordered, _ := json.Marshal(original)
		if _, err := DecodeExportDescriptor(ordered); err != nil {
			t.Fatal("reordered database descriptor rejected", err)
		}
	}
}

func TestExportDescriptorRejectsAmbiguousWireAndState(t *testing.T) {
	for _, body := range []string{
		"", "null", exportDescriptorQueuedFixture + "{}", strings.Repeat(" ", 8193),
		strings.Replace(exportDescriptorQueuedFixture, `"status":"queued"`, `"status":"ready"`, 1),
		strings.Replace(exportDescriptorQueuedFixture, `"event_count":null`, `"event_count":0`, 1),
		strings.Replace(exportDescriptorQueuedFixture, `"status":"queued"`, `"status":"queued","status":"queued"`, 1),
		strings.Replace(exportDescriptorQueuedFixture, `"id":`, `"ID":`, 1),
		strings.Replace(exportDescriptorQueuedFixture, `.000000Z`, `Z`, 1),
		strings.Replace(exportDescriptorQueuedFixture, `"event_count":null`, `"event_count":null,"object_reference":"private"`, 1),
		strings.Replace(exportDescriptorQueuedFixture, `"event_count":null`, `"event_count":null,"captured_at":null`, 1),
	} {
		if _, err := DecodeExportDescriptor([]byte(body)); !errors.Is(err, ErrExport) {
			t.Fatal("invalid descriptor accepted", err)
		}
	}
}
