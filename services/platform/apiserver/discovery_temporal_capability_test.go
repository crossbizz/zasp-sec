package apiserver

import (
	"testing"
	"time"
)

func TestTemporalDiscoveryNoIOWaitReadback(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	after := now.Add(5 * time.Second)
	code := "retryable"
	base := IntegrationSync{ID: "pid_72000001-0000-4000-8000-000000000001", IntegrationID: "pid_72000002-0000-4000-8000-000000000002", TriggerKind: "manual", Status: "queued", Attempt: 0, RequestedAt: now, LastErrorCode: &code, RetryAt: &after}
	for _, name := range []string{"valid", "missing_not_before", "missing_code", "foreign_code", "zero_time", "past_request", "started", "complete", "snapshot", "expired_wait", "revoked_terminal"} {
		t.Run(name, func(t *testing.T) {
			v := base
			switch name {
			case "missing_not_before":
				v.RetryAt = nil
			case "missing_code":
				v.LastErrorCode = nil
			case "foreign_code":
				c := "outcome_unknown"
				v.LastErrorCode = &c
			case "zero_time":
				z := time.Time{}
				v.RetryAt = &z
			case "past_request":
				z := now.Add(-time.Second)
				v.RetryAt = &z
			case "started":
				v.StartedAt = &now
			case "complete":
				v.CompletedAt = &after
			case "snapshot":
				s := "pid_72000003-0000-4000-8000-000000000003"
				v.SnapshotID = &s
			case "expired_wait":
				v.RequestedAt = now.Add(-24 * time.Hour)
				v.RetryAt = &now
			case "revoked_terminal":
				c := "revoked"
				v.LastErrorCode = &c
				v.RetryAt = nil
				v.Status = "failed"
				v.CompletedAt = &after
			}
			want := name == "valid" || name == "expired_wait" || name == "revoked_terminal"
			if got := (&DiscoveryRepository{temporal: true}).validSync(v, v.IntegrationID, v.ID); got != want {
				t.Fatalf("scoped readback %v want %v", got, want)
			}
			if (&DiscoveryRepository{}).validSync(v, v.IntegrationID, v.ID) {
				t.Fatal("legacy validator relaxed")
			}
		})
	}
}
