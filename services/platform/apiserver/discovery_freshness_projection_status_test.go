package apiserver

import (
	"testing"
	"time"
)

// The freshness function reports a current projection with the code
// outcome_unknown. Only that exact combination is normalized; every other
// status reaches the validator unchanged.
func TestNormalizeCurrentProjectionStatus(t *testing.T) {
	t.Parallel()
	snapshot := "pid_72000001-0000-4000-8000-000000000001"
	completed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	code := func(value string) *string { return &value }

	current := IntegrationProjectionStatus{State: "current", SnapshotID: &snapshot, CompletedAt: &completed, LastErrorCode: code("outcome_unknown")}
	if validProjectionStatus(current) {
		t.Fatal("the unnormalized current status was valid")
	}
	normalizeCurrentProjectionStatus(&current)
	if current.LastErrorCode != nil || !validProjectionStatus(current) {
		t.Fatalf("current status = %#v", current)
	}

	unchanged := []IntegrationProjectionStatus{
		{State: "current", SnapshotID: &snapshot, CompletedAt: &completed, LastErrorCode: code("terminal")},
		{State: "current", SnapshotID: &snapshot, LastErrorCode: code("outcome_unknown")},
		{State: "current", CompletedAt: &completed, LastErrorCode: code("outcome_unknown")},
		{State: "degraded", SnapshotID: &snapshot, LastErrorCode: code("outcome_unknown")},
		{State: "degraded", SnapshotID: &snapshot, CompletedAt: &completed, LastErrorCode: code("terminal")},
		{State: "pending", SnapshotID: &snapshot, LastErrorCode: code("retryable")},
	}
	for index, status := range unchanged {
		before := status.LastErrorCode
		normalizeCurrentProjectionStatus(&status)
		if status.LastErrorCode != before {
			t.Fatalf("status %d was changed: %#v", index, status)
		}
	}
	for _, index := range []int{0, 1, 2} {
		if validProjectionStatus(unchanged[index]) {
			t.Fatalf("invalid current status %d was accepted", index)
		}
	}
	normalizeCurrentProjectionStatus(nil)
}
