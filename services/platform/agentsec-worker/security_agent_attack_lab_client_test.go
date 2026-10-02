package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAttackLabReconcilerStrictSQLWire(t *testing.T) {
	type envelope struct {
		Expires  time.Time       `json:"lease_expires_at"`
		Snapshot json.RawMessage `json:"snapshot"`
	}
	literal := []byte(`{"lease_expires_at":"2026-09-19T09:12:33.439693Z","snapshot":{"source":{"evidence":{"version":"pinned"}},"complete":false}}`)
	var got envelope
	if strictAttackLabJSON(literal, &got) != nil || got.Expires.IsZero() || len(got.Snapshot) == 0 {
		t.Fatal("actual PostgreSQL timestamp/object envelope rejected")
	}
	for _, bad := range []string{
		`{"lease_expires_at":"bad","snapshot":{}}`,
		`{"lease_expires_at":null,"snapshot":{}}`,
		`{"lease_expires_at":"2026-09-19T09:12:33Z"}`,
		`{"Lease_expires_at":"2026-09-19T09:12:33Z","snapshot":{}}`,
		`{"lease_expires_at":"2026-09-19T09:12:33Z","snapshot":{"nested":{"x":1,"x":2}}}`,
		`{"lease_expires_at":"2026-09-19T09:12:33Z","snapshot":{},"unknown":true}`,
	} {
		if strictAttackLabJSON([]byte(bad), &got) == nil {
			t.Fatalf("ambiguous/missing wire accepted: %s", bad)
		}
	}
}
