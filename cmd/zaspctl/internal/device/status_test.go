package device

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeviceDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		body    string
		exit    int
		message string
	}{
		{`{"status":{"policy_status":"verified_cache","policy_revision":9,"mode":"enforce","remote_state":"connected"}}`, 0, "signed policy are available"},
		{`{"status":{"policy_status":"policy_expired","remote_state":"receipt_ack_pending"}}`, 3, "Check device network"},
		{`{"status":{"policy_status":"verified_cache","policy_revision":7,"mode":"monitor","dropped_receipts":3}}`, 0, "receipts were dropped"},
		{`{"status":{"policy_status":"spoofed","remote_state":"SECRET_TEXT"}}`, 3, "ask IT"},
		{`{"error":"peer_denied"}`, 3, "ask IT"},
	} {
		var output bytes.Buffer
		got := inspect([]string{"doctor"}, &output, &output, func() ([]byte, error) { return []byte(tc.body), nil })
		if got != tc.exit || !strings.Contains(output.String(), tc.message) || strings.Contains(output.String(), "SECRET_TEXT") {
			t.Fatalf("got %d %s", got, output.String())
		}
	}
}

func TestWindowsInventoryDoctor(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		age     time.Duration
		state   string
		pending int
		want    int
	}{{0, "connected", 0, 0}, {16 * time.Minute, "connected", 0, 3}, {0, "scan_unavailable", 0, 3}, {0, "sync_unavailable", 2, 3}} {
		when := now.Add(-tc.age)
		raw, _ := json.Marshal(map[string]any{"windows_inventory": inventoryHealth{CheckedAt: when, LastContact: &when, State: tc.state, Pending: tc.pending}})
		var o bytes.Buffer
		code := inspect([]string{"doctor"}, &o, &o, func() ([]byte, error) { return raw, nil })
		if code != tc.want || !strings.Contains(o.String(), "Windows inventory only") || strings.Contains(o.String(), "signed policy are available") {
			t.Fatalf("%d %s", code, o.String())
		}
	}
}
