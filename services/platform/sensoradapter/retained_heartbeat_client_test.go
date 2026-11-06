package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
)

// Terminal receipt validation is exercised against the real production client;
// controlled HTTP replies do not establish a database commit or provider proof.
func TestProductionClientRetainedHeartbeatExactWireAndReceipt(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	wire := retainedClientWire(t, now)
	makeClient := func(enabled bool, do func(*http.Request) (*http.Response, error)) *ProductionClient {
		c, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Token: func() ([]byte, error) { return []byte(fixtureSensorToken()), nil }, Do: do, Now: func() time.Time { return now }, NodeCoverageRetention: enabled, SensorID: "pid_10000001-0000-4000-8000-000000000001"})
		if err != nil {
			t.Fatal("retained client constructor refused")
		}
		return c
	}
	reply := func(status int, body []byte, header http.Header) *http.Response {
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}
	}
	t.Run("exact_pending_bytes_and_expired_resolution_not_restamped", func(t *testing.T) {
		for _, disposition := range []string{"accepted", "expired_not_committed"} {
			calls := 0
			c := makeClient(true, func(r *http.Request) (*http.Response, error) {
				calls++
				raw, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(raw, wire) || r.Method != http.MethodPost || r.URL.String() != "https://runtime.example.test/internal/v1/sensor/heartbeat" || r.Header.Get("X-Zasp-Schema-Version") != nodecoveragewire.HeartbeatSchema || r.Header.Get("Content-Type") != heartbeatMediaType || r.Header.Get("Authorization") != "Bearer "+fixtureSensorToken() || r.Header.Get("X-Zasp-Expected-Enrollment") != "" {
					t.Error("retained transport changed original wire or authority")
				}
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > 31*time.Second {
					t.Error("retained request missing bounded operation deadline")
				}
				rec := retainedClientReceipt(wire, now, disposition)
				b, _ := json.Marshal(rec)
				return reply(http.StatusOK, b, http.Header{"Cache-Control": []string{"no-store"}, "Content-Type": []string{"application/json"}}), nil
			})
			got, err := c.SendRetainedHeartbeat(context.Background(), wire)
			if err != nil || calls != 1 || got.Disposition != disposition || got.Sequence != 7 {
				t.Fatal("strict terminal receipt refused")
			}
		}
	})
	t.Run("explicit_optin_and_invalid_wire_never_send", func(t *testing.T) {
		calls := 0
		do := func(*http.Request) (*http.Response, error) { calls++; return nil, nil }
		if _, err := makeClient(false, do).SendRetainedHeartbeat(context.Background(), wire); err == nil {
			t.Fatal("legacy configuration sent retained telemetry")
		}
		for _, raw := range [][]byte{nil, []byte(`{"sequence":7}`), append(append([]byte{}, wire...), []byte(`{}`)...), bytes.Repeat([]byte{' '}, nodecoveragewire.MaxEnvelopeBytes+1)} {
			if _, err := makeClient(true, do).SendRetainedHeartbeat(context.Background(), raw); err == nil {
				t.Fatal("invalid retained body sent")
			}
		}
		for _, sensorID := range []string{"", "pid_00000000-0000-0000-0000-000000000000", "foreign"} {
			if _, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Token: func() ([]byte, error) { return []byte(fixtureSensorToken()), nil }, Do: do, Now: func() time.Time { return now }, NodeCoverageRetention: true, SensorID: sensorID}); err == nil {
				t.Fatal("retention enabled without canonical expected sensor ID")
			}
		}
		if calls != 0 {
			t.Fatal("invalid admission reached network")
		}
	})
	t.Run("legacy204_unknown_mismatch_and_ambiguous_receipts_never_resolve", func(t *testing.T) {
		for _, mode := range []string{"legacy204", "foreign-sensor", "digest", "sequence", "source-time", "expiry", "unknown-disposition", "duplicate-key", "trailing", "unknown-field", "cache", "content-type", "duplicate-content-type", "oversize"} {
			c := makeClient(true, func(*http.Request) (*http.Response, error) {
				rec := retainedClientReceipt(wire, now, "accepted")
				status := http.StatusOK
				h := http.Header{"Cache-Control": []string{"no-store"}, "Content-Type": []string{"application/json"}}
				switch mode {
				case "foreign-sensor":
					rec.SensorID = "pid_10000002-0000-4000-8000-000000000002"
				case "digest":
					rec.RequestDigest = strings.Repeat("0", 64)
				case "sequence":
					rec.Sequence++
				case "source-time":
					rec.SourceObservedAt = rec.SourceObservedAt.Add(time.Second)
				case "expiry":
					rec.ExpiresAt = rec.ExpiresAt.Add(time.Second)
				case "unknown-disposition":
					rec.Disposition = "unknown"
				case "legacy204":
					status = http.StatusNoContent
				case "cache":
					h.Set("Cache-Control", "public")
				case "content-type":
					h.Set("Content-Type", "text/plain")
				case "duplicate-content-type":
					h.Add("Content-Type", "application/json")
				}
				raw, _ := json.Marshal(rec)
				switch mode {
				case "duplicate-key":
					raw = append([]byte(`{"sequence":7,`), raw[1:]...)
				case "trailing":
					raw = append(raw, []byte(`{}`)...)
				case "unknown-field":
					raw = append([]byte(`{"extra":true,`), raw[1:]...)
				case "oversize":
					raw = bytes.Repeat([]byte{' '}, 16385)
				}
				return reply(status, raw, h), nil
			})
			if _, err := c.SendRetainedHeartbeat(context.Background(), wire); err == nil {
				t.Fatalf("unconfirmed receipt resolved pending: %s", mode)
			}
		}
	})
	t.Run("canceled_request_no_send_and_legacy_wire_unchanged", func(t *testing.T) {
		calls := 0
		c := makeClient(true, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Header.Get("X-Zasp-Schema-Version") != heartbeatSchema {
				t.Error("legacy schema widened")
			}
			return reply(http.StatusNoContent, nil, http.Header{"Cache-Control": []string{"no-store"}}), nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.SendRetainedHeartbeat(ctx, wire); err == nil || calls != 0 {
			t.Fatal("canceled pending observation sent")
		}
		if err := c.Heartbeat(context.Background(), Heartbeat{Sequence: 9, Status: "healthy", Capabilities: []string{"process"}, Kernel: "6.8.1", BTF: true}); err != nil || calls != 1 {
			t.Fatal("legacy heartbeat204 contract changed")
		}
	})
}
func retainedClientReceipt(raw []byte, now time.Time, disposition string) nodecoveragewire.Receipt {
	var env nodecoveragewire.Envelope
	_ = json.Unmarshal(raw, &env)
	sum := sha256.Sum256(raw)
	return nodecoveragewire.Receipt{SensorID: "pid_10000001-0000-4000-8000-000000000001", Sequence: env.Sequence, RequestDigest: hex.EncodeToString(sum[:]), Disposition: disposition, ResolvedAt: now, SourceObservedAt: env.SourceObservedAt, ExpiresAt: env.SourceObservedAt.Add(time.Duration(env.TTLSeconds) * time.Second)}
}
func retainedClientWire(t *testing.T, now time.Time) []byte {
	t.Helper()
	selection, _ := coverageFixture(t, now)
	b, err := json.Marshal(selection)
	if err != nil {
		t.Fatal("selection fixture encoding")
	}
	var selected nodecoveragewire.NodeCoverageSelection
	if json.Unmarshal(b, &selected) != nil {
		t.Fatal("selection fixture transfer")
	}
	source := now.Add(-time.Minute)
	env := nodecoveragewire.Envelope{Heartbeat: nodecoveragewire.Heartbeat{Sequence: 7, Status: "degraded", Capabilities: []string{"process"}, Kernel: "unknown", BTF: false}, CoverageSchema: nodecoveragewire.CoverageSchema, StateUID: "11111111-1111-4111-8111-111111111111", StorageEpoch: 2, Selection: selected, TargetDigest: strings.Repeat("b", 64), InventoryObservedAt: source, SourceObservedAt: source, TTLSeconds: 30, SensorDaemonSetUID: "22222222-2222-4222-8222-222222222222", TetragonDaemonSetUID: "33333333-3333-4333-8333-333333333333", SelectedNodes: []nodecoveragewire.SelectedNode{{NodeName: "node-a", NodeUID: "44444444-4444-4444-8444-444444444444", BootID: "55555555-5555-4555-8555-555555555555"}}, Reports: []nodecoveragewire.NodeCoverageV2{}}
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal("retained fixture encoding")
	}
	return append([]byte(" \n"), wire...)
}
