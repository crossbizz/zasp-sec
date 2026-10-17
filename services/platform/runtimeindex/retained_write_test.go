package runtimeindex

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"testing"
	"time"
)

type retainedWriteGate func(context.Context, domain.Scope, []string) (map[string]bool, error)

func (f retainedWriteGate) VisibleEvents(ctx context.Context, s domain.Scope, ids []string) (map[string]bool, error) {
	return f(ctx, s, ids)
}
func (f retainedWriteGate) RecordRetainedWrite(context.Context, RetainedWriteReceipt) error {
	return nil
}
func TestRetainedWriteValidatesWholeArchiveBeforePartition(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
			scope := testScope(t, 1)
			body := testBody(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
			driver := &driverStub{}
			calls := 0
			gate := retainedWriteGate(func(_ context.Context, s domain.Scope, ids []string) (map[string]bool, error) {
				calls++
				if s != scope || len(ids) != 1 {
					t.Fatal("scope or membership lost")
				}
				return map[string]bool{ids[0]: !expired}, nil
			})
			store, err := NewRetained(retainedTestDriver{driver}, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000}, gate)
			if err != nil {
				t.Fatal(err)
			}
			in := Batch{Scope: scope, BatchID: testID(t, 9), Generation: 3, InputDigest: sha256.Sum256(body), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "v1", Body: body}
			out, err := store.Apply(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.DocumentIDs) != 1 || out.Retention == nil || calls != 2 {
				t.Fatal("whole originalreceipt or finalgate lost")
			}
			if expired {
				if driver.calls != 0 || len(out.Retention.SuppressedDocumentIDs) != 1 || len(out.Retention.WrittenDocumentIDs) != 0 {
					t.Fatal("expired event written or misreported")
				}
			} else if driver.calls != 1 || len(out.Retention.WrittenDocumentIDs) != 1 {
				t.Fatal("live event notwritten")
			}
			in.InputDigest = sha256.Sum256([]byte("changed"))
			before := calls
			if _, err := store.Apply(context.Background(), in); err == nil || calls != before {
				t.Fatal("invalid wholearchive reached retentionauthority")
			}
		})
	}
}

func TestRetainedWriteMixedBatchKeepsWholeReceiptAndExplicitPartition(t *testing.T) {
	scope := testScope(t, 1)
	var wire struct {
		Source string           `json:"source"`
		Events []map[string]any `json:"events"`
	}
	if json.Unmarshal(testBody(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)), &wire) != nil {
		t.Fatal("archive fixture")
	}
	second := make(map[string]any)
	for k, v := range wire.Events[0] {
		second[k] = v
	}
	second["event_id"] = "event-2"
	second["evidence_id"] = "pid_79000002-0000-4000-8000-000000000002"
	wire.Events = append(wire.Events, second)
	body, _ := json.Marshal(wire)
	driver := &driverStub{}
	gate := retainedWriteGate(func(_ context.Context, _ domain.Scope, ids []string) (map[string]bool, error) {
		if len(ids) != 2 {
			t.Fatal("trimmed membership")
		}
		return map[string]bool{ids[0]: false, ids[1]: true}, nil
	})
	store, err := NewRetained(retainedTestDriver{driver}, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000}, gate)
	if err != nil {
		t.Fatal(err)
	}
	input := Batch{Scope: scope, BatchID: testID(t, 9), Generation: 3, InputDigest: sha256.Sum256(body), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "v1", Body: body}
	out, err := store.Apply(context.Background(), input)
	if err != nil || len(out.DocumentIDs) != 2 || driver.calls != 1 || len(driver.input.Documents) != 1 || driver.input.ContentDigest != out.ContentDigest || out.Retention == nil || len(out.Retention.WrittenDocumentIDs) != 1 || len(out.Retention.SuppressedDocumentIDs) != 1 || out.Retention.WrittenDocumentIDs[0] != driver.input.Documents[0].DocumentID {
		t.Fatal("mixed source receipt/provider partition inconsistent", err)
	}
}

// This explicit fixture capability models an already terminal provider result;
// ordinary driverStub remains a legacy driver and cannot silently opt in.
type retainedTestDriver struct{ *driverStub }

func (d retainedTestDriver) ApplyRetained(ctx context.Context, input DriverBatch) (DriverResult, error) {
	return d.driverStub.Apply(ctx, input)
}
func TestRetainedWriteRequiresExplicitTerminalDriver(t *testing.T) {
	gate := retainedWriteGate(func(context.Context, domain.Scope, []string) (map[string]bool, error) {
		t.Fatal("constructor reached authority without retained capability")
		return nil, nil
	})
	if store, err := NewRetained(&driverStub{}, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000}, gate); store != nil || err != ErrConfiguration {
		t.Fatal("normal driver silently supplied retained terminal authority")
	}
}
