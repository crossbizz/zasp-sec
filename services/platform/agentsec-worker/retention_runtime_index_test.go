package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

type retentionIndexDBFixture struct {
	queries, records int
	admissions       int
	admissionError   bool
	recordError      bool
	request          map[string]any
}

func (d *retentionIndexDBFixture) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	d.queries++
	if len(args) == 3 {
		return json.RawMessage(`true`), nil
	}
	var wire struct {
		IDs []string `json:"event_ids"`
	}
	_ = json.Unmarshal(args[0].([]byte), &wire)
	items := make([]map[string]any, len(wire.IDs))
	for i, id := range wire.IDs {
		items[i] = map[string]any{"event_id": id, "visible": false}
	}
	raw, _ := json.Marshal(map[string]any{"items": items})
	return raw, nil
}
func (d *retentionIndexDBFixture) CommitRetainedJSON(_ context.Context, q string, body []byte, pin string) (json.RawMessage, error) {
	if strings.Contains(q, "visibility(") {
		d.admissions++
		if d.admissionError {
			return nil, errors.New("admission commit unavailable")
		}
		var request struct {
			IDs []string `json:"event_ids"`
		}
		_ = json.Unmarshal(body, &request)
		items := make([]map[string]any, len(request.IDs))
		for i, id := range request.IDs {
			items[i] = map[string]any{"event_id": id, "visible": false}
		}
		raw, _ := json.Marshal(map[string]any{"admission_id": fmt.Sprintf("%064x", d.admissions), "items": items})
		return raw, nil
	}
	d.records++
	_ = json.Unmarshal(body, &d.request)
	if pin != migrations.RetentionAuditProfileChecksum() || d.recordError {
		return nil, errors.New("commit unavailable")
	}
	return json.RawMessage(`{"partition_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), nil
}

type retentionProviderDriverFixture struct{ calls int }

func (d *retentionProviderDriverFixture) Apply(context.Context, runtimeindex.DriverBatch) (runtimeindex.DriverResult, error) {
	d.calls++
	return runtimeindex.DriverResult{}, errors.New("unexpected expired write")
}
func TestRetentionIndexActualExecutorRequiresPrivateLeaseAndDurablePartition(t *testing.T) {
	for _, phase := range []string{"confirmed", "unknown_partition", "unknown_admission"} {
		t.Run(phase, func(t *testing.T) {
			lease := runtimeStageLease(t, runtimeevent.RuntimeStageIndex)
			body := runtimeIndexBody(lease)
			lease.InputDigest = sha256.Sum256(body)
			db := &retentionIndexDBFixture{recordError: phase == "unknown_partition", admissionError: phase == "unknown_admission"}
			gate, err := newRetentionIndexVisibility(db, migrations.RetentionAuditProfileChecksum())
			if err != nil {
				t.Fatal(err)
			}
			driver := &retentionProviderDriverFixture{}
			index, err := runtimeindex.NewRetained(driver, runtimeindex.Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000}, gate)
			if err != nil {
				t.Fatal(err)
			}
			receipts := &runtimeReceiptStoreStub{}
			executor, err := newRuntimeIndexExecutor(runtimeIndexExecutorConfig{Reader: &runtimeArchivedReaderStub{body: body}, Index: index, Receipts: receipts, ImplementationVersion: "runtime-index-v1"})
			if err != nil {
				t.Fatal(err)
			}
			execution := runtimeStageExecution{lease: lease, workerID: "actual-index-worker", leaseToken: "actual-index-token-0001"}
			effect, err := executor.ExecuteAuthorized(context.Background(), execution)
			if phase != "confirmed" {
				if err == nil || effect != (runtimeStageEffect{}) || receipts.putCalls != 0 {
					t.Fatal("unconfirmed partition published originalstage receipt")
				}
			} else {
				receipt, decodeErr := runtimeevent.DecodeStageReceipt(receipts.put.Body)
				if err != nil || decodeErr != nil || len(receipt.ItemIDs) != 1 || effect.EffectDigest == ([sha256.Size]byte{}) {
					t.Fatal("suppression trimmed whole originalsource receipt", err, decodeErr)
				}
			}
			if phase == "unknown_admission" {
				if driver.calls != 0 || db.records != 0 || receipts.putCalls != 0 {
					t.Fatal("HTTP or partition after uncertain admission")
				}
				return
			}
			if driver.calls != 0 || db.records != 1 || db.request["worker_id"] != "actual-index-worker" || db.request["lease_token"] != "actual-index-token-0001" || len(db.request["suppressed_document_ids"].([]any)) != 1 || len(db.request["written_document_ids"].([]any)) != 0 || len(db.request["admission_ids"].([]any)) != 2 {
				t.Fatal("provider effect or durable partition binding wrong")
			}
			if phase == "confirmed" {
				first := append([]any(nil), db.request["admission_ids"].([]any)...)
				if _, err := executor.ExecuteAuthorized(context.Background(), execution); err != nil {
					t.Fatal(err)
				}
				second := db.request["admission_ids"].([]any)
				if len(second) != 2 || second[0] == first[0] || second[0] == first[1] || second[1] == first[0] || second[1] == first[1] {
					t.Fatal("same lease consumed another privateexecution admission")
				}
			}
			before := db.queries
			if _, err := gate.VisibleEvents(context.Background(), lease.Scope, []string{lease.BatchID.String()}); err == nil || db.queries != before {
				t.Fatal("scope alone granted indexauthority")
			}
		})
	}
}

func (d *retentionProviderDriverFixture) ApplyRetained(ctx context.Context, input runtimeindex.DriverBatch) (runtimeindex.DriverResult, error) {
	return d.Apply(ctx, input)
}
