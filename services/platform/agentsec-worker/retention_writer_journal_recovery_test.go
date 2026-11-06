package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

type recoveredWriterJournalFixture struct {
	writerJournalDBFixture
	unknown      string
	mismatch     bool
	lookupFailed bool
	lookups      int
	statusValue  retentionJournalStatus
}

func (d *recoveredWriterJournalFixture) CommitRetentionJournal(ctx context.Context, q string, body []byte, pin string) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return nil, errRuntimeUnavailable
	}
	operation := strings.TrimSuffix(strings.TrimPrefix(q, "SELECT zasp_retention_journal_v1."), "($1::jsonb)")
	if operation == "execution_status" {
		d.lookups++
		var id, capability string
		_ = json.Unmarshal(fields["execution_id"], &id)
		_ = json.Unmarshal(fields["capability"], &capability)
		if d.lookupFailed || id != d.executionID || sha256.Sum256([]byte(capability)) != d.privateHash {
			return nil, errRuntimeUnavailable
		}
		// Clone only this public status DTO. No raw capability or lease is stored.
		raw, _ := json.Marshal(d.statusValue)
		var status retentionJournalStatus
		_ = json.Unmarshal(raw, &status)
		if d.mismatch {
			switch d.unknown {
			case "begin_execution":
				status.Binding = json.RawMessage(`{}`)
			case "admit_execution":
				status.Admissions[0].Items = json.RawMessage(`[]`)
			case "reserve_request":
				status.Descriptor = json.RawMessage(`{}`)
			case "append_terminal":
				status.Terminal = json.RawMessage(`{}`)
			case "close_inventory":
				status.Inventory.AdmissionIDs = []string{}
			case "seal_partition":
				status.Partition = json.RawMessage(`{}`)
			}
		}
		raw, _ = json.Marshal(status)
		return raw, nil
	}
	raw, err := d.writerJournalDBFixture.CommitRetentionJournal(ctx, q, body, pin)
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	_ = json.Unmarshal(raw, &result)
	switch operation {
	case "begin_execution":
		_ = json.Unmarshal(fields["kind"], &d.statusValue.Kind)
		d.statusValue.ExecutionID = d.executionID
		d.statusValue.State = "begun"
		var binding map[string]any
		_ = json.Unmarshal(fields["binding"], &binding)
		d.statusValue.Binding = normalizeRetentionJournalBinding(binding, false)
		no := false
		d.statusValue.SendPermitted = &no
		d.statusValue.Admissions = make([]struct {
			Key   string          `json:"admission_key"`
			ID    string          `json:"admission_id"`
			Items json.RawMessage `json:"items"`
		}, 0)
	case "admit_execution":
		var key, id string
		_ = json.Unmarshal(fields["admission_key"], &key)
		_ = json.Unmarshal(result["admission_id"], &id)
		d.statusValue.Admissions = append(d.statusValue.Admissions, struct {
			Key   string          `json:"admission_key"`
			ID    string          `json:"admission_id"`
			Items json.RawMessage `json:"items"`
		}{key, id, result["items"]})
	case "reserve_request":
		d.statusValue.State = "reserved"
		d.statusValue.Descriptor = fields["descriptor"]
		_ = json.Unmarshal(result["reservation_digest"], &d.statusValue.ReservationDigest)
	case "claim_send":
		d.statusValue.State = "dispatched"
		_ = json.Unmarshal(result["dispatch_digest"], &d.statusValue.DispatchDigest)
	case "append_terminal":
		d.statusValue.State = "terminal"
		d.statusValue.Terminal = fields["observation"]
	case "close_inventory":
		d.statusValue.State = "closed"
		_ = json.Unmarshal(result["inventory_digest"], &d.statusValue.InventoryDigest)
		d.statusValue.Inventory = &struct {
			AdmissionIDs []string `json:"admission_ids"`
			RequestCount int      `json:"request_count"`
			Digest       string   `json:"inventory_digest"`
		}{Digest: *d.statusValue.InventoryDigest}
		_ = json.Unmarshal(fields["admission_ids"], &d.statusValue.Inventory.AdmissionIDs)
		_ = json.Unmarshal(fields["request_count"], &d.statusValue.Inventory.RequestCount)
	case "seal_partition":
		d.statusValue.State = "sealed"
		_ = json.Unmarshal(result["partition_digest"], &d.statusValue.PartitionDigest)
		var partition map[string]any
		_ = json.Unmarshal(fields["partition"], &partition)
		d.statusValue.Partition = normalizeRetentionJournalBinding(partition, true)
	}
	if operation == d.unknown {
		return raw, errRetentionJournalCommitUnknown
	}
	return raw, nil
}
func TestRetainedWriterJournalExactUnknownCommitRecovery(t *testing.T) {
	for _, operation := range []string{"begin_execution", "admit_execution", "reserve_request", "claim_send", "append_terminal", "close_inventory", "seal_partition"} {
		for _, mode := range []string{"exact", "mismatch", "lookup unavailable"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				lease := runtimeStageLease(t, runtimeevent.RuntimeStageIndex)
				execution := runtimeStageExecution{lease: lease, workerID: "journal-recovery-worker", leaseToken: "journal-recovery-token-0001"}
				ctx := context.WithValue(retentionAdmissionContext(context.Background()), retentionStageContextKey{}, execution)
				db := &recoveredWriterJournalFixture{unknown: operation, mismatch: mode == "mismatch", lookupFailed: mode == "lookup unavailable"}
				gate, err := newRetentionJournalIndexVisibility(db, migrations.RetentionAuditProfileChecksum(), migrations.RetentionJournalProfileChecksum(), &journalReceiptFixture{})
				if err != nil {
					t.Fatal("recovery fixture constructor refused")
				}
				input := runtimeindex.RetainedExecutionInput{Kind: "raw-index", Scope: lease.Scope, BatchID: lease.BatchID.String(), Generation: lease.Generation, InputDigest: lease.InputDigest, DocumentIDs: []string{strings.Repeat("a", 64)}, EventIDs: []string{lease.BatchID.String()}}
				run := func() string {
					var err error
					ctx, err = runtimeindex.BeginRetainedJournal(ctx, gate, input)
					if err != nil {
						return "begin_execution"
					}
					if _, err = gate.VisibleEvents(ctx, lease.Scope, input.EventIDs); err != nil {
						return "admit_execution"
					}
					journal := runtimeindex.RetainedJournalFromContext(ctx).(*retentionWriterJournal)
					descriptor := runtimeindex.RetainedRequestDescriptor{Method: "POST", Target: "zasp-runtime-events-v1", Path: "/zasp-runtime-events-v1/_bulk", Query: "refresh=wait_for&timeout=10s", MediaType: "application/x-ndjson", BodySHA256: strings.Repeat("a", 64), BodyLength: 1, SerializerProfile: "runtime-retained-bulk-v1", DocumentIDs: input.DocumentIDs, EventIDs: input.EventIDs}
					if journal.ReserveRequest(ctx, descriptor) != nil {
						return "reserve_request"
					}
					permitted, err := journal.ClaimSend(ctx)
					if err != nil || !permitted {
						if operation == "claim_send" && (permitted || journal.dispatch != "") {
							t.Fatal("lookup recreated unconfirmed dispatch capability")
						}
						return "claim_send"
					}
					if journal.AppendTerminal(ctx, 200, []byte(`{"errors":false,"took":1,"items":[{"create":{"_index":"zasp-runtime-events-v1","_id":"`+strings.Repeat("a", 64)+`","_version":1,"result":"created","status":201,"_seq_no":0,"_primary_term":1,"_shards":{"total":1,"successful":1,"failed":0}}}]}`)) != nil {
						return "append_terminal"
					}
					receipt := runtimeindex.RetainedWriteReceipt{Scope: lease.Scope, BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, OriginalContentDigest: sha256.Sum256([]byte("source")), DocumentIDs: input.DocumentIDs, EventIDs: input.EventIDs, Partition: runtimeindex.WritePartition{WrittenDocumentIDs: input.DocumentIDs, SuppressedDocumentIDs: []string{}, ProviderContentDigest: sha256.Sum256([]byte("provider"))}}
					if gate.RecordRetainedWrite(ctx, receipt) != nil {
						if operation == "close_inventory" {
							return "close_inventory"
						}
						return "seal_partition"
					}
					return "completed"
				}
				result := run()
				if operation == "claim_send" || mode != "exact" {
					if result != operation {
						t.Fatal("mismatched or unavailable status changed original refusal boundary")
					}
				} else if result != "completed" {
					t.Fatal("exact private committed status did not recover original operation")
				}
				if db.lookups != 1 {
					t.Fatal("ambiguous commit was not resolved by exactly one bounded lookup")
				}
				count := 0
				for _, name := range db.calls {
					if name == operation {
						count++
					}
				}
				if count != 1 {
					t.Fatal("uncertain mutation was replayed")
				}
			})
		}
	}
}
