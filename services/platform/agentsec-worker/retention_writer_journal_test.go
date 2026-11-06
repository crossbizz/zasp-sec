package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

type writerJournalDBFixture struct {
	retentionIndexDBFixture
	fail        string
	calls       []string
	privateHash [sha256.Size]byte
	executionID string
	suppressed  bool
}

func (d *writerJournalDBFixture) CommitRetentionJournal(_ context.Context, q string, body []byte, pin string) (json.RawMessage, error) {
	if !migrations.IsRetentionJournalProfileChecksum(pin) {
		return nil, errRuntimeUnavailable
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil {
		return nil, errRuntimeUnavailable
	}
	var id, capability string
	_ = json.Unmarshal(envelope["execution_id"], &id)
	_ = json.Unmarshal(envelope["capability"], &capability)
	if id == capability || !retentionCycleKeyPattern.MatchString(id) || !retentionCycleKeyPattern.MatchString(capability) {
		return nil, errRuntimeUnavailable
	}
	hash := sha256.Sum256([]byte(capability))
	if d.executionID != "" && (d.executionID != id || d.privateHash != hash) {
		return nil, errRuntimeUnavailable
	}
	d.executionID = id
	d.privateHash = hash
	operation := strings.TrimSuffix(strings.TrimPrefix(q, "SELECT zasp_retention_journal_v1."), "($1::jsonb)")
	d.calls = append(d.calls, operation)
	if d.fail == operation {
		return nil, errRuntimeUnavailable
	}
	switch operation {
	case "begin_execution":
		b, _ := json.Marshal(map[string]string{"execution_id": id, "state": "begun"})
		return b, nil
	case "admit_execution":
		var binding struct {
			IDs []string `json:"event_ids"`
		}
		_ = json.Unmarshal(envelope["binding"], &binding)
		items := []map[string]any{}
		for _, event := range binding.IDs {
			items = append(items, map[string]any{"event_id": event, "visible": !d.suppressed})
		}
		b, _ := json.Marshal(map[string]any{"admission_id": fmt.Sprintf("%064x", len(d.calls)), "items": items})
		return b, nil
	case "reserve_request":
		return json.RawMessage(`{"reservation_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), nil
	case "claim_send":
		return json.RawMessage(`{"send_permitted":true,"dispatch_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`), nil
	case "append_terminal":
		return json.RawMessage(`{"recorded":true}`), nil
	case "close_inventory":
		return json.RawMessage(`{"inventory_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`), nil
	case "seal_partition":
		return json.RawMessage(`{"partition_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`), nil
	}
	return nil, errRuntimeUnavailable
}

type journalReceiptFixture struct {
	runtimeReceiptStoreStub
	getCalls           int
	corrupt, uncertain bool
}

func (s *journalReceiptFixture) Put(ctx context.Context, input artifactstore.PutRequest) (artifactstore.Artifact, error) {
	result, err := s.runtimeReceiptStoreStub.Put(ctx, input)
	if s.uncertain {
		return artifactstore.Artifact{}, errors.New("unknown artifact put")
	}
	return result, err
}
func (s *journalReceiptFixture) Get(_ context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	s.getCalls++
	if locator.Reference != s.result.Reference || locator.Scope != s.result.Scope || locator.VersionID != "" && locator.VersionID != s.result.VersionID {
		return artifactstore.Artifact{}, artifactstore.ErrGet
	}
	result := s.result
	result.Body = bytes.Clone(result.Body)
	if s.corrupt {
		result.Body = append(result.Body, ' ')
	}
	return result, nil
}
func TestRetainedWorkerJournalArtifactCommitAndCapturedBoundaries(t *testing.T) {
	for _, phase := range []string{"confirmed", "uncertain put", "changed pinned bytes", "claim unknown", "late captured", "suppressed zero request"} {
		t.Run(phase, func(t *testing.T) {
			lease := runtimeStageLease(t, runtimeevent.RuntimeStageIndex)
			execution := runtimeStageExecution{lease: lease, workerID: "journal-index-worker", leaseToken: "journal-test-token-0001"}
			ctx, cancel := context.WithCancel(context.WithValue(retentionAdmissionContext(context.Background()), retentionStageContextKey{}, execution))
			defer cancel()
			db := &writerJournalDBFixture{suppressed: phase == "suppressed zero request"}
			artifacts := &journalReceiptFixture{uncertain: phase == "uncertain put", corrupt: phase == "changed pinned bytes"}
			gate, err := newRetentionJournalIndexVisibility(db, migrations.RetentionAuditProfileChecksum(), migrations.RetentionJournalProfileChecksum(), artifacts)
			if err != nil {
				t.Fatal("real journal capability constructor refused")
			}
			input := runtimeindex.RetainedExecutionInput{Kind: "raw-index", Scope: lease.Scope, BatchID: lease.BatchID.String(), Generation: lease.Generation, InputDigest: lease.InputDigest, DocumentIDs: []string{strings.Repeat("a", 64)}, EventIDs: []string{lease.BatchID.String()}}
			ctx, err = runtimeindex.BeginRetainedJournal(ctx, gate, input)
			if err != nil {
				t.Fatal("private execution begin refused")
			}
			if _, err = gate.VisibleEvents(ctx, lease.Scope, input.EventIDs); err != nil {
				t.Fatal("bound admission refused")
			}
			journal := runtimeindex.RetainedJournalFromContext(ctx).(*retentionWriterJournal)
			if phase == "suppressed zero request" {
				receipt := runtimeindex.RetainedWriteReceipt{Scope: lease.Scope, BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, OriginalContentDigest: sha256.Sum256([]byte("original")), DocumentIDs: input.DocumentIDs, EventIDs: input.EventIDs, Partition: runtimeindex.WritePartition{SuppressedDocumentIDs: input.DocumentIDs, WrittenDocumentIDs: []string{}, ProviderContentDigest: sha256.Sum256([]byte("empty"))}}
				if gate.RecordRetainedWrite(ctx, receipt) != nil || artifacts.putCalls != 0 || strings.Join(db.calls, ",") != "begin_execution,admit_execution,close_inventory,seal_partition" {
					t.Fatal("zero-request closure bypassed journal or fabricated HTTP")
				}
				return
			}
			descriptor := runtimeindex.RetainedRequestDescriptor{Method: "POST", Target: "zasp-runtime-events-v1", Path: "/zasp-runtime-events-v1/_bulk", Query: "refresh=wait_for&timeout=10s", MediaType: "application/x-ndjson", BodySHA256: strings.Repeat("a", 64), BodyLength: 1, SerializerProfile: "runtime-retained-bulk-v1"}
			ctx = runtimeindex.WithRetainedBulkItems(ctx, input.DocumentIDs, input.EventIDs)
			if phase == "claim unknown" {
				db.fail = "claim_send"
			}
			permit, err := runtimeindex.PrepareRetainedBulk(ctx, descriptor)
			if phase == "claim unknown" {
				if err == nil || permit != nil || artifacts.putCalls != 0 {
					t.Fatal("unknown claim minted volatile authority")
				}
				return
			}
			if err != nil || runtimeindex.ConsumeRetainedSendPermit(ctx, permit) != nil {
				t.Fatal("confirmed claim failed")
			}
			if phase == "late captured" {
				cancel()
			}
			// Controlled complete bytes represent the previously validated SDK capture;
			// no request body, capability or lease is an artifact fixture or log field.
			terminal := []byte(`{"errors":false,"took":1,"items":[{"create":{"_index":"zasp-runtime-events-v1","_id":"` + strings.Repeat("a", 64) + `","_version":1,"result":"created","status":201,"_seq_no":0,"_primary_term":1,"_shards":{"total":1,"successful":1,"failed":0}}}]}`)
			err = journal.AppendTerminal(ctx, 200, terminal)
			if phase == "changed pinned bytes" {
				if err == nil || strings.Contains(strings.Join(db.calls, ","), "append_terminal") {
					t.Fatal("changed stored bytes became terminal SQL evidence")
				}
				return
			}
			if err != nil || artifacts.putCalls != 1 || artifacts.getCalls < 1 || !bytes.Equal(artifacts.put.Body, terminal) {
				t.Fatal("exact version-pinned actual capture custody failed")
			}
			if bytes.Contains(artifacts.put.Body, []byte(journal.capability)) || bytes.Contains(artifacts.put.Body, []byte(execution.leaseToken)) {
				t.Fatal("private authority entered an artifact")
			}
			if phase == "late captured" {
				before := len(db.calls)
				if _, err := gate.VisibleEvents(ctx, lease.Scope, input.EventIDs); err == nil || len(db.calls) != before {
					t.Fatal("captured append restored forward authority")
				}
			}
		})
	}
	if _, err := newRetentionJournalIndexVisibility(&retentionIndexDBFixture{}, migrations.RetentionAuditProfileChecksum(), migrations.RetentionJournalProfileChecksum(), &journalReceiptFixture{}); err == nil {
		t.Fatal("missing actual journal capability admitted")
	}
	if validRetentionRuntimeConfiguration(workerRuntimeConfig{RetentionJournalProfileChecksum: migrations.RetentionJournalProfileChecksum()}) {
		t.Fatal("orphan journal pin admitted")
	}
}
