package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestProductionSandboxSnapshotRetainsVersionedBindingBytes(t *testing.T) {
	lease, receipt, archive, oldBody := candidateRepositoryFixture(t)
	var wire map[string]any
	if err := json.Unmarshal(oldBody, &wire); err != nil {
		t.Fatal(err)
	}
	wire["schema"] = "runtime-candidate-snapshot-v2"
	wire["candidates"].([]any)[0].(map[string]any)["sandbox_id"] = "sandbox-a"
	body, err := json.MarshalIndent(wire, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	lease.ImplementationVersion = "runtime-correlation-v3"
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, body)}}
	repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive)
	if err != nil || !snapshot.ValidFor(lease.Scope, lease.BatchID, lease.Generation, sha256.Sum256(archive)) || !bytes.Equal(snapshot.Bytes(), body) {
		t.Fatal("v3 reader rejected the sandbox-bound snapshot", err)
	}
	if database.calls != 1 || database.statements[0] != `SELECT zasp_runtime_freeze_sandbox_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)` {
		t.Fatal("sandbox version reused the historical freeze function")
	}
	values := snapshot.Candidates()
	if !snapshot.HasSandboxBindings() || len(values) != 1 || !values[0].SandboxObserved || values[0].SandboxID != "sandbox-a" || values[0].SourceSensorID != fixtureID(t, 803) {
		t.Fatal("snapshot lost the semantic sandbox or its enrolled source")
	}
	values[0].SandboxID = "changed"
	if snapshot.Candidates()[0].SandboxID != "sandbox-a" {
		t.Fatal("caller changed immutable sandbox identity")
	}
}

func TestProductionSandboxSnapshotBindsSameBatchToArchivedSemanticIdentity(t *testing.T) {
	for _, name := range []string{"matching", "changed sandbox", "historical null", "foreign enrollment"} {
		t.Run(name, func(t *testing.T) {
			lease, oldReceipt, oldArchive, oldBody := candidateRepositoryFixture(t)
			var archiveWire, snapshotWire map[string]any
			if json.Unmarshal(oldArchive, &archiveWire) != nil || json.Unmarshal(oldBody, &snapshotWire) != nil {
				t.Fatal("invalid fixtures")
			}
			archiveWire["source"] = "otlp"
			event := archiveWire["events"].([]any)[0].(map[string]any)
			for _, key := range []string{"event_id", "class", "action", "workload_id"} {
				delete(event, key)
			}
			event["attributes"] = map[string]string{"event.id": "event-1", "event.class": "tool", "event.action": "invoke", "agent.id": fixtureID(t, 804).String(), "session.id": fixtureID(t, 805).String(), "task.id": "task-a", "tool.id": "tool-a", "sandbox.id": "sandbox-a", "trace.id": strings.Repeat("a", 32), "span.id": strings.Repeat("b", 16)}
			archive, err := json.Marshal(archiveWire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeArchivedBatch(lease.Scope, archive); err != nil {
				t.Fatal("invalid semantic archive", err)
			}
			receiptValue, err := DecodeStageReceipt(oldReceipt)
			if err != nil {
				t.Fatal(err)
			}
			receiptValue.ArchiveDigest = sha256.Sum256(archive)
			receiptValue.InputDigest = receiptValue.ArchiveDigest
			receipt, receiptDigest, _, err := EncodeStageReceipt(receiptValue)
			if err != nil {
				t.Fatal(err)
			}
			snapshotWire["schema"] = "runtime-candidate-snapshot-v2"
			snapshotWire["source_sensor_id"] = fixtureID(t, 803).String()
			snapshotWire["archive_digest"] = hex.EncodeToString(receiptValue.ArchiveDigest[:])
			snapshotWire["index_receipt_digest"] = hex.EncodeToString(receiptDigest[:])
			candidate := snapshotWire["candidates"].([]any)[0].(map[string]any)
			candidate["batch_id"], candidate["generation"] = lease.BatchID.String(), lease.Generation
			candidate["archive_digest"], candidate["index_receipt_digest"] = snapshotWire["archive_digest"], snapshotWire["index_receipt_digest"]
			candidate["sandbox_id"] = "sandbox-a"
			switch name {
			case "changed sandbox":
				candidate["sandbox_id"] = "sandbox-b"
			case "historical null":
				candidate["sandbox_id"] = nil
			case "foreign enrollment":
				candidate["source_sensor_id"] = fixtureID(t, 809).String()
			}
			body, err := json.Marshal(snapshotWire)
			if err != nil {
				t.Fatal(err)
			}
			lease.ImplementationVersion = "runtime-correlation-v3"
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, body)}}
			repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive)
			if (err == nil) != (name == "matching") {
				t.Fatal("same-batch semantic binding mismatch", err)
			}
			if name == "matching" && (len(snapshot.Candidates()) != 1 || snapshot.Candidates()[0].SandboxID != "sandbox-a") {
				t.Fatal("archived sandbox lost")
			}
		})
	}
}

func TestProductionSandboxSnapshotRequiresClosedVersionedIdentity(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		version string
		schema  string
		mutate  func(map[string]any)
		accept  bool
	}{
		{"historical unknown", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { c["sandbox_id"] = nil }, true},
		{"missing is not unknown", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { delete(c, "sandbox_id") }, false},
		{"empty is not historical", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { c["sandbox_id"] = "" }, false},
		{"oversize", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { c["sandbox_id"] = strings.Repeat("x", 257) }, false},
		{"wrong type", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { c["sandbox_id"] = 42 }, false},
		{"alias", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { delete(c, "sandbox_id"); c["Sandbox_ID"] = "sandbox-a" }, false},
		{"null provenance", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { c["source_sensor_id"] = nil }, false},
		{"unknown field", "runtime-correlation-v3", "runtime-candidate-snapshot-v2", func(c map[string]any) { c["sandbox_source"] = "caller-asserted" }, false},
		{"v2 cannot consume v2 snapshot", "runtime-correlation-v2", "runtime-candidate-snapshot-v2", nil, false},
		{"v3 cannot consume v1 snapshot", "runtime-correlation-v3", "runtime-candidate-snapshot-v1", func(c map[string]any) { delete(c, "sandbox_id") }, false},
		{"v1 snapshot cannot add sandbox", "runtime-correlation-v2", "runtime-candidate-snapshot-v1", nil, false},
		{"historical v2", "runtime-correlation-v2", "runtime-candidate-snapshot-v1", func(c map[string]any) { delete(c, "sandbox_id") }, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			lease, receipt, archive, oldBody := candidateRepositoryFixture(t)
			var wire map[string]any
			if err := json.Unmarshal(oldBody, &wire); err != nil {
				t.Fatal(err)
			}
			wire["schema"] = scenario.schema
			candidate := wire["candidates"].([]any)[0].(map[string]any)
			candidate["sandbox_id"] = "sandbox-a"
			if scenario.mutate != nil {
				scenario.mutate(candidate)
			}
			body, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			lease.ImplementationVersion = scenario.version
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{candidateEnvelope(t, body)}}
			repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, archive)
			if (err == nil) != scenario.accept {
				t.Fatal("snapshot acceptance mismatch", err)
			}
			if scenario.accept {
				if len(snapshot.Candidates()) != 1 || snapshot.Candidates()[0].SandboxObserved || snapshot.Candidates()[0].SandboxID != "" {
					t.Fatal("unknown history was discarded or invented")
				}
				if snapshot.HasSandboxBindings() != (scenario.version == "runtime-correlation-v3") {
					t.Fatal("snapshot version lost")
				}
			}
		})
	}
}
