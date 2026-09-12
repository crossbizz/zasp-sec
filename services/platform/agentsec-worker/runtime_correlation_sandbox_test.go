package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func sandboxExecutorFixture(t *testing.T) frozenExecutorFixture {
	t.Helper()
	fixture := newFrozenExecutorFixture(t)
	fixture.config.ImplementationVersion = "runtime-correlation-v3"
	fixture.execution.lease.ImplementationVersion = "runtime-correlation-v3"
	var wire map[string]any
	if err := json.Unmarshal(fixture.snapshot.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	wire["schema"] = "runtime-candidate-snapshot-v2"
	body, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(body), "sha256": hex.EncodeToString(digest[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(frozenExecutorDatabase{envelope}, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	fixture.config.Candidates = repository
	fixture.snapshot, err = repository.FreezeCandidates(context.Background(), fixture.execution.lease, fixture.execution.workerID, fixture.execution.leaseToken, fixture.artifacts.input.Body, fixture.archive)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestSandboxCorrelationWorkerDrainsVersionsWithoutReinterpretingReceipts(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3"} {
		t.Run(version, func(t *testing.T) {
			fixture := newFrozenExecutorFixture(t)
			if version == "runtime-correlation-v3" {
				fixture = sandboxExecutorFixture(t)
			}
			fixture.config.ImplementationVersion = "runtime-correlation-v3"
			fixture.execution.lease.ImplementationVersion = version
			executor, err := newRuntimeCorrelationExecutor(fixture.config)
			if err != nil {
				t.Fatal("compatible v3 worker rejected", err)
			}
			authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{fixture.execution.lease}}
			processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageCorrelate, ImplementationVersion: "runtime-correlation-v3", WorkerID: fixture.execution.workerID, LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: time.Second, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return fixture.execution.leaseToken, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); err != nil || len(authority.finishes) != 1 || authority.finishes[0].Outcome != runtimeevent.StageOutcomeSucceeded {
				t.Fatal("compatible job did not complete", authority.finishes, err)
			}
			receipt, err := runtimecorrelation.DecodeReceipt(fixture.artifacts.put.Body)
			if err != nil || receipt.ImplementationVersion != version || authority.finishes[0].Lease.ImplementationVersion != version {
				t.Fatal("worker reinterpreted job version", err)
			}
			if version == "runtime-correlation-v3" {
				if receipt.CandidateSnapshotDigest != fixture.snapshot.Digest() || len(receipt.Results) != 1 || receipt.Results[0].Confidence.String() != "exact" || receipt.Results[0].SandboxID != "sandbox-a" || receipt.Results[0].SandboxSourceSensorID.String() != "pid_00000095-0000-4000-8000-000000000095" {
					t.Fatal("v3 receipt lost sandbox provenance")
				}
			} else {
				old := newFrozenExecutorFixture(t)
				old.config.ImplementationVersion = version
				old.execution.lease.ImplementationVersion = version
				if version == "runtime-correlation-v1" {
					old.config.Candidates = nil
				}
				original, err := newRuntimeCorrelationExecutor(old.config)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := original.ExecuteAuthorized(context.Background(), old.execution); err != nil || !bytes.Equal(old.artifacts.put.Body, fixture.artifacts.put.Body) {
					t.Fatal("historical receipt bytes changed", err)
				}
			}
		})
	}
}

func TestSandboxCorrelationExecutorRequiresAuthorityAndMatchingSnapshot(t *testing.T) {
	for _, scenario := range []string{"unprivileged entry", "v1 snapshot", "missing worker", "missing token", "future version"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := sandboxExecutorFixture(t)
			if scenario == "v1 snapshot" {
				fixture.config.Candidates = runtimeCandidateAuthorityFunc(func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
					return newFrozenExecutorFixture(t).snapshot, nil
				})
			}
			executor, err := newRuntimeCorrelationExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing worker":
				fixture.execution.workerID = ""
			case "missing token":
				fixture.execution.leaseToken = ""
			case "future version":
				fixture.execution.lease.ImplementationVersion = "runtime-correlation-v4"
			}
			if scenario == "unprivileged entry" {
				_, err = executor.Execute(context.Background(), fixture.execution.lease)
			} else {
				_, err = executor.ExecuteAuthorized(context.Background(), fixture.execution)
			}
			if !errors.Is(err, errRuntimeStageMalformed) || fixture.graph.calls != 0 || fixture.artifacts.putCalls != 0 {
				t.Fatal("unbound v3 execution produced effects", err)
			}
		})
	}
}

func TestSandboxCorrelationProductionFactoryBindsVersionedAdmission(t *testing.T) {
	fixture := sandboxExecutorFixture(t)
	fixture.config.Candidates = nil
	if _, err := newRuntimeCorrelationExecutorWithDatabase(fixture.config, nil); err == nil {
		t.Fatal("v3 factory accepted missing database")
	}
	digest := fixture.snapshot.Digest()
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(fixture.snapshot.Bytes()), "sha256": hex.EncodeToString(digest[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	database := &runtimeCandidateCompositionDatabase{envelope: envelope}
	executor, err := newRuntimeCorrelationExecutorWithDatabase(fixture.config, database)
	if err != nil {
		t.Fatal("v3 production factory unavailable", err)
	}
	if _, err := executor.ExecuteAuthorized(context.Background(), fixture.execution); err != nil || database.statement != `SELECT zasp_runtime_freeze_sandbox_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)` || len(database.arguments) != 12 || database.arguments[5] != fixture.execution.workerID || database.arguments[6] != fixture.execution.leaseToken {
		t.Fatal("v3 factory lost exact sandbox admission", err)
	}
}

func TestSandboxCorrelationCancellationCannotProduceCompletion(t *testing.T) {
	for _, phase := range []string{"freeze", "graph", "receipt"} {
		t.Run(phase, func(t *testing.T) {
			fixture := sandboxExecutorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch phase {
			case "freeze":
				fixture.config.Candidates = runtimeCandidateAuthorityFunc(func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
					cancel()
					return fixture.snapshot, nil
				})
			case "graph":
				fixture.config.Graph = frozenGraphFunc(func(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
					result, err := fixture.graph.ApplySnapshot(ctx, snapshot)
					cancel()
					return result, err
				})
			case "receipt":
				fixture.config.Receipts = frozenCancelArtifactStore{fixture.artifacts, cancel}
			}
			executor, err := newRuntimeCorrelationExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, fixture.execution)
			if !errors.Is(err, errRuntimeStageRetryable) || effect != (runtimeStageEffect{}) {
				t.Fatal("canceled v3 effect reported as complete", err)
			}
			wantGraph, wantPut := 1, 0
			if phase == "freeze" {
				wantGraph = 0
			}
			if phase == "receipt" {
				wantPut = 1
			}
			if fixture.graph.calls != wantGraph || fixture.artifacts.putCalls != wantPut {
				t.Fatal("v3 execution crossed cancellation boundary", fixture.graph.calls, fixture.artifacts.putCalls)
			}
		})
	}
}

func TestSandboxCorrelationWorkerRetainsInferredBindingAndClearsAmbiguity(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		fixture := sandboxExecutorFixture(t)
		var archiveWire, snapshotWire map[string]any
		if json.Unmarshal(runtimeIndexBody(fixture.execution.lease), &archiveWire) != nil || json.Unmarshal(fixture.snapshot.Bytes(), &snapshotWire) != nil {
			t.Fatal("invalid fixture")
		}
		lineage := map[string]any{"profile": "kubernetes-container-v1", "cluster_uid": "12345678-1234-1234-1234-123456789001", "node_uid": "12345678-1234-1234-1234-123456789002", "boot_id": "12345678-1234-1234-1234-123456789003", "pod_uid": "12345678-1234-1234-1234-123456789004", "container_id": "containerd://" + strings.Repeat("a", 64)}
		archiveWire["events"].([]any)[0].(map[string]any)["observed_lineage"] = lineage
		archive, err := json.Marshal(archiveWire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtimeevent.DecodeArchivedBatch(fixture.execution.lease.Scope, archive); err != nil {
			t.Fatal("invalid runtime archive fixture", err)
		}
		index, err := runtimeevent.DecodeStageReceipt(fixture.artifacts.input.Body)
		if err != nil {
			t.Fatal(err)
		}
		index.ArchiveDigest = sha256.Sum256(archive)
		index.InputDigest = index.ArchiveDigest
		indexBody, indexDigest, indexReference, err := runtimeevent.EncodeStageReceipt(index)
		if err != nil {
			t.Fatal(err)
		}
		fixture.artifacts.input.Body, fixture.artifacts.input.SHA256, fixture.artifacts.input.Size = indexBody, indexDigest, int64(len(indexBody))
		fixture.artifacts.input.Locator.Reference = indexReference
		fixture.execution.lease.InputReference = runtimeTestReceiptReference(fixture.execution.lease, indexReference.String())
		fixture.artifacts.inputReference = fixture.execution.lease.InputReference
		snapshotWire["archive_digest"], snapshotWire["index_receipt_digest"] = hex.EncodeToString(index.ArchiveDigest[:]), hex.EncodeToString(indexDigest[:])
		snapshotWire["runtime_sensor_id"] = snapshotWire["source_sensor_id"]
		candidates := []any{}
		count := 1
		if ambiguous {
			count = 2
		}
		for ordinal := 1; ordinal <= count; ordinal++ {
			sandbox := "sandbox-a"
			if ordinal == 2 {
				sandbox = "sandbox-b"
			}
			candidates = append(candidates, map[string]any{"batch_id": "pid_00000098-0000-4000-8000-000000000098", "generation": 1, "event_ordinal": ordinal, "source_sensor_id": "pid_00000097-0000-4000-8000-000000000097", "agent_id": "pid_79000002-0000-4000-8000-000000000002", "session_id": "pid_79000003-0000-4000-8000-000000000003", "archive_digest": strings.Repeat("b", 64), "index_receipt_digest": strings.Repeat("c", 64), "observed_lineage": lineage, "event_time": "2026-08-20T12:00:00.000Z", "sandbox_id": sandbox})
		}
		snapshotWire["candidates"] = candidates
		snapshotBody, err := json.Marshal(snapshotWire)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(snapshotBody)
		envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(snapshotBody), "sha256": hex.EncodeToString(digest[:]), "replayed": false})
		if err != nil {
			t.Fatal(err)
		}
		fixture.config.Candidates = nil
		fixture.config.Reader = &runtimeArchivedReaderStub{body: archive}
		executor, err := newRuntimeCorrelationExecutorWithDatabase(fixture.config, &runtimeCandidateCompositionDatabase{envelope: envelope})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := executor.ExecuteAuthorized(context.Background(), fixture.execution); err != nil {
			t.Fatal("runtime sandbox worker failed", err)
		}
		receipt, err := runtimecorrelation.DecodeReceipt(fixture.artifacts.put.Body)
		if err != nil || receipt.ImplementationVersion != "runtime-correlation-v3" || receipt.CandidateSnapshotDigest != digest || len(receipt.Results) != 1 {
			t.Fatal("inferred receipt binding", err)
		}
		result := receipt.Results[0]
		if ambiguous {
			if result.Confidence.String() != "probable" || !result.AgentID.IsZero() || !result.SessionID.IsZero() || result.SandboxID != "" || !result.SandboxSourceSensorID.IsZero() {
				t.Fatal("ambiguous worker receipt invented identity")
			}
		} else if result.Confidence.String() != "strong" || result.AgentID.String() != "pid_79000002-0000-4000-8000-000000000002" || result.SessionID.String() != "pid_79000003-0000-4000-8000-000000000003" || result.SandboxID != "sandbox-a" || result.SandboxSourceSensorID.String() != "pid_00000097-0000-4000-8000-000000000097" {
			t.Fatal("worker receipt lost inferred sandbox binding")
		}
	}
}

func TestSandboxCorrelationCompositionNegotiatesHealthy49And50(t *testing.T) {
	for _, schema := range []int{49, 50} {
		t.Run(map[int]string{49: "prestage49", 50: "active50"}[schema], func(t *testing.T) {
			config := validRuntimeCorrelationConfig()
			config.RuntimeStageVersion = "runtime-correlation-v3"
			fixture := sandboxExecutorFixture(t)
			executor, err := newRuntimeCorrelationExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			database := &sandboxWorkerRoutingDatabase{schema: schema}
			dependencies, err := composeRuntimeStageWorkerRuntime(config, database, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageCorrelate, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
			if err != nil {
				t.Fatal("v3 worker cannot pre-stage", err)
			}
			if err := dependencies.Ready(context.Background()); err != nil {
				t.Fatal("v3 readiness rejected healthy release", err)
			}
			if err := dependencies.Processor.RunOnce(context.Background()); err != nil {
				t.Fatal("v3 poll rejected healthy release", err)
			}
			want := `SELECT zasp_runtime_claim_correlation_v3($1,$2,$3,$4)`
			if schema == 49 {
				want = `SELECT zasp_runtime_claim_correlation_v2($1,$2,$3,$4)`
			}
			if database.claim != want || database.claims != 1 || database.sandboxChecks < 2 {
				t.Fatal("poll did not negotiate pinned immutable capability", database.claim, database.claims, database.sandboxChecks)
			}
		})
	}
}

type sandboxWorkerRoutingDatabase struct {
	readyWorkerDatabase
	schema                int
	claim                 string
	claims, sandboxChecks int
}

func (database *sandboxWorkerRoutingDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	switch statement {
	case `SELECT jsonb_build_object('ready',zasp_production_runtime_sandbox_binding_readiness($1,$2) AND zasp_runtime_principal_ready($3))`:
		database.sandboxChecks++
		if !reflect.DeepEqual(args, []any{migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint(), "zasp_runtime_correlation_worker"}) {
			return nil, errors.New("sandbox release pin mismatch")
		}
		if database.schema == 49 {
			return nil, &pgconn.PgError{Code: "42883"}
		}
		return json.RawMessage(`{"ready":true}`), nil
	case `SELECT jsonb_build_object('ready',zasp_production_runtime_correlation_routing_readiness($1,$2) AND zasp_runtime_principal_ready($3))`:
		if database.schema != 49 || !reflect.DeepEqual(args, []any{migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint(), "zasp_runtime_correlation_worker"}) {
			return nil, errors.New("unexpected fallback or predecessor pin mismatch")
		}
		return json.RawMessage(`{"ready":true}`), nil
	case `SELECT zasp_runtime_claim_correlation_v3($1,$2,$3,$4)`, `SELECT zasp_runtime_claim_correlation_v2($1,$2,$3,$4)`:
		database.claim = statement
		database.claims++
		return json.RawMessage(`[]`), nil
	default:
		return nil, errors.New("unexpected sandbox composition operation")
	}
}
