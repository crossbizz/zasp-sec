package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func preciseExecutorFixture(t *testing.T, counts ...int) frozenExecutorFixture {
	t.Helper()
	options := preciseExecutorFixtureOptions{}
	if len(counts) > 0 {
		options.eventCount, options.withCandidate = counts[0], true
	}
	return preciseExecutorFixtureWithOptions(t, options)
}

type preciseExecutorFixtureOptions struct {
	eventCount     int
	withCandidate  bool
	archiveVersion string
}

func preciseExecutorFixtureWithOptions(t *testing.T, options preciseExecutorFixtureOptions) frozenExecutorFixture {
	t.Helper()
	f := newFrozenExecutorFixture(t)
	f.config.ImplementationVersion = "runtime-correlation-v4"
	f.execution.lease.ImplementationVersion = "runtime-correlation-v4"
	lineage := runtimelineage.PreciseObservation{Observation: runtimelineage.Observation{Profile: "kubernetes-container-v2", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64)}, SourceEventTime: "2026-09-10T10:00:00.000000002Z"}
	event := sensoradapter.PreciseRuntimeEvent{RuntimeEvent: sensoradapter.RuntimeEvent{EventID: "event-1", Class: "process", Action: "exec", WorkloadID: "runtime-a", EventTime: "2026-09-10T10:00:00.000Z", EvidenceID: "pid_00000008-0000-4000-8000-000000000008"}, ObservedLineage: lineage}
	events := []sensoradapter.PreciseRuntimeEvent{event}
	if options.eventCount > 0 {
		events = make([]sensoradapter.PreciseRuntimeEvent, options.eventCount)
		for i := range events {
			events[i] = event
			events[i].EventID = fmt.Sprintf("event-%d", i)
		}
	}
	archive, err := json.Marshal(struct {
		Version string                              `json:"version"`
		Source  string                              `json:"source"`
		Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}{"runtime-archive-v2", "tetragon", events})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeevent.DecodePreciseArchivedBatch(f.execution.lease.Scope, archive); err != nil {
		t.Fatal(err)
	}
	index, err := runtimeevent.DecodeStageReceipt(f.artifacts.input.Body)
	if err != nil {
		t.Fatal(err)
	}
	index.ImplementationVersion = "runtime-index-v2"
	if options.archiveVersion != "" {
		index.ArchiveVersionID = options.archiveVersion
		index.InputVersionID = options.archiveVersion
	}
	index.ArchiveDigest = sha256.Sum256(archive)
	index.InputDigest = index.ArchiveDigest
	body, digest, ref, err := runtimeevent.EncodeStageReceipt(index)
	if err != nil {
		t.Fatal(err)
	}
	f.artifacts.input.Body, f.artifacts.input.SHA256, f.artifacts.input.Size = body, digest, int64(len(body))
	f.artifacts.input.Locator.Reference = ref
	f.execution.lease.InputReference = runtimeTestReceiptReference(f.execution.lease, ref.String())
	f.artifacts.inputReference = f.execution.lease.InputReference
	var wire map[string]any
	if err := json.Unmarshal(f.snapshot.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	wire["schema"] = "runtime-candidate-snapshot-v3"
	wire["runtime_sensor_id"] = wire["source_sensor_id"]
	wire["archive_digest"] = hex.EncodeToString(index.ArchiveDigest[:])
	wire["index_receipt_digest"] = hex.EncodeToString(digest[:])
	if options.withCandidate {
		semanticLineage := lineage.Observation
		semanticLineage.Profile = "kubernetes-container-v1"
		wire["candidates"] = []any{map[string]any{"batch_id": "pid_00000098-0000-4000-8000-000000000098", "generation": 1, "event_ordinal": 1, "source_sensor_id": "pid_00000097-0000-4000-8000-000000000097", "agent_id": "pid_79000002-0000-4000-8000-000000000002", "session_id": "pid_79000003-0000-4000-8000-000000000003", "archive_digest": strings.Repeat("b", 64), "index_receipt_digest": strings.Repeat("c", 64), "observed_lineage": semanticLineage, "event_time": "2026-09-10T10:00:01.000Z", "sandbox_id": strings.Repeat("<", 256)}}
	}
	snapshot, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	sd := sha256.Sum256(snapshot)
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(snapshot), "sha256": hex.EncodeToString(sd[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := runtimeevent.NewPostgresProductionPipelineRepository(frozenExecutorDatabase{envelope}, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	f.config.PreciseCandidates = repo
	f.config.Reader = &runtimeArchivedReaderStub{body: archive}
	f.archive = archive
	return f
}

type preciseCandidateAuthorityFunc func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.PreciseFrozenCandidateSnapshot, error)

func TestPreciseCorrelationExecutorReplaysOnlyUnderNewLeaseWindow(t *testing.T) {
	for _, renew := range []bool{false, true} {
		t.Run(fmt.Sprint(renew), func(t *testing.T) {
			f := preciseExecutorFixture(t)
			original := f.config.PreciseCandidates
			f.execution.renewal = &runtimeStageLeaseRenewal{expiresAt: f.execution.lease.LeaseExpiresAt}
			calls := 0
			f.config.PreciseCandidates = preciseCandidateAuthorityFunc(func(ctx context.Context, lease runtimeevent.StageLease, worker, token string, receipt, archive []byte) (runtimeevent.PreciseFrozenCandidateSnapshot, error) {
				calls++
				if calls == 1 {
					if renew {
						f.execution.renewal.mu.Lock()
						f.execution.renewal.expiresAt = lease.LeaseExpiresAt.Add(time.Minute)
						f.execution.renewal.mu.Unlock()
					}
					return runtimeevent.PreciseFrozenCandidateSnapshot{}, runtimeevent.ErrProductionPipelineUnavailable
				}
				if calls != 2 || !lease.LeaseExpiresAt.After(f.execution.lease.LeaseExpiresAt) {
					t.Fatal("replay without newer lease")
				}
				return original.FreezePreciseCandidates(ctx, lease, worker, token, receipt, archive)
			})
			executor, err := newRuntimeCorrelationExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = executor.ExecuteAuthorized(context.Background(), f.execution)
			if renew {
				if err != nil || calls != 2 || f.graph.calls != 1 || f.artifacts.putCalls != 1 {
					t.Fatal("renewed replay failed", err)
				}
			} else if err != errRuntimeStageRetryable || calls != 1 || f.graph.calls != 0 || f.artifacts.putCalls != 0 {
				t.Fatal("unconfirmed retry wrote effects", err)
			}
		})
	}
}

func TestPreciseCorrelationExecutorRejectsOldIndexAndOldWorker(t *testing.T) {
	for _, scenario := range []string{"old index", "old worker", "missing token", "missing worker"} {
		t.Run(scenario, func(t *testing.T) {
			f := preciseExecutorFixture(t)
			switch scenario {
			case "old index":
				index, err := runtimeevent.DecodeStageReceipt(f.artifacts.input.Body)
				if err != nil {
					t.Fatal(err)
				}
				index.ImplementationVersion = "runtime-index-v1"
				body, digest, ref, err := runtimeevent.EncodeStageReceipt(index)
				if err != nil {
					t.Fatal(err)
				}
				f.artifacts.input.Body, f.artifacts.input.Size, f.artifacts.input.SHA256 = body, int64(len(body)), digest
				f.artifacts.input.Locator.Reference = ref
				f.execution.lease.InputReference = runtimeTestReceiptReference(f.execution.lease, ref.String())
				f.artifacts.inputReference = f.execution.lease.InputReference
			case "old worker":
				f.config.ImplementationVersion = "runtime-correlation-v3"
			case "missing token":
				f.execution.leaseToken = ""
			case "missing worker":
				f.execution.workerID = ""
			}
			executor, err := newRuntimeCorrelationExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = executor.ExecuteAuthorized(context.Background(), f.execution)
			if err != errRuntimeStageMalformed || f.graph.calls != 0 || f.artifacts.putCalls != 0 {
				t.Fatal("incompatible execution wrote effects", err)
			}
		})
	}
}

func TestPreciseCorrelationExecutorPreflightsReceiptBeforeGraph(t *testing.T) {
	f := preciseExecutorFixture(t, 1000)
	// Independently prove this is a valid, attributed correlation before checking
	// the write boundary. A malformed archive would not exercise receipt size.
	snapshot, err := f.config.PreciseCandidates.FreezePreciseCandidates(context.Background(), f.execution.lease, f.execution.workerID, f.execution.leaseToken, f.artifacts.input.Body, f.archive)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtimecorrelation.CorrelatePreciseFrozen(runtimecorrelation.Batch{Scope: f.execution.lease.Scope, BatchID: f.execution.lease.BatchID, Generation: f.execution.lease.Generation, ArchiveDigest: sha256.Sum256(f.archive), Body: f.archive}, snapshot)
	if err != nil || len(result.Results) != 1000 || result.Results[0].Confidence.String() != "strong" {
		t.Fatal("invalid large correlation fixture", err)
	}
	executor, err := newRuntimeCorrelationExecutor(f.config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.ExecuteAuthorized(context.Background(), f.execution)
	if err != errRuntimeStageMalformed || f.graph.calls != 0 || f.artifacts.putCalls != 0 {
		t.Fatal("receipt rejection followed graph side effects", err, f.graph.calls, f.artifacts.putCalls)
	}
}

func (f preciseCandidateAuthorityFunc) FreezePreciseCandidates(ctx context.Context, lease runtimeevent.StageLease, worker, token string, receipt, archive []byte) (runtimeevent.PreciseFrozenCandidateSnapshot, error) {
	return f(ctx, lease, worker, token, receipt, archive)
}

func TestPreciseCorrelationExecutorRejectsAuthorityFailuresBeforeEffects(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		failure error
		want    error
	}{
		{"denied", runtimeevent.ErrCandidateSnapshotDenied, errRuntimeStageDenied},
		{"overflow", runtimeevent.ErrCandidateSnapshotOverflow, errRuntimeStageMalformed},
		{"unavailable", runtimeevent.ErrProductionPipelineUnavailable, errRuntimeStageRetryable},
		{"invalid", runtimeevent.ErrProductionPipeline, errRuntimeStageMalformed},
		{"provider", errors.New("private provider detail"), errWorkerExecution},
		{"empty snapshot", nil, errRuntimeStageMalformed},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := preciseExecutorFixture(t)
			f.config.PreciseCandidates = preciseCandidateAuthorityFunc(func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.PreciseFrozenCandidateSnapshot, error) {
				return runtimeevent.PreciseFrozenCandidateSnapshot{}, scenario.failure
			})
			executor, err := newRuntimeCorrelationExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(context.Background(), f.execution)
			if err != scenario.want || effect != (runtimeStageEffect{}) || f.graph.calls != 0 || f.artifacts.putCalls != 0 {
				t.Fatal("authority failure escaped boundary", err)
			}
		})
	}
}

func TestPreciseCorrelationExecutorPreservesHistoricalJobs(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3"} {
		t.Run(version, func(t *testing.T) {
			f := newFrozenExecutorFixture(t)
			if version == "runtime-correlation-v3" {
				f = sandboxExecutorFixture(t)
			}
			f.execution.lease.ImplementationVersion = version
			f.config.ImplementationVersion = version
			old, err := newRuntimeCorrelationExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := old.ExecuteAuthorized(context.Background(), f.execution); err != nil {
				t.Fatal(err)
			}
			want := bytes.Clone(f.artifacts.put.Body)
			f.config.ImplementationVersion = "runtime-correlation-v4"
			f.config.PreciseCandidates = preciseCandidateAuthorityFunc(func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.PreciseFrozenCandidateSnapshot, error) {
				t.Fatal("historical job used precise authority")
				return runtimeevent.PreciseFrozenCandidateSnapshot{}, nil
			})
			newer, err := newRuntimeCorrelationExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newer.ExecuteAuthorized(context.Background(), f.execution); err != nil || !bytes.Equal(want, f.artifacts.put.Body) {
				t.Fatal("historical bytes changed", err)
			}
		})
	}
}

func TestPreciseCorrelationExecutorCancellationFencesEffects(t *testing.T) {
	for _, phase := range []string{"freeze", "graph", "receipt"} {
		t.Run(phase, func(t *testing.T) {
			f := preciseExecutorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch phase {
			case "freeze":
				original := f.config.PreciseCandidates
				f.config.PreciseCandidates = preciseCandidateAuthorityFunc(func(ctx context.Context, lease runtimeevent.StageLease, worker, token string, receipt, archive []byte) (runtimeevent.PreciseFrozenCandidateSnapshot, error) {
					snapshot, err := original.FreezePreciseCandidates(ctx, lease, worker, token, receipt, archive)
					cancel()
					return snapshot, err
				})
			case "graph":
				f.config.Graph = frozenGraphFunc(func(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
					result, err := f.graph.ApplySnapshot(ctx, snapshot)
					cancel()
					return result, err
				})
			case "receipt":
				f.config.Receipts = frozenCancelArtifactStore{f.artifacts, cancel}
			}
			executor, err := newRuntimeCorrelationExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, f.execution)
			if err != errRuntimeStageRetryable || effect != (runtimeStageEffect{}) {
				t.Fatal("canceled execution completed", err)
			}
			wantGraph, wantPut := 1, 0
			if phase == "freeze" {
				wantGraph = 0
			}
			if phase == "receipt" {
				wantPut = 1
			}
			if f.graph.calls != wantGraph || f.artifacts.putCalls != wantPut {
				t.Fatal("crossed cancellation boundary")
			}
		})
	}
}

func TestPreciseCorrelationExecutorConsumesV2AndWritesV4(t *testing.T) {
	f := preciseExecutorFixture(t)
	executor, err := newRuntimeCorrelationExecutor(f.config)
	if err != nil {
		t.Fatal("V4 executor unavailable", err)
	}
	effect, err := executor.ExecuteAuthorized(context.Background(), f.execution)
	if err != nil || !validRuntimeStageEffect(effect) {
		t.Fatal("precise execution failed", err)
	}
	receipt, err := runtimecorrelation.DecodePreciseReceipt(f.artifacts.put.Body)
	if err != nil || len(receipt.Results) != 1 || receipt.Results[0].Confidence.String() != "unattributed" || receipt.CandidateSnapshotDigest == ([sha256.Size]byte{}) || receipt.EffectDigest != effect.EffectDigest {
		t.Fatal("V4 receipt lost authority", err)
	}
	if f.graph.calls != 1 || f.artifacts.putCalls != 1 {
		t.Fatal("missing durable effects")
	}
	if _, err := runtimecorrelation.DecodeReceipt(f.artifacts.put.Body); err == nil {
		t.Fatal("old reader consumed V4")
	}
}

func TestPreciseCorrelationExecutorWritesAdmittedStrongBinding(t *testing.T) {
	f := preciseExecutorFixture(t, 1)
	executor, err := newRuntimeCorrelationExecutor(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteAuthorized(context.Background(), f.execution); err != nil {
		t.Fatal(err)
	}
	receipt, err := runtimecorrelation.DecodePreciseReceipt(f.artifacts.put.Body)
	if err != nil || len(receipt.Results) != 1 {
		t.Fatal("strong receipt missing", err)
	}
	r := receipt.Results[0]
	if r.Confidence.String() != "strong" || r.AgentID.String() != "pid_79000002-0000-4000-8000-000000000002" || r.SessionID.String() != "pid_79000003-0000-4000-8000-000000000003" || r.SandboxSourceSensorID.String() != "pid_00000097-0000-4000-8000-000000000097" || r.SandboxID != strings.Repeat("<", 256) {
		t.Fatal("admitted binding lost")
	}
	if f.graph.calls != 1 || f.artifacts.putCalls != 1 {
		t.Fatal("missing strong effects")
	}
}

func TestPreciseCorrelationExecutorRefusesMissingAuthorityAndUnprivilegedExecution(t *testing.T) {
	f := preciseExecutorFixture(t)
	f.config.PreciseCandidates = nil
	if _, err := newRuntimeCorrelationExecutor(f.config); err == nil {
		t.Fatal("missing precise authority accepted")
	}
	f = preciseExecutorFixture(t)
	executor, err := newRuntimeCorrelationExecutor(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), f.execution.lease); err != errRuntimeStageMalformed {
		t.Fatal("unprivileged V4 execution accepted", err)
	}
	if f.graph.calls != 0 || f.artifacts.putCalls != 0 {
		t.Fatal("unprivileged effects")
	}
}
