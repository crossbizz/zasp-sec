package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

func TestRuntimeCorrelationV2CompositionRequiresCandidateReadiness(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2"} {
		for _, available := range []bool{false, true} {
			t.Run(version+"/available="+strconv.FormatBool(available), func(t *testing.T) {
				config := validRuntimeCorrelationConfig()
				config.RuntimeStageVersion = version
				database := &runtimeCandidateReadinessDatabase{available: available}
				executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
					t.Fatal("unready worker reached execution")
					return runtimeStageEffect{}, errRuntimeStageRetryable
				})
				dependencies, err := composeRuntimeStageWorkerRuntime(config, database, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageCorrelate, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
				if err != nil {
					t.Fatal(err)
				}
				err = dependencies.Ready(context.Background())
				wantReady := version == "runtime-correlation-v1" || available
				if (err == nil) != wantReady {
					t.Fatal("candidate authority didn't gate v2 readiness", err)
				}
				if !wantReady && dependencies.Processor.RunOnce(context.Background()) == nil {
					t.Fatal("unready worker accepted a poll")
				}
				if (database.candidateCalls > 0) != (version == "runtime-correlation-v2") || database.otherCalls != 0 {
					t.Fatal("readiness crossed version or execution boundary")
				}
			})
		}
	}
}

type runtimeCandidateReadinessDatabase struct {
	readyWorkerDatabase
	available                  bool
	candidateCalls, otherCalls int
	routingCalls               int
}

func (database *runtimeCandidateReadinessDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	if strings.Contains(statement, "zasp_production_runtime_correlation_routing_readiness") {
		database.routingCalls++
		return json.RawMessage(`{"ready":true}`), nil
	}
	if strings.Contains(statement, "zasp_production_runtime_candidate_authority_readiness") {
		database.candidateCalls++
		if !database.available {
			return nil, errors.New("candidate authority missing")
		}
		return json.RawMessage(`{"ready":true}`), nil
	}
	if strings.Contains(statement, "zasp_recovery_execution_readiness") {
		return json.RawMessage(`{"ready":true}`), nil
	}
	database.otherCalls++
	return nil, errors.New("unexpected database operation")
}

func TestRuntimeCorrelationCompositionSelectsImmutableClaimCapability(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2"} {
		t.Run(version, func(t *testing.T) {
			config := validRuntimeCorrelationConfig()
			config.RuntimeStageVersion = version
			database := &runtimeCandidateReadinessDatabase{available: true}
			executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
				t.Fatal("readiness executed work")
				return runtimeStageEffect{}, errRuntimeStageRetryable
			})
			dependencies, err := composeRuntimeStageWorkerRuntime(config, database, &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageCorrelate, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := dependencies.Ready(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := 0
			if version == "runtime-correlation-v2" {
				want = 1
			}
			if database.routingCalls != want {
				t.Fatal("composition did not bind versioned claim capability", database.routingCalls, want)
			}
		})
	}
}

func TestRuntimeCorrelationV2WorkerPreservesV1JobsAndReceipts(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2"} {
		t.Run(version, func(t *testing.T) {
			fixture := newFrozenExecutorFixture(t)
			fixture.execution.lease.ImplementationVersion = version
			candidateCalls := 0
			fixture.config.Candidates = runtimeCandidateAuthorityFunc(func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
				candidateCalls++
				return fixture.snapshot, nil
			})
			executor, err := newRuntimeCorrelationExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{fixture.execution.lease}}
			processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageCorrelate, ImplementationVersion: "runtime-correlation-v2", WorkerID: fixture.execution.workerID, LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: time.Second, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return fixture.execution.leaseToken, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); err != nil || len(authority.finishes) != 1 || authority.finishes[0].Outcome != runtimeevent.StageOutcomeSucceeded {
				t.Fatal("mixed-version worker stranded a known job", err)
			}
			receipt, err := runtimecorrelation.DecodeReceipt(fixture.artifacts.put.Body)
			if err != nil || receipt.ImplementationVersion != version || authority.finishes[0].Lease.ImplementationVersion != version {
				t.Fatal("job version was reinterpreted", err)
			}
			if version == "runtime-correlation-v1" {
				if candidateCalls != 0 || receipt.CandidateSnapshotDigest != ([sha256.Size]byte{}) {
					t.Fatal("v1 acquired new candidate semantics")
				}
				legacy := newFrozenExecutorFixture(t)
				legacy.config.ImplementationVersion, legacy.config.Candidates = version, nil
				legacy.execution.lease.ImplementationVersion = version
				original, err := newRuntimeCorrelationExecutor(legacy.config)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := original.Execute(context.Background(), legacy.execution.lease); err != nil || !bytes.Equal(legacy.artifacts.put.Body, fixture.artifacts.put.Body) {
					t.Fatal("v1 receipt bytes changed on upgraded worker", err)
				}
			} else if candidateCalls != 1 || receipt.CandidateSnapshotDigest != fixture.snapshot.Digest() {
				t.Fatal("v2 omitted its snapshot")
			}
		})
	}
}

func TestRuntimeCorrelationProductionFactoryBindsDatabaseCandidateAuthority(t *testing.T) {
	fixture := newFrozenExecutorFixture(t)
	fixture.config.Candidates = nil
	if _, err := newRuntimeCorrelationExecutorWithDatabase(fixture.config, nil); err == nil {
		t.Fatal("v2 missing production database accepted")
	}
	digest := fixture.snapshot.Digest()
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(fixture.snapshot.Bytes()), "sha256": hex.EncodeToString(digest[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	database := &runtimeCandidateCompositionDatabase{envelope: envelope}
	executor, err := newRuntimeCorrelationExecutorWithDatabase(fixture.config, database)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := executor.config.Candidates.(*runtimeevent.PostgresProductionPipelineRepository); !ok {
		t.Fatal("production factory didn't bind the correlation repository")
	}
	if _, err := executor.ExecuteAuthorized(context.Background(), fixture.execution); err != nil || database.calls != 1 || database.statement != "SELECT zasp_runtime_freeze_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)" || len(database.arguments) != 12 || database.arguments[5] != fixture.execution.workerID || database.arguments[6] != fixture.execution.leaseToken {
		t.Fatal("injected database didn't receive exact admission", err)
	}
	config := validRuntimeCorrelationConfig()
	config.RuntimeStageVersion = "runtime-correlation-v2"
	if !validWorkerRuntimeConfig(config) {
		t.Fatal("production config cannot consume v2 jobs")
	}
	config.RuntimeStageVersion = "runtime-correlation-v5"
	if validWorkerRuntimeConfig(config) {
		t.Fatal("unknown correlation implementation accepted")
	}
}

func TestRuntimeProjectionConsumesSnapshotBoundV2Receipt(t *testing.T) {
	fixture := newFrozenExecutorFixture(t)
	correlator, err := newRuntimeCorrelationExecutor(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	correlation, err := correlator.ExecuteAuthorized(context.Background(), fixture.execution)
	if err != nil {
		t.Fatal(err)
	}
	lease := fixture.execution.lease
	lease.Stage, lease.ImplementationVersion = runtimeevent.RuntimeStageProject, "runtime-projection-v1"
	lease.InputDigest = correlation.EffectDigest
	lease.InputVersionID = fixture.artifacts.output.VersionID
	lease.InputReference = runtimeTestReceiptReference(lease, fixture.artifacts.output.Reference.String())
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: fixture.artifacts.output, outputReference: runtimeTestReceiptReference(lease, mustProductID(t, "pid_00000096-0000-4000-8000-000000000096").String())}
	graph := &runtimeCorrelationGraphStoreStub{}
	projector, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: &runtimeArchivedReaderStub{body: fixture.archive}, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-projection-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := projector.Execute(context.Background(), lease)
	if err != nil || artifacts.putCalls != 1 || graph.calls != 1 || effect.EffectDigest == ([sha256.Size]byte{}) {
		t.Fatal("v2 receipt didn't reach the projection consumer", err)
	}
	projection, err := runtimeprojection.DecodeReceipt(artifacts.put.Body)
	if err != nil || projection.InputDigest != correlation.EffectDigest || len(projection.Items) != 1 || projection.Items[0].AgentID.IsZero() || projection.Items[0].SessionID.IsZero() {
		t.Fatal("projection lost v2 predecessor binding", err)
	}
	// A self-consistent artifact still cannot cross the stage's committed digest.
	lease.InputDigest = sha256.Sum256([]byte("other correlation result"))
	artifacts.putCalls, graph.calls = 0, 0
	if _, err := projector.Execute(context.Background(), lease); err == nil || artifacts.putCalls != 0 || graph.calls != 0 {
		t.Fatal("foreign v2 effect reached projection writes")
	}
}

type runtimeCandidateCompositionDatabase struct {
	envelope  json.RawMessage
	calls     int
	statement string
	arguments []any
}

func (database *runtimeCandidateCompositionDatabase) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	database.calls++
	database.statement = statement
	database.arguments = append([]any(nil), arguments...)
	return bytes.Clone(database.envelope), nil
}

var _ artifactstore.ObjectReferencingArtifactStore = (*runtimeCorrelationArtifactStoreStub)(nil)
