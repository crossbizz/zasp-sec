package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
)

func TestPreciseCorrelationFactoryBindsDatabaseAuthority(t *testing.T) {
	f := preciseExecutorFixture(t, 1)
	snapshot, err := f.config.PreciseCandidates.FreezePreciseCandidates(context.Background(), f.execution.lease, f.execution.workerID, f.execution.leaseToken, f.artifacts.input.Body, f.archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := snapshot.Digest()
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(snapshot.Bytes()), "sha256": hex.EncodeToString(digest[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	f.config.Candidates, f.config.PreciseCandidates = nil, nil
	if _, err := newRuntimeCorrelationExecutorWithDatabase(f.config, nil); err == nil {
		t.Fatal("factory accepted missing V4 database")
	}
	database := &runtimeCandidateCompositionDatabase{envelope: envelope}
	executor, err := newRuntimeCorrelationExecutorWithDatabase(f.config, database)
	if err != nil {
		t.Fatal("V4 database factory unavailable", err)
	}
	if _, err := executor.ExecuteAuthorized(context.Background(), f.execution); err != nil {
		t.Fatal(err)
	}
	if database.statement != `SELECT zasp_runtime_freeze_precise_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)` || len(database.arguments) != 12 || database.arguments[5] != f.execution.workerID || database.arguments[6] != f.execution.leaseToken {
		t.Fatal("factory lost bound precise admission")
	}
	receipt, err := runtimecorrelation.DecodePreciseReceipt(f.artifacts.put.Body)
	if err != nil || receipt.CandidateSnapshotDigest != digest || receipt.Results[0].Confidence.String() != "strong" {
		t.Fatal("factory lost admitted binding", err)
	}
	if nilWorkerDependency(executor.config.Candidates) {
		t.Fatal("factory omitted historical drain authority")
	}
}

func TestPreciseCorrelationFactoryRejectsInjectedAuthority(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3", "runtime-correlation-v4"} {
		t.Run(version, func(t *testing.T) {
			f := preciseExecutorFixture(t)
			f.config.ImplementationVersion = version
			f.config.Candidates = nil
			if _, err := newRuntimeCorrelationExecutorWithDatabase(f.config, &runtimeCandidateCompositionDatabase{}); err == nil {
				t.Fatal("factory accepted caller-supplied precise authority")
			}
		})
	}
}
