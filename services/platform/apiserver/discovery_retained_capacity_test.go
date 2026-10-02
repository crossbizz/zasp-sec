package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type retainedCapacityDatabase struct {
	discoveryCallDatabase
	available bool
	probeErr  error
}

func TestRetainedDiscoveryApplyDispatch(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	job := "pid_80000001-0000-4000-8000-000000000001"
	key := strings.Repeat("a", 40)
	input := ExecutionCompleteSnapshot{CompleteSnapshot: CompleteSnapshot{IntegrationID: job, SyncID: job, SnapshotID: job, Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/" + key, ManifestChecksum: make([]byte, 32), CollectedAt: time.Now().UTC().Add(-time.Second), CursorProvider: "aws", CursorValue: "done", Entities: json.RawMessage(`[]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`)}, JobID: job, Worker: "worker-01", LeaseToken: "lease-token-000000000001", ManifestKey: key, ManifestVersionID: "version-1", ManifestMediaType: "application/json", ManifestSchemaVersion: "manifest_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", ManifestSizeBytes: 100}
	wrapper := strings.Replace(postgresExecutionApplySnapshotSQL, "zasp_execution_apply_complete_snapshot", "zasp_temporal72.apply_retained_snapshot", 1)
	for _, mode := range []string{"current72", "absent72", "invalid72"} {
		t.Run(mode, func(t *testing.T) {
			d := &retainedCapacityDatabase{available: mode == "current72"}
			result, _ := json.Marshal(ExecutionSnapshotApplyResult{SnapshotApplyResult: SnapshotApplyResult{SnapshotID: job, CommittedAt: time.Now().UTC().Add(-time.Second)}, CandidateDigest: make([]byte, 32), ManifestVersionID: "version-1"})
			d.responses = map[string]json.RawMessage{wrapper: result, postgresExecutionApplySnapshotSQL: result}
			if mode == "invalid72" {
				d.probeErr = errors.New("invalid installed authority")
			}
			r := &DiscoveryExecutionRepository{database: d, authority: DiscoveryExecutionAuthorityWorker}
			_, err := r.ApplyCompleteSnapshot(context.Background(), identity.Scope, input)
			if mode == "invalid72" {
				if err == nil || len(d.queries) != 0 {
					t.Fatal("invalid72 apply fell back", err, d.queries)
				}
				return
			}
			want := wrapper
			if mode == "absent72" {
				want = postgresExecutionApplySnapshotSQL
			}
			if err != nil || len(d.queries) != 1 || d.queries[0] != want {
				t.Fatal("wrong retained apply route", err, d.queries)
			}
		})
	}
}

func (d *retainedCapacityDatabase) TemporalDiscoveryRetainedAvailable(context.Context, string) (bool, error) {
	return d.available, d.probeErr
}

func TestRetainedDiscoveryCapacityDispatch(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	job := "pid_80000001-0000-4000-8000-000000000001"
	wrapper := `SELECT zasp_temporal72.claim_retained_delivery($1,$2,$3,$4,$5,$6,$7)`
	for _, mode := range []string{"current72", "absent72", "invalid72"} {
		t.Run(mode, func(t *testing.T) {
			d := &retainedCapacityDatabase{available: mode == "current72"}
			d.responses = map[string]json.RawMessage{
				wrapper:                           json.RawMessage(`{"id":"` + job + `","state":"queued","attempt":0,"disposition":"busy"}`),
				postgresExecutionClaimDeliverySQL: json.RawMessage(`{"id":"` + job + `","state":"queued","attempt":0,"disposition":"busy"}`),
			}
			if mode == "invalid72" {
				d.probeErr = errors.New("invalid installed authority")
			}
			r := &DiscoveryExecutionRepository{database: d, authority: DiscoveryExecutionAuthorityWorker}
			claim, err := r.ClaimDiscoveryDelivery(context.Background(), identity.Scope, job, "worker-01", "lease-token-000000000001", 30)
			if mode == "invalid72" {
				if err == nil || len(d.queries) != 0 {
					t.Fatal("invalid72 fell back or dispatched", err, d.queries)
				}
				return
			}
			want := wrapper
			if mode == "absent72" {
				want = postgresExecutionClaimDeliverySQL
			}
			if err != nil || claim.Disposition != "busy" || len(d.queries) != 1 || d.queries[0] != want {
				t.Fatal("wrong retained claim route", claim, err, d.queries)
			}
		})
	}
}
