package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

const preciseFreezeSQL = `SELECT zasp_runtime_freeze_precise_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

func preparePreciseCandidateArchive(t *testing.T, body []byte) []byte {
	t.Helper()
	var input struct {
		Source string
		Events []map[string]json.RawMessage
	}
	if err := json.Unmarshal(body, &input); err != nil {
		t.Fatal(err)
	}
	events := make([]sensoradapter.PreciseRuntimeEvent, len(input.Events))
	for i, raw := range input.Events {
		event := &events[i]
		for key, dest := range map[string]*string{"event_id": &event.EventID, "class": &event.Class, "action": &event.Action, "workload_id": &event.WorkloadID, "event_time": &event.EventTime, "evidence_id": &event.EvidenceID} {
			if err := json.Unmarshal(raw[key], dest); err != nil {
				t.Fatal(err)
			}
		}
		var lineage runtimelineage.Observation
		if err := json.Unmarshal(raw["observed_lineage"], &lineage); err != nil {
			t.Fatal(err)
		}
		lineage.Profile = "kubernetes-container-v2"
		event.ObservedLineage = runtimelineage.PreciseObservation{Observation: lineage, SourceEventTime: "2026-09-10T10:00:01.000000001Z"}
	}
	encoded, err := json.Marshal(struct {
		Version string                              `json:"version"`
		Source  string                              `json:"source"`
		Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}{"runtime-archive-v2", input.Source, events})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeevent.DecodePreciseArchivedBatch(fixtureRequestIdentity(t).Scope, encoded); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRuntimePrecisionFreezeUsesExactWindowAndRetainsReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	for _, name := range []string{"runtime_precision.sql", "runtime_precision_candidates.sql"} {
		sql, err := os.ReadFile("../migrations/sql/fragments/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	seedSemantic := func(ordinal int, when string) []any {
		return seedRuntimeCandidateBatchVersion(t, ctx, admin, ordinal, sandboxSemantic, "otlp", ordinal, 1, "runtime-correlation-v3", func(event map[string]any) {
			event["event_time"] = when
			event["observed_lineage"].(map[string]string)["process_start_time"] = "2026-09-10T09:50:00Z"
		})
	}
	lower := seedSemantic(1, "2026-09-10T09:55:01.000Z")
	upper := seedSemantic(2, "2026-09-10T10:05:01.000Z")
	freezeSandboxFixture(t, ctx, worker, lower)
	freezeSandboxFixture(t, ctx, worker, upper)
	contract := candidateFixtureWire{schema: "runtime-event-v2", archive: "runtime-archive-v2", index: "runtime-index-v2", prepare: preparePreciseCandidateArchive}
	seedTarget := func(ordinal int, wire candidateFixtureWire) []any {
		return seedRuntimeCandidateBatchInput(t, ctx, admin, ordinal, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v4", func(event map[string]any) {
			event["observed_lineage"].(map[string]string)["process_start_time"] = "2026-09-10T09:50:00Z"
		}, true, wire)
	}
	target := seedTarget(3, contract)
	var ignored []byte
	if err := worker.QueryRow(ctx, preciseFreezeSQL, target...).Scan(&ignored); err == nil {
		t.Fatal("ungranted worker executed draft")
	} else {
		requireSandboxSQLState(t, err, "42501")
	}
	if _, err := admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION public.zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) TO zasp_runtime_correlation_worker`); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	correlations := map[string]runtimecorrelation.CorrelatedBatch{}
	correlationReceipts := map[string][]byte{}
	projections := map[string]runtimeprojection.ProjectedBatch{}
	freeze := func(args []any) ([]byte, bool) {
		t.Helper()
		var digest [sha256.Size]byte
		copy(digest[:], args[9].([]byte))
		lease := runtimeevent.StageLease{Scope: fixtureRequestIdentity(t).Scope, BatchID: mustProductID(t, args[3].(string)), Generation: args[4].(int64), Stage: runtimeevent.RuntimeStageCorrelate, Attempt: args[7].(int), ImplementationVersion: args[8].(string), InputDigest: digest, PredecessorDigest: &digest, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v2", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
		if err := admin.QueryRow(ctx, `SELECT work.lease_expires_at,predecessor.result_reference,predecessor.result_version_id FROM zasp_runtime_stage_work work JOIN zasp_runtime_stage_work predecessor ON (predecessor.organization_id,predecessor.workspace_id,predecessor.environment_id,predecessor.batch_id,predecessor.batch_generation,predecessor.stage)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation,'index') WHERE (work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation,work.stage)=($1,$2,$3,$4,$5,'correlate')`, args[:5]...).Scan(&lease.LeaseExpiresAt, &lease.InputReference, &lease.InputVersionID); err != nil {
			t.Fatal(err)
		}
		snapshot, err := repository.FreezePreciseCandidates(ctx, lease, args[5].(string), args[6].(string), args[10].([]byte), args[11].([]byte))
		if err != nil {
			t.Fatal("Go/PostgreSQL precise freeze rejected", err)
		}
		body := snapshot.Bytes()
		if snapshot.Digest() != sha256.Sum256(body) || !snapshot.ValidFor(lease.Scope, lease.BatchID, lease.Generation, sha256.Sum256(args[11].([]byte))) {
			t.Fatal("repository snapshot binding lost")
		}
		result, err := runtimecorrelation.CorrelatePreciseFrozen(runtimecorrelation.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: sha256.Sum256(args[11].([]byte)), Body: args[11].([]byte)}, snapshot)
		if err != nil || len(result.Results) != 1 || result.CandidateSnapshotDigest != snapshot.Digest() {
			t.Fatal("actual snapshot correlation failed", err)
		}
		if prior, found := correlations[args[3].(string)]; found && (prior.ContentDigest != result.ContentDigest || prior.Results[0] != result.Results[0]) {
			t.Fatal("late evidence rewrote frozen correlation")
		}
		correlations[args[3].(string)] = result
		indexReceipt, err := runtimeevent.DecodeStageReceipt(args[10].([]byte))
		if err != nil {
			t.Fatal(err)
		}
		receiptBody, receiptDigest, _, err := runtimecorrelation.EncodePreciseReceipt(runtimecorrelation.Receipt{
			ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation,
			InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest,
			ArchiveReference: indexReceipt.ArchiveReference, ArchiveVersionID: indexReceipt.ArchiveVersionID, ArchiveDigest: indexReceipt.ArchiveDigest,
			EffectDigest: result.ContentDigest, CandidateSnapshotDigest: snapshot.Digest(), Results: result.Results,
		})
		if err != nil || receiptDigest != sha256.Sum256(receiptBody) {
			t.Fatal("actual precise correlation receipt failed", err)
		}
		decoded, err := runtimecorrelation.DecodePreciseReceipt(receiptBody)
		if err != nil || decoded.Results[0] != result.Results[0] || decoded.CandidateSnapshotDigest != snapshot.Digest() || decoded.InputReference != lease.InputReference || decoded.InputVersionID != lease.InputVersionID || decoded.InputDigest != lease.InputDigest {
			t.Fatal("actual precise receipt replay changed", err)
		}
		if prior, found := correlationReceipts[lease.BatchID.String()]; found && !bytes.Equal(prior, receiptBody) {
			t.Fatal("late evidence changed precise receipt bytes")
		}
		correlationReceipts[lease.BatchID.String()] = receiptBody
		projected, err := runtimeprojection.ProjectPrecise(runtimeprojection.Batch{Scope: decoded.Scope, BatchID: decoded.BatchID, Generation: decoded.Generation, ArchiveReference: decoded.ArchiveReference, ArchiveVersionID: decoded.ArchiveVersionID, ArchiveDigest: decoded.ArchiveDigest, Body: args[11].([]byte), Correlations: decoded.Results})
		if err != nil || len(projected.Items) != 1 {
			t.Fatal("actual precise projection failed", err)
		}
		item := projected.Items[0]
		binding := decoded.Results[0]
		if item.EventID != binding.EventID || item.Confidence != binding.Confidence || item.AgentID != binding.AgentID || item.SessionID != binding.SessionID || item.SandboxID != binding.SandboxID || item.SandboxSourceSensorID != binding.SandboxSourceSensorID {
			t.Fatal("actual projection lost admitted binding")
		}
		if prior, found := projections[lease.BatchID.String()]; found && (prior.ContentDigest != projected.ContentDigest || prior.Items[0] != item) {
			t.Fatal("late evidence changed precise projection")
		}
		projections[lease.BatchID.String()] = projected
		return body, snapshot.Replayed()
	}
	body, replayed := freeze(target)
	var snapshot struct {
		Schema     string
		Candidates []struct {
			BatchID   string `json:"batch_id"`
			SandboxID string `json:"sandbox_id"`
		}
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if replayed || snapshot.Schema != "runtime-candidate-snapshot-v3" || len(snapshot.Candidates) != 1 || snapshot.Candidates[0].BatchID != upper[3] || snapshot.Candidates[0].SandboxID != "candidate-sandbox" {
		t.Fatalf("precise window or sandbox lost: %s", body)
	}
	firstResult := correlations[target[3].(string)].Results[0]
	if firstResult.Confidence != domain.EvidenceConfidenceStrong || firstResult.SandboxID != "candidate-sandbox" || firstResult.SandboxSourceSensorID.String() != sandboxSemantic || firstResult.AgentID.IsZero() || firstResult.SessionID.IsZero() {
		t.Fatal("unique precise candidate failed to assign enrolled binding")
	}
	var retained []byte
	if err := admin.QueryRow(ctx, `SELECT snapshot_body FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1`, target[3]).Scan(&retained); err != nil || !bytes.Equal(retained, body) {
		t.Fatal("snapshot not durably retained", err)
	}
	if err := worker.QueryRow(ctx, runtimeSandboxFreezeSQL, target...).Scan(&ignored); err == nil {
		t.Fatal("old worker accepted V4 lease")
	}
	freezeSandboxFixture(t, ctx, worker, seedSemantic(4, "2026-09-10T10:00:01.000Z"))
	again, replayed := freeze(target)
	if !replayed || !bytes.Equal(again, body) {
		t.Fatal("late candidate rewrote replay")
	}
	next := seedTarget(5, contract)
	nextBody, _ := freeze(next)
	if err := json.Unmarshal(nextBody, &snapshot); err != nil || len(snapshot.Candidates) != 2 {
		t.Fatal("fresh snapshot missed late candidate", err)
	}
	conflict := correlations[next[3].(string)].Results[0]
	if conflict.Confidence != domain.EvidenceConfidenceProbable || !conflict.AgentID.IsZero() || !conflict.SessionID.IsZero() || conflict.SandboxID != "" || !conflict.SandboxSourceSensorID.IsZero() {
		t.Fatal("competing precise candidates assigned identity")
	}
	badContract := contract
	badContract.prepare = func(t *testing.T, body []byte) []byte {
		return bytes.Replace(preparePreciseCandidateArchive(t, body), []byte(`"source_event_time":"2026-09-10T10:00:01.000000001Z"`), []byte(`"source_event_time":"2026-09-10T10:00:02Z"`), 1)
	}
	forged := seedTarget(6, badContract)
	if err := worker.QueryRow(ctx, preciseFreezeSQL, forged...).Scan(&ignored); err == nil {
		t.Fatal("digest-bound wrong-bin lineage accepted")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_deliveries SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE batch_id=$1`, target[3]); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, preciseFreezeSQL, target...).Scan(&ignored); err == nil {
		t.Fatal("expired delivery replayed")
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1`, forged[3]).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected lineage retained snapshot", err)
	}
	// Physical-boundary fixtures use owner inserts, not claimed API admission.
	// 1001 observations just outside the exact window must not hide the two
	// valid candidates through an earlier coarse-range LIMIT.
	freezeSandboxFixture(t, ctx, worker, seedSemantic(7, "2026-09-10T09:55:01.000Z"))
	duplicate := `INSERT INTO zasp_runtime_candidate_observations SELECT (jsonb_populate_record(NULL::zasp_runtime_candidate_observations,to_jsonb(original)||jsonb_build_object('event_ordinal',ordinal))).* FROM zasp_runtime_candidate_observations original CROSS JOIN generate_series(2,1000) ordinal WHERE original.batch_id=$1 AND original.event_ordinal=1`
	if _, err := admin.Exec(ctx, duplicate, lower[3]); err != nil {
		t.Fatal(err)
	}
	bounded := seedTarget(8, contract)
	boundedBody, _ := freeze(bounded)
	if err := json.Unmarshal(boundedBody, &snapshot); err != nil || len(snapshot.Candidates) != 2 {
		t.Fatal("coarse-range bound hid precise candidates", err)
	}
	if _, err := admin.Exec(ctx, duplicate, upper[3]); err != nil {
		t.Fatal(err)
	}
	overflow := seedTarget(9, contract)
	if err := worker.QueryRow(ctx, preciseFreezeSQL, overflow...).Scan(&ignored); err == nil {
		t.Fatal("precise candidate overflow silently truncated")
	} else {
		requireSandboxSQLState(t, err, "54000")
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1`, overflow[3]).Scan(&count); err != nil || count != 0 {
		t.Fatal("overflow retained a partial snapshot", err)
	}
	for i, change := range []func(*candidateFixtureWire){
		func(c *candidateFixtureWire) { c.schema = "runtime-event-v1" },
		func(c *candidateFixtureWire) { c.index = "runtime-index-v1" },
		func(c *candidateFixtureWire) { c.archive = "runtime-archive-v1" },
		func(c *candidateFixtureWire) {
			c.prepare = func(t *testing.T, b []byte) []byte {
				return bytes.Replace(preparePreciseCandidateArchive(t, b), []byte(`"runtime-archive-v2"`), []byte(`"runtime-archive-v1"`), 1)
			}
		},
	} {
		incompatible := contract
		change(&incompatible)
		args := seedTarget(10+i, incompatible)
		if err := worker.QueryRow(ctx, preciseFreezeSQL, args...).Scan(&ignored); err == nil {
			t.Fatalf("incompatible version %d accepted", i)
		} else {
			requireSandboxSQLState(t, err, "22023")
		}
	}
}
