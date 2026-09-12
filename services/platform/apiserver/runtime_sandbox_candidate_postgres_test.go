package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

const runtimeSandboxFreezeSQL = `SELECT zasp_runtime_freeze_sandbox_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

const sandboxAnchor = "pid_78900001-0000-4000-8000-000000000001"
const sandboxSemantic = "pid_78900002-0000-4000-8000-000000000002"

func runtimeSandboxPredecessor(t *testing.T, ctx context.Context) (*pgx.Conn, *pgx.Conn) {
	t.Helper()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	scopeArgs := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	seedRuntimeCandidateSensor(t, ctx, admin, scopeArgs, sandboxAnchor, "tetragon")
	seedRuntimeCandidateSensor(t, ctx, admin, scopeArgs, sandboxSemantic, "otlp")
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES($1,$2,$3,$4,$5)`, append(scopeArgs, sandboxSemantic, sandboxAnchor)...); err != nil {
		t.Fatal(err)
	}
	return admin, worker
}

func freezeSandboxFixture(t *testing.T, ctx context.Context, worker *pgx.Conn, args []any) runtimeevent.FrozenCandidateSnapshot {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	var digest [sha256.Size]byte
	copy(digest[:], args[9].([]byte))
	lease := runtimeevent.StageLease{Scope: scope, BatchID: mustProductID(t, args[3].(string)), Generation: args[4].(int64), Stage: runtimeevent.RuntimeStageCorrelate, Attempt: args[7].(int), ImplementationVersion: args[8].(string), InputDigest: digest, PredecessorDigest: &digest, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v1", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
	result, err := repository.FreezeCandidates(ctx, lease, args[5].(string), args[6].(string), args[10].([]byte), args[11].([]byte))
	if err != nil {
		t.Fatal("actual PostgreSQL snapshot rejected", err)
	}
	return result
}

func correlateSandboxFixture(t *testing.T, args []any, snapshot runtimeevent.FrozenCandidateSnapshot) runtimecorrelation.CorrelatedBatch {
	t.Helper()
	input := runtimecorrelation.Batch{Scope: fixtureRequestIdentity(t).Scope, BatchID: mustProductID(t, args[3].(string)), Generation: args[4].(int64), Body: args[11].([]byte), ArchiveDigest: sha256.Sum256(args[11].([]byte))}
	var result runtimecorrelation.CorrelatedBatch
	var err error
	if snapshot.HasSandboxBindings() {
		result, err = runtimecorrelation.CorrelateSandboxFrozen(input, snapshot)
	} else {
		result, err = runtimecorrelation.CorrelateFrozen(input, snapshot)
	}
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRuntimeSandboxCandidateAuthorityPreservesHistoricalUnknownAndV2Replay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	old := seedRuntimeCandidateBatch(t, ctx, admin, 1, sandboxSemantic, "otlp", 1)
	before := freezeSandboxFixture(t, ctx, worker, old)
	backlog := seedRuntimeCandidateBatch(t, ctx, admin, 2, sandboxAnchor, "tetragon", 0)
	var oldObservation string
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(o)::text FROM zasp_runtime_candidate_observations o WHERE batch_id=$1`, old[3]).Scan(&oldObservation); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	newArgs := seedRuntimeCandidateBatchVersion(t, ctx, admin, 3, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", nil)
	newSnapshot := freezeSandboxFixture(t, ctx, worker, newArgs)
	if len(newSnapshot.Candidates()) != 2 || newSnapshot.Candidates()[0].SandboxObserved || newSnapshot.Candidates()[0].SandboxID != "" || !newSnapshot.Candidates()[1].SandboxObserved || newSnapshot.Candidates()[1].SandboxID != "candidate-sandbox" {
		t.Fatal("historical unknown was discarded or rewritten")
	}
	if result := correlateSandboxFixture(t, newArgs, newSnapshot); result.Results[0].Confidence != domain.EvidenceConfidenceExact || result.Results[0].SandboxID != "candidate-sandbox" {
		t.Fatal("own explicit identity lost")
	}
	target := seedRuntimeCandidateBatchVersion(t, ctx, admin, 4, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v3", nil)
	result := correlateSandboxFixture(t, target, freezeSandboxFixture(t, ctx, worker, target))
	if len(result.Results) != 1 || result.Results[0].Confidence != domain.EvidenceConfidenceProbable || !result.Results[0].AgentID.IsZero() || !result.Results[0].SessionID.IsZero() || result.Results[0].SandboxID != "" || !result.Results[0].SandboxSourceSensorID.IsZero() {
		t.Fatal("unknown plus known binding became authoritative")
	}
	oldAfter := freezeSandboxFixture(t, ctx, worker, old)
	if !oldAfter.Replayed() || !bytes.Equal(before.Bytes(), oldAfter.Bytes()) || before.Digest() != oldAfter.Digest() {
		t.Fatal("historical v2 snapshot changed")
	}
	var unchanged bool
	if err := admin.QueryRow(ctx, `SELECT (to_jsonb(o)-'sandbox_id')=$2::jsonb AND sandbox_id IS NULL FROM zasp_runtime_candidate_observations o WHERE batch_id=$1`, old[3], oldObservation).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("historical observation backfilled", err)
	}
	backlogSnapshot := freezeSandboxFixture(t, ctx, worker, backlog)
	if backlogSnapshot.HasSandboxBindings() || bytes.Contains(backlogSnapshot.Bytes(), []byte(`"sandbox_id"`)) || len(backlogSnapshot.Candidates()) != 2 {
		t.Fatal("v2 backlog changed snapshot schema")
	}
	if result := correlateSandboxFixture(t, backlog, backlogSnapshot); result.Results[0].Confidence != domain.EvidenceConfidenceStrong || result.Results[0].SandboxID != "" {
		t.Fatal("v2 matching semantics changed")
	}
}

func TestRuntimeSandboxCandidateAuthorityFreezesBeforeConflictingLateAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	first := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", nil)
	freezeSandboxFixture(t, ctx, worker, first)
	target := seedRuntimeCandidateBatchVersion(t, ctx, admin, 2, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v3", nil)
	before := freezeSandboxFixture(t, ctx, worker, target)
	initial := correlateSandboxFixture(t, target, before)
	if initial.Results[0].Confidence != domain.EvidenceConfidenceStrong || initial.Results[0].SandboxID != "candidate-sandbox" || initial.Results[0].SandboxSourceSensorID.String() != sandboxSemantic {
		t.Fatal("unique enrolled sandbox did not assign Strong")
	}
	late := seedRuntimeCandidateBatchVersion(t, ctx, admin, 3, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", func(event map[string]any) {
		event["attributes"].(map[string]string)["sandbox.id"] = "different-sandbox"
	})
	freezeSandboxFixture(t, ctx, worker, late)
	again := freezeSandboxFixture(t, ctx, worker, target)
	replayed := correlateSandboxFixture(t, target, again)
	if !again.Replayed() || !bytes.Equal(before.Bytes(), again.Bytes()) || before.Digest() != again.Digest() || initial.ContentDigest != replayed.ContentDigest || initial.Results[0] != replayed.Results[0] {
		t.Fatal("late admission rewrote frozen sandbox attribution")
	}
	next := seedRuntimeCandidateBatchVersion(t, ctx, admin, 4, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v3", nil)
	conflict := correlateSandboxFixture(t, next, freezeSandboxFixture(t, ctx, worker, next))
	if conflict.Results[0].Confidence != domain.EvidenceConfidenceProbable || !conflict.Results[0].AgentID.IsZero() || !conflict.Results[0].SessionID.IsZero() || conflict.Results[0].SandboxID != "" || !conflict.Results[0].SandboxSourceSensorID.IsZero() {
		t.Fatal("same agent/session competing sandboxes assigned identity")
	}
	// The schema permits historical null on old rows, but never by mutating an
	// admitted known binding. The worker cannot read the private table directly.
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_candidate_observations SET sandbox_id=NULL WHERE batch_id=$1`, first[3]); err == nil {
		t.Fatal("admitted sandbox was mutable")
	} else {
		requireSandboxSQLState(t, err, "55000")
	}
	if _, err := worker.Exec(ctx, `SELECT sandbox_id FROM zasp_runtime_candidate_observations`); err == nil {
		t.Fatal("worker bypassed frozen candidate authority")
	} else {
		requireSandboxSQLState(t, err, "42501")
	}
}

func requireSandboxSQLState(t *testing.T, err error, want string) {
	t.Helper()
	var provider *pgconn.PgError
	if !errors.As(err, &provider) || provider.Code != want {
		t.Fatalf("SQLSTATE wanted %s: %v", want, err)
	}
}

func TestRuntimeSandboxCandidateAuthorityDeniesUnboundExecutionWithoutEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	for index, scenario := range []struct{ name, code string }{{"wrong principal", "42501"}, {"foreign scope", "P0002"}, {"expired lease", "P0002"}, {"expired delivery", "P0002"}, {"wrong version", "22023"}, {"revoked source", "42501"}} {
		t.Run(scenario.name, func(t *testing.T) {
			args := seedRuntimeCandidateBatchVersion(t, ctx, admin, index+1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", nil)
			batch := args[3]
			caller := worker
			switch scenario.name {
			case "wrong principal":
				caller = admin
			case "foreign scope":
				args[1] = "pid_78900000-0000-4000-8000-000000000099"
			case "wrong version":
				args[8] = "runtime-correlation-v2"
			case "expired lease":
				if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE batch_id=$1 AND stage='correlate'`, batch); err != nil {
					t.Fatal(err)
				}
			case "expired delivery":
				if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_deliveries SET visibility_deadline=clock_timestamp()-interval '1 second' WHERE batch_id=$1`, batch); err != nil {
					t.Fatal(err)
				}
			case "revoked source":
				if _, err := admin.Exec(ctx, `UPDATE zasp_sensors SET revoked_at=clock_timestamp() WHERE id=$1`, sandboxSemantic); err != nil {
					t.Fatal(err)
				}
			}
			var payload []byte
			requireSandboxSQLState(t, caller.QueryRow(ctx, runtimeSandboxFreezeSQL, args...).Scan(&payload), scenario.code)
			var empty bool
			if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_observations WHERE batch_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1)`, batch).Scan(&empty); err != nil || !empty {
				t.Fatal("denied execution left evidence", err)
			}
		})
	}
}

func TestRuntimeSandboxCandidateAuthoritySeparatesEnrolledNamespaces(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	scope := fixtureRequestIdentity(t).Scope
	scopeArgs := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	const otherSource = "pid_78900002-0000-4000-8000-000000000009"
	seedRuntimeCandidateSensor(t, ctx, admin, scopeArgs, otherSource, "otlp")
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES($1,$2,$3,$4,$5)`, append(scopeArgs, otherSource, sandboxAnchor)...); err != nil {
		t.Fatal(err)
	}
	for index, source := range []string{sandboxSemantic, otherSource} {
		freezeSandboxFixture(t, ctx, worker, seedRuntimeCandidateBatchVersion(t, ctx, admin, index+1, source, "otlp", 1, 1, "runtime-correlation-v3", nil))
	}
	target := seedRuntimeCandidateBatchVersion(t, ctx, admin, 3, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v3", nil)
	snapshot := freezeSandboxFixture(t, ctx, worker, target)
	if len(snapshot.Candidates()) != 2 || snapshot.Candidates()[0].SandboxID != snapshot.Candidates()[1].SandboxID || snapshot.Candidates()[0].SourceSensorID == snapshot.Candidates()[1].SourceSensorID {
		t.Fatal("source namespace collapsed in database snapshot")
	}
	result := correlateSandboxFixture(t, target, snapshot)
	if result.Results[0].Confidence != domain.EvidenceConfidenceProbable || !result.Results[0].AgentID.IsZero() || !result.Results[0].SessionID.IsZero() || result.Results[0].SandboxID != "" || !result.Results[0].SandboxSourceSensorID.IsZero() {
		t.Fatal("different enrolled namespaces became authoritative")
	}
}

func TestRuntimeSandboxCandidateAuthorityMalformedLaterEventRollsBackAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	args := seedRuntimeCandidateBatchInput(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 2, "runtime-correlation-v3", func(event map[string]any) {
		attributes := event["attributes"].(map[string]string)
		if attributes["event.id"] == "candidate-event-1-1" {
			attributes["sandbox.id"] = ""
		}
	}, false)
	var payload []byte
	requireSandboxSQLState(t, worker.QueryRow(ctx, runtimeSandboxFreezeSQL, args...).Scan(&payload), "22023")
	var empty bool
	if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_observations WHERE batch_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1)`, args[3]).Scan(&empty); err != nil || !empty {
		t.Fatal("late malformed event left partial admission", err)
	}
}

func TestRuntimeSandboxCandidateAuthorityOverflowRollsBackNewAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	first := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 500, "runtime-correlation-v3", nil)
	before := freezeSandboxFixture(t, ctx, worker, first)
	if len(before.Candidates()) != 500 {
		t.Fatal("overflow control did not admit actual candidate observations")
	}
	other := seedRuntimeCandidateBatchVersion(t, ctx, admin, 2, sandboxSemantic, "otlp", 1, 501, "runtime-correlation-v3", nil)
	var payload []byte
	requireSandboxSQLState(t, worker.QueryRow(ctx, runtimeSandboxFreezeSQL, other...).Scan(&payload), "54000")
	var preserved bool
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_candidate_observations)=500 AND NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_observations WHERE batch_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1)`, other[3]).Scan(&preserved); err != nil || !preserved {
		t.Fatal("overflow left partial candidate evidence", err)
	}
	again := freezeSandboxFixture(t, ctx, worker, first)
	if !again.Replayed() || !bytes.Equal(before.Bytes(), again.Bytes()) {
		t.Fatal("overflow changed prior frozen history")
	}
}

func TestRuntimeSandboxCandidateAuthorityRejectsMalformedSandboxAtomically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	for index, scenario := range []struct {
		name  string
		value any
		code  string
	}{
		{"missing", nil, "22023"}, {"null", nil, "22023"}, {"number", 7, "22023"}, {"empty", "", "22023"}, {"oversize bytes", strings.Repeat("x", 257), "22023"},
		{"leading space", " sandbox", "23514"}, {"trailing tab", "sandbox\t", "23514"}, {"leading NBSP", "\u00a0sandbox", "23514"}, {"internal newline", "sand\nbox", "23514"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			args := seedRuntimeCandidateBatchInput(t, ctx, admin, index+1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", func(event map[string]any) {
				old := event["attributes"].(map[string]string)
				attributes := make(map[string]any, len(old))
				for k, v := range old {
					attributes[k] = v
				}
				if scenario.name == "missing" {
					delete(attributes, "sandbox.id")
				} else {
					attributes["sandbox.id"] = scenario.value
				}
				event["attributes"] = attributes
			}, false)
			var payload []byte
			err := worker.QueryRow(ctx, runtimeSandboxFreezeSQL, args...).Scan(&payload)
			requireSandboxSQLState(t, err, scenario.code)
			var empty bool
			if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_observations WHERE batch_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1)`, args[3]).Scan(&empty); err != nil || !empty {
				t.Fatal("rejected semantic identity left evidence", err)
			}
		})
	}
}

func TestRuntimeSandboxCandidateAuthorityPreservesValidTextBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	for index, value := range []string{strings.Repeat("é", 128), "sandbox\tinner", "sandbox\u00a0inner", "\u200bsandbox"} {
		args := seedRuntimeCandidateBatchVersion(t, ctx, admin, index+1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", func(event map[string]any) { event["attributes"].(map[string]string)["sandbox.id"] = value })
		snapshot := freezeSandboxFixture(t, ctx, worker, args)
		found := false
		for _, candidate := range snapshot.Candidates() {
			if candidate.BatchID.String() == args[3] {
				found = candidate.SandboxObserved && candidate.SandboxID == value
			}
		}
		if !found {
			t.Fatal("valid semantic sandbox text was rejected or normalized")
		}
	}
}

func TestRuntimeSandboxCandidateAuthorityRejectsRelabeledHistoricalSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	args := seedRuntimeCandidateBatch(t, ctx, admin, 1, sandboxSemantic, "otlp", 1)
	before := freezeSandboxFixture(t, ctx, worker, args)
	installRuntimeSandboxDraft(t, ctx, admin)
	// Simulate forbidden relabeling using the test owner. No production API can
	// perform this mutation; the v3 freeze must still refuse the old snapshot.
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-correlation-v3' WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
		t.Fatal(err)
	}
	args[8] = "runtime-correlation-v3"
	var payload []byte
	err := worker.QueryRow(ctx, runtimeSandboxFreezeSQL, args...).Scan(&payload)
	var provider *pgconn.PgError
	if !errors.As(err, &provider) || provider.Code != "23505" {
		t.Fatal("historical snapshot reinterpreted as v3", err)
	}
	var body []byte
	if err := admin.QueryRow(ctx, `SELECT snapshot_body FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1`, args[3]).Scan(&body); err != nil || !bytes.Equal(body, before.Bytes()) {
		t.Fatal("rejected version reuse changed history", err)
	}
}

// These are explicitly seeded committed archive/index rows in disposable PG,
// not authenticated ingestion or provider attestation.
func TestRuntimeSandboxCandidateAuthorityRetainsAdmittedBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	scope := fixtureRequestIdentity(t).Scope
	scopeArgs := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	const anchor = "pid_78900001-0000-4000-8000-000000000001"
	const semantic = "pid_78900002-0000-4000-8000-000000000002"
	seedRuntimeCandidateSensor(t, ctx, admin, scopeArgs, anchor, "tetragon")
	seedRuntimeCandidateSensor(t, ctx, admin, scopeArgs, semantic, "otlp")
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES($1,$2,$3,$4,$5)`, append(scopeArgs, semantic, anchor)...); err != nil {
		t.Fatal(err)
	}
	args := seedRuntimeCandidateBatch(t, ctx, admin, 1, semantic, "otlp", 1)
	// Controlled new-version lease fixture; this is not the production claim path.
	if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,$5,'correlate',3,'runtime-correlation-v3',$6,$6,'leased',1,'candidate-worker','candidate-lease-token-01',clock_timestamp()+interval '1 hour')`, args[0], args[1], args[2], args[3], args[4], args[9]); err != nil {
		t.Fatal(err)
	}
	args[8] = "runtime-correlation-v3"
	var payload []byte
	if err := worker.QueryRow(ctx, runtimeSandboxFreezeSQL, args...).Scan(&payload); err != nil {
		t.Fatal("v3 database admission did not retain the binding", err)
	}
	var envelope struct {
		Snapshot string `json:"snapshot"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	body, err := hex.DecodeString(envelope.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Schema     string `json:"schema"`
		Candidates []struct {
			SandboxID string `json:"sandbox_id"`
			Source    string `json:"source_sensor_id"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Schema != "runtime-candidate-snapshot-v2" || len(snapshot.Candidates) != 1 || snapshot.Candidates[0].SandboxID != "candidate-sandbox" || snapshot.Candidates[0].Source != semantic {
		t.Fatal("sandbox or enrolled source not frozen", string(body))
	}
}
