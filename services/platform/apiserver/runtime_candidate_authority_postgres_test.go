package apiserver

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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

const runtimeCandidateFreezeSQL = `SELECT zasp_runtime_freeze_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

func TestRuntimeCandidateAuthorityRunnerRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	for cycle := 0; cycle < 2; cycle++ {
		if err := runner.UpProductionRuntimeCandidateAuthority(ctx); err != nil {
			t.Fatal("candidate upgrade", err)
		}
		metadata := migrations.ProductionRuntimeCandidateAuthority()
		var ready bool
		if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_candidate_authority_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("candidate runner readiness", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 47 {
			t.Fatal("candidate runner did not record exact version", version, err)
		}
		apiConfig := admin.Config().Copy()
		apiConfig.User = "invocation_discovery_api"
		api, err := pgx.ConnectConfig(ctx, apiConfig)
		if err != nil {
			t.Fatal(err)
		}
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			api.Close(ctx)
			t.Fatal(err)
		}
		repository, err := NewPostgresRepository(database)
		if err != nil {
			api.Close(ctx)
			t.Fatal(err)
		}
		err = repository.Ready(ctx)
		api.Close(ctx)
		if err != nil {
			t.Fatal("actual API startup rejected schema 47", err)
		}
		if err := runner.DownProductionRuntimeCandidateAuthority(ctx); err != nil {
			t.Fatal("candidate downgrade", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 46 {
			t.Fatal("candidate runner did not restore exact version", version, err)
		}
	}
}

func TestRuntimeCandidateAuthorityEmptyRollbackRestoresPriorSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing, runner.UpProductionReconciliationLanePlan} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var before string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_reconciliation_lane_plan_live_fingerprint()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	metadata := migrations.ProductionRuntimeCandidateAuthority()
	if _, err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
		t.Fatal(err)
	}
	var liveFingerprint, expectedFingerprint string
	var secure bool
	if err := transaction.QueryRow(ctx, `SELECT zasp_production_runtime_candidate_authority_live_fingerprint(),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_candidate_authority_fingerprint'),zasp_production_runtime_candidate_authority_security_ready()`).Scan(&liveFingerprint, &expectedFingerprint, &secure); err != nil || !secure || liveFingerprint != expectedFingerprint {
		t.Fatalf("candidate schema security=%t live=%s expected=%s error=%v", secure, liveFingerprint, expectedFingerprint, err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		t.Fatal(err)
	}
	const readinessSQL = `SELECT zasp_production_runtime_candidate_authority_readiness($1,$2)`
	var ready bool
	if err := transaction.QueryRow(ctx, readinessSQL, metadata.Checksum(), expectedFingerprint).Scan(&ready); err != nil || !ready {
		t.Fatal("candidate schema readiness failed", err)
	}
	prior := migrations.ProductionReconciliationLanePlan()
	if err := transaction.QueryRow(ctx, `SELECT zasp_production_reconciliation_lane_plan_readiness($1,$2)`, prior.Checksum(), migrations.ProductionReconciliationLanePlanSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("prior compatibility readiness failed", err)
	}
	for _, drift := range []struct{ name, sql string }{
		{"function body", `DO $drift$ DECLARE definition text; BEGIN SELECT pg_get_functiondef('public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure) INTO definition; EXECUTE replace(definition,'interval ''5 minutes''','interval ''6 minutes'''); END $drift$`},
		{"function grant", `GRANT EXECUTE ON FUNCTION public.zasp_runtime_candidate_lineage_valid(jsonb,timestamptz) TO PUBLIC`},
		{"table grant", `GRANT SELECT ON public.zasp_runtime_candidate_snapshots TO zasp_discovery_api`},
		{"column grant", `GRANT SELECT(agent_id) ON public.zasp_runtime_candidate_observations TO zasp_runtime_correlation_worker`},
		{"forced RLS", `ALTER TABLE public.zasp_runtime_candidate_observations NO FORCE ROW LEVEL SECURITY`},
		{"extra policy", `CREATE POLICY unexpected_candidate_reader ON public.zasp_runtime_candidate_snapshots FOR SELECT TO PUBLIC USING(true)`},
		{"disabled trigger", `ALTER TABLE public.zasp_runtime_candidate_snapshots DISABLE TRIGGER zasp_runtime_candidate_snapshots_immutable`},
		{"removed index", `DROP INDEX public.zasp_runtime_candidate_lookup_v47`},
		{"future version", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(48,'unexpected_future_release',repeat('a',64))`},
		{"missing fingerprint", `DELETE FROM zasp_schema_metadata WHERE key='production_runtime_candidate_authority_fingerprint'`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := transaction.Exec(ctx, `SAVEPOINT candidate_drift`); err != nil {
				t.Fatal(err)
			}
			defer transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT candidate_drift`)
			if _, err := transaction.Exec(ctx, drift.sql); err != nil {
				t.Fatal(err)
			}
			// Missing stored metadata is a Down guard; the public readiness caller
			// supplies its independently pinned fingerprint, not this mutable row.
			if drift.name != "missing fingerprint" {
				if _, err := transaction.Exec(ctx, `SAVEPOINT candidate_readiness`); err != nil {
					t.Fatal(err)
				}
				err := transaction.QueryRow(ctx, readinessSQL, metadata.Checksum(), expectedFingerprint).Scan(&ready)
				if err == nil && ready {
					t.Fatal("drifted candidate schema remained ready")
				}
				if _, err := transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT candidate_readiness`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := transaction.Exec(ctx, metadata.DownSQL()); err == nil {
				t.Fatal("candidate rollback accepted schema drift")
			}
		})
	}
	if _, err := transaction.Exec(ctx, `DELETE FROM zasp_schema_versions WHERE version=47`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
		t.Fatal("empty candidate authority cannot roll back", err)
	}
	var after string
	var absent bool
	if err := transaction.QueryRow(ctx, `SELECT zasp_production_reconciliation_lane_plan_live_fingerprint(),to_regclass('public.zasp_runtime_candidate_snapshots') IS NULL AND to_regclass('public.zasp_runtime_candidate_observations') IS NULL AND to_regprocedure('public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)') IS NULL`).Scan(&after, &absent); err != nil || after != before || !absent {
		t.Fatal("candidate rollback failed exact prior restoration", err)
	}
}

// Actual PostgreSQL authority proof with explicitly seeded committed stage rows.
// Graph/S3 crash recovery and authenticated ingest are separate composed gates.
func TestRuntimeCandidateAuthorityFreezesReplayAfterLateAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing, runner.UpProductionReconciliationLanePlan} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	metadata := migrations.ProductionRuntimeCandidateAuthority()
	if _, err := admin.Exec(ctx, metadata.UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"candidate_coordinator", "candidate_archive", "candidate_index", "candidate_correlation", "candidate_projection", "candidate_gateway"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_register_principals(session_user,'candidate_coordinator','candidate_archive','candidate_index','candidate_correlation','candidate_projection','candidate_gateway')`); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "candidate_correlation"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	identity := fixtureRequestIdentity(t)
	scope := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}
	const anchor = "pid_78900001-0000-4000-8000-000000000001"
	const semantic = "pid_78900002-0000-4000-8000-000000000002"
	for _, source := range []struct{ id, kind string }{{anchor, "tetragon"}, {semantic, "otlp"}} {
		args := append(append([]any(nil), scope...), source.id, source.kind)
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Candidate proof source',$5,'active')`, args...); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,decode(repeat('ab',16),'hex'),digest($4,'sha256'),clock_timestamp()+interval '1 day')`, args[:4]...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES($1,$2,$3,$4,$5)`, append(append([]any(nil), scope...), semantic, anchor)...); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil || repository.Ready(ctx) != nil || repository.ReadyCandidates(ctx) != nil {
		t.Fatal("candidate repository readiness", err)
	}
	correlations := make(map[string]runtimecorrelation.CorrelatedBatch)
	correlationReceipts := make(map[string][]byte)
	freeze := func(args []any) ([]byte, bool) {
		t.Helper()
		var inputDigest [sha256.Size]byte
		copy(inputDigest[:], args[9].([]byte))
		lease := runtimeevent.StageLease{Scope: identity.Scope, BatchID: mustProductID(t, args[3].(string)), Generation: args[4].(int64), Stage: runtimeevent.RuntimeStageCorrelate, Attempt: args[7].(int), ImplementationVersion: args[8].(string), InputDigest: inputDigest, PredecessorDigest: &inputDigest}
		if err := admin.QueryRow(ctx, `SELECT work.lease_expires_at,predecessor.result_reference,predecessor.result_version_id FROM zasp_runtime_stage_work work JOIN zasp_runtime_stage_work predecessor ON (predecessor.organization_id,predecessor.workspace_id,predecessor.environment_id,predecessor.batch_id,predecessor.batch_generation,predecessor.stage)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation,'index') WHERE (work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation,work.stage)=($1,$2,$3,$4,$5,'correlate')`, args[:5]...).Scan(&lease.LeaseExpiresAt, &lease.InputReference, &lease.InputVersionID); err != nil {
			t.Fatal(err)
		}
		snapshot, err := repository.FreezeCandidates(ctx, lease, args[5].(string), args[6].(string), args[10].([]byte), args[11].([]byte))
		if err != nil {
			t.Fatal("registered repository freeze", err)
		}
		var response []byte
		if err := worker.QueryRow(ctx, runtimeCandidateFreezeSQL, args...).Scan(&response); err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Snapshot string `json:"snapshot"`
			SHA256   string `json:"sha256"`
			Replayed bool   `json:"replayed"`
		}
		if err := json.Unmarshal(response, &wire); err != nil {
			t.Fatal(err)
		}
		body, err := hex.DecodeString(wire.Snapshot)
		if err != nil || len(body) == 0 || len(body) > 1<<20 {
			t.Fatal("invalid frozen snapshot bytes")
		}
		digest := sha256.Sum256(body)
		if wire.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("snapshot checksum drift")
		}
		if !wire.Replayed || !bytes.Equal(snapshot.Bytes(), body) || snapshot.Digest() != digest || !snapshot.ValidFor(identity.Scope, lease.BatchID, lease.Generation, sha256.Sum256(args[11].([]byte))) {
			t.Fatal("repository snapshot differs from exact database replay")
		}
		correlated, err := runtimecorrelation.CorrelateFrozen(runtimecorrelation.Batch{Scope: identity.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: sha256.Sum256(args[11].([]byte)), Body: args[11].([]byte)}, snapshot)
		if err != nil || correlated.CandidateSnapshotDigest != snapshot.Digest() {
			t.Fatal("actual database snapshot correlation", err)
		}
		indexReceipt, err := runtimeevent.DecodeStageReceipt(args[10].([]byte))
		if err != nil {
			t.Fatal(err)
		}
		receiptBody, _, _, err := runtimecorrelation.EncodeReceipt(runtimecorrelation.Receipt{ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest, ArchiveReference: indexReceipt.ArchiveReference, ArchiveVersionID: indexReceipt.ArchiveVersionID, ArchiveDigest: indexReceipt.ArchiveDigest, EffectDigest: correlated.ContentDigest, CandidateSnapshotDigest: snapshot.Digest(), Results: correlated.Results})
		if err != nil {
			t.Fatal("actual snapshot receipt", err)
		}
		if _, err := runtimecorrelation.DecodeReceipt(receiptBody); err != nil {
			t.Fatal(err)
		}
		key := lease.BatchID.String()
		if prior, exists := correlations[key]; exists && (prior.ContentDigest != correlated.ContentDigest || !bytes.Equal(correlationReceipts[key], receiptBody)) {
			t.Fatal("late admission or revocation changed frozen correlation/receipt replay")
		}
		correlations[key], correlationReceipts[key] = correlated, bytes.Clone(receiptBody)
		return body, snapshot.Replayed()
	}
	count := func(body []byte) int {
		t.Helper()
		var value struct {
			Candidates []json.RawMessage `json:"candidates"`
		}
		if json.Unmarshal(body, &value) != nil || value.Candidates == nil {
			t.Fatal("snapshot omitted its candidate set")
		}
		return len(value.Candidates)
	}
	first := seedRuntimeCandidateBatch(t, ctx, admin, 1, semantic, "otlp", 1)
	assertCandidateRepositoryAdapterErrors(t, ctx, first)
	for _, table := range []string{"zasp_runtime_candidate_observations", "zasp_runtime_candidate_snapshots"} {
		if _, err := worker.Exec(ctx, "SELECT * FROM "+table); err == nil {
			t.Fatal("worker read private candidate table directly")
		}
	}
	for index, value := range map[int]any{0: anchor, 1: anchor, 2: anchor, 3: anchor, 4: int64(99), 5: "wrong-worker", 6: "wrong-lease-token-001", 7: 2, 8: "runtime-correlation-v1", 9: make([]byte, 32), 10: []byte(`{}`), 11: []byte(`{}`)} {
		wrong := append([]any(nil), first...)
		wrong[index] = value
		var ignored []byte
		if err := worker.QueryRow(ctx, runtimeCandidateFreezeSQL, wrong...).Scan(&ignored); err == nil {
			t.Fatalf("invalid candidate authority at %d accepted", index)
		}
	}
	for index := range first {
		wrong := append([]any(nil), first...)
		wrong[index] = nil
		var ignored []byte
		if err := worker.QueryRow(ctx, runtimeCandidateFreezeSQL, wrong...).Scan(&ignored); err == nil {
			t.Fatalf("null candidate authority at %d accepted", index)
		}
	}
	proveRuntimeCandidateRunnerContention(t, ctx, admin, worker, first)
	proveConcurrentRuntimeCandidateRollback(t, ctx, admin, worker, first)
	freeze(first)
	if result := correlations[first[3].(string)].Results[0]; result.Confidence != domain.EvidenceConfidenceExact || result.AgentID.IsZero() || result.SessionID.IsZero() {
		t.Fatal("admitted semantic evidence lost explicit identity")
	}
	target := seedRuntimeCandidateBatch(t, ctx, admin, 2, anchor, "tetragon", 0)
	frozen, replayed := freeze(target)
	if replayed || count(frozen) != 1 {
		t.Fatal("unique candidate was not frozen")
	}
	if result := correlations[target[3].(string)].Results[0]; result.Confidence != domain.EvidenceConfidenceStrong || result.AgentID.IsZero() || result.SessionID.IsZero() {
		t.Fatal("qualified actual snapshot didn't produce Strong")
	}
	late := seedRuntimeCandidateBatch(t, ctx, admin, 3, semantic, "otlp", 2)
	freeze(late)
	retried, replayed := freeze(target)
	if !replayed || !bytes.Equal(frozen, retried) {
		t.Fatal("late competing admission changed frozen replay")
	}
	next := seedRuntimeCandidateBatch(t, ctx, admin, 4, anchor, "tetragon", 0)
	fresh, replayed := freeze(next)
	if replayed || count(fresh) != 2 {
		t.Fatal("new batch silently dropped the competing candidate")
	}
	if result := correlations[next[3].(string)].Results[0]; result.Confidence != domain.EvidenceConfidenceProbable || !result.AgentID.IsZero() || !result.SessionID.IsZero() {
		t.Fatal("competing actual snapshot gained authoritative identity")
	}
	t.Run("identical lineage in another enrollment domain is excluded", func(t *testing.T) {
		const otherAnchor = "pid_78900012-0000-4000-8000-000000000012"
		const otherSemantic = "pid_78900013-0000-4000-8000-000000000013"
		for _, source := range []struct{ id, kind string }{{otherAnchor, "tetragon"}, {otherSemantic, "otlp"}} {
			seedRuntimeCandidateSensor(t, ctx, admin, scope, source.id, source.kind)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES($1,$2,$3,$4,$5)`, append(append([]any(nil), scope...), otherSemantic, otherAnchor)...); err != nil {
			t.Fatal(err)
		}
		other, replayed := freeze(seedRuntimeCandidateBatch(t, ctx, admin, 13, otherSemantic, "otlp", 13))
		if replayed || count(other) != 1 {
			t.Fatal("other domain did not retain its own isolated candidate")
		}
		original, replayed := freeze(seedRuntimeCandidateBatch(t, ctx, admin, 14, anchor, "tetragon", 0))
		if replayed || count(original) != 2 {
			t.Fatal("identical lineage crossed an enrollment domain")
		}
	})
	t.Run("unpaired source does not gain runtime authority", func(t *testing.T) {
		const unpaired = "pid_78900014-0000-4000-8000-000000000014"
		seedRuntimeCandidateSensor(t, ctx, admin, scope, unpaired, "otlp")
		unpairedBatch := seedRuntimeCandidateBatch(t, ctx, admin, 15, unpaired, "otlp", 15)
		body, replayed := freeze(unpairedBatch)
		if replayed || count(body) != 0 {
			t.Fatal("unpaired source gained implicit runtime candidates")
		}
		var observations int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_candidate_observations WHERE batch_id=$1`, unpairedBatch[3]).Scan(&observations); err != nil || observations != 0 {
			t.Fatal("unpaired source admitted runtime candidate observations", err)
		}
	})
	t.Run("retained evidence refuses rollback", func(t *testing.T) {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback(context.Background())
		if _, err := transaction.Exec(ctx, migrations.ProductionRuntimeCandidateAuthority().DownSQL()); err == nil {
			t.Fatal("candidate rollback erased retained observations and snapshots")
		} else {
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != "55000" {
				t.Fatal("unexpected rollback refusal", err)
			}
		}
	})
	t.Run("replay requires live delivery", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_deliveries SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE batch_id=$1`, target[3]); err != nil {
			t.Fatal(err)
		}
		defer admin.Exec(ctx, `UPDATE zasp_runtime_deliveries SET lease_expires_at=clock_timestamp()+interval '1 hour' WHERE batch_id=$1`, target[3])
		var ignored []byte
		if err := worker.QueryRow(ctx, runtimeCandidateFreezeSQL, target...).Scan(&ignored); err == nil {
			t.Fatal("frozen replay ignored expired delivery")
		}
	})
	t.Run("replay rechecks worker after stage lock", func(t *testing.T) {
		observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close(context.Background())
		defer observer.Exec(ctx, `INSERT INTO zasp_runtime_principal_bindings(principal_name,authority_role) VALUES('candidate_correlation','zasp_runtime_correlation_worker') ON CONFLICT DO NOTHING`)
		err = blockedRuntimeCandidateCall(t, ctx, admin, worker, observer, target, `SELECT 1 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate' FOR UPDATE`, func(_ pgx.Tx) {
			if _, err := observer.Exec(ctx, `DELETE FROM zasp_runtime_principal_bindings WHERE principal_name='candidate_correlation'`); err != nil {
				t.Fatal(err)
			}
		})
		if err == nil {
			t.Fatal("frozen replay accepted worker revoked during stage lock wait")
		}
	})
	t.Run("snapshot foreign key wait cannot outlive lease", func(t *testing.T) {
		pending := seedRuntimeCandidateBatch(t, ctx, admin, 8, anchor, "tetragon", 0)
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE batch_id=$1 AND stage='correlate'`, pending[3]); err != nil {
			t.Fatal(err)
		}
		observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close(context.Background())
		err = blockedRuntimeCandidateCall(t, ctx, admin, worker, observer, pending, `SELECT 1 FROM zasp_runtime_batch_authorities WHERE batch_id=$1 FOR UPDATE`, func(_ pgx.Tx) {
			for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); {
				var expired bool
				if err := observer.QueryRow(ctx, `SELECT clock_timestamp()>lease_expires_at FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate'`, pending[3]).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
			t.Fatal("lease did not expire while foreign key was blocked")
		})
		if err == nil {
			t.Fatal("snapshot committed after lease expired during foreign-key wait")
		}
		var retained int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1`, pending[3]).Scan(&retained); err != nil || retained != 0 {
			t.Fatal("late snapshot was not rolled back", err)
		}
	})
	for index, enrollment := range []struct{ name, id, column string }{{"source", semantic, "source_sensor_id"}, {"anchor", anchor, "runtime_sensor_id"}} {
		t.Run(enrollment.name+" revocation during admission wait", func(t *testing.T) {
			pending := seedRuntimeCandidateBatch(t, ctx, admin, 10+index, semantic, "otlp", 10+index)
			observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(context.Background())
			defer admin.Exec(ctx, `UPDATE zasp_sensors SET state='active',revoked_at=NULL WHERE id=$1`, enrollment.id)
			err = blockedRuntimeCandidateCall(t, ctx, admin, worker, observer, pending, `SELECT 1 FROM zasp_sensors WHERE id=(SELECT `+enrollment.column+` FROM zasp_runtime_batch_domains WHERE batch_id=$1) FOR UPDATE`, func(blocker pgx.Tx) {
				if _, err := blocker.Exec(ctx, `UPDATE zasp_sensors SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1`, enrollment.id); err != nil {
					t.Fatal(err)
				}
			})
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
				t.Fatal("admission accepted an enrollment revoked during the lock wait", err)
			}
			var retained int
			if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1)+(SELECT count(*) FROM zasp_runtime_candidate_observations WHERE batch_id=$1)`, pending[3]).Scan(&retained); err != nil || retained != 0 {
				t.Fatal("revoked admission retained candidate evidence", err)
			}
		})
	}
	// Physical-boundary fixture: retained observations from a now-revoked source
	// must not consume an internal LIMIT and hide later viable identities. These
	// additional rows are seeded by the owner, not claimed as authenticated ingest.
	const freshSource = "pid_78900011-0000-4000-8000-000000000011"
	for _, query := range []string{
		`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Overflow fixture','otlp','active')`,
		`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,decode(repeat('ab',16),'hex'),digest($4,'sha256'),clock_timestamp()+interval '1 day')`,
	} {
		if _, err := admin.Exec(ctx, query, append(append([]any(nil), scope...), freshSource)...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES($1,$2,$3,$4,$5)`, append(append([]any(nil), scope...), freshSource, anchor)...); err != nil {
		t.Fatal(err)
	}
	freeze(seedRuntimeCandidateBatch(t, ctx, admin, 5, freshSource, "otlp", 3))
	freeze(seedRuntimeCandidateBatch(t, ctx, admin, 6, freshSource, "otlp", 4))
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_candidate_observations SELECT (jsonb_populate_record(NULL::zasp_runtime_candidate_observations,to_jsonb(original)||jsonb_build_object('event_ordinal',ordinal))).* FROM zasp_runtime_candidate_observations original CROSS JOIN generate_series(2,999) ordinal WHERE original.batch_id=$1 AND original.event_ordinal=1`, first[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_sensors SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1`, semantic); err != nil {
		t.Fatal(err)
	}
	overflow := seedRuntimeCandidateBatch(t, ctx, admin, 7, anchor, "tetragon", 0)
	var ignored []byte
	if err := worker.QueryRow(ctx, runtimeCandidateFreezeSQL, overflow...).Scan(&ignored); err == nil {
		t.Fatal("internal limit hid a later viable candidate behind revoked observations")
	}
	t.Run("historical frozen replay survives enrollment revocation", func(t *testing.T) {
		// The source was already revoked above. Revoke the target anchor too:
		// historical replay remains fixed, but it still needs a live worker lease.
		if _, err := admin.Exec(ctx, `UPDATE zasp_sensors SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1`, anchor); err != nil {
			t.Fatal(err)
		}
		defer admin.Exec(ctx, `UPDATE zasp_sensors SET state='active',revoked_at=NULL WHERE id=$1`, anchor)
		body, replayed := freeze(target)
		if !replayed || !bytes.Equal(body, frozen) {
			t.Fatal("historical snapshot changed after source and anchor revocation")
		}
	})
	t.Run("maximum target count remains bounded and fails closed", func(t *testing.T) {
		maximum := seedRuntimeCandidateBatchEvents(t, ctx, admin, 9, anchor, "tetragon", 0, 1000)
		statement, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer statement.Rollback(context.Background())
		if _, err := statement.Exec(ctx, `SET LOCAL statement_timeout='10s'`); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		err = statement.QueryRow(ctx, runtimeCandidateFreezeSQL, maximum...).Scan(&ignored)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "54000" {
			t.Fatal("maximum-target overflow did not fail closed within its database budget", err)
		}
		t.Logf("1000 distinct targets with 1001 bounded keys per target: overflow refusal in %s; owned local fixture, not production throughput", time.Since(started))
		if err := statement.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var retained int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1`, maximum[3]).Scan(&retained); err != nil || retained != 0 {
			t.Fatal("maximum-target overflow left a snapshot", err)
		}
	})
}

// Injected driver failures still pass through the production JSON adapter's
// sanitization. This is adapter evidence, not a claimed live server fault.
func assertCandidateRepositoryAdapterErrors(t *testing.T, ctx context.Context, args []any) {
	t.Helper()
	var digest [sha256.Size]byte
	copy(digest[:], args[9].([]byte))
	lease := runtimeevent.StageLease{Scope: fixtureRequestIdentity(t).Scope, BatchID: mustProductID(t, args[3].(string)), Generation: args[4].(int64), Stage: runtimeevent.RuntimeStageCorrelate, Attempt: args[7].(int), ImplementationVersion: args[8].(string), InputDigest: digest, PredecessorDigest: &digest, InputReference: "s3://zasp-evidence/index-receipt.json", InputVersionID: "index-v1", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
	for _, scenario := range []struct {
		code string
		want error
	}{{"54000", runtimeevent.ErrCandidateSnapshotOverflow}, {"42501", runtimeevent.ErrCandidateSnapshotDenied}, {"P0002", runtimeevent.ErrProductionPipelineUnavailable}, {"22023", runtimeevent.ErrProductionPipelineUnavailable}, {"40001", runtimeevent.ErrProductionPipelineUnavailable}, {"08006", runtimeevent.ErrProductionPipelineUnavailable}} {
		driver := &databaseDriver{rowErr: &pgconn.PgError{Code: scenario.code, Message: "provider-secret", Detail: "private-driver-detail"}}
		database, err := NewPostgresJSONDatabase(driver)
		if err != nil {
			t.Fatal(err)
		}
		repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
		if err != nil {
			t.Fatal(err)
		}
		_, err = repository.FreezeCandidates(ctx, lease, args[5].(string), args[6].(string), args[10].([]byte), args[11].([]byte))
		if !errors.Is(err, scenario.want) || len(driver.queryArguments) != 12 || strings.Contains(fmt.Sprint(err), "provider-secret") || strings.Contains(fmt.Sprint(err), "private-driver-detail") {
			t.Fatal("production adapter candidate error mapping", scenario.code, err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func seedRuntimeCandidateSensor(t *testing.T, ctx context.Context, admin *pgx.Conn, scope []any, sensor, kind string) {
	t.Helper()
	args := append(append([]any(nil), scope...), sensor, kind)
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Candidate isolation fixture',$5,'active')`, args...); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,decode(repeat('ab',16),'hex'),digest($4,'sha256'),clock_timestamp()+interval '1 day')`, args[:4]...); err != nil {
		t.Fatal(err)
	}
}

func proveRuntimeCandidateRunnerContention(t *testing.T, ctx context.Context, admin, worker *pgx.Conn, args []any) {
	t.Helper()
	migrator, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(context.Background())
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: migrator})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Rollback(context.Background())
	metadata := migrations.ProductionRuntimeCandidateAuthority()
	var ready bool
	if err := admission.QueryRow(ctx, `SELECT zasp_production_runtime_candidate_authority_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("worker preflight failed before runner contention", err)
	}
	for _, phase := range []string{"before snapshot access", "after snapshot insert"} {
		if phase == "after snapshot insert" {
			var response []byte
			if err := admission.QueryRow(ctx, runtimeCandidateFreezeSQL, args...).Scan(&response); err != nil {
				t.Fatal("worker failed after downgrade contention", err)
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		started := time.Now()
		err := runner.DownProductionRuntimeCandidateAuthority(attempt)
		elapsed := time.Since(started)
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || elapsed >= time.Second {
			t.Fatalf("runner did not promptly refuse contention %s: duration=%s error=%v", phase, elapsed, err)
		}
		var version int
		if err := admin.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&version); err != nil || version != 47 {
			t.Fatal("contended downgrade changed the schema", err)
		}
	}
	if err := admission.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}

func proveConcurrentRuntimeCandidateRollback(t *testing.T, ctx context.Context, admin, worker *pgx.Conn, args []any) {
	t.Helper()
	migrator, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(context.Background())
	admission, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Rollback(context.Background())
	var response []byte
	if err := admission.QueryRow(ctx, runtimeCandidateFreezeSQL, args...).Scan(&response); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		transaction, err := migrator.Begin(ctx)
		if err != nil {
			done <- err
			return
		}
		_, err = transaction.Exec(ctx, migrations.ProductionRuntimeCandidateAuthority().DownSQL())
		transaction.Rollback(context.Background())
		done <- err
	}()
	settled := false
	defer func() {
		admission.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("concurrent rollback did not drain")
			}
		}
	}()
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, migrator.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("rollback did not wait for the first uncommitted candidate admission")
	}
	if err := admission.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		settled = true
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "55000" {
			t.Fatal("rollback did not refuse newly committed evidence", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rollback did not settle after candidate admission committed")
	}
	var observations, snapshots int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_candidate_observations),(SELECT count(*) FROM zasp_runtime_candidate_snapshots)`).Scan(&observations, &snapshots); err != nil || observations != 1 || snapshots != 1 {
		t.Fatal("concurrent rollback lost candidate provenance", err)
	}
}

func blockedRuntimeCandidateCall(t *testing.T, ctx context.Context, admin, worker, observer *pgx.Conn, args []any, lockSQL string, whileBlocked func(pgx.Tx)) error {
	t.Helper()
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, lockSQL, args[3]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var output []byte
		done <- worker.QueryRow(ctx, runtimeCandidateFreezeSQL, args...).Scan(&output)
	}()
	settled := false
	defer func() {
		blocker.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("blocked candidate call did not drain")
			}
		}
	}()
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, worker.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("candidate call did not reach the expected database lock")
	}
	whileBlocked(blocker)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		settled = true
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("candidate call did not settle after lock release")
		return nil
	}
}

func seedRuntimeCandidateBatch(t *testing.T, ctx context.Context, admin *pgx.Conn, ordinal int, sensor, source string, candidate int) []any {
	t.Helper()
	return seedRuntimeCandidateBatchEvents(t, ctx, admin, ordinal, sensor, source, candidate, 1)
}

func seedRuntimeCandidateBatchEvents(t *testing.T, ctx context.Context, admin *pgx.Conn, ordinal int, sensor, source string, candidate, eventCount int) []any {
	t.Helper()
	scope := fixtureRequestIdentity(t).Scope
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	batch := fmt.Sprintf("pid_78900003-0000-4000-8000-%012d", ordinal)
	lineage := map[string]string{"profile": "kubernetes-container-v1", "cluster_uid": "78900004-0000-4000-8000-000000000004", "node_uid": "78900005-0000-4000-8000-000000000005", "boot_id": "78900006-0000-4000-8000-000000000006", "pod_uid": "78900007-0000-4000-8000-000000000007", "container_id": "containerd://" + strings.Repeat("b", 64), "process_id": "123", "process_start_time": "2026-09-10T10:00:00Z", "cgroup_id": "456"}
	event := map[string]any{"observed_lineage": lineage, "event_time": "2026-09-10T10:00:01.000Z", "evidence_id": fmt.Sprintf("pid_78900008-0000-4000-8000-%012d", ordinal)}
	if source == "otlp" {
		event["attributes"] = map[string]string{"event.id": fmt.Sprintf("candidate-event-%d", ordinal), "event.class": "tool", "event.action": "invoke", "agent.id": fmt.Sprintf("pid_78900009-0000-4000-8000-%012d", candidate), "session.id": fmt.Sprintf("pid_78900010-0000-4000-8000-%012d", candidate), "task.id": "candidate-task", "tool.id": "candidate-tool", "sandbox.id": "candidate-sandbox", "trace.id": strings.Repeat("a", 32), "span.id": strings.Repeat("b", 16)}
	} else {
		event["event_id"] = fmt.Sprintf("candidate-event-%d", ordinal)
		event["class"] = "process"
		event["action"] = "exec"
		event["workload_id"] = "candidate-runtime"
	}
	events := []any{event}
	if eventCount > 1 {
		if source != "tetragon" || eventCount > 1000 {
			t.Fatal("unsupported multi-event fixture")
		}
		events = make([]any, eventCount)
		for i := range events {
			copied := make(map[string]any, len(event))
			for key, value := range event {
				copied[key] = value
			}
			copied["event_id"] = fmt.Sprintf("candidate-event-%d-%d", ordinal, i)
			copied["evidence_id"] = fmt.Sprintf("pid_78900008-0000-4000-8000-%012d", ordinal*1000+i)
			copied["event_time"] = time.Date(2026, 9, 10, 10, 0, 1, i*int(time.Millisecond), time.UTC).Format("2006-01-02T15:04:05.000Z")
			events[i] = copied
		}
	}
	body, err := json.Marshal(map[string]any{"source": source, "events": events})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeevent.DecodeArchivedBatch(scope, body); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(body)
	indexDigest := sha256.Sum256([]byte("index-" + batch))
	rawReference := "s3://zasp-evidence/runtime/" + batch + ".json"
	indexBody, indexReceiptDigest, indexReference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: scope, BatchID: mustProductID(t, batch), Generation: int64(ordinal), InputReference: rawReference, InputVersionID: "raw-v1", InputDigest: archiveDigest, ArchiveReference: rawReference, ArchiveVersionID: "raw-v1", ArchiveDigest: archiveDigest, EffectDigest: indexDigest, ItemIDs: []string{"evt_" + strings.Repeat("c", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	indexObject := "s3://zasp-evidence/organizations/" + org + "/workspaces/" + workspace + "/environments/" + environment + "/artifacts/" + indexReference.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,$4,$5,$5,1,$6,$7,$8,$8,$9,'application/json','runtime-event-v1',$10,$13,$11,$12,'raw-v1',$8,$10,'fixture-kms-reference',clock_timestamp(),'processing')`, org, workspace, environment, batch, sensor, int64(ordinal), "candidate-request-"+batch, archiveDigest[:], source, len(body), "runtime/"+batch+".json", rawReference, eventCount); err != nil {
		t.Fatal(err)
	}
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) VALUES($1,$2,$3,$4,$5,'archive',1,'runtime-archive-v1',$6,'succeeded',1,$6,$7,'raw-v1',$6,clock_timestamp())`, []any{org, workspace, environment, batch, int64(ordinal), archiveDigest[:], rawReference}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) VALUES($1,$2,$3,$4,$5,'index',2,'runtime-index-v1',$6,$6,'succeeded',1,$7,$8,'index-v1',$9,clock_timestamp())`, []any{org, workspace, environment, batch, int64(ordinal), archiveDigest[:], indexDigest[:], indexObject, indexReceiptDigest[:]}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,$5,'correlate',3,'runtime-correlation-v2',$6,$6,'leased',1,'candidate-worker','candidate-lease-token-01',clock_timestamp()+interval '1 hour')`, []any{org, workspace, environment, batch, int64(ordinal), indexDigest[:]}},
		{`INSERT INTO zasp_runtime_deliveries(organization_id,workspace_id,environment_id,batch_id,batch_generation,message_id,message_digest,receive_count,disposition,lease_owner,lease_token,lease_expires_at,visibility_deadline) VALUES($1,$2,$3,$4,$5,$4,$6,1,'held','candidate-coordinator','coordinator-lease-token',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour')`, []any{org, workspace, environment, batch, int64(ordinal), archiveDigest[:]}},
	} {
		if _, err := admin.Exec(ctx, query.sql, query.args...); err != nil {
			t.Fatal(err)
		}
	}
	return []any{org, workspace, environment, batch, int64(ordinal), "candidate-worker", "candidate-lease-token-01", 1, "runtime-correlation-v2", indexDigest[:], indexBody, body}
}
