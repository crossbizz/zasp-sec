package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func installRuntimeSandboxDraft(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	metadata := migrations.ProductionRuntimeSandboxBinding()
	if _, err := admin.Exec(ctx, metadata.UpSQL()); err != nil {
		var provider *pgconn.PgError
		if errors.As(err, &provider) {
			t.Logf("sandbox migration position=%d internal_position=%d context=%s query=%s", provider.Position, provider.InternalPosition, provider.Where, provider.InternalQuery)
		}
		t.Fatal(err)
	}
	var fingerprint string
	var secure bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_live_fingerprint(),zasp_production_runtime_sandbox_binding_security_ready()`).Scan(&fingerprint, &secure); err != nil || !secure || fingerprint != migrations.ProductionRuntimeSandboxBindingSemanticFingerprint() {
		var columns string
		_ = admin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('name',attname,'position',attnum,'dropped',attisdropped) ORDER BY attnum)::text FROM pg_attribute WHERE attrelid='zasp_runtime_candidate_observations'::regclass AND attnum>0`).Scan(&columns)
		t.Log("candidate observation catalog", columns)
		t.Fatalf("sandbox schema fingerprint=%s secure=%t error=%v", fingerprint, secure, err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_metadata(key,value) VALUES('production_runtime_sandbox_binding_checksum',$1)`, metadata.Checksum()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSandboxRoutingOldReadersLeaveV3WorkUntouched(t *testing.T) {
	for _, state := range []string{"pending", "retryable", "expired leased", "exhausted", "final attempt"} {
		t.Run(state, func(t *testing.T) { proveSandboxOldReadersLeaveV3Untouched(t, state) })
	}
}

func proveSandboxOldReadersLeaveV3Untouched(t *testing.T, state string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	args := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v3", nil)
	switch state {
	case "pending", "retryable":
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET state=$2,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE batch_id=$1 AND stage='correlate'`, args[3], state); err != nil {
			t.Fatal(err)
		}
	case "expired leased":
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
			t.Fatal(err)
		}
	case "exhausted", "final attempt":
		attempt := 100
		if state == "final attempt" {
			attempt = 99
		}
		// Seed attempts directly, without disabling or spoofing the mutation fence.
		if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt) VALUES($1,$2,$3,$4,$5,'correlate',3,'runtime-correlation-v3',$6,$6,'pending',$7)`, args[0], args[1], args[2], args[3], args[4], args[9], attempt); err != nil {
			t.Fatal(err)
		}
	}
	readState := func() string {
		t.Helper()
		var body string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('work',(SELECT jsonb_agg(to_jsonb(w) ORDER BY batch_id,stage) FROM zasp_runtime_stage_work w),'fairness',(SELECT jsonb_agg(to_jsonb(f) ORDER BY stage,organization_id) FROM zasp_runtime_stage_fairness f),'batch',(SELECT jsonb_agg(to_jsonb(b) ORDER BY batch_id) FROM zasp_runtime_batch_authorities b),'delivery',(SELECT jsonb_agg(to_jsonb(d) ORDER BY batch_id) FROM zasp_runtime_deliveries d))::text`).Scan(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	before := readState()
	for _, statement := range []string{`SELECT zasp_runtime_claim_stage('old-reader','old-reader-token-01',60,10)`, `SELECT zasp_runtime_claim_correlation_v2('v2-reader','v2-reader-token-01',60,10)`} {
		var claimed json.RawMessage
		if err := worker.QueryRow(ctx, statement).Scan(&claimed); err != nil {
			t.Fatal("old reader cannot drain its compatible backlog on50", err)
		}
		if string(claimed) != "[]" || readState() != before {
			t.Fatal("old reader mutated v3 work", string(claimed))
		}
	}
	var claimed json.RawMessage
	if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_correlation_v3('v3-reader','v3-reader-token-01',60,10)`).Scan(&claimed); err != nil {
		t.Fatal("v3 reader cannot claim new work", err)
	}
	var leases []struct {
		Batch   string `json:"batch_id"`
		Version string `json:"implementation_version"`
		Attempt int    `json:"attempt"`
	}
	if err := json.Unmarshal(claimed, &leases); err != nil {
		t.Fatal(err)
	}
	if state == "exhausted" {
		var terminal bool
		if err := admin.QueryRow(ctx, `SELECT state='failed' AND last_error_class='exhausted' AND attempt=100 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate'`, args[3]).Scan(&terminal); err != nil || !terminal || len(leases) != 0 {
			t.Fatal("v3 exhaustion didn't settle", string(claimed), err)
		}
	} else if len(leases) != 1 || leases[0].Batch != args[3] || leases[0].Version != "runtime-correlation-v3" || state == "final attempt" && leases[0].Attempt != 100 {
		t.Fatal("v3 routing mismatch", string(claimed))
	}
	var marker string
	if err := worker.QueryRow(ctx, `SELECT COALESCE(current_setting('zasp.runtime_correlation_claim_version',true),'')`).Scan(&marker); err != nil || marker != "" {
		t.Fatal("v3 reader leaked compatibility marker", marker, err)
	}
}

func TestRuntimeSandboxRoutingReadinessRejectsDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	metadata := migrations.ProductionRuntimeSandboxBinding()
	var ready bool
	if err := worker.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("valid sandbox readiness rejected", err)
	}
	for _, drift := range []struct{ name, sql string }{
		{"column grant", `GRANT SELECT(sandbox_id) ON zasp_runtime_candidate_observations TO zasp_runtime_correlation_worker`},
		{"private helper grant", `GRANT EXECUTE ON FUNCTION zasp_runtime_claim_stage_sandbox_compatible(text,text,integer,integer,boolean) TO PUBLIC`},
		{"session helper grant", `GRANT EXECUTE ON FUNCTION zasp_runtime_claim_session_stage_compatible(text,text,integer,integer,boolean) TO PUBLIC`},
		{"projection wrong role", `GRANT EXECUTE ON FUNCTION zasp_runtime_claim_projection_v2(text,text,integer,integer) TO zasp_runtime_coordinator`},
		{"completion wrong role", `GRANT EXECUTE ON FUNCTION zasp_runtime_claim_completion_v2(text,text,integer,integer) TO zasp_runtime_projection_worker`},
		{"session trigger disabled", `ALTER TABLE zasp_runtime_stage_work DISABLE TRIGGER zasp_runtime_session_claim_version`},
		{"projection readiness revoked", `REVOKE EXECUTE ON FUNCTION zasp_production_runtime_sandbox_binding_readiness(text,text) FROM zasp_runtime_projection_worker`},
		{"freeze body", `DO $d$ DECLARE body text; BEGIN SELECT pg_get_functiondef('zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure) INTO body; EXECUTE replace(body,'interval ''5 minutes''','interval ''6 minutes'''); END $d$`},
		{"missing fingerprint", `DELETE FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint'`},
		{"wrong checksum", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_sandbox_binding_checksum'`},
		{"future release", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(51,'unexpected_future_release',repeat('a',64))`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, drift.sql); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("drifted sandbox readiness didn't fail closed", ready, err)
			}
		})
	}
}

func TestRuntimeSandboxFreezeRejectsReleaseDrift(t *testing.T) {
	for _, replay := range []bool{false, true} {
		for _, drift := range []struct{ name, sql string }{
			{"missing fingerprint", `DELETE FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint'`},
			{"checksum drift", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_sandbox_binding_checksum'`},
			{"future release", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(51,'unexpected_future_release',repeat('a',64))`},
		} {
			name := "admission/" + drift.name
			if replay {
				name = "replay/" + drift.name
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				admin, worker := runtimeSandboxPredecessor(t, ctx)
				installRuntimeSandboxDraft(t, ctx, admin)
				args := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", nil)
				if replay {
					freezeSandboxFixture(t, ctx, worker, args)
				}
				state := func() string {
					t.Helper()
					var body string
					if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('observations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY batch_id,event_ordinal) FROM zasp_runtime_candidate_observations o),'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY batch_id,generation) FROM zasp_runtime_candidate_snapshots s))::text`).Scan(&body); err != nil {
						t.Fatal(err)
					}
					return body
				}
				before := state()
				if _, err := admin.Exec(ctx, drift.sql); err != nil {
					t.Fatal(err)
				}
				var payload []byte
				requireSandboxSQLState(t, worker.QueryRow(ctx, runtimeSandboxFreezeSQL, args...).Scan(&payload), "55000")
				if state() != before {
					t.Fatal("drifted release changed candidate history")
				}
			})
		}
	}
}

func TestRuntimeSandboxFreezeRechecksReadinessAfterAdmissionWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	args := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", nil)
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, args, runtimeSandboxFreezeSQL, `SELECT s.id FROM zasp_sensors s JOIN zasp_runtime_batch_authorities b ON b.sensor_id=s.id WHERE b.batch_id=$1 FOR UPDATE OF s`, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_sandbox_binding_checksum'`); err != nil {
			t.Fatal(err)
		}
	})
	requireSandboxSQLState(t, err, "55000")
	var empty bool
	if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_observations WHERE batch_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1)`, args[3]).Scan(&empty); err != nil || !empty {
		t.Fatal("post-wait readiness drift admitted evidence", err)
	}
}
