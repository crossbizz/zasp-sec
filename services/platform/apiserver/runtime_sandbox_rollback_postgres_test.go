package apiserver

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Exercise the embedded reversal before registering the release runner. Every
// failure must roll back both catalog changes and the release record together.
func rollbackRuntimeSandboxDraft(ctx context.Context, admin *pgx.Conn) error {
	tx, err := admin.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, migrations.ProductionRuntimeSandboxBinding().DownSQL()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM zasp_schema_versions WHERE version=50`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func TestRuntimeSandboxRunnerRecognizesExactRelease50(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: admin})
	if err != nil {
		t.Fatal(err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 50 {
		t.Fatal("installed release50 unrecognized", version, err)
	}
	for _, version := range []int64{49, 50} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=$1`, version); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		_, err = runner.Version(ctx)
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if !errors.Is(err, migrations.ErrInvalidState) {
			t.Fatal("version accepted tampered release", version, err)
		}
	}
}

func TestRuntimeSandboxRunnerRoundTripAndContention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	migrator, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(context.Background())
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: migrator})
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []struct {
		name          string
		run           func(context.Context) error
		before, after int64
	}{
		{"up", runner.UpProductionRuntimeSandboxBinding, 49, 50},
		{"down", runner.DownProductionRuntimeSandboxBinding, 50, 49},
	} {
		for _, table := range []string{"zasp_schema_versions", "zasp_schema_metadata", "zasp_runtime_batch_authorities", "zasp_runtime_stage_work", "zasp_runtime_candidate_observations", "zasp_runtime_candidate_snapshots", "zasp_runtime_session_events", "zasp_runtime_session_projection_receipts", "zasp_runtime_session_search_outbox"} {
			t.Run(direction.name+"/"+table, func(t *testing.T) {
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, `LOCK TABLE `+pgx.Identifier{table}.Sanitize()+` IN ACCESS SHARE MODE`); err != nil {
					t.Fatal(err)
				}
				bounded, stop := context.WithTimeout(ctx, 2*time.Second)
				err = direction.run(bounded)
				timedOut := bounded.Err() != nil
				stop()
				if timedOut || !errors.Is(err, migrations.ErrDatabase) {
					t.Fatal("contention must fail immediately with database error", err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if version, err := runner.Version(ctx); err != nil || version != direction.before {
					t.Fatal("contended migration changed release", version, err)
				}
			})
		}
		if err := direction.run(ctx); err != nil {
			t.Fatal(direction.name, err)
		}
		if version, err := runner.Version(ctx); err != nil || version != direction.after {
			t.Fatal("completed migration version", version, err)
		}
	}
	if err := runner.UpProductionRuntimeSandboxBinding(ctx); err != nil {
		t.Fatal("runner reinstall", err)
	}
}

func TestRuntimeSandboxRollbackRestores49WithHistoricalEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	args := seedRuntimeCandidateBatch(t, ctx, admin, 1, sandboxSemantic, "otlp", 1)
	before := freezeSandboxFixture(t, ctx, worker, args)
	var observations string
	if err := admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(o) ORDER BY batch_id,event_ordinal)::text FROM zasp_runtime_candidate_observations o`).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	if err := rollbackRuntimeSandboxDraft(ctx, admin); err != nil {
		t.Fatal("safe rollback rejected", err)
	}
	var ready, restored bool
	prior := migrations.ProductionRuntimeCorrelationRouting()
	if err := worker.QueryRow(ctx, `SELECT zasp_production_runtime_correlation_routing_readiness($1,$2)`, prior.Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("exact schema49 contract not restored", ready, err)
	}
	if err := admin.QueryRow(ctx, `SELECT (SELECT jsonb_agg(to_jsonb(o) ORDER BY batch_id,event_ordinal) FROM zasp_runtime_candidate_observations o)=$1::jsonb AND NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key LIKE 'production_runtime_sandbox_binding_%') AND to_regprocedure('zasp_runtime_claim_correlation_v3(text,text,integer,integer)') IS NULL`, observations).Scan(&restored); err != nil || !restored {
		t.Fatal("rollback altered historical observations or retained new authority", err)
	}
	after := freezeSandboxFixture(t, ctx, worker, args)
	if !after.Replayed() || !bytes.Equal(before.Bytes(), after.Bytes()) || before.Digest() != after.Digest() {
		t.Fatal("rollback changed historical snapshot bytes")
	}
	installRuntimeSandboxDraft(t, ctx, admin)
}

func TestRuntimeSandboxRollbackRejectsRetainedV3AndReleaseDrift(t *testing.T) {
	for _, scenario := range []string{"v3 work", "sandbox evidence", "missing fingerprint", "wrong checksum", "future release"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, worker := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			switch scenario {
			case "v3 work", "sandbox evidence":
				args := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", nil)
				if scenario == "sandbox evidence" {
					freezeSandboxFixture(t, ctx, worker, args)
				}
			default:
				statement := map[string]string{
					"missing fingerprint": `DELETE FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint'`,
					"wrong checksum":      `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_sandbox_binding_checksum'`,
					"future release":      `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(51,'unexpected_future_release',repeat('a',64))`,
				}[scenario]
				if _, err := admin.Exec(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
			state := func() string {
				t.Helper()
				var value string
				if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('schema',(SELECT jsonb_agg(to_jsonb(v) ORDER BY version) FROM zasp_schema_versions v),'metadata',(SELECT jsonb_agg(to_jsonb(m) ORDER BY key) FROM zasp_schema_metadata m),'work',(SELECT jsonb_agg(to_jsonb(w) ORDER BY batch_id,stage) FROM zasp_runtime_stage_work w),'observations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY batch_id,event_ordinal) FROM zasp_runtime_candidate_observations o),'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY batch_id,generation) FROM zasp_runtime_candidate_snapshots s),'fingerprint',zasp_production_runtime_sandbox_binding_live_fingerprint())::text`).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := state()
			requireSandboxSQLState(t, rollbackRuntimeSandboxDraft(ctx, admin), "55000")
			if state() != before {
				t.Fatal("rejected rollback changed schema or evidence")
			}
			runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: admin})
			if err != nil {
				t.Fatal(err)
			}
			want := migrations.ErrInvalidState
			if scenario == "v3 work" || scenario == "sandbox evidence" {
				want = migrations.ErrDatabase
			}
			if err := runner.DownProductionRuntimeSandboxBinding(ctx); !errors.Is(err, want) {
				t.Fatal("runner rejection", err, "want", want)
			}
			if state() != before {
				t.Fatal("rejected runner changed schema or evidence")
			}
		})
	}
}

func TestRuntimeSandboxRollbackEvidenceGuardsIndependentOfWorkVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	args := seedRuntimeCandidateBatch(t, ctx, admin, 1, sandboxSemantic, "otlp", 1)
	freezeSandboxFixture(t, ctx, worker, args)
	other := seedRuntimeCandidateBatch(t, ctx, admin, 2, sandboxSemantic, "otlp", 1)
	installRuntimeSandboxDraft(t, ctx, admin)
	// Deliberately insert catalog-valid evidence as the fixture administrator.
	// No v3 work exists. Each evidence guard must independently prevent erasure.
	for _, scenario := range []struct {
		name, sql string
		args      []any
	}{
		{"known observation", `INSERT INTO zasp_runtime_candidate_observations SELECT (jsonb_populate_record(NULL::zasp_runtime_candidate_observations,to_jsonb(o)||jsonb_build_object('event_ordinal',2,'sandbox_id','retained-binding'))).* FROM zasp_runtime_candidate_observations o WHERE batch_id=$1`, []any{args[3]}},
		{"v2 snapshot", `INSERT INTO zasp_runtime_candidate_snapshots SELECT (jsonb_populate_record(NULL::zasp_runtime_candidate_snapshots,to_jsonb(s)||jsonb_build_object('batch_id',$2::text,'generation',$3::bigint,'snapshot_body',convert_to('{"schema":"runtime-candidate-snapshot-v2"}','UTF8'),'snapshot_digest',digest(convert_to('{"schema":"runtime-candidate-snapshot-v2"}','UTF8'),'sha256')))).* FROM zasp_runtime_candidate_snapshots s WHERE batch_id=$1`, []any{args[3], other[3], other[4]}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, scenario.sql, scenario.args...); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, migrations.ProductionRuntimeSandboxBinding().DownSQL())
			requireSandboxSQLState(t, err, "55000")
		})
	}
}
