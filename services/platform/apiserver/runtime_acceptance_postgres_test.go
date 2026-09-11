package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeAcceptanceRunnerRefusesActiveReadersWithoutHoldingSensorLocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	worker, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	for _, phase := range []struct {
		name    string
		version int64
		migrate func(context.Context) error
	}{
		{"upgrade", 47, runner.UpProductionRuntimeAcceptance},
		{"rollback", 48, runner.DownProductionRuntimeAcceptance},
	} {
		for _, table := range []string{"zasp_schema_versions", "zasp_sensors", "zasp_schema_metadata"} {
			t.Run(phase.name+"/"+table, func(t *testing.T) {
				tx, err := worker.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, `SELECT 1 FROM `+pgx.Identifier{table}.Sanitize()+` LIMIT 1`); err != nil {
					t.Fatal(err)
				}
				// The reader retains its catalog lock while it next needs sensors.
				// A migration waiting on that reader must not retain sensor locks.
				attemptCtx, attemptCancel := context.WithTimeout(ctx, 2*time.Second)
				defer attemptCancel()
				if err := phase.migrate(attemptCtx); !errors.Is(err, migrations.ErrDatabase) || attemptCtx.Err() != nil {
					t.Fatalf("migration must refuse contention before its deadline: err=%v context=%v", err, attemptCtx.Err())
				}
				if _, err := tx.Exec(attemptCtx, `SELECT 1 FROM zasp_sensors LIMIT 1`); err != nil {
					t.Fatal("reader could not continue after migration refusal", err)
				}
				if version, err := runner.Version(attemptCtx); err != nil || version != phase.version {
					t.Fatal("contended migration changed schema", version, err)
				}
			})
			if t.Failed() {
				t.FailNow()
			}
		}
		if err := phase.migrate(ctx); err != nil {
			t.Fatal("uncontended migration failed after reader release", err)
		}
	}
}

func TestRuntimeAcceptanceRunnerAndAPIStartup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for cycle := 0; cycle < 2; cycle++ {
		if err := runner.UpProductionRuntimeAcceptance(ctx); err != nil {
			t.Fatal("acceptance runner upgrade", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 48 {
			t.Fatal("acceptance runner version", version, err)
		}
		config := admin.Config().Copy()
		config.User = "invocation_discovery_api"
		api, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			_ = api.Close(ctx)
			t.Fatal(err)
		}
		repository, err := NewPostgresRepository(database)
		if err != nil {
			_ = api.Close(ctx)
			t.Fatal(err)
		}
		err = repository.Ready(ctx)
		_ = api.Close(ctx)
		if err != nil {
			t.Fatal("actual API startup rejected schema48", err)
		}
		if err := runner.DownProductionRuntimeAcceptance(ctx); err != nil {
			t.Fatal("acceptance runner rollback", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 47 {
			t.Fatal("acceptance rollback version", version, err)
		}
	}
}

func TestRuntimeAcceptanceMigrationPreservesCandidateReadinessAndRollback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var before string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_candidate_authority_live_fingerprint()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	metadata := migrations.ProductionRuntimeAcceptance()
	if _, err := tx.Exec(ctx, metadata.UpSQL()); err != nil {
		t.Fatal(err)
	}
	var live, expected string
	var secure bool
	if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_acceptance_live_fingerprint(),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_acceptance_fingerprint'),zasp_production_runtime_acceptance_security_ready()`).Scan(&live, &expected, &secure); err != nil || !secure || live != expected {
		t.Fatalf("acceptance fingerprint secure=%t live=%s expected=%s err=%v", secure, live, expected, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_acceptance_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("acceptance readiness", err)
	}
	prior := migrations.ProductionRuntimeCandidateAuthority()
	if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_candidate_authority_readiness($1,$2)`, prior.Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("candidate compatibility readiness", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM zasp_schema_versions WHERE version=48`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, metadata.DownSQL()); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_candidate_authority_live_fingerprint()`).Scan(&after); err != nil || after != before {
		t.Fatal("rollback changed candidate fingerprint", err)
	}
}
