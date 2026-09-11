package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeCandidateAuthorityWorkerReadinessRejectsMissingFutureAndDriftedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
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
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatal("v1 rejected predecessor 46", err)
	}
	if repository.ReadyCandidates(ctx) != runtimeevent.ErrProductionPipelineUnavailable {
		t.Fatal("v2 accepted missing schema 47")
	}
	if err := runner.UpProductionRuntimeCandidateAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReadyCandidates(ctx); err != nil {
		t.Fatal("registered worker rejected exact schema 47", err)
	}
	for _, scenario := range []struct {
		name, change, restore string
		restoreArgs           []any
	}{
		{"future", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(48,'unexpected_future_release',repeat('a',64))`, `DELETE FROM zasp_schema_versions WHERE version=48`, nil},
		{"checksum", `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=47`, `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=47`, []any{migrations.ProductionRuntimeCandidateAuthority().Checksum()}},
		{"grant drift", `GRANT EXECUTE ON FUNCTION public.zasp_runtime_candidate_lineage_valid(jsonb,timestamptz) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION public.zasp_runtime_candidate_lineage_valid(jsonb,timestamptz) FROM PUBLIC`, nil},
		{"principal revoked", `REVOKE zasp_runtime_correlation_worker FROM candidate_correlation GRANTED BY zasp_discovery_authority`, `GRANT zasp_runtime_correlation_worker TO candidate_correlation GRANTED BY zasp_discovery_authority`, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, scenario.change); err != nil {
				t.Fatal(err)
			}
			if scenario.name == "principal revoked" {
				var member bool
				if err := admin.QueryRow(ctx, `SELECT pg_has_role('candidate_correlation','zasp_runtime_correlation_worker','MEMBER')`).Scan(&member); err != nil || member {
					t.Fatal("fixture did not revoke the registered grant", err)
				}
			}
			got := repository.ReadyCandidates(ctx)
			if _, err := admin.Exec(ctx, scenario.restore, scenario.restoreArgs...); err != nil {
				t.Fatal(err)
			}
			if got != runtimeevent.ErrProductionPipelineUnavailable {
				t.Fatal("v2 accepted drifted authority", got)
			}
			if err := repository.ReadyCandidates(ctx); err != nil {
				t.Fatal("restored authority stayed unready", err)
			}
		})
	}
}

func TestRuntimeAcceptanceCandidateWorkerReadinessRejectsReleaseDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority, runner.UpProductionRuntimeAcceptance} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
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
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.ReadyCandidates(ctx); err != nil {
		t.Fatal("registered candidate worker rejected exact schema48", err)
	}
	config.User = "invocation_discovery_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	apiRepository, err := NewPostgresRepository(apiDatabase)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name, change, restore string
		restoreArgs           []any
	}{
		{"future49", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(49,'unexpected_future_release',repeat('a',64))`, `DELETE FROM zasp_schema_versions WHERE version=49`, nil},
		{"release48 checksum", `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=48`, `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=48`, []any{migrations.ProductionRuntimeAcceptance().Checksum()}},
		{"release47 checksum", `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=47`, `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=47`, []any{migrations.ProductionRuntimeCandidateAuthority().Checksum()}},
		{"release48 fingerprint", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_acceptance_fingerprint'`, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_acceptance_fingerprint'`, []any{migrations.ProductionRuntimeAcceptanceSemanticFingerprint()}},
		{"acceptance grant drift", `GRANT EXECUTE ON FUNCTION public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text) FROM PUBLIC`, nil},
		{"principal revoked", `REVOKE zasp_runtime_correlation_worker FROM candidate_correlation GRANTED BY zasp_discovery_authority`, `GRANT zasp_runtime_correlation_worker TO candidate_correlation GRANTED BY zasp_discovery_authority`, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, scenario.change); err != nil {
				t.Fatal(err)
			}
			got := repository.ReadyCandidates(ctx)
			checkAPI := scenario.name != "principal revoked" && scenario.name != "release47 checksum"
			var apiErr error
			if checkAPI {
				apiErr = apiRepository.Ready(ctx)
			}
			if _, err := admin.Exec(ctx, scenario.restore, scenario.restoreArgs...); err != nil {
				t.Fatal(err)
			}
			if got != runtimeevent.ErrProductionPipelineUnavailable {
				t.Error("candidate worker accepted drifted release48 authority", got)
			}
			if checkAPI && apiErr == nil {
				t.Error("API accepted drifted release48 authority")
			}
			if err := repository.ReadyCandidates(ctx); err != nil {
				t.Fatal("restored release48 stayed unready", err)
			}
			if err := apiRepository.Ready(ctx); err != nil {
				t.Fatal("restored API release48 stayed unready", err)
			}
		})
	}
}
