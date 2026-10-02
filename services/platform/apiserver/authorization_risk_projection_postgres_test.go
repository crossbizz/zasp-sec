package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Compatibility proof for the existing registered projection principal. This
// does not stand in for P7's separate forward-effect machine Check contract.
func TestP7RiskIsolationPreservesRegisteredProjection(t *testing.T) {
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cancel()
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
			if err := up(ctx); err != nil {
				t.Fatal("registered61 prerequisite", err)
			}
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE auth80_risk_scheduler LOGIN INHERIT;
CREATE ROLE auth80_risk_projection LOGIN INHERIT;
CREATE ROLE auth80_graph_projection LOGIN INHERIT;
CREATE ROLE auth80_search_projection LOGIN INHERIT;
SELECT zasp_execution_register_principals(session_user,'auth80_risk_scheduler','security_agent_v33_discovery_worker_login','auth80_risk_projection','auth80_graph_projection','auth80_search_projection')`); err != nil {
			t.Fatal("projection principal registration", err)
		}
		var principal string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_execution_principals WHERE authority_role='zasp_projection_risk_worker'`).Scan(&principal); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = principal
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		probe := func(stage string) {
			var principalReady, legacyReady bool
			principalErr := worker.QueryRow(ctx, `SELECT zasp_execution_principal_ready('zasp_projection_risk_worker')`).Scan(&principalReady)
			legacyErr := worker.QueryRow(ctx, `SELECT zasp_execution_readiness($1,$2)`, migrations.ProductionDiscoveryExecution().Checksum(), migrations.ProductionDiscoveryExecutionSemanticFingerprint()).Scan(&legacyReady)
			t.Logf("%s projection readiness principal=%v error=%v legacy=%v error=%v", stage, principalReady, principalErr, legacyReady, legacyErr)
			if principalErr != nil || legacyErr != nil || !principalReady || legacyReady {
				t.Fatal("unexpected canonical61 profile")
			}
		}
		probe("before80")
		var before, after string
		const sourceIdentity = `SELECT encode(digest(convert_to(pg_get_functiondef('public.zasp_execution_apply_risk_projection(text,text,text,text,text,text,text,text,text,bigint,bytea,jsonb)'::regprocedure),'UTF8'),'sha256'),'hex')`
		if err := owner.QueryRow(ctx, sourceIdentity).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationProjection(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationEnforcement(ctx); err != nil {
			t.Fatal(err)
		}
		probe("after80")
		if err := owner.QueryRow(ctx, sourceIdentity).Scan(&after); err != nil || before != after {
			t.Fatalf("source14 writer changed: %v", err)
		}
		input := seedAutomaticProjection(t, ctx, owner, automaticSourceIdentity(t, o, w, e, actor))
		var baselinePaths, baselineFindings int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_risk_attack_paths WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3),(SELECT count(*) FROM zasp_risk_findings WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3)`, o, w, e).Scan(&baselinePaths, &baselineFindings); err != nil || baselinePaths != 1 || baselineFindings != 0 {
			t.Fatalf("retained attack-path fixture baseline paths=%d findings=%d error=%v", baselinePaths, baselineFindings, err)
		}
		items := make([]map[string]any, 0, len(input.Items))
		for _, item := range input.Items {
			items = append(items, map[string]any{"section": item.Section, "id": item.ID.String(), "payload": item.Payload})
		}
		encoded, err := json.Marshal(items)
		if err != nil {
			t.Fatal(err)
		}
		call := func() (map[string]any, error) {
			var raw []byte
			err := worker.QueryRow(ctx, postgresExecutionApplyRiskProjectionSQL, o, w, e, input.SnapshotID.String(), input.Version, input.Worker, input.LeaseToken, input.IntegrationID.String(), input.Source, input.Generation, input.InputDigest[:], encoded).Scan(&raw)
			var result map[string]any
			if err == nil {
				err = json.Unmarshal(raw, &result)
			}
			return result, err
		}
		result, err := call()
		if err != nil || result["replayed"] != false || result["snapshot_id"] != input.SnapshotID.String() || !strings.HasPrefix(fmt.Sprint(result["driver_receipt"]), "postgres:risk-input:"+input.SnapshotID.String()+":sha256:") {
			t.Fatalf("registered native writer refused after isolation: %v", err)
		}
		var paths, findings int
		if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_risk_attack_paths WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3),(SELECT count(*) FROM zasp_risk_findings WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3)`, o, w, e).Scan(&paths, &findings); err != nil || paths != 2 || findings != 1 {
			t.Fatalf("native projection paths=%d findings=%d error=%v", paths, findings, err)
		}
		result, err = call()
		if err != nil || result["replayed"] != true {
			t.Fatalf("registered writer replay failed: %v", err)
		}
		var visible int
		var denied *pgconn.PgError
		if err = api.QueryRow(ctx, `SELECT count(*) FROM zasp_risk_attack_paths`).Scan(&visible); !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatalf("API inherited projection authority rows=%d error=%v", visible, err)
		}
		if _, err = worker.Exec(ctx, `SELECT * FROM zasp_risk_attack_paths`); err == nil {
			t.Fatal("projection login gained raw table access")
		}
		t.Log("Native SQL compatibility only: canonical61 intentionally closes old constructor readiness; deployed Temporal72 profile and P7 machine authority remain separate gates")
	})
}
