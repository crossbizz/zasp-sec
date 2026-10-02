package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const multistepReservePlannerBudgetTestSQL = `SELECT zasp_security_agent_budget_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const multistepSettlePlannerBudgetTestSQL = `SELECT zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

func multistepBudgetRepositoryClaim() SecurityAgentRunClaim {
	return SecurityAgentRunClaim{OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003", RunID: "pid_78000001-0000-4000-8000-000000000001", DefinitionID: "pid_78000002-0000-4000-8000-000000000002", DefinitionVersion: 3, TriggerID: "pid_78000003-0000-4000-8000-000000000003", State: "planning", Version: 2, Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
}

func multistepBudgetFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, string), starters ...func(*testing.T) string) {
	t.Helper()
	runSecurityAgentAttackPathFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		for index, apply := range []func(context.Context) error{
			runner.UpProductionIntegrationSetup,
			runner.UpProductionIntegrationWebhook,
			runner.UpProductionRuntimeQueueReplay,
			runner.UpProductionRedTeamSafety,
			runner.UpProductionRedTeamInvocation,
			runner.UpProductionRedTeamArtifacts,
			runner.UpProductionRuntimeSessions,
			runner.UpProductionRuntimeSessionReads,
			runner.UpProductionRuntimeSessionSearch,
			runner.UpProductionRuntimeSessionQuery,
			runner.UpProductionRuntimeSessionEvidence,
			runner.UpProductionRuntimeEnrollmentPairing,
			runner.UpProductionReconciliationLanePlan,
			runner.UpProductionRuntimeCandidateAuthority,
			runner.UpProductionRuntimeAcceptance,
			runner.UpProductionRuntimeCorrelationRouting,
			runner.UpProductionRuntimeSandboxBinding,
			runner.UpProductionRuntimePrecision,
			runner.UpProductionAuditExports,
			runner.UpProductionSecurityAgentBudgets,
		} {
			if err := apply(ctx); err != nil {
				t.Fatalf("budget fixture migration%d: %v", 34+index, err)
			}
		}
		if version, err := runner.Version(ctx); err != nil || version != 53 {
			t.Fatalf("budget fixture release=%d: %v", version, err)
		}
		exercise(ctx, owner, dsn)
	}, starters...)
}

func multistepVersionedExistingTestFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string, string), starters ...func(*testing.T) string) {
	t.Helper()
	multistepBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const ws = "pid_6a000002-0000-4000-8000-000000000002"
		const env = "pid_6a000003-0000-4000-8000-000000000003"
		const target = "pid_89000011-0000-4000-8000-000000000001"
		const definition = "pid_89000012-0000-4000-8000-000000000002"
		const actor = "pid_89000014-0000-4000-8000-000000000004"
		if _, err := owner.Exec(ctx, `UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3);
 INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
 VALUES($1,$2,$3,$4,'agent_endpoint','Versioned draft target','active',now(),now(),'agent',now(),now()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/versioned_draft_0001","target_kinds":["agent_endpoint"]}}');
 SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,'pid_89000013-0000-4000-8000-000000000003',$4,'ref:red-team/versioned_draft_0001','read_only',1,decode(repeat('ab',32),'hex'),now()+interval '1 hour');
 INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
 VALUES($1,$2,$3,$5,'Versioned draft test',$4,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}',$6)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, target, definition, actor); err != nil {
			t.Fatal(err)
		}
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = "security_agent_v33_api_login"
		api, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close(context.Background())
		exercise(ctx, owner, api, org, ws, env, definition, actor)
	}, starters...)
}

func multistepSeedExistingTestSimulationEvidence(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, actor string) string {
	t.Helper()
	const evidence = "pid_89e23800-0000-4000-8000-000000000004"
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name) VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000001','kubernetes','1','Simulation fixture');
 INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000002','pid_89e23800-0000-4000-8000-000000000001','lifecycle-evidence-sync-0001',decode(repeat('ab',32),'hex'),'manual',$4,'1','1');
 INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,complete,collected_at) VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000003','pid_89e23800-0000-4000-8000-000000000001','pid_89e23800-0000-4000-8000-000000000002',1,'kubernetes','s3://zasp-evidence/lifecycle/manifest.json',decode(repeat('ab',32),'hex'),'candidate',decode(repeat('ab',32),'hex'),false,clock_timestamp());
 INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at) VALUES($1,$2,$3,$5,'pid_89e23800-0000-4000-8000-000000000001','pid_89e23800-0000-4000-8000-000000000003','pid_89000011-0000-4000-8000-000000000001','s3://zasp-evidence/lifecycle/evidence.json',decode(repeat('ab',32),'hex'),'application/json','1','1',clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, org, ws, env, actor, evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func multistepValidReservationTestPermit(payload json.RawMessage, claim SecurityAgentRunClaim, digest string, tokens, cost int64, reservationIDs ...string) bool {
	reservationID := "new-reservation"
	if len(reservationIDs) == 1 {
		reservationID = reservationIDs[0]
	}
	var envelope struct {
		Permit struct {
			OrganizationID string    `json:"organization_id"`
			WorkspaceID    string    `json:"workspace_id"`
			EnvironmentID  string    `json:"environment_id"`
			RunID          string    `json:"run_id"`
			Attempt        int       `json:"attempt"`
			Version        int64     `json:"version"`
			ExpiresAt      time.Time `json:"expires_at"`
			ReservationID  string    `json:"reservation_id"`
			InputDigest    string    `json:"input_digest"`
			Model          string    `json:"model"`
			Policy         string    `json:"cost_policy_version"`
			Unit           string    `json:"cost_unit"`
			Tokens         int64     `json:"maximum_tokens"`
			Cost           int64     `json:"maximum_cost_nano_credits"`
		} `json:"budget_permit"`
	}
	if json.Unmarshal(payload, &envelope) != nil {
		return false
	}
	p := envelope.Permit
	return p.OrganizationID == claim.OrganizationID && p.WorkspaceID == claim.WorkspaceID && p.EnvironmentID == claim.EnvironmentID && p.RunID == claim.RunID && p.Attempt == claim.Attempt && p.Version == claim.Version && !p.ExpiresAt.IsZero() && p.ReservationID == reservationID && p.InputDigest == digest && p.Model == "fixture-model" && p.Policy == "fixture-policy" && p.Unit == "openrouter_credit" && p.Tokens == tokens && p.Cost == cost
}

func multistepBudgetWorkerBinary(t *testing.T, ctx context.Context) string {
	t.Helper()
	if binary, present := os.LookupEnv("ZASP_BUDGET_PROVIDER_WORKER_BINARY"); present {
		if err := multistepValidateBudgetWorkerBinary(binary); err != nil {
			t.Fatalf("invalid prebuilt budget worker: %v", err)
		}
		return binary
	}
	binary := filepath.Join(t.TempDir(), "budget-provider-worker.test")
	if output, err := runSandboxWorkerCommand(ctx, exec.Command("go", "test", "-race", "-c", "-o", binary, "../agentsec-worker")); err != nil {
		t.Fatalf("compile owned budget worker: %v\n%s", err, output)
	}
	return binary
}

func multistepValidateBudgetWorkerBinary(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("budget worker binary must be an absolute path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("budget worker binary must be a regular executable file")
	}
	return nil
}
