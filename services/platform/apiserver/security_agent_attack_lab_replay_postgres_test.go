package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Records the production database response without replacing its behavior.
type attackLabReplayDatabase struct {
	*PostgresJSONDatabase
	last json.RawMessage
}

func (d *attackLabReplayDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	raw, err := d.PostgresJSONDatabase.QueryJSON(ctx, q, args...)
	d.last = append(json.RawMessage(nil), raw...)
	return raw, err
}

// The classifier must not require the lease that a committed receipt cleared.
// Fresh operations and stale Prepare still need their operation's own authority.
func TestSecurityAgentAttackLabRepositoryReceiptReplayPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		const source = "pid_8a400001-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at)
 VALUES($1,$2,$3,$4,$5,1,$6,'complete',1,digest('replay-source','sha256'),'fail','s3://fixture-bucket/replay-source','replay-source','source-version',digest('replay-evidence','sha256'),100,clock_timestamp());
 INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at)
 SELECT organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,'controlled objective','controlled behavior','[]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at FROM zasp_red_team_runs WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, o, w, e, source, testID, actor); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		recording := &attackLabReplayDatabase{PostgresJSONDatabase: database}
		repository, err := NewSecurityAgentWorkerRepository(recording)
		if err != nil {
			t.Fatal(err)
		}
		const workerID, lease = "attack-lab-replay-worker", "attack-lab-replay-original-lease"
		index := 0
		for _, action := range []string{"start_attack_lab", "run_test", "rerun_test"} {
			for _, operation := range []string{"accept", "fail", "prepare"} {
				index++
				t.Run(action+"_"+operation, func(t *testing.T) {
					run := fmt.Sprintf("pid_8a4100%02d-0000-4000-8000-000000000001", index)
					finding := fmt.Sprintf("pid_8a4200%02d-0000-4000-8000-000000000001", index)
					approval := fmt.Sprintf("pid_8a4300%02d-0000-4000-8000-000000000001", index)
					audit := fmt.Sprintf("pid_8a4400%02d-0000-4000-8000-000000000001", index)
					correlation := fmt.Sprintf("pid_8a4500%02d-0000-4000-8000-000000000001", index)
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET version=version+1,body=jsonb_set(body,'{definition_version}',to_jsonb(version+1)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e); err != nil {
						t.Fatal(err)
					}
					seedExistingTestPreparation(t, ctx, owner, o, w, e, testID, actor, run, finding, action, workerID, lease)
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{verification_kind}',to_jsonb(CASE WHEN $4='start_attack_lab' THEN 'attack_lab_run' ELSE 'test_run' END)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$5 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, pgx.QueryExecModeSimpleProtocol, o, w, e, action, actor); err != nil {
						t.Fatal(err)
					}
					claim := SecurityAgentRunClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, RunID: run, TriggerID: finding, State: "planning", Version: 2, Attempt: 1}
					if err := owner.QueryRow(ctx, `SELECT definition_id,definition_version,lease_expires_at FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&claim.DefinitionID, &claim.DefinitionVersion, &claim.LeaseExpiresAt); err != nil {
						t.Fatal(err)
					}
					claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
					loaded, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
					if err != nil {
						t.Fatal(err)
					}
					expires := time.Now().UTC().Add(4 * time.Minute)
					invoke := func(c SecurityAgentRunClaim, token, model string) error {
						switch operation {
						case "accept":
							_, err := repository.AcceptSecurityAgentPlannerCandidate(ctx, c, workerID, token, SecurityAgentPlannerSubmission{InputDigest: loaded.InputDigest, OutputDigest: "sha256:" + strings.Repeat("a", 64), Model: model, PolicyVersion: "fixture-policy", Summary: "Run configured action", Action: action, TargetID: testID}, approval, expires, audit, correlation)
							return err
						case "fail":
							_, err := repository.FailSecurityAgentPlanner(ctx, c, workerID, token, SecurityAgentPlannerFailure{InputDigest: loaded.InputDigest, Model: model, PolicyVersion: "fixture-policy", ErrorCode: "planner_unavailable"}, audit, correlation)
							return err
						default:
							_, err := repository.PrepareSecurityAgentRun(ctx, c, workerID, token, approval, expires, audit, correlation)
							return err
						}
					}
					snapshot := func() string { return existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run) }
					before := snapshot()
					if err := invoke(claim, "attack-lab-replay-wrong-lease", "fixture-model"); err == nil || snapshot() != before {
						t.Fatalf("fresh work accepted wrong lease: %v", err)
					}
					for _, foreign := range []SecurityAgentRunClaim{func() SecurityAgentRunClaim {
						c := claim
						c.EnvironmentID = "pid_8affffff-0000-4000-8000-000000000001"
						return c
					}(), func() SecurityAgentRunClaim {
						c := claim
						c.RunID = "pid_8affffff-0000-4000-8000-000000000002"
						return c
					}()} {
						if err := invoke(foreign, lease, "fixture-model"); err == nil || snapshot() != before {
							t.Fatalf("foreign/missing run accepted: %v", err)
						}
					}
					if err := invoke(claim, lease, "fixture-model"); err != nil {
						t.Fatalf("first registered operation: %v", err)
					}
					first := append(json.RawMessage(nil), recording.last...)
					before = snapshot()
					if operation == "prepare" {
						if err := invoke(claim, lease, "fixture-model"); err == nil || snapshot() != before {
							t.Fatalf("stale Prepare authorized new work: %v", err)
						}
						return
					}
					if err := invoke(claim, lease, "fixture-model"); err != nil {
						t.Errorf("lost-response receipt blocked by repository route: %v", err)
					} else {
						var expected, got map[string]any
						json.Unmarshal(first, &expected)
						json.Unmarshal(recording.last, &got)
						expected["replayed"] = true
						want, _ := json.Marshal(expected)
						actual, _ := json.Marshal(got)
						if !equalIntegrationJSON(want, actual) || snapshot() != before {
							t.Errorf("retained response or authority changed: %s", recording.last)
						}
					}
					if err := invoke(claim, lease, "altered-model"); err == nil || snapshot() != before {
						t.Errorf("altered intent replayed: %v", err)
					}
					// A current definition edit must not reinterpret this exact-version receipt.
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET version=version+1,body=body||'{"allowed_actions":["update_finding_response"],"verification_kind":"finding_state"}'::jsonb WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e); err != nil {
						t.Fatal(err)
					}
					if err := invoke(claim, lease, "fixture-model"); err != nil || snapshot() != before {
						t.Errorf("exact-version history replay refused: %v", err)
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions d SET version=h.version,body=h.definition FROM zasp_security_agent_definition_versions h WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(h.organization_id,h.workspace_id,h.environment_id,h.definition_id) AND (h.organization_id,h.workspace_id,h.environment_id,h.version)=($1,$2,$3,$4)`, o, w, e, claim.DefinitionVersion); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	})
}
