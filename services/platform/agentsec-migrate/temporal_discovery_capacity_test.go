package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

const capacityIntegration = "pid_72900001-0000-4000-8000-000000000001"
const capacitySchedule = "pid_72900002-0000-4000-8000-000000000002"
const capacityLegacyJob = "pid_72900003-0000-4000-8000-000000000003"

func capacityCloneIntegration(t *testing.T, f scheduleReplayFixture) {
	capacityCloneIntegrationAs(t, f, capacityIntegration, capacitySchedule, "pid_72900004-0000-4000-8000-000000000004")
}

func capacityCloneIntegrationAs(t *testing.T, f scheduleReplayFixture, integration, schedule, connection string) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) SELECT organization_id,workspace_id,environment_id,$2,kind,connector_version,display_name||' second',configuration,state FROM zasp_integrations WHERE id=$1`,
		`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,id,integration_id,provider,connection_reference,state,verified_at) SELECT organization_id,workspace_id,environment_id,'pid_72900004-0000-4000-8000-000000000004',$2,provider,connection_reference,state,verified_at FROM zasp_integration_connections WHERE integration_id=$1`,
		`INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source) SELECT organization_id,workspace_id,environment_id,$2,'pid_72900004-0000-4000-8000-000000000004',provider,subject_kind,subject_id,connection_version,configuration_digest,source FROM zasp_discovery_connection_subjects WHERE integration_id=$1`,
		`INSERT INTO zasp_discovery_schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,state,next_run_at) SELECT organization_id,workspace_id,environment_id,'pid_72900002-0000-4000-8000-000000000002',$2,cadence_seconds,state,next_run_at FROM zasp_discovery_schedules WHERE integration_id=$1`,
	} {
		q = strings.ReplaceAll(q, "pid_72900004-0000-4000-8000-000000000004", connection)
		q = strings.ReplaceAll(q, capacitySchedule, schedule)
		if _, err := f.owner.Exec(f.ctx, q, replayIntegration, integration); err != nil {
			t.Fatal("second integration fixture", err)
		}
	}
}

func capacityAdmit(t *testing.T, f scheduleReplayFixture, worker *pgx.Conn, schedule, integration string) (orchestration.DiscoveryStart, time.Time) {
	t.Helper()
	var nominal, deadline time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT anchor FROM zasp_temporal72.schedules WHERE id=$1`, schedule).Scan(&nominal); err != nil {
		t.Fatal(err)
	}
	if nominal.Nanosecond() != 0 {
		nominal = nominal.Truncate(time.Second).Add(time.Second)
	}
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,$6)`, replayOrg, replayWorkspace, replayEnvironment, schedule, integration, nominal).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var admitted orchestration.DiscoveryAdmission
	if json.Unmarshal(raw, &admitted) != nil || admitted.Start == nil {
		t.Fatal("capacity admission", string(raw))
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT deadline FROM zasp_temporal72.runs WHERE job_id=$1`, admitted.Start.Ref.RunID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	return *admitted.Start, deadline
}

func capacityLegacy(t *testing.T, f scheduleReplayFixture, integration string) {
	t.Helper()
	var raw []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,'pid_72900005-0000-4000-8000-000000000005',$6,'pid_72900006-0000-4000-8000-000000000006','capacity-retained-729',decode(repeat('ab',32),'hex'),'manual','parser_v1','tool_v1')`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, integration, capacityLegacyJob).Scan(&raw); err != nil {
		t.Fatal("retained request", err)
	}
}

func capacityPrepare(t *testing.T, f scheduleReplayFixture, worker *pgx.Conn, start orchestration.DiscoveryStart, deadline time.Time) map[string]json.RawMessage {
	t.Helper()
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,0,'')`, start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID, start.IntegrationID, start.InputDigest, deadline).Scan(&raw); err != nil {
		t.Fatal("prepare", err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTemporalDiscoverySymmetricOwnershipPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixture(t)
	prepared := capacityPrepare(t, f, worker, start, deadline)
	if prepared["effect_id"] == nil {
		t.Fatal("first owner did not acquire")
	}
	capacityLegacy(t, f, replayIntegration)
	var raw []byte
	err := worker.QueryRow(f.ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001',30)`, replayOrg, replayWorkspace, replayEnvironment, capacityLegacyJob).Scan(&raw)
	if err == nil {
		t.Fatalf("retained claim acquired while72 has unresolved provider authority: %s", raw)
	}
	if pgerr, ok := err.(*pgconn.PgError); !ok || pgerr.Code != "23502" {
		t.Fatal("unexpected direct-old compatibility error", err)
	}
	var unchanged bool
	if err := f.owner.QueryRow(f.ctx, `SELECT state='queued' AND attempt=0 AND lease_owner IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations WHERE sync_id=job.authority_id) FROM zasp_discovery_jobs job WHERE id=$1`, capacityLegacyJob).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("blocked claim changed authority", unchanged, err)
	}
	var effect string
	if json.Unmarshal(prepared["effect_id"], &effect) != nil {
		t.Fatal("effect")
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,'{"outcome":"outcome_unknown"}')`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, effect).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.settle($1,$2,$3,$4,$5,$6,$7,'cancelled','')`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, start.IntegrationID, start.InputDigest, deadline).Scan(&raw); err != nil || !strings.Contains(string(raw), "outcome_unknown") {
		t.Fatal("unknown settlement", string(raw), err)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.claim_retained_delivery($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001',30)`, replayOrg, replayWorkspace, replayEnvironment, capacityLegacyJob).Scan(&raw); err != nil || !strings.Contains(string(raw), `"busy"`) {
		t.Fatal("unknown72 released ownership", string(raw), err)
	}
}

func TestTemporalDiscoverySharedCapacityPostgres(t *testing.T) {
	f, worker, first, deadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) {
		capacityCloneIntegration(t, f)
		if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_discovery_execution_quotas(organization_id,max_active_jobs) VALUES($1,1)`, replayOrg); err != nil {
			t.Fatal(err)
		}
	})
	if capacityPrepare(t, f, worker, first, deadline)["effect_id"] == nil {
		t.Fatal("first capacity owner did not acquire")
	}
	var nominal, secondDeadline time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT anchor FROM zasp_temporal72.schedules WHERE id=$1`, capacitySchedule).Scan(&nominal); err != nil {
		t.Fatal(err)
	}
	if nominal.Nanosecond() != 0 {
		nominal = nominal.Truncate(time.Second).Add(time.Second)
	}
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,$6)`, replayOrg, replayWorkspace, replayEnvironment, capacitySchedule, capacityIntegration, nominal).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var second orchestration.DiscoveryAdmission
	if json.Unmarshal(raw, &second) != nil || second.Start == nil {
		t.Fatal("second admission", string(raw))
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT deadline FROM zasp_temporal72.runs WHERE job_id=$1`, second.Start.Ref.RunID).Scan(&secondDeadline); err != nil {
		t.Fatal(err)
	}
	result := capacityPrepare(t, f, worker, *second.Start, secondDeadline)
	var wait orchestration.DiscoveryPage
	if result["effect_id"] != nil || result["input"] != nil || json.Unmarshal(result["page"], &wait) != nil || wait.Outcome != "retryable" {
		t.Fatalf("second integration bypassed org quota1: %s", result)
	}
	var noAuthority bool
	if err := f.owner.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations WHERE sync_id=(SELECT sync_id FROM zasp_temporal72.runs WHERE job_id=$1)) AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.page_effects WHERE job_id=$1)`, second.Start.Ref.RunID).Scan(&noAuthority); err != nil || !noAuthority {
		t.Fatal("capacity wait granted effect authority", noAuthority, err)
	}
}

func TestTemporalDiscoveryRetainedPreparationPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) { capacityCloneIntegration(t, f) })
	capacityLegacy(t, f, replayIntegration)
	var raw []byte
	claim := `SELECT zasp_temporal72.claim_retained_delivery($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001',30)`
	claimArgs := []any{replayOrg, replayWorkspace, replayEnvironment, capacityLegacyJob}
	if err := worker.QueryRow(f.ctx, claim, claimArgs...).Scan(&raw); err != nil || !strings.Contains(string(raw), `"claimed"`) {
		t.Fatal("first retained claim", string(raw), err)
	}
	input := `SELECT zasp_execution_job_input($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001')`
	if err := worker.QueryRow(f.ctx, input, claimArgs...).Scan(&raw); err != nil {
		t.Fatal("retained first input", err)
	}
	if err := worker.QueryRow(f.ctx, input, claimArgs...).Scan(&raw); err == nil {
		t.Fatal("same prepared attempt authorized a second send")
	}
	result := capacityPrepare(t, f, worker, start, deadline)
	if result["effect_id"] != nil || result["page"] == nil {
		t.Fatal("72 bypassed retained preparation", result)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_execution_finish_job($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001','failed',decode(repeat('bc',32),'hex'),'outcome_unknown','unknown provider outcome',0)`, claimArgs...).Scan(&raw); err != nil {
		t.Fatal("retained unknown settlement", err)
	}
	if err := worker.QueryRow(f.ctx, claim, claimArgs...).Scan(&raw); err == nil {
		t.Fatalf("quarantined retained preparation acknowledged/dispatched: %s", raw)
	} else if pgerr, ok := err.(*pgconn.PgError); !ok || pgerr.Code != "55P03" {
		t.Fatal("quarantine not retriable pending evidence", err)
	}
	var retained bool
	if err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal72.active_owners($1) WHERE job_id=$2 AND ownership='legacy') AND (SELECT count(*) FROM zasp_temporal72.retained_dispatches WHERE job_id=$2)=1`, replayOrg, capacityLegacyJob).Scan(&retained); err != nil || !retained {
		t.Fatal("unresolved effect released capacity", retained, err)
	}
}

func TestTemporalDiscoveryPreexistingPreparationPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	capacityLegacy(t, f, replayIntegration)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.discovery
	worker, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(f.ctx)
	args := []any{replayOrg, replayWorkspace, replayEnvironment, capacityLegacyJob}
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'preexisting-worker','preexisting-token-0001',900)`, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	query := `SELECT zasp_execution_job_input($1,$2,$3,$4,'preexisting-worker','preexisting-token-0001')`
	if err := worker.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil {
		t.Fatal("pre72 dispatch", err)
	}
	runDiscoveryCLI(t, f, false)
	if err := worker.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("pre72 unresolved generation authorized another input after cutover")
	} else if pgerr, ok := err.(*pgconn.PgError); !ok || pgerr.Code != "55P03" {
		t.Fatal("cutover uncertainty not pending", err)
	}
	var retained bool
	if err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal72.active_owners($1) WHERE job_id=$2 AND ownership='legacy') AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.retained_dispatches) AND (SELECT count(*) FROM zasp_discovery_generation_reservations)=1`, replayOrg, capacityLegacyJob).Scan(&retained); err != nil || !retained {
		t.Fatal("pre72 uncertainty discarded or reauthorized", retained, err)
	}
}

func TestTemporalDiscoveryBulkCapacityProgressPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixture(t)
	capacityPrepare(t, f, worker, start, deadline)
	capacityLegacy(t, f, replayIntegration)
	otherOrg := "pid_72900007-0000-4000-8000-000000000007"
	// One older blocked tenant and one later independent tenant. The same IDs
	// deliberately recur across tenants; every eligibility lookup must be scoped.
	for _, q := range []string{
		`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) SELECT $2,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state FROM zasp_integrations WHERE organization_id=$1`,
		`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,id,integration_id,provider,connection_reference,state,verified_at) SELECT $2,workspace_id,environment_id,id,integration_id,provider,connection_reference,state,verified_at FROM zasp_integration_connections WHERE organization_id=$1`,
		`INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source) SELECT $2,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source FROM zasp_discovery_connection_subjects WHERE organization_id=$1`,
	} {
		if _, err := f.owner.Exec(f.ctx, q, replayOrg, otherOrg); err != nil {
			t.Fatal(err)
		}
	}
	var raw []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,'pid_72900005-0000-4000-8000-000000000005',$6,'pid_72900006-0000-4000-8000-000000000006','capacity-independent-729',decode(repeat('ab',32),'hex'),'manual','parser_v1','tool_v1')`, otherOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, capacityLegacyJob).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_execution_claim_jobs('capacity-bulk','capacity-bulk-token-0001',30,1)`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Items []struct {
			OrganizationID string `json:"organization_id"`
			ID             string `json:"id"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &response) != nil || len(response.Items) != 1 || response.Items[0].OrganizationID != otherOrg || response.Items[0].ID != capacityLegacyJob {
		t.Fatalf("oldest blocked tenant starved independent tenant at limit1: %s", raw)
	}
	var unchanged bool
	if err := f.owner.QueryRow(f.ctx, `SELECT state='queued' AND attempt=0 AND lease_owner IS NULL FROM zasp_discovery_jobs WHERE organization_id=$1 AND id=$2`, replayOrg, capacityLegacyJob).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("bulk skip granted authority", unchanged, err)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_discovery_claim_jobs('capacity-bulk','capacity-bulk-token-0001',30,1,'discovery')`).Scan(&raw); err == nil {
		t.Fatal("retired SQL10 discovery grant restored")
	}
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest) VALUES($1,$2,$3,'pid_72900009-0000-4000-8000-000000000009','runtime','pid_72900010-0000-4000-8000-000000000010','capacity-retained-runtime',decode(repeat('ac',32),'hex'))`, replayOrg, replayWorkspace, replayEnvironment); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.runtime
	runtime, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(f.ctx)
	if err := runtime.QueryRow(f.ctx, `SELECT zasp_discovery_claim_jobs('capacity-runtime','capacity-runtime-token-0001',30,1,'runtime')`).Scan(&raw); err != nil || !strings.Contains(string(raw), "pid_72900009-0000-4000-8000-000000000009") {
		t.Fatal("retained runtime claim changed", string(raw), err)
	}
}

func TestTemporalDiscoveryCapacityCollectorIOPostgres(t *testing.T) {
	for _, mode := range []string{"temporal_same_resource", "legacy_same_resource", "temporal_quota", "legacy_quota"} {
		t.Run(mode, func(t *testing.T) {
			quota := strings.HasSuffix(mode, "quota")
			f, worker, start, deadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) {
				for _, q := range []string{`UPDATE zasp_integrations SET configuration=jsonb_set(configuration,'{external_id_reference}','"ref:aws/external-id/customer-0001"') WHERE id=$1`, `UPDATE zasp_integration_connections SET connection_reference='ref:aws/external-id/customer-0001' WHERE integration_id=$1`, `UPDATE zasp_discovery_connection_subjects SET configuration_digest=(SELECT digest(convert_to(configuration::text,'UTF8'),'sha256') FROM zasp_integrations WHERE id=$1) WHERE integration_id=$1`} {
					if _, err := f.owner.Exec(f.ctx, q, replayIntegration); err != nil {
						t.Fatal(err)
					}
				}
				if quota {
					capacityCloneIntegration(t, f)
					if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_discovery_execution_quotas(organization_id,max_active_jobs) VALUES($1,1)`, replayOrg); err != nil {
						t.Fatal(err)
					}
				}
			})
			integration := replayIntegration
			if quota {
				integration = capacityIntegration
			}
			capacityLegacy(t, f, integration)
			cfg := f.owner.Config()
			dsn := (&url.URL{Scheme: "postgres", User: url.User(f.registration.discovery), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
			start.Continuation = &orchestration.DiscoveryContinuation{Deadline: deadline}
			encoded, _ := json.Marshal(start)
			order := "temporal"
			if strings.HasPrefix(mode, "legacy") {
				order = "legacy"
			}
			child := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestDiscoveryCapacityInstalledIO$", "-count=1", "-v")
			child.Env = append(os.Environ(), "ZASP_P4B_FIX1_WORKER_DSN="+dsn, "ZASP_P4B_START="+string(encoded), "ZASP_P4B_FIX1_LEGACY_JOB="+capacityLegacyJob, "ZASP_P4B_FIX1_ORDER="+order)
			if quota {
				child.Env = append(child.Env, "ZASP_P4B_FIX1_OWNER_DSN="+f.owner.Config().ConnString())
				if order == "legacy" {
					child.Env = append(child.Env, "ZASP_P4B_FIX1_HISTORICAL_EDGE=1")
				}
			}
			output, err := child.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatal("actual mixed-owner collector child", err)
			}
			var valid bool
			if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_discovery_syncs WHERE state='succeeded')=2 AND (SELECT count(*) FROM zasp_discovery_snapshot_inputs WHERE jsonb_array_length(entities)>0)=2 AND (SELECT count(*) FROM zasp_projection_work)=6 AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.active_owners($1)) AND (SELECT deadline FROM zasp_temporal72.runs WHERE job_id=$2)=$3`, replayOrg, start.Ref.RunID, deadline).Scan(&valid); err != nil || !valid {
				var diagnostic []byte
				if diagErr := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_object('syncs',(SELECT jsonb_agg(jsonb_build_object('id',id,'state',state,'code',last_error_code,'error',last_error)) FROM zasp_discovery_syncs),'jobs',(SELECT jsonb_agg(jsonb_build_object('id',id,'state',state,'attempt',attempt,'error',last_error)) FROM zasp_discovery_jobs),'snapshots',(SELECT jsonb_agg(jsonb_build_object('sync',s.sync_id,'generation',s.generation,'entities',jsonb_array_length(i.entities))) FROM zasp_discovery_snapshots s JOIN zasp_discovery_snapshot_inputs i ON i.snapshot_id=s.id),'projections',(SELECT count(*) FROM zasp_projection_work),'owners',(SELECT jsonb_agg(to_jsonb(o)) FROM zasp_temporal72.active_owners($1) o),'deadline',(SELECT deadline=$2 FROM zasp_temporal72.runs))`, replayOrg, deadline).Scan(&diagnostic); diagErr == nil {
					t.Log("persisted collector diagnostics", string(diagnostic))
				}
				t.Fatal("verified terminal release/nonempty inventories/original deadline", valid, err)
			}
			if quota {
				capacityRelationshipCompatibility(t, f, worker, order == "legacy")
			}
		})
	}
}

func TestTemporalDiscoveryRetainedSafeResumePostgres(t *testing.T) {
	f, worker, _, _ := temporalDiscoveryPageFixture(t)
	capacityLegacy(t, f, replayIntegration)
	args := []any{replayOrg, replayWorkspace, replayEnvironment, capacityLegacyJob}
	claim := `SELECT zasp_temporal72.claim_retained_delivery($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001',30)`
	input := `SELECT zasp_execution_job_input($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001')`
	var raw []byte
	if err := worker.QueryRow(f.ctx, claim, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, input, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var first map[string]json.RawMessage
	if json.Unmarshal(raw, &first) != nil {
		t.Fatal("input decode")
	}
	key := "organizations/" + replayOrg + "/workspaces/" + replayWorkspace + "/environments/" + replayEnvironment + "/artifacts/pid_72900008-0000-4000-8000-000000000008"
	checkpointArgs := append(append([]any{}, args...), "s3://zasp-evidence/"+key, key)
	if err := worker.QueryRow(f.ctx, `SELECT zasp_execution_checkpoint_partial($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001',0,'aws','cursor_v1','page-2',$5,$6,'version-safe-partial-1',decode(repeat('cd',32),'hex'),100,'application/json','manifest_v1','parser_v1','tool_v1')`, checkpointArgs...).Scan(&raw); err != nil {
		t.Fatal("known safe checkpoint", err)
	}
	var checkpoint struct {
		Digest string `json:"checkpoint_digest"`
	}
	if json.Unmarshal(raw, &checkpoint) != nil || checkpoint.Digest == "" {
		t.Fatal("checkpoint", string(raw))
	}
	finish := `SELECT zasp_execution_finish_job($1,$2,$3,$4,'capacity-worker','capacity-lease-token-0001','retryable',decode($5,'base64'),'partial','bounded partial',0)`
	finishArgs := append(append([]any{}, args...), checkpoint.Digest)
	if err := worker.QueryRow(f.ctx, finish, finishArgs...).Scan(&raw); err != nil {
		t.Fatal("bound partial completion", err)
	}
	tx, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE zasp_discovery_jobs SET completion_digest=decode(repeat('ef',32),'hex') WHERE id=$1`, capacityLegacyJob); err != nil {
		t.Fatal(err)
	}
	var safe bool
	if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal72.retained_retry_safe(job) FROM zasp_discovery_jobs job WHERE id=$1`, capacityLegacyJob).Scan(&safe); err != nil || safe {
		t.Fatal("forged completion retained authority", safe, err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, claim, args...).Scan(&raw); err != nil || !strings.Contains(string(raw), `"claimed"`) {
		t.Fatal("safe next attempt", string(raw), err)
	}
	if err := worker.QueryRow(f.ctx, input, args...).Scan(&raw); err != nil {
		t.Fatal("safe resumed input", err)
	}
	var resumed map[string]json.RawMessage
	if json.Unmarshal(raw, &resumed) != nil || string(resumed["generation"]) != string(first["generation"]) || string(resumed["snapshot_id"]) != string(first["snapshot_id"]) || string(resumed["attempt"]) != "2" || string(resumed["checkpoint_version"]) != "1" {
		t.Fatal("resume changed scope/generation/snapshot", string(raw))
	}
	if err := worker.QueryRow(f.ctx, finish, finishArgs...).Scan(&raw); err != nil {
		t.Fatal("stale completion fixture", err)
	}
	if err := worker.QueryRow(f.ctx, claim, args...).Scan(&raw); err != nil || !strings.Contains(string(raw), `"busy"`) {
		t.Fatal("stale checkpoint authorized resend", string(raw), err)
	}
	var intact bool
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_temporal72.retained_dispatches)=2 AND (SELECT count(*) FROM zasp_discovery_generation_reservations)=1 AND (SELECT checkpoint_version=1 AND checkpoint_digest=decode($2,'base64') AND safe_completion_digest IS NULL FROM zasp_temporal72.retained_dispatches WHERE job_id=$1 AND attempt=2) AND (SELECT attempt=2 AND state='retryable' FROM zasp_discovery_jobs WHERE id=$1)`, capacityLegacyJob, checkpoint.Digest).Scan(&intact); err != nil || !intact {
		t.Fatal("resume evidence changed", intact, err)
	}
}

func TestTemporalDiscoveryCapacityReplicasPostgres(t *testing.T) {
	f, first, firstStart, firstDeadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) {
		capacityCloneIntegration(t, f)
		if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_discovery_execution_quotas(organization_id,max_active_jobs) VALUES($1,1)`, replayOrg); err != nil {
			t.Fatal(err)
		}
	})
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.discovery
	second, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(f.ctx)
	secondStart, secondDeadline := capacityAdmit(t, f, second, capacitySchedule, capacityIntegration)
	tx, err := first.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	var raw []byte
	if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,0,'')`, replayOrg, replayWorkspace, replayEnvironment, firstStart.Ref.RunID, firstStart.IntegrationID, firstStart.InputDigest, firstDeadline).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	type response struct {
		raw []byte
		err error
	}
	done := make(chan response, 1)
	secondPID, firstPID := second.PgConn().PID(), first.PgConn().PID()
	queryCtx, cancelQuery := context.WithTimeout(f.ctx, 20*time.Second)
	joined := false
	defer func() {
		tx.Rollback(context.Background())
		cancelQuery()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("capacity query did not join")
			}
		}
	}()
	go func() {
		var encoded []byte
		err := second.QueryRow(queryCtx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,0,'')`, replayOrg, replayWorkspace, replayEnvironment, secondStart.Ref.RunID, secondStart.IntegrationID, secondStart.InputDigest, secondDeadline).Scan(&encoded)
		done <- response{encoded, err}
	}()
	observed := false
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		if err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted AND ((classid::bigint<<32)|objid::bigint)=hashtextextended(concat_ws(chr(31),'zasp-recovery-hold',$3::text,$4::text,$5::text),0)) AND $2=ANY(pg_blocking_pids($1))`, secondPID, firstPID, replayOrg, replayWorkspace, replayEnvironment).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if observed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !observed {
		t.Fatal("did not observe exact retained recovery scope lock")
	}
	t.Log("second wait persistence observed blocked on unchanged recovery scope lock; releasing first transaction")
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	var completed response
	select {
	case completed = <-done:
		joined = true
	case <-time.After(5 * time.Second):
		t.Fatal("wait receipt did not finish after rollback")
	}
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	var result map[string]json.RawMessage
	var wait orchestration.DiscoveryPage
	if json.Unmarshal(completed.raw, &result) != nil || result["effect_id"] != nil || json.Unmarshal(result["page"], &wait) != nil || wait.Outcome != "retryable" {
		t.Fatal("concurrent replica acquired uncommitted slot", string(completed.raw))
	}
	var atomic bool
	if err := f.owner.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations) AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.page_effects) AND (SELECT count(*) FROM zasp_temporal72.page_waits)=1 AND (SELECT state='admitted' AND checkpoint_version=0 FROM zasp_temporal72.runs WHERE job_id=$1)`, firstStart.Ref.RunID).Scan(&atomic); err != nil || !atomic {
		t.Fatal("contended/rolled-back acquisition leaked authority", atomic, err)
	}
	time.Sleep(5100 * time.Millisecond)
	if err := second.QueryRow(f.ctx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`, replayOrg, replayWorkspace, replayEnvironment, secondStart.Ref.RunID, secondStart.IntegrationID, secondStart.InputDigest, secondDeadline, wait.CheckpointVersion, wait.ReceiptDigest).Scan(&raw); err != nil {
		t.Fatal("replica made no progress after lock release", err)
	}
	if !strings.Contains(string(raw), `"effect_id"`) {
		t.Fatal("released capacity did not authorize first effect", string(raw))
	}
	// The second replica now has a COMMITTED unresolved preparation. The first
	// replica must not acquire merely because the metadata transaction ended.
	blocked := capacityPrepare(t, f, first, firstStart, firstDeadline)
	if blocked["effect_id"] != nil || blocked["page"] == nil {
		t.Fatal("committed replica owner did not retain quota", blocked)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_temporal72.active_owners($1))=1 AND (SELECT count(*) FROM zasp_temporal72.page_effects)=1 AND (SELECT count(*) FROM zasp_temporal72.page_waits)=2`, replayOrg).Scan(&atomic); err != nil || !atomic {
		t.Fatal("replica committed capacity evidence", atomic, err)
	}
}

func TestTemporalDiscoveryDefaultCapacityPostgres(t *testing.T) {
	ids := func(n int) (string, string, string) {
		return fmt.Sprintf("pid_729100%02d-0000-4000-8000-000000000001", n), fmt.Sprintf("pid_729200%02d-0000-4000-8000-000000000001", n), fmt.Sprintf("pid_729300%02d-0000-4000-8000-000000000001", n)
	}
	f, worker, start, deadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) {
		for n := 1; n <= 4; n++ {
			i, s, c := ids(n)
			capacityCloneIntegrationAs(t, f, i, s, c)
		}
	})
	if capacityPrepare(t, f, worker, start, deadline)["effect_id"] == nil {
		t.Fatal("first default slot")
	}
	for n := 1; n <= 4; n++ {
		i, s, _ := ids(n)
		next, budget := capacityAdmit(t, f, worker, s, i)
		result := capacityPrepare(t, f, worker, next, budget)
		if n < 4 && result["effect_id"] == nil || n == 4 && (result["effect_id"] != nil || result["page"] == nil) {
			t.Fatal("default organization limit4", n, result)
		}
	}
	var bounded bool
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_temporal72.active_owners($1))=4 AND (SELECT count(*) FROM zasp_temporal72.page_effects)=4 AND (SELECT count(*) FROM zasp_temporal72.page_waits)=1 AND NOT EXISTS(SELECT 1 FROM zasp_discovery_execution_quotas WHERE organization_id=$1)`, replayOrg).Scan(&bounded); err != nil || !bounded {
		t.Fatal("default capacity evidence", bounded, err)
	}
}
