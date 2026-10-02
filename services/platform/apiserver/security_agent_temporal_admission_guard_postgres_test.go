package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Returning NEW from capacity_guard must fail both subtests even when73's
// catalog and registration are consistently pinned to that defective body.
// Neither caller below uses73's candidate selector or admission precheck.
func TestTemporalAdmissionRetainedInsertGuardPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		if _, err := owner.Exec(ctx, `CREATE ROLE p4c_discovery_scheduler LOGIN INHERIT;
CREATE ROLE p4c_projection_risk LOGIN INHERIT;
CREATE ROLE p4c_projection_graph LOGIN INHERIT;
CREATE ROLE p4c_projection_search LOGIN INHERIT;
SELECT zasp_execution_register_principals(session_user,'p4c_discovery_scheduler','security_agent_v33_discovery_worker_login','p4c_projection_risk','p4c_projection_graph','p4c_projection_search')`); err != nil {
			t.Fatal(err)
		}
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery} {
			if err := up(ctx); err != nil {
				t.Fatal("accepted predecessor", err)
			}
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE definition_id=$1;
UPDATE zasp_security_agent_definitions SET activation='autonomous',body=body||jsonb_build_object('autonomy','autonomous','max_steps',1,'allowed_actions',jsonb_build_array('run_test'),'enabled',true,'concurrency_limit',1) WHERE definition_id=$2;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$3 FROM zasp_security_agent_definitions WHERE definition_id=$2;
INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) SELECT organization_id,workspace_id,environment_id,'p4c-guard-prior',definition_id,1,'p4c-guard-prior-source',$3,'running' FROM zasp_security_agent_definitions WHERE definition_id=$2;
INSERT INTO zasp_temporal66.run_owners(organization_id,workspace_id,environment_id,run_id,execution_owner,definition_version,input_digest) SELECT organization_id,workspace_id,environment_id,run_id,'temporal',1,repeat('a',64) FROM zasp_security_agent_runs WHERE run_id='p4c-guard-prior'`, pgx.QueryExecModeSimpleProtocol, testID, public62Definition, actor); err != nil {
			t.Fatal("controlled historical capacity", err)
		}
		if err := runner.UpProductionTemporalAdmission(ctx); err != nil {
			t.Fatal(err)
		}
		if os.Getenv("ZASP_TEST_P4C_GUARD_MUTANT") == "1" {
			restore := installTemporalAdmissionGuardMutant(t, ctx, owner)
			defer restore()
		}
		t.Run("retained70_hidden_capacity", func(t *testing.T) {
			var permitted bool
			if err := worker.QueryRow(ctx, `SELECT has_function_privilege(current_user,'zasp_temporal70.op02(text,integer,text,text)','EXECUTE') AND zasp_temporal70.client_ready($1,$2)`, migrations.ProductionTemporalCompatibility().Checksum(), migrations.TemporalCompatibilityFingerprint()).Scan(&permitted); err != nil || !permitted {
				t.Fatal("installed retained caller unavailable", permitted, err)
			}
			invoke := func() int {
				var result struct {
					Created int `json:"created"`
				}
				var raw []byte
				if err := worker.QueryRow(ctx, `SELECT zasp_temporal70.op02($1,$2,$3,$4)`, existingTestReadPins([]any{"p4c-retained-boundary", 1})...).Scan(&raw); err != nil {
					t.Fatal("actual retained70 selector", err)
				}
				if err := json.Unmarshal(raw, &result); err != nil {
					t.Fatal(err)
				}
				return result.Created
			}
			before := temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, public62Definition)
			if count := invoke(); count != 0 {
				t.Fatalf("INSERT capacity rejection missing: retained70 admitted %d despite hidden Temporal owner", count)
			}
			if after := temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, public62Definition); after != before {
				t.Fatal("INSERT refusal left parent/trigger/audit/admission/start", before, after)
			}
			// Controlled terminal evidence has no provider, child or cleanup
			// obligation. Release is checked through the actual retained caller.
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='needs_human',completed_at=clock_timestamp() WHERE run_id='p4c-guard-prior'`); err != nil {
				t.Fatal(err)
			}
			if count := invoke(); count != 1 {
				t.Fatal("verified capacity release did not admit retained work", count)
			}
			var exact bool
			if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4))=2
 AND (SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4))=1
 AND (SELECT count(*) FROM zasp_security_agent_audit a JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE (r.organization_id,r.workspace_id,r.environment_id,r.definition_id)=($1,$2,$3,$4))=1
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal73.admissions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4))`, o, w, e, public62Definition).Scan(&exact); err != nil || !exact {
				t.Fatal("retained release receipt shape", exact, err)
			}
			after := temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, public62Definition)
			if count := invoke(); count != 0 {
				t.Fatal("retained duplicate admitted another parent", count)
			}
			if temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, public62Definition) != after {
				t.Fatal("retained retry changed durable receipts")
			}
		})
		t.Run("retained_api_row_contention", func(t *testing.T) {
			const definition = "pid_f0731001-0000-4000-8000-000000000001"
			const run = "pid_f0731002-0000-4000-8000-000000000002"
			const audit = "pid_f0731003-0000-4000-8000-000000000003"
			const receipt = "pid_f0731004-0000-4000-8000-000000000004"
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
SELECT organization_id,workspace_id,environment_id,$4,'supervised',1,1,(body-'existing_test')||jsonb_build_object('id',$4::text,'autonomy','supervised','allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state'),'security-agent-actions-v1' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$5);
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$6 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4);
INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'update_finding_response',true,$6) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, w, e, definition, public62Definition, actor); err != nil {
				t.Fatal("retained finding family fixture", err)
			}
			args := []any{o, w, e, definition, actor, "p4c-guard-contention-0001", int64(1), run, "finding", public62Finding, audit, audit, receipt}
			before := temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, definition)
			holder, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(ctx)
			if _, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
				t.Fatal(err)
			}
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='3s'`); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			var raw []byte
			err = tx.QueryRow(ctx, postgresSecurityAgentRunV24SQL, args...).Scan(&raw)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "40001" || pgErr.Message != "admission organization busy" || !strings.Contains(pgErr.Where, "zasp_temporal73.capacity_guard") {
				t.Fatalf("row-boundary contention did not refuse: elapsed=%s err=%v", time.Since(started), err)
			}
			if time.Since(started) >= 3*time.Second {
				t.Fatal("row guard waited in reverse lock order")
			}
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err = holder.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, definition) != before {
				t.Fatal("row contention left partial product records")
			}
			if err = api.QueryRow(ctx, postgresSecurityAgentRunV24SQL, args...).Scan(&raw); err != nil {
				t.Fatal("retained API retry after lock release", err)
			}
			var result struct {
				ID       string `json:"id"`
				Replayed bool   `json:"replayed"`
			}
			if json.Unmarshal(raw, &result) != nil || result.ID != run || result.Replayed {
				t.Fatal("retained API acceptance", string(raw))
			}
			accepted := temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, definition)
			if err = api.QueryRow(ctx, postgresSecurityAgentRunV24SQL, args...).Scan(&raw); err != nil {
				t.Fatal("same request at full capacity", err)
			}
			if json.Unmarshal(raw, &result) != nil || result.ID != run || !result.Replayed {
				t.Fatal("full-capacity exact replay", string(raw))
			}
			if temporalAdmissionGuardSnapshot(t, ctx, owner, o, w, e, definition) != accepted {
				t.Fatal("exact full-capacity replay wrote another effect")
			}
			t.Log("actual retained API hit capacity_guard40001 before timeout; rollback, retry and exact full-capacity replay passed")
		})
	})
}

func temporalAdmissionGuardSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, d string) string {
	t.Helper()
	var value string
	err := owner.QueryRow(ctx, `WITH parents AS(SELECT * FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4))
SELECT jsonb_build_object(
 'parents',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY run_id),'[]') FROM parents r),
 'triggers',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY run_id),'[]') FROM zasp_security_agent_trigger_receipts r WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)),
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY audit_id),'[]') FROM zasp_security_agent_audit a WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND (body->>'definition_id'=$4 OR run_id IN(SELECT run_id FROM parents))),
 'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY receipt_id),'[]') FROM zasp_security_agent_request_receipts r WHERE (organization_id,workspace_id,environment_id,resource_id)=($1,$2,$3,$4)),
 'admissions',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY run_id),'[]') FROM zasp_temporal73.admissions a WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)),
 'starts73',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY run_id,revision),'[]') FROM zasp_temporal73.commands c WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND run_id IN(SELECT run_id FROM parents)),
 'starts65',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY event_id),'[]') FROM zasp_temporal65.commands c WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND run_id IN(SELECT run_id FROM parents)))::text`, o, w, e, d).Scan(&value)
	if err != nil {
		t.Fatal("guard product snapshot", err)
	}
	return value
}

// This test-only mutation changes no migration file and no predecessor. Its
// normalized catalog pin is recomputed, then substituted through73 functions
// and registration so current_ready remains true for the behavioral RED.
func installTemporalAdmissionGuardMutant(t *testing.T, ctx context.Context, owner *pgx.Conn) func() {
	t.Helper()
	rows, err := owner.Query(ctx, `SELECT pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace='zasp_temporal73'::regnamespace ORDER BY oid`)
	if err != nil {
		t.Fatal(err)
	}
	var definitions []string
	for rows.Next() {
		var d string
		if err = rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		definitions = append(definitions, d)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	original := migrations.TemporalAdmissionFingerprint()
	mutate := func(definitions []string, fingerprint string) error {
		tx, err := owner.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		for _, d := range definitions {
			if _, err = tx.Exec(ctx, d); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `ALTER TABLE zasp_temporal73.registration DISABLE TRIGGER immutable; UPDATE zasp_temporal73.registration SET fingerprint=$1; ALTER TABLE zasp_temporal73.registration ENABLE TRIGGER immutable`, pgx.QueryExecModeSimpleProtocol, fingerprint); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	restore := func() {
		if err := mutate(definitions, original); err != nil {
			t.Errorf("restore exact73 definitions: %v", err)
			return
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal73.current_ready() AND zasp_temporal73.fingerprint()=$1 AND zasp_temporal72.current_ready()`, original).Scan(&ready); err != nil || !ready {
			t.Errorf("restored catalog rejected: %v %v", ready, err)
			return
		}
		for _, d := range definitions {
			var found bool
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='zasp_temporal73'::regnamespace AND pg_get_functiondef(oid)=$1)`, d).Scan(&found); err != nil || !found {
				t.Errorf("exact saved function not restored: %v %v", found, err)
				return
			}
		}
		t.Log("mutation cleanup restored every saved73 function and original registration;73/72 readiness true")
	}
	if _, err = owner.Exec(ctx, `CREATE OR REPLACE FUNCTION zasp_temporal73.capacity_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'BEGIN RETURN NEW;END'`); err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	if err = owner.QueryRow(ctx, `SELECT zasp_temporal73.fingerprint()`).Scan(&fingerprint); err != nil {
		restore()
		t.Fatal(err)
	}
	rows, err = owner.Query(ctx, `SELECT pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace='zasp_temporal73'::regnamespace ORDER BY oid`)
	if err != nil {
		restore()
		t.Fatal(err)
	}
	var mutated []string
	for rows.Next() {
		var d string
		if err = rows.Scan(&d); err != nil {
			rows.Close()
			restore()
			t.Fatal(err)
		}
		mutated = append(mutated, strings.ReplaceAll(d, original, fingerprint))
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		restore()
		t.Fatal(err)
	}
	if err = mutate(mutated, fingerprint); err != nil {
		restore()
		t.Fatal(err)
	}
	var ready bool
	if err = owner.QueryRow(ctx, `SELECT zasp_temporal73.current_ready() AND zasp_temporal73.fingerprint()=$1 AND zasp_temporal70.current_ready() AND zasp_temporal72.current_ready()`, fingerprint).Scan(&ready); err != nil || !ready {
		restore()
		t.Fatal("internally consistent mutant readiness", ready, err)
	}
	t.Logf("behavioral mutant installed with valid73/70/72 readiness; catalog pin=%s", fingerprint)
	return restore
}
