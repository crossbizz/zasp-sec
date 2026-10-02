package apiserver

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A shipped retained scheduler must not create work without a durable start.
// This exercises its installed repository, not an isolated capacity helper.
func TestTemporalAdmissionScheduledInstalledPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		// This older Security Agent fixture registers discovery/API/outbox but
		// not the scheduler.72 requires all four exact, separate logins.
		if _, err := owner.Exec(ctx, `CREATE ROLE p4c_discovery_scheduler LOGIN INHERIT;
CREATE ROLE p4c_projection_risk LOGIN INHERIT;
CREATE ROLE p4c_projection_graph LOGIN INHERIT;
CREATE ROLE p4c_projection_search LOGIN INHERIT;
SELECT zasp_execution_register_principals(session_user,'p4c_discovery_scheduler','security_agent_v33_discovery_worker_login','p4c_projection_risk','p4c_projection_graph','p4c_projection_search')`); err != nil {
			t.Fatal("exact fixture principal registration", err)
		}
		runner := precisionMigrationRunner(t, owner)
		for index, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery} {
			if err := up(ctx); err != nil {
				if index == 5 {
					tx, txErr := owner.Begin(ctx)
					if txErr != nil {
						t.Fatal(txErr)
					}
					defer tx.Rollback(ctx)
					_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalDiscovery().UpSQL())
					var detail string
					queryErr := tx.QueryRow(ctx, `SELECT jsonb_build_object('roles_ready',zasp_temporal72.roles_ready(),'principals',(SELECT jsonb_agg(to_jsonb(p)) FROM zasp_temporal72.principals p),'fingerprint',zasp_temporal72.fingerprint())::text`).Scan(&detail)
					t.Logf("72 fixture boundary DDL=%v query=%v detail=%s", ddlErr, queryErr, detail)
				}
				t.Fatal("accepted predecessor", index+67, err)
			}
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE definition_id=$1;
UPDATE zasp_security_agent_definitions SET activation='autonomous',body=body||jsonb_build_object('autonomy','autonomous','max_steps',1,'allowed_actions',jsonb_build_array('run_test'),'enabled',true,'concurrency_limit',1) WHERE definition_id=$2;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$3 FROM zasp_security_agent_definitions WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, testID, public62Definition, actor); err != nil {
			t.Fatal("controlled product fixture", err)
		}
		// Historical owner setup is deliberately done before73. The retained
		// worker cannot see this Temporal-owned parent through66 RLS.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES($1,$2,$3,'p4c-prior',$4,1,'p4c-prior-source',$5,'running');
INSERT INTO zasp_temporal66.run_owners VALUES($1,$2,$3,'p4c-prior','temporal',1,repeat('a',64))`, pgx.QueryExecModeSimpleProtocol, o, w, e, public62Definition, actor); err != nil {
			t.Fatal("historical owner fixture", err)
		}
		// The installed CLI/Runner is part of this boundary. A helper-only
		// implementation cannot satisfy this test.
		up, ok := any(runner).(interface{ UpProductionTemporalAdmission(context.Context) error })
		if !ok {
			t.Fatal("installed common admission migration is missing")
		}
		if err := up.UpProductionTemporalAdmission(ctx); err != nil {
			tx, txErr := owner.Begin(ctx)
			if txErr != nil {
				t.Fatal(txErr)
			}
			defer tx.Rollback(ctx)
			_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalAdmission().UpSQL())
			var detail string
			queryErr := tx.QueryRow(ctx, `SELECT zasp_temporal73.fingerprint()`).Scan(&detail)
			t.Logf("73 independent catalog compile DDL=%v query=%v fingerprint=%s", ddlErr, queryErr, detail)
			t.Fatal("common admission installation", err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentWorkerRepository(db)
		if err != nil {
			t.Fatal("shipped repository composition", err)
		}
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "p4c-at-capacity", 1); err != nil || count != 0 {
			t.Fatal("scheduler bypassed another execution owner's capacity", count, err)
		}
		var rejected int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal73.admissions`).Scan(&rejected); err != nil || rejected != 0 {
			t.Fatal("rejected candidate consumed admission", rejected, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='needs_human',completed_at=clock_timestamp() WHERE run_id='p4c-prior'`); err != nil {
			t.Fatal("controlled settled prior parent", err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO public.zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,stop_reason) VALUES($1,$2,$3,'p4c-prior',$4,1,clock_timestamp(),'budget_usage_unknown');
INSERT INTO zasp_temporal68.provider_reservations(organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits) VALUES($1,$2,$3,'p4c-prior',1,'p4c-provider',decode(repeat('a',64),'hex'),'controlled-model','controlled-cost','openrouter_credit',100,100)`, pgx.QueryExecModeSimpleProtocol, o, w, e, public62Definition); err != nil {
			t.Fatal("controlled unknown provider receipt", err)
		}
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "p4c-unresolved", 1); err != nil || count != 0 {
			t.Fatal("terminal Temporal parent released unresolved provider occupancy", count, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_temporal68.provider_reservations SET released_at=clock_timestamp() WHERE reservation_id='p4c-provider'`); err != nil {
			t.Fatal("controlled never-dispatched provider release", err)
		}
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "p4c-scheduler", 1); err != nil || count != 1 {
			t.Fatal("actual scheduled existing-test admission", count, err)
		}
		var atomic bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(a.execution_owner='retained_single_action') AND bool_and(c.revision=1 AND c.kind='start') FROM zasp_temporal73.admissions a JOIN zasp_temporal73.commands c USING(organization_id,workspace_id,environment_id,run_id) WHERE a.definition_id=$1`, public62Definition).Scan(&atomic); err != nil || !atomic {
			t.Fatal("scheduled work has no atomic scoped start", atomic, err)
		}
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "p4c-retry", 1); err != nil || count != 0 {
			t.Fatal("duplicate scheduled delivery created work", count, err)
		}
		apiDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		parse := func(raw string) domain.ProductID {
			id, err := domain.ParseProductID(raw)
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		identity.Scope, err = domain.NewScope(parse(o), parse(w), parse(e))
		if err != nil {
			t.Fatal(err)
		}
		identity.PrincipalID = parse(actor)
		identity.CredentialKind = CredentialBrowserSession
		// This retained API caller admits another definition and then repeats
		// its exact request while that definition is at capacity one.
		seedShippedManualAdmission(t, ctx, owner, apiDB, identity, o, w, e, testID, actor)
		exerciseTemporalAdmissionIsolationAndRaces(t, ctx, owner, worker, repository, o, w, e, testID, actor)
		var predecessor bool
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal72.current_ready() AND zasp_temporal71.current_ready() AND zasp_temporal69.current_ready()`).Scan(&predecessor); err != nil || !predecessor {
			t.Fatal("accepted predecessors changed", predecessor, err)
		}
	})
}

func exerciseTemporalAdmissionIsolationAndRaces(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, repository *SecurityAgentWorkerRepository, o, w, e, testID, actor string) {
	t.Helper()
	// Reuse only tenant/product fixture construction. This helper neither
	// installs nor invokes the retired63 scheduler or executor.
	o2, w2, e2 := worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 73)
	public62Seed(t, ctx, owner, o2, w2, e2, testID, actor)
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4);
UPDATE zasp_security_agent_definitions SET activation='autonomous',body=body||jsonb_build_object('autonomy','autonomous','max_steps',1,'allowed_actions',jsonb_build_array('run_test'),'enabled',true,'concurrency_limit',1) WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$5);
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$6 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$5)`, pgx.QueryExecModeSimpleProtocol, o2, w2, e2, testID, public62Definition, actor); err != nil {
		t.Fatal("same-identity independent tenant", err)
	}
	// Isolate candidate fairness from the retained worker's RLS-visible count:
	// settle the controlled retained parent and occupy the first definition
	// with its already-Temporal historical owner. No ownership row is changed.
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='needs_human',completed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4) AND run_id<>'p4c-prior';
UPDATE zasp_security_agent_runs SET state='running',completed_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,'p4c-prior')`, pgx.QueryExecModeSimpleProtocol, o, w, e, public62Definition); err != nil {
		t.Fatal("controlled hidden first-tenant occupancy", err)
	}
	// More blocked sources than the selector's limit*4 scan window. If its
	// pre-LIMIT count regresses, the eligible second tenant is starved.
	for n := 0; n < 5; n++ {
		id := fmt.Sprintf("pid_f0730000-0000-4000-8000-%012d", n+1)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Blocked first tenant','high','open')`, o, w, e, id); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "p4c-fairness", 1); err != nil || count != 1 {
		t.Fatal("full first tenant starved independent same-name tenant", count, err)
	}
	var independent bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND count(DISTINCT organization_id)=2 AND count(DISTINCT run_id)=2 FROM zasp_temporal73.admissions WHERE definition_id=$1`, public62Definition).Scan(&independent); err != nil || !independent {
		t.Fatal("same definition identity crossed tenant boundary", independent, err)
	}
	config := worker.Config().Copy()
	other, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	otherDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: other})
	if err != nil {
		t.Fatal(err)
	}
	otherRepository, err := NewSecurityAgentWorkerRepository(otherDB)
	if err != nil {
		t.Fatal(err)
	}
	connections := []*pgx.Conn{worker, other}
	repositories := []*SecurityAgentWorkerRepository{repository, otherRepository}
	for first := 0; first < 2; first++ {
		definition := fmt.Sprintf("pid_f0730001-0000-4000-8000-%012d", first+1)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
SELECT organization_id,workspace_id,environment_id,$4,activation,version,definition_version,body||jsonb_build_object('id',$4::text),plan_catalog_version FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$5);
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$6 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, pgx.QueryExecModeSimpleProtocol, o2, w2, e2, definition, public62Definition, actor); err != nil {
			t.Fatal("race definition", err)
		}
		second := 1 - first
		if _, err := connections[first].Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		if count, err := repositories[first].ScheduleSecurityAgentTriggers(ctx, "p4c-race-first", 1); err != nil || count != 1 {
			t.Fatal("first overlapping admission", first, count, err)
		}
		if count, err := repositories[second].ScheduleSecurityAgentTriggers(ctx, "p4c-race-second", 1); err != nil || count != 0 {
			t.Fatal("competing connection bypassed held slot", first, count, err)
		}
		var uncommitted int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal73.admissions WHERE definition_id=$1`, definition).Scan(&uncommitted); err != nil || uncommitted != 0 {
			t.Fatal("uncommitted admission became visible", uncommitted, err)
		}
		if _, err := connections[first].Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if count, err := repositories[second].ScheduleSecurityAgentTriggers(ctx, "p4c-race-retry", 1); err != nil || count != 1 {
			t.Fatal("rollback retained capacity or source receipt", first, count, err)
		}
		if count, err := repositories[first].ScheduleSecurityAgentTriggers(ctx, "p4c-race-late", 1); err != nil || count != 0 {
			t.Fatal("late competitor bypassed committed slot", first, count, err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal73.admissions WHERE definition_id=$1)=1 AND (SELECT count(*) FROM zasp_security_agent_runs WHERE definition_id=$1)=1 AND (SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE definition_id=$1)=1 AND (SELECT count(*) FROM zasp_temporal73.commands c JOIN zasp_temporal73.admissions a USING(organization_id,workspace_id,environment_id,run_id) WHERE a.definition_id=$1)=1`, definition).Scan(&exact); err != nil || !exact {
			t.Fatal("race/rollback duplicated durable work", first, exact, err)
		}
	}
}
