package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"testing"
)

func exerciseAuthorizationProjectionMachines(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *authorization.PostgresProjectionRepository, writer authorization.TupleWriter, checker authorization.Checker, human authorization.CheckRequest, store, model string, live bool) {
	t.Helper()
	o, w, e := human.OrganizationID, human.WorkspaceID, human.EnvironmentID
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	agent := "pid_79000100-0000-4000-8000-000000000100"
	run1 := "pid_79000101-0000-4000-8000-000000000101"
	run2 := "pid_79000102-0000-4000-8000-000000000102"
	target := "pid_79000103-0000-4000-8000-000000000103"
	exec(`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,'{}','projection-test')`, o, w, e, agent)
	exec(`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$4,'posture','Projection finding','low','open')`, o, w, e, target)
	for _, run := range []string{run1, run2} {
		exec(`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES($1,$2,$3,$4,$5,1,$6,$7,'queued')`, o, w, e, run, agent, target, human.PrincipalID)
		exec(`INSERT INTO zasp_authorization79.grants(organization_id,workspace_id,environment_id,kind,id,principal_kind,principal_id,permission,task_id) VALUES($1,$2,$3,'finding',$4,'agent',$5,'manage_findings',$6)`, o, w, e, target, agent, run)
	}
	reconcile := func() {
		t.Helper()
		if receipt, err := authorization.Reconcile(ctx, repository, writer, o, store, model); err != nil || !receipt.Applied {
			t.Fatal("machine reconciliation", err)
		}
	}
	machine := human
	machine.PrincipalKind = "agent"
	machine.PrincipalID = agent
	machine.ResourceType = "finding"
	machine.ResourceID = target
	machine.Permission = "manage_findings"
	check := func(run string, allowed bool) {
		t.Helper()
		machine.TaskID = run
		if !live {
			return
		}
		result, err := authorization.CheckRevision(ctx, repository, checker, machine, store, model)
		if err != nil || result.Decision.Allowed != allowed {
			t.Fatalf("task delegation allowed=%t expected=%t err=%v", result.Decision.Allowed, allowed, err)
		}
	}
	reconcile()
	check(run1, true)
	check(run2, true)
	check("pid_79000104-0000-4000-8000-000000000104", false)
	exec(`DELETE FROM zasp_authorization79.grants WHERE organization_id=$1 AND task_id=$2`, o, run1)
	reconcile()
	check(run1, false)
	check(run2, true)
	exec(`UPDATE zasp_security_agent_definitions SET activation='draft' WHERE organization_id=$1 AND definition_id=$2`, o, agent)
	reconcile()
	check(run2, false)
	var machineMembers int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization79.members WHERE organization_id=$1 AND kind='agent' AND id=$2`, o, agent).Scan(&machineMembers); err != nil || machineMembers != 0 {
		t.Fatal("deactivated machine membership remained", err)
	}
	integration := "pid_79000300-0000-4000-8000-000000000300"
	connection := "pid_79000301-0000-4000-8000-000000000301"
	service := "pid_79000302-0000-4000-8000-000000000302"
	sync := "pid_79000303-0000-4000-8000-000000000303"
	exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,state) VALUES($1,$2,$3,$4,'aws','1','Projection service','active')`, o, w, e, integration)
	exec(`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,$5,'aws','ref:projection/connection','verified',clock_timestamp())`, o, w, e, integration, connection)
	exec(`INSERT INTO zasp_discovery_schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,next_run_at) VALUES($1,$2,$3,$4,$5,300,clock_timestamp())`, o, w, e, service, integration)
	exec(`INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'projection-service-sync',digest('service-task','sha256'),'schedule',$6,'1','1')`, o, w, e, sync, integration, service)
	exec(`INSERT INTO zasp_authorization79.grants(organization_id,workspace_id,environment_id,kind,id,principal_kind,principal_id,permission,task_id) VALUES($1,$2,$3,'finding',$4,'service',$5,'manage_findings',$6)`, o, w, e, target, service, sync)
	machine.PrincipalKind = "service"
	machine.PrincipalID = service
	reconcile()
	check(sync, true)
	check(run2, false)
	if live {
		foreign := machine
		foreign.OrganizationID = "pid_79000304-0000-4000-8000-000000000304"
		result, err := checker.Check(ctx, foreign)
		if err != nil || result.Allowed {
			t.Fatal("cross-tenant machine grant escaped", err)
		}
	}
	exec(`UPDATE zasp_integration_connections SET state='revoked',revoked_at=clock_timestamp() WHERE organization_id=$1 AND id=$2`, o, connection)
	if _, err := authorization.CheckRevision(ctx, repository, checker, machine, store, model); err == nil {
		t.Fatal("connection revoke was not pending")
	}
	reconcile()
	check(sync, false)
	// SQL rejects a duplicated product parent at snapshot time, before any FGA write.
	otherWorkspace := "pid_79000200-0000-4000-8000-000000000200"
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Second')`, o, otherWorkspace)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Duplicate','test')`, o, otherWorkspace, e)
	if receipt, err := authorization.Reconcile(ctx, repository, writer, o, store, model); err == nil || receipt.Applied {
		t.Fatal("two SQL parents accepted")
	}
	exec(`DELETE FROM zasp_environments WHERE organization_id=$1 AND workspace_id=$2 AND id=$3`, o, otherWorkspace, e)
	reconcile()
	t.Log("product agent/service membership, two independent tasks, per-task/activation/connection revoke, cross-tenant denial and duplicate SQL ancestry verified")
}
