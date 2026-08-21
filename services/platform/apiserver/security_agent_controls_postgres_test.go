package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionSecurityAgentControlsPostgresFencesAndReplaysExactSwitches(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE security_agent_api_controls_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE security_agent_worker_controls_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'security_agent_api_controls_login','security_agent_worker_controls_login')`).Scan(&registered); err != nil || !registered {
		t.Fatalf("registered=%t err=%v", registered, err)
	}
	if err := runner.UpProductionIdentityAdministration(ctx); err != nil {
		t.Fatal(err)
	}
	metadata := migrations.ProductionSecurityAgentControls()
	if err := runner.UpProductionSecurityAgentControls(ctx); err != nil {
		t.Fatalf("v20 up: %v", err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_controls_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionSecurityAgentControlsSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("readiness=%t err=%v", ready, err)
	}
	organization := "pid_7a000001-0000-4000-8000-000000000001"
	workspace := "pid_7a000002-0000-4000-8000-000000000002"
	environment := "pid_7a000003-0000-4000-8000-000000000003"
	actor := "pid_7a000004-0000-4000-8000-000000000004"
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Control tenant','control.invalid')`, []any{organization}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Production')`, []any{workspace, organization}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, []any{environment, organization, workspace}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	connectAs := func(principal string) *pgx.Conn {
		t.Helper()
		config, parseErr := pgx.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		config.User = principal
		value, connectErr := pgx.ConnectConfig(ctx, config)
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		return value
	}
	api := connectAs("security_agent_api_controls_login")
	defer api.Close(context.Background())
	worker := connectAs("security_agent_worker_controls_login")
	defer worker.Close(context.Background())
	workerDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSecurityAgentWorkerRepository(workerDatabase); err != nil {
		t.Fatalf("v20 worker repository rejected current execution authority: %v", err)
	}
	mainDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	mainRepository, err := NewPostgresRepository(mainDatabase)
	if err != nil || mainRepository.schema != SecurityAgentControlsSchemaVersion {
		t.Fatalf("main repository=%#v err=%v", mainRepository, err)
	}
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	securityAgentRepository, err := NewSecurityAgentPostgresRepository(apiDatabase)
	if err != nil || securityAgentRepository.schema != SecurityAgentControlsSchemaVersion {
		t.Fatalf("security agent repository=%#v err=%v", securityAgentRepository, err)
	}
	var detail json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_security_agent_execution_control_detail($1,$2,$3)`, organization, workspace, environment).Scan(&detail); err != nil || string(detail) != `{"global": {"target": "global", "enabled": true, "version": 1, "action_key": "*"}, "actions": [{"target": "action", "enabled": false, "version": 0, "action_key": "update_finding_response"}], "environment": {"target": "environment", "enabled": false, "version": 0, "action_key": "*"}}` {
		t.Fatalf("initial detail=%s err=%v", detail, err)
	}
	var workerCanRead, workerCanWrite, apiCanRead, apiCanWrite, apiCanTable, apiCanBypass bool
	if err := connection.QueryRow(ctx, `SELECT has_function_privilege('security_agent_worker_controls_login','zasp_security_agent_execution_control_detail(text,text,text)','EXECUTE'),has_function_privilege('security_agent_worker_controls_login','zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)','EXECUTE'),has_function_privilege('security_agent_api_controls_login','zasp_security_agent_execution_control_detail(text,text,text)','EXECUTE'),has_function_privilege('security_agent_api_controls_login','zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)','EXECUTE'),has_table_privilege('security_agent_api_controls_login','zasp_security_agent_kill_switches','SELECT'),has_function_privilege('security_agent_api_controls_login','zasp_security_agent_set_kill_switch(text,text,text,text,boolean,bigint,text,text,text)','EXECUTE')`).Scan(&workerCanRead, &workerCanWrite, &apiCanRead, &apiCanWrite, &apiCanTable, &apiCanBypass); err != nil || workerCanRead || workerCanWrite || !apiCanRead || !apiCanWrite || apiCanTable || apiCanBypass {
		t.Fatalf("acl worker read=%t write=%t api read=%t write=%t table=%t bypass=%t err=%v", workerCanRead, workerCanWrite, apiCanRead, apiCanWrite, apiCanTable, apiCanBypass, err)
	}
	foreignEnvironment := "pid_7a000099-0000-4000-8000-000000000099"
	if err := api.QueryRow(ctx, `SELECT zasp_security_agent_execution_control_detail($1,$2,$3)`, organization, workspace, foreignEnvironment).Scan(&detail); err == nil {
		t.Fatal("execution controls disclosed for a nonexistent tenant scope")
	}
	mutate := func(idempotency, target, action string, enabled bool, expected int64, audit, correlation, receipt string) (json.RawMessage, error) {
		var payload json.RawMessage
		err := api.QueryRow(ctx, `SELECT zasp_security_agent_mutate_execution_control($1,$2,$3,$4,$5,$6,$7,$8,$9,transaction_timestamp()+interval '4 minutes',$10,$11,$12)`, organization, workspace, environment, actor, idempotency, target, action, enabled, expected, audit, correlation, receipt).Scan(&payload)
		return payload, err
	}
	if _, err := mutate("control-global-denied-0001", "global", "*", false, 1, "pid_7a000010-0000-4000-8000-000000000010", "pid_7a000011-0000-4000-8000-000000000011", "pid_7a000012-0000-4000-8000-000000000012"); err == nil {
		t.Fatal("tenant API changed the platform-global execution control")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false,version=2 WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*')`); err != nil {
		t.Fatal(err)
	}
	if _, err := mutate("control-env-before-global", "environment", "*", true, 0, "pid_7a000013-0000-4000-8000-000000000013", "pid_7a000014-0000-4000-8000-000000000014", "pid_7a000015-0000-4000-8000-000000000015"); err == nil {
		t.Fatal("environment execution enabled while global execution was disabled")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=true,version=3 WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*')`); err != nil {
		t.Fatal(err)
	}
	environmentResult, err := mutate("control-environment-enable-0001", "environment", "*", true, 0, "pid_7a000020-0000-4000-8000-000000000020", "pid_7a000021-0000-4000-8000-000000000021", "pid_7a000022-0000-4000-8000-000000000022")
	if err != nil || !strings.Contains(string(environmentResult), `"target": "environment"`) || !strings.Contains(string(environmentResult), `"version": 1`) || !strings.Contains(string(environmentResult), `"replayed": false`) {
		t.Fatalf("environment=%s err=%v", environmentResult, err)
	}
	replay, err := mutate("control-environment-enable-0001", "environment", "*", true, 0, "pid_7a000030-0000-4000-8000-000000000030", "pid_7a000031-0000-4000-8000-000000000031", "pid_7a000032-0000-4000-8000-000000000032")
	if err != nil || !strings.Contains(string(replay), `"replayed": true`) || !strings.Contains(string(replay), `"receipt_id": "pid_7a000022-0000-4000-8000-000000000022"`) {
		t.Fatalf("replay=%s err=%v", replay, err)
	}
	if _, err := mutate("control-action-enable-0001", "action", "update_finding_response", true, 0, "pid_7a000050-0000-4000-8000-000000000050", "pid_7a000051-0000-4000-8000-000000000051", "pid_7a000052-0000-4000-8000-000000000052"); err != nil {
		t.Fatal(err)
	}
	if _, err := mutate("control-unknown-action-0001", "action", "create_temporary_policy", true, 0, "pid_7a000060-0000-4000-8000-000000000060", "pid_7a000061-0000-4000-8000-000000000061", "pid_7a000062-0000-4000-8000-000000000062"); err == nil {
		t.Fatal("unshipped action was enabled")
	}
	var postgresError *pgconn.PgError
	err = api.QueryRow(ctx, `SELECT zasp_security_agent_mutate_execution_control($1,$2,$3,$4,'control-environment-stale-0001','environment','*',false,0,transaction_timestamp()+interval '4 minutes','pid_7a000070-0000-4000-8000-000000000070','pid_7a000071-0000-4000-8000-000000000071','pid_7a000072-0000-4000-8000-000000000072')`, organization, workspace, environment, actor).Scan(&detail)
	if !errors.As(err, &postgresError) || postgresError.Code != "40001" {
		t.Fatalf("stale error=%v", err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_security_agent_execution_control_detail($1,$2,$3)`, organization, workspace, environment).Scan(&detail); err != nil || !strings.Contains(string(detail), `"global": {"target": "global", "enabled": true, "version": 3`) || !strings.Contains(string(detail), `"environment": {"target": "environment", "enabled": true, "version": 1`) || !strings.Contains(string(detail), `"action", "enabled": true, "version": 1`) {
		t.Fatalf("enabled detail=%s err=%v", detail, err)
	}
	if err := runner.DownProductionSecurityAgentControls(ctx); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("data-aware down error=%v", err)
	}
}
