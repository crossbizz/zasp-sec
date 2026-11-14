package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations/baseline"
)

// completion.sql section V6 (provider remediation actions) against the real
// catalog: the baseline artifact is installed as the operator on a disposable
// PostgreSQL, the section is applied twice as the superuser (an existing
// installation applies it the same way), the catalog is re-sealed, and the
// section's functions are exercised as the product's own service logins.
//
// The section's writers are executable only by their owner and are reached
// through zasp_authorization80 functions that need an attested request proof,
// which a database test cannot mint. The test therefore grants the API role
// EXECUTE on those writers on this disposable database only and re-seals;
// the proof wrapper itself is tested for refusing a request without a proof.

const (
	remediationOrg         = "pid_a0000000-0000-4000-8000-000000000001"
	remediationWorkspace   = "pid_a0000000-0000-4000-8000-000000000002"
	remediationEnvironment = "pid_a0000000-0000-4000-8000-000000000003"
	remediationIntegration = "pid_a0000000-0000-4000-8000-000000000040"
	remediationAgentEntity = "pid_a0000000-0000-4000-8000-000000000030"
	remediationRequester   = "pid_a0000000-0000-4000-8000-000000000050"
	remediationApprover    = "pid_a0000000-0000-4000-8000-000000000051"
	remediationAdmin       = "pid_a0000000-0000-4000-8000-000000000052"
	remediationReadRole    = "arn:aws:iam::123456789012:role/zasp-read"
	remediationWriteRole   = "arn:aws:iam::123456789012:role/zasp-remediation"
)

func remediationSQLState(err error) (string, string) {
	var provider *pgconn.PgError
	if errors.As(err, &provider) {
		return provider.Code, provider.Message
	}
	return "", ""
}

func remediationSection(t *testing.T) string {
	t.Helper()
	completion, err := os.ReadFile(filepath.Join("..", "migrations", "baseline", "completion.sql"))
	if err != nil {
		t.Fatal(err)
	}
	const header = "-- V6. Provider remediation actions of the Security Agent"
	start := strings.Index(string(completion), header)
	if start < 0 || strings.Count(string(completion), header) != 1 {
		t.Fatal("completion.sql does not hold exactly one section V6")
	}
	return string(completion[start:])
}

type remediationDatabase struct {
	t    *testing.T
	ctx  context.Context
	conn *pgx.Conn
}

// as runs one statement as a service login and returns its JSON result.
func (database remediationDatabase) as(login, statement string, arguments ...any) (json.RawMessage, error) {
	database.t.Helper()
	if _, err := database.conn.Exec(database.ctx, `SET SESSION AUTHORIZATION `+login); err != nil {
		database.t.Fatal(err)
	}
	var result []byte
	err := database.conn.QueryRow(database.ctx, statement, arguments...).Scan(&result)
	if _, resetErr := database.conn.Exec(database.ctx, `RESET SESSION AUTHORIZATION`); resetErr != nil {
		database.t.Fatal(resetErr)
	}
	return result, err
}

func (database remediationDatabase) exec(statement string, arguments ...any) {
	database.t.Helper()
	if _, err := database.conn.Exec(database.ctx, statement, arguments...); err != nil {
		database.t.Fatalf("%s: %v", strings.SplitN(statement, "\n", 2)[0], err)
	}
}

func (database remediationDatabase) text(statement string, arguments ...any) string {
	database.t.Helper()
	var value *string
	if err := database.conn.QueryRow(database.ctx, statement, arguments...).Scan(&value); err != nil {
		database.t.Fatalf("%s: %v", statement, err)
	}
	if value == nil {
		return ""
	}
	return *value
}

func (database remediationDatabase) seal() {
	database.t.Helper()
	database.exec(`SET ROLE zasp_discovery_authority`)
	var accepted, intact bool
	if err := database.conn.QueryRow(database.ctx, `SELECT zasp_baseline.accept(zasp_baseline.state()->>'artifact')`).Scan(&accepted); err != nil || !accepted {
		database.t.Fatalf("re-seal: accepted=%t err=%v", accepted, err)
	}
	if err := database.conn.QueryRow(database.ctx, `SELECT zasp_baseline.intact()`).Scan(&intact); err != nil || !intact {
		database.t.Fatalf("re-sealed catalog: intact=%t err=%v", intact, err)
	}
	database.exec(`RESET ROLE`)
}

func startRemediationDatabase(t *testing.T) remediationDatabase {
	t.Helper()
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE zasp_operator LOGIN CREATEROLE BYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE zasp_remediation OWNER zasp_operator TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'`); err != nil {
		t.Fatal(err)
	}
	_ = admin.Close(ctx)
	operatorConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	superuser := operatorConfig.Copy()
	superuser.Database = "zasp_remediation"
	operatorConfig.User, operatorConfig.Database = "zasp_operator", "zasp_remediation"
	operator, err := pgx.ConnectConfig(ctx, operatorConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.Install(ctx, operator); err != nil {
		t.Fatalf("baseline install: %v (%v)", err, errors.Unwrap(err))
	}
	_ = operator.Close(ctx)
	conn, err := pgx.ConnectConfig(ctx, superuser)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	database := remediationDatabase{t: t, ctx: ctx, conn: conn}
	section := remediationSection(t)
	// Twice: the section is re-runnable, and a baseline that already carries
	// it takes it again without a change.
	for pass := 0; pass < 2; pass++ {
		if _, err := conn.Exec(ctx, "BEGIN;\n"+section+"\nCOMMIT;", pgx.QueryExecModeSimpleProtocol); err != nil {
			_, _ = conn.Exec(ctx, `ROLLBACK`)
			t.Fatalf("section V6 pass %d: %v", pass+1, err)
		}
	}
	database.seal()
	return database
}

func (database remediationDatabase) seed() {
	database.t.Helper()
	// Tenant fixtures are written without their collection history: the
	// section reads these rows and nothing else of them.
	database.exec(`SET session_replication_role=replica`)
	database.exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Remediation test','remediation.example')`, remediationOrg)
	database.exec(`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Default')`, remediationWorkspace, remediationOrg)
	database.exec(`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, remediationEnvironment, remediationOrg, remediationWorkspace)
	database.exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($1,$2,'org-ref','admin-ref','security_admin'),($3,$2,'org-ref','approver-ref','security_engineer')`, remediationAdmin, remediationOrg, remediationApprover)
	database.exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state)
VALUES($1,$2,$3,$4,'aws','1','AWS',jsonb_build_object('role_arn',$5::text,'external_id_reference','ref:aws/external-id/abcdefgh12345678','region','us-east-1'),'active')`, remediationOrg, remediationWorkspace, remediationEnvironment, remediationIntegration, remediationReadRole)
	database.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind,winning_integration_id,winning_provider)
VALUES($1,$2,$3,$4,'agent','support-agent',jsonb_build_object('account_id','123456789012','agent_id','AGENT12345','arn','arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345','name','support-agent','region','us-east-1'),now(),now(),'agent',$5,'aws')`, remediationOrg, remediationWorkspace, remediationEnvironment, remediationAgentEntity, remediationIntegration)
	database.exec(`INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,first_seen_at,last_seen_at,provider,source_kind)
VALUES($1,$2,$3,$4,'aws',$5,'arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345','pid_a0000000-0000-4000-8000-000000000041','present',now(),now(),'aws','aws_bedrock_agent')`, remediationOrg, remediationWorkspace, remediationEnvironment, remediationIntegration, remediationAgentEntity)
	for _, fixture := range [][4]string{
		{"pid_a0000000-0000-4000-8000-000000000010", "attach_bedrock_guardrail", "guardrail_state", "pid_a0000000-0000-4000-8000-000000000020"},
		{"pid_a0000000-0000-4000-8000-000000000011", "detach_role_administrator_policy", "role_policy_state", "pid_a0000000-0000-4000-8000-000000000021"},
	} {
		rule := map[string]string{"attach_bedrock_guardrail": "agent_guardrail_missing", "detach_role_administrator_policy": "agent_role_administrator_access"}[fixture[1]]
		database.exec(`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
VALUES($1,$2,$3,$4,'supervised',2,1,jsonb_build_object('id',$4::text,'name','Remediation','enabled',true,'autonomy','supervised','environment_ids',jsonb_build_array($3::text),'trigger_kind','finding','trigger_source',$7::text,
 'allowed_actions',jsonb_build_array($5::text),'verification_kind',$6::text,'concurrency_limit',1,'max_duration_seconds',3600,'max_steps',1,'ai_token_budget',1000,'max_ai_cost_nano_credits',1000),'security-agent-actions-v1')`,
			remediationOrg, remediationWorkspace, remediationEnvironment, fixture[0], fixture[1], fixture[2], rule)
		database.exec(`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,agent_id) VALUES($1,$2,$3,$4,'prowler',$5,'Discovered AWS control','high','open',$6)`,
			remediationOrg, remediationWorkspace, remediationEnvironment, fixture[3], rule, remediationAgentEntity)
	}
	database.exec(`SET session_replication_role=origin`)
	// Test-only grants on this disposable database (see the comment above).
	database.exec(`GRANT EXECUTE ON FUNCTION public.zasp_security_agent_provider_remediation_run(text,text,text,text,text,text,bigint,text,text,text,jsonb,text,text,text,text),
 public.zasp_security_agent_decide_approval_v24(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text),
 public.zasp_production_security_agent_existing_tests_run_context_core(text,text,text,text),
 public.zasp_production_security_agent_existing_tests_approval_ctx_core(text,text,text,text),
 zasp_sa_export_prior.definition_control_core(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) TO zasp_security_agent_api`)
	database.exec(`GRANT USAGE ON SCHEMA zasp_sa_export_prior TO zasp_security_agent_api`)
	database.exec(`GRANT EXECUTE ON FUNCTION zasp_authorization80.integration_remediation_role_write(text,text,text,text,text,text,bigint,text,text),zasp_authorization80.integration_remediation_role_value(text,text,text,text) TO zasp_discovery_api`)
	// The decision's direct guard asks for a checked request when the session
	// is an API login; this test's sessions carry none, so the guard is
	// answered for them here. Nothing else of the decision changes.
	database.exec(`CREATE OR REPLACE FUNCTION zasp_authorization80.direct_guard(o text DEFAULT NULL,w text DEFAULT NULL,e text DEFAULT NULL,actor text DEFAULT NULL) RETURNS boolean LANGUAGE sql AS 'SELECT true'`)
	database.seal()
}

const (
	remediationAPI    = "zasp_svc_security_agent_api"
	remediationWorker = "zasp_svc_security_agent_worker"
	remediationAction = "zasp_svc_security_agent_action"
)

func (database remediationDatabase) setControl(action string, expected int64, idempotency, suffix string) (json.RawMessage, error) {
	return database.as(remediationAPI, `SELECT zasp_sa_export_prior.definition_control_core($1,$2,$3,$4,$5,$6,$7,true,$8,clock_timestamp()+interval '2 minutes',$9,$10,$11)`,
		remediationOrg, remediationWorkspace, remediationEnvironment, remediationAdmin, idempotency, map[bool]string{true: "environment", false: "action"}[action == "*"], action, expected,
		"pid_c0000000-0000-4000-8000-0000000001"+suffix, "pid_c0000000-0000-4000-8000-0000000002"+suffix, "pid_c0000000-0000-4000-8000-0000000003"+suffix)
}

func (database remediationDatabase) request(definition, run, finding, action, parameters, suffix string) (json.RawMessage, error) {
	return database.as(remediationAPI, `SELECT public.zasp_security_agent_provider_remediation_run($1,$2,$3,$4,$5,$6,2,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)`,
		remediationOrg, remediationWorkspace, remediationEnvironment, definition, remediationRequester, "remediation-request-"+suffix, run, finding, action, parameters,
		"pid_d0000000-0000-4000-8000-0000000001"+suffix, "pid_d0000000-0000-4000-8000-0000000002"+suffix, "pid_d0000000-0000-4000-8000-0000000003"+suffix, "pid_d0000000-0000-4000-8000-0000000004"+suffix)
}

func (database remediationDatabase) decide(approval, actor, suffix string) (json.RawMessage, error) {
	return database.as(remediationAPI, `SELECT public.zasp_security_agent_decide_approval_v24($1,$2,$3,$4,$5,$6,1,'approved',clock_timestamp(),$7,$8,$9)`,
		remediationOrg, remediationWorkspace, remediationEnvironment, approval, actor, "remediation-decision-"+suffix,
		"pid_e0000000-0000-4000-8000-0000000001"+suffix, "pid_e0000000-0000-4000-8000-0000000002"+suffix, "pid_e0000000-0000-4000-8000-0000000003"+suffix)
}

// dispatch plays the Security Agent worker: it claims the approved run as a
// prepared run and executes it with the statements the worker uses.
func (database remediationDatabase) dispatch(run, suffix string) json.RawMessage {
	database.t.Helper()
	claimed, err := database.as(remediationWorker, `SELECT zasp_security_agent_claim_runs_v23('security-agent-1',$1,60,5)`, "run-lease-token-"+suffix)
	var claims struct {
		Items []struct {
			RunID    string `json:"run_id"`
			Prepared bool   `json:"prepared"`
		} `json:"items"`
	}
	if err != nil || json.Unmarshal(claimed, &claims) != nil || len(claims.Items) != 1 || claims.Items[0].RunID != run || !claims.Items[0].Prepared {
		database.t.Fatalf("claim of the approved run=%s err=%v", claimed, err)
	}
	executed, err := database.as(remediationWorker, `SELECT zasp_security_agent_execute_run_v24($1,$2,$3,$4,'security-agent-1',$5,$6,$7)`, remediationOrg, remediationWorkspace, remediationEnvironment, run, "run-lease-token-"+suffix,
		"pid_f0000000-0000-4000-8000-0000000001"+suffix, "pid_f0000000-0000-4000-8000-0000000002"+suffix)
	if err != nil {
		database.t.Fatalf("execute: %v", err)
	}
	return executed
}

func TestSecurityAgentProviderRemediationSectionPostgres(t *testing.T) {
	database := startRemediationDatabase(t)
	database.seed()

	t.Run("the sections grant nothing to PUBLIC and own what they add", func(t *testing.T) {
		const added = `(p.proname LIKE '%provider_remediation%' OR p.proname LIKE 'guardrail%' OR p.proname LIKE 'integration_remediation%' OR p.proname LIKE 'integration_set_remediation%' OR p.proname='security_agent_remediation_run')`
		if count := database.text(`SELECT count(*)::text FROM pg_proc p WHERE ` + added); count != "20" {
			t.Fatalf("functions of sections V6 and V7=%s", count)
		}
		if open := database.text(`SELECT string_agg(p.oid::regprocedure::text,', ') FROM pg_proc p WHERE ` + added + ` AND (has_function_privilege('public',p.oid,'execute') OR pg_get_userbyid(p.proowner)<>'zasp_discovery_authority')`); open != "" {
			t.Fatalf("functions executable by PUBLIC or with another owner: %s", open)
		}
		if loose := database.text(`SELECT string_agg(c.relname,', ') FROM pg_class c WHERE c.relname IN('zasp_integration_remediation_roles','zasp_security_agent_provider_remediations','zasp_guardrail_policies','zasp_guardrail_decisions')
 AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR pg_get_userbyid(c.relowner)<>'zasp_discovery_authority' OR has_table_privilege('public',c.oid,'select'))`); loose != "" {
			t.Fatalf("tables without forced row security, with another owner or readable by PUBLIC: %s", loose)
		}
		if tables := database.text(`SELECT count(*)::text FROM pg_class c WHERE c.relkind='r' AND c.relname IN('zasp_integration_remediation_roles','zasp_security_agent_provider_remediations','zasp_guardrail_policies','zasp_guardrail_decisions')`); tables != "4" {
			t.Fatalf("tables=%s", tables)
		}
	})

	t.Run("execution controls accept the new actions and the old ones", func(t *testing.T) {
		if _, err := database.setControl("*", 0, "control-environment-0001", "01"); err != nil {
			t.Fatalf("environment switch: %v", err)
		}
		for index, action := range []string{"attach_bedrock_guardrail", "detach_role_administrator_policy", "revoke_integration_connection", "update_finding_response"} {
			suffix := []string{"02", "03", "04", "05"}[index]
			result, err := database.setControl(action, 0, "control-action-00000"+suffix, suffix)
			var value struct {
				ActionKey string `json:"action_key"`
				Enabled   bool   `json:"enabled"`
				Version   int64  `json:"version"`
			}
			if err != nil || json.Unmarshal(result, &value) != nil || value.ActionKey != action || !value.Enabled || value.Version != 1 {
				t.Fatalf("switch of %q=%s err=%v", action, result, err)
			}
		}
		if _, err := database.setControl("delete_everything", 0, "control-action-0000006", "06"); err == nil {
			t.Fatal("a switch for an unknown action was accepted")
		} else if code, _ := remediationSQLState(err); code != "22023" {
			t.Fatalf("unknown action state=%q err=%v", code, err)
		}
		// Both control lists hold the two actions and all eight earlier ones.
		for _, function := range []string{
			"zasp_authorization80.security_agent_execution_controls(text,text,text,text)",
			"zasp_authorization80.security_agent_set_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)",
		} {
			definition := database.text(`SELECT pg_get_functiondef($1::regprocedure)`, function)
			for _, key := range securityAgentExecutionControlActions {
				if !strings.Contains(definition, "'"+key+"'") {
					t.Fatalf("%s does not list %q", function, key)
				}
			}
		}
	})

	t.Run("a request is refused before a run exists", func(t *testing.T) {
		const definition, finding = "pid_a0000000-0000-4000-8000-000000000010", "pid_a0000000-0000-4000-8000-000000000020"
		guardrail := `{"guardrail_identifier":"gr1abc","guardrail_version":"1"}`
		refused := func(name, wantState, wantMessage string, call func() (json.RawMessage, error)) {
			t.Helper()
			result, err := call()
			state, message := remediationSQLState(err)
			if err == nil || state != wantState || message != wantMessage {
				t.Fatalf("%s: result=%s state=%q message=%q", name, result, state, message)
			}
		}
		// No remediation role is configured yet.
		refused("no remediation role", "55000", "security agent remediation role not configured", func() (json.RawMessage, error) {
			return database.request(definition, "pid_b0000000-0000-4000-8000-000000000001", finding, "attach_bedrock_guardrail", guardrail, "11")
		})
		// The remediation role is set through the integration's own writer.
		setRole := func(role string, expected int64, suffix string) (json.RawMessage, error) {
			return database.as("zasp_svc_api", `SELECT zasp_authorization80.integration_remediation_role_write($1,$2,$3,$4,$5,$6,$7,$8,$9)`, remediationOrg, remediationWorkspace, remediationEnvironment, remediationAdmin, remediationIntegration, role, expected,
				"pid_c1000000-0000-4000-8000-0000000001"+suffix, "pid_c1000000-0000-4000-8000-0000000002"+suffix)
		}
		refused("the read role as the remediation role", "22023", "integration remediation role must be a separate role of the same account", func() (json.RawMessage, error) { return setRole(remediationReadRole, 0, "01") })
		refused("a role of another account", "22023", "integration remediation role must be a separate role of the same account", func() (json.RawMessage, error) {
			return setRole("arn:aws:iam::210987654321:role/zasp-remediation", 0, "02")
		})
		refused("a stale version", "40001", "integration remediation role version conflict", func() (json.RawMessage, error) { return setRole(remediationWriteRole, 3, "03") })
		result, err := setRole(remediationWriteRole, 0, "04")
		var role IntegrationRemediationRole
		if err != nil || !exactJSONFields(result, "audit_id", "configured", "correlation_id", "integration_id", "role_arn", "supported", "updated_at", "version") {
			t.Fatalf("set role=%s err=%v", result, err)
		}
		if json.Unmarshal(result, &role) != nil || !validIntegrationRemediationRole(role, remediationIntegration) || !role.Configured || *role.RoleARN != remediationWriteRole || role.Version != 1 {
			t.Fatalf("role=%#v", role)
		}
		if audited := database.text(`SELECT count(*)::text FROM zasp_workflow_audit WHERE operation='putIntegrationRemediationRole' AND resource_id=$1`, remediationIntegration); audited != "1" {
			t.Fatalf("role change audit rows=%s", audited)
		}
		refused("an action for another rule", "22023", "security agent run definition rejected", func() (json.RawMessage, error) {
			return database.request(definition, "pid_b0000000-0000-4000-8000-000000000002", finding, "detach_role_administrator_policy", `{"policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess"}`, "12")
		})
		refused("a finding of another rule", "22023", "security agent remediation finding rule mismatch", func() (json.RawMessage, error) {
			return database.request(definition, "pid_b0000000-0000-4000-8000-000000000003", "pid_a0000000-0000-4000-8000-000000000021", "attach_bedrock_guardrail", guardrail, "13")
		})
		refused("a guardrail of another account", "22023", "security agent remediation parameters rejected", func() (json.RawMessage, error) {
			return database.request(definition, "pid_b0000000-0000-4000-8000-000000000004", finding, "attach_bedrock_guardrail", `{"guardrail_identifier":"arn:aws:bedrock:us-east-1:210987654321:guardrail/gr1abc","guardrail_version":"1"}`, "14")
		})
		refused("an extra parameter", "22023", "security agent remediation parameters rejected", func() (json.RawMessage, error) {
			return database.request(definition, "pid_b0000000-0000-4000-8000-000000000005", finding, "attach_bedrock_guardrail", `{"guardrail_identifier":"gr1abc","guardrail_version":"1","agent_id":"OTHER"}`, "15")
		})
		// The authorized statement needs the request's proof.
		refused("the authorized statement without a proof", "42501", "current security agent trigger authorization required", func() (json.RawMessage, error) {
			return database.as(remediationAPI, `SELECT zasp_authorization80.security_agent_remediation_run($1,$2,$3,$4,$5,$6::jsonb,NULL)`, remediationOrg, remediationWorkspace, remediationEnvironment, definition, remediationRequester,
				`{"organization_id":"`+remediationOrg+`","workspace_id":"`+remediationWorkspace+`","environment_id":"`+remediationEnvironment+`","definition_id":"`+definition+`","actor_id":"`+remediationRequester+`","idempotency_key":"remediation-request-16","definition_version":2,"run_id":"pid_b0000000-0000-4000-8000-000000000006","trigger_kind":"finding","trigger_id":"`+finding+`","action":"attach_bedrock_guardrail","parameters":`+guardrail+`,"approval_id":"pid_d0000000-0000-4000-8000-000000000116","audit_id":"pid_d0000000-0000-4000-8000-000000000216","correlation_id":"pid_d0000000-0000-4000-8000-000000000316","receipt_id":"pid_d0000000-0000-4000-8000-000000000416"}`)
		})
		if runs := database.text(`SELECT count(*)::text FROM zasp_security_agent_runs`); runs != "0" {
			t.Fatalf("a refused request left %s runs", runs)
		}
	})

	t.Run("attach a guardrail: request, approval, dispatch, lease, verified report", func(t *testing.T) {
		const definition, finding, run, approval = "pid_a0000000-0000-4000-8000-000000000010", "pid_a0000000-0000-4000-8000-000000000020", "pid_b0000000-0000-4000-8000-000000000010", "pid_d0000000-0000-4000-8000-000000000121"
		result, err := database.request(definition, run, finding, "attach_bedrock_guardrail", `{"guardrail_identifier":"gr1abc","guardrail_version":"1"}`, "21")
		var admitted SecurityAgentRunResult
		if err != nil || !exactJSONFields(result, "agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version") || json.Unmarshal(result, &admitted) != nil ||
			admitted.ID != run || admitted.State != "waiting_approval" || admitted.Replayed || !validSecurityAgentRunResult(admitted, SecurityAgentRunRequest{DefinitionID: definition, ExpectedVersion: 2, TriggerKind: "finding", TriggerID: finding}) {
			t.Fatalf("admission=%s err=%v", result, err)
		}
		// The same request again replays its receipt; a second request on the
		// same finding version is refused and names the first run.
		replayed, err := database.request(definition, run, finding, "attach_bedrock_guardrail", `{"guardrail_identifier":"gr1abc","guardrail_version":"1"}`, "21")
		if err != nil || !strings.Contains(string(replayed), `"replayed": true`) {
			t.Fatalf("replay=%s err=%v", replayed, err)
		}
		if _, err := database.request(definition, "pid_b0000000-0000-4000-8000-000000000011", finding, "attach_bedrock_guardrail", `{"guardrail_identifier":"gr1abc","guardrail_version":"2"}`, "22"); err == nil {
			t.Fatal("a second remediation of the same finding version was admitted")
		} else if state, message := remediationSQLState(err); state != "23505" || message != "security agent remediation already requested" {
			t.Fatalf("second request state=%q message=%q", state, message)
		}
		// The requester cannot approve their own request.
		if _, err := database.decide(approval, remediationRequester, "20"); err == nil {
			t.Fatal("the requester approved their own remediation")
		}
		decided, err := database.decide(approval, remediationApprover, "21")
		approved, decodeErr := remediationDecision(decided)
		if err != nil || decodeErr != nil || approved.State != "approved" || approved.ExpectedEffect != "Attach Bedrock guardrail" || !approved.Reversible || approved.TTLSeconds != 0 || !validSecurityAgentApprovalShape(approved) {
			t.Fatalf("decision=%s err=%v", decided, err)
		}
		executed := database.dispatch(run, "21")
		var dispatch SecurityAgentExecuteResult
		if json.Unmarshal(executed, &dispatch) != nil || dispatch.RunID != run || dispatch.State != "running" || dispatch.EffectState != "pending" || !validProductID(dispatch.StepID) || !validProductID(dispatch.OutcomeID) {
			t.Fatalf("dispatch=%s", executed)
		}
		// The Security Agent worker's role cannot lease the effect, and the
		// action worker's lease carries the role and a reference, no secret.
		if _, err := database.as(remediationWorker, `SELECT zasp_security_agent_claim_provider_remediations('security-agent-1','action-lease-token-0001',60,5)`); err == nil {
			t.Fatal("the Security Agent worker leased a provider remediation")
		}
		repository := &SecurityAgentActionRepository{database: remediationJSONDatabase{database: database, login: remediationAction}, current: true}
		claims, err := repository.ClaimProviderRemediations(database.ctx, "security-agent-action-1", "action-lease-token-0001", 60, 5)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claims=%#v err=%v", claims, err)
		}
		claim := claims[0]
		if claim.RunID != run || claim.StepID != dispatch.StepID || claim.Action != "attach_bedrock_guardrail" || claim.RemediationRoleARN != remediationWriteRole || claim.RemediationRoleARN == remediationReadRole || claim.ExternalIDReference != "ref:aws/external-id/abcdefgh12345678" ||
			claim.Target.AgentID != "AGENT12345" || claim.Target.Region != "us-east-1" || claim.Parameters["guardrail_identifier"] != "gr1abc" || claim.Parameters["guardrail_version"] != "1" || claim.Attempt != 1 {
			t.Fatalf("claim=%#v", claim)
		}
		// A leased remediation is not handed out twice, and another worker's
		// token cannot report it.
		if again, err := repository.ClaimProviderRemediations(database.ctx, "security-agent-action-2", "action-lease-token-0002", 60, 5); err != nil || len(again) != 0 {
			t.Fatalf("second claim=%#v err=%v", again, err)
		}
		verified := ProviderRemediationOutcome{State: ProviderRemediationVerified, Prior: map[string]any{"agent_id": "AGENT12345", "guardrail_configuration": nil, "changed": true}, Observed: map[string]any{"agent_id": "AGENT12345", "guardrail_configuration": map[string]any{"guardrail_identifier": "gr1abc", "guardrail_version": "1"}, "prepare": "prepared"}}
		if _, err := repository.FinishProviderRemediation(database.ctx, claim, "security-agent-action-2", "action-lease-token-0002", verified); !errors.Is(err, ErrRepositoryConflict) {
			t.Fatalf("report under another lease err=%v", err)
		}
		finished, err := repository.FinishProviderRemediation(database.ctx, claim, "security-agent-action-1", "action-lease-token-0001", verified)
		if err != nil || finished.State != "remediated" || finished.EffectState != "verified" {
			t.Fatalf("finished=%#v err=%v", finished, err)
		}
		if state := database.text(`SELECT state||' '||COALESCE(last_error_code,'-') FROM zasp_security_agent_runs WHERE run_id=$1`, run); state != "remediated -" {
			t.Fatalf("run state=%q", state)
		}
		// The rollback record is stored with the remediation and in the audit.
		if prior := database.text(`SELECT prior::text FROM zasp_security_agent_provider_remediations WHERE run_id=$1 AND state='verified'`, run); !strings.Contains(prior, `"guardrail_configuration": null`) || !strings.Contains(prior, `"changed": true`) {
			t.Fatalf("stored rollback record=%s", prior)
		}
		events := database.text(`SELECT string_agg(event_kind,',' ORDER BY created_at,event_kind) FROM zasp_security_agent_audit WHERE run_id=$1`, run)
		if events != "approval_requested,run_queued,approval_decided,effect_dispatched,effect_verified" && events != "run_queued,approval_requested,approval_decided,effect_dispatched,effect_verified" {
			t.Fatalf("audit events=%s", events)
		}
		if rollback := database.text(`SELECT (body->'rollback')::text FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='effect_verified'`, run); !strings.Contains(rollback, `"guardrail_configuration": null`) {
			t.Fatalf("audited rollback record=%s", rollback)
		}
		// The run and its approval read back through the readers the API uses,
		// in the shapes the API decodes.
		context, err := database.as(remediationAPI, `SELECT public.zasp_production_security_agent_existing_tests_run_context_core($1,$2,$3,$4)`, remediationOrg, remediationWorkspace, remediationEnvironment, run)
		if err != nil {
			t.Fatalf("run context: %v", err)
		}
		// The whole run decodes into the public run detail and is valid as one.
		detail, err := decodeSecurityAgentRunContextEnvelope(context, run)
		if err != nil || !validSecurityAgentRunDetail(detail, run) || len(detail.ActionDetails) != 1 || detail.ActionDetails[0].Rollback.Support != "manual" || detail.ActionDetails[0].Result == nil || detail.ActionDetails[0].Result.State != "verified" {
			t.Fatalf("run detail=%#v err=%v context=%s", detail, err, context)
		}
		if public, err := json.Marshal(detail); err != nil {
			t.Fatal(err)
		} else {
			t.Logf("public run detail: %s", public)
		}
		var steps []struct {
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(extractJSONField(extractJSONField(context, "action_details"), "steps"), &steps) != nil || len(steps) != 1 {
			t.Fatalf("action details=%s", context)
		}
		arguments, err := decodeSecurityAgentActionArguments("attach_bedrock_guardrail", steps[0].Arguments)
		if err != nil || arguments.TargetID != remediationAgentEntity || arguments.IntegrationID != remediationIntegration || arguments.GuardrailIdentifier != "gr1abc" || arguments.GuardrailVersion != "1" {
			t.Fatalf("action arguments=%#v err=%v context=%s", arguments, err, context)
		}
		approvalContext, err := database.as(remediationAPI, `SELECT public.zasp_production_security_agent_existing_tests_approval_ctx_core($1,$2,$3,$4)`, remediationOrg, remediationWorkspace, remediationEnvironment, approval)
		if err != nil {
			t.Fatalf("approval context: %v", err)
		}
		projected, err := decodeSecurityAgentApprovalContext(extractJSONField(approvalContext, "context"), approved)
		if err != nil || projected.Action != "attach_bedrock_guardrail" || projected.Risk.Class != "moderate" {
			t.Fatalf("approval context=%#v err=%v raw=%s", projected, err, approvalContext)
		}
	})

	t.Run("detach a policy: an identity administrator approves, a refusal hands the run to a person", func(t *testing.T) {
		const definition, finding, run, approval = "pid_a0000000-0000-4000-8000-000000000011", "pid_a0000000-0000-4000-8000-000000000021", "pid_b0000000-0000-4000-8000-000000000020", "pid_d0000000-0000-4000-8000-000000000131"
		if _, err := database.request(definition, run, finding, "detach_role_administrator_policy", `{"policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess"}`, "31"); err != nil {
			t.Fatalf("admission: %v", err)
		}
		// An approver who is not an identity administrator is refused.
		if _, err := database.decide(approval, remediationApprover, "30"); err == nil {
			t.Fatal("a destructive remediation was approved without an identity administrator")
		} else if state, message := remediationSQLState(err); state != "42501" || message != "security agent irreversible approval rejected" {
			t.Fatalf("non-admin decision state=%q message=%q", state, message)
		}
		decided, err := database.decide(approval, remediationAdmin, "31")
		approved, decodeErr := remediationDecision(decided)
		if err != nil || decodeErr != nil || approved.State != "approved" || approved.ExpectedEffect != "Detach administrator policy from agent role" || approved.Reversible || !validSecurityAgentApprovalShape(approved) {
			t.Fatalf("decision=%s err=%v", decided, err)
		}
		database.dispatch(run, "31")
		repository := &SecurityAgentActionRepository{database: remediationJSONDatabase{database: database, login: remediationAction}, current: true}
		claims, err := repository.ClaimProviderRemediations(database.ctx, "security-agent-action-1", "action-lease-token-0003", 60, 5)
		if err != nil || len(claims) != 1 || claims[0].Action != "detach_role_administrator_policy" || claims[0].Parameters["policy_arn"] != "arn:aws:iam::aws:policy/AdministratorAccess" {
			t.Fatalf("claims=%#v err=%v", claims, err)
		}
		finished, err := repository.FinishProviderRemediation(database.ctx, claims[0], "security-agent-action-1", "action-lease-token-0003", ProviderRemediationOutcome{State: ProviderRemediationFailed, FailureCode: "policy_not_attached"})
		if err != nil || finished.State != "needs_human" || finished.EffectState != "known_failure" {
			t.Fatalf("finished=%#v err=%v", finished, err)
		}
		if state := database.text(`SELECT state||' '||COALESCE(last_error_code,'-') FROM zasp_security_agent_runs WHERE run_id=$1`, run); state != "needs_human policy_not_attached" {
			t.Fatalf("run state=%q", state)
		}
		if state := database.text(`SELECT state||' '||failure_code||' '||(prior IS NULL)::text FROM zasp_security_agent_provider_remediations WHERE run_id=$1`, run); state != "needs_human policy_not_attached true" {
			t.Fatalf("remediation=%q", state)
		}
		// A finished remediation cannot be reported again.
		if _, err := repository.FinishProviderRemediation(database.ctx, claims[0], "security-agent-action-1", "action-lease-token-0003", ProviderRemediationOutcome{State: ProviderRemediationFailed, FailureCode: "policy_not_attached"}); !errors.Is(err, ErrRepositoryConflict) {
			t.Fatalf("second report err=%v", err)
		}
	})
}

// remediationJSONDatabase serves the action repository's statements as one
// service login on the test's connection.
type remediationJSONDatabase struct {
	database remediationDatabase
	login    string
}

func (database remediationJSONDatabase) SchemaVersion(context.Context) (string, error) {
	return "", ErrRepositoryUnavailable
}

func (database remediationJSONDatabase) Exec(context.Context, string, ...any) error {
	return ErrRepositoryUnavailable
}

func (database remediationJSONDatabase) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	result, err := database.database.as(database.login, statement, arguments...)
	if err != nil {
		return nil, classifyPostgresError(err)
	}
	return result, nil
}

// remediationDecision is the approval of a decision result, without the
// decision's own receipt members.
func remediationDecision(raw json.RawMessage) (SecurityAgentApproval, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return SecurityAgentApproval{}, err
	}
	for _, key := range []string{"audit_id", "correlation_id", "receipt_id", "replayed"} {
		if _, present := fields[key]; !present {
			return SecurityAgentApproval{}, errors.New("decision member missing: " + key)
		}
		delete(fields, key)
	}
	approval, err := json.Marshal(fields)
	if err != nil {
		return SecurityAgentApproval{}, err
	}
	var value SecurityAgentApproval
	return value, json.Unmarshal(approval, &value)
}
