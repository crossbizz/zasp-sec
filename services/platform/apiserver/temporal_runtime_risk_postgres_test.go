package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestTemporalRuntimeRiskPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission} {
			if err := up(ctx); err != nil {
				t.Fatal("install", err)
			}
		}
		if err := runner.UpProductionTemporalAutomaticSources(ctx); err != nil {
			tx, txErr := owner.Begin(ctx)
			if txErr != nil {
				t.Fatal(txErr)
			}
			defer tx.Rollback(ctx)
			_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalAutomaticSources().UpSQL())
			var pin, base, domain string
			pinErr := tx.QueryRow(ctx, `SELECT zasp_temporal77.fingerprint()`).Scan(&pin)
			baseErr := tx.QueryRow(ctx, `SELECT zasp_temporal77.base67_fingerprint(),zasp_temporal77.domain67_fingerprint()`).Scan(&base, &domain)
			t.Logf("independent77 DDL=%v fingerprint=%s pin_error=%v base_projection=%s domain_projection=%s projection_error=%v", ddlErr, pin, pinErr, base, domain, baseErr)
			t.Fatal("install77", err)
		}
		var compilerHash, compilerOwner, compilerACL string
		if err := owner.QueryRow(ctx, `SELECT encode(digest(convert_to(pg_get_functiondef(oid),'UTF8'),'sha256'),'hex'),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure`).Scan(&compilerHash, &compilerOwner, &compilerACL); err != nil {
			t.Fatal(err)
		}
		t.Logf("effective SQL compiler hash=%s owner=%s acl=%s", compilerHash, compilerOwner, compilerACL)
		t.Run("policy deployment compiler", func(t *testing.T) {
			for _, risk := range []string{"", "low", "medium", "high", "critical"} {
				t.Run("risk="+risk, func(t *testing.T) {
					p := policy.Policy{ID: "policy-risk", Name: "Risk", Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: "invoke"}}, Action: policy.ActionBlock, Rollout: "monitor", FailureMode: "closed", Risk: risk}
					compiled, included, err := policy.CompileGatewayPolicy(p)
					if err != nil || !included {
						t.Fatal(err)
					}
					raw, _ := json.Marshal(p)
					var actual json.RawMessage
					if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.deployment_compile($1::jsonb,true)`, raw).Scan(&actual); err != nil {
						t.Fatal("persistent SQL risk compiler", err)
					}
					want, _ := json.Marshal(compiled)
					assertAutomaticRuleJSON(t, "SQL/Go compiled", actual, want)
					var fromSQL policy.CompiledPolicy
					if json.Unmarshal(actual, &fromSQL) != nil {
						t.Fatal("compiled decode")
					}
					secret := []byte("0123456789abcdef0123456789abcdef")
					bundle, err := policy.SignBundle(secret, e, []policy.CompiledPolicy{fromSQL})
					if err != nil || policy.VerifyBundle(secret, bundle) != nil {
						t.Fatal("SQL compiled signed consumer", err)
					}
					var rebuilt json.RawMessage
					if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.deployment_compile($1::jsonb,false)`, actual).Scan(&rebuilt); err != nil {
						t.Fatal("compiled SQL risk compiler", err)
					}
					assertAutomaticRuleJSON(t, "compiled revalidation", rebuilt, actual)
					if risk != "" {
						fromSQL.Risk = "low"
						if risk == "low" {
							fromSQL.Risk = "critical"
						}
						bundle.Policies[0] = fromSQL
						if policy.VerifyBundle(secret, bundle) == nil {
							t.Fatal("SQL annotation tamper retained signature")
						}
						for _, bad := range []any{nil, "", "severe", 7} {
							var malformed map[string]any
							json.Unmarshal(raw, &malformed)
							malformed["risk"] = bad
							badRaw, _ := json.Marshal(malformed)
							if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.deployment_compile($1::jsonb,true)`, badRaw).Scan(&rebuilt); err == nil {
								t.Fatal("SQL compiler accepted invalid annotation", bad)
							}
						}
					}
				})
			}
		})
		var principal string
		for _, name := range []string{"risk77_coordinator", "risk77_archive", "risk77_index", "risk77_correlation", "risk77_projection", "risk77_gateway"} {
			if _, err := owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
				t.Fatal("fixture runtime login", err)
			}
		}
		var runtimeReady bool
		if err := owner.QueryRow(ctx, `SELECT zasp_runtime_register_principals(session_user,'risk77_coordinator','risk77_archive','risk77_index','risk77_correlation','risk77_projection','risk77_gateway')`).Scan(&runtimeReady); err != nil || !runtimeReady {
			t.Fatal("fixture runtime binding", runtimeReady, err)
		}
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_runtime_principal_bindings WHERE authority_role='zasp_gateway_control'`).Scan(&principal); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = principal
		gateway, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer gateway.Close(context.Background())
		const device = "pid_f0771000-0000-4000-8000-000000000001"
		const enrollment = "pid_f0771000-0000-4000-8000-000000000002"
		const credential = "pid_f0771000-0000-4000-8000-000000000003"
		if _, err := owner.Exec(ctx, `
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Risk gateway','active');
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at,consumed_at,format_version,locator_digest,token_generation,device_version_at_issue,v15_issued_at)
VALUES($1,$2,$3,$5,$4,'runtime-gateway-enroll',decode(repeat('51',16),'hex'),digest(convert_to($5,'UTF8'),'sha256'),transaction_timestamp()+interval '1 hour',transaction_timestamp(),1,digest(convert_to($5||':locator','UTF8'),'sha256'),1,1,transaction_timestamp());
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at)
VALUES($1,$2,$3,$6,$4,$5,digest(convert_to($5||':credential','UTF8'),'sha256'),'runtime-gateway','ref:gateway/public/gateway-key-1',decode(repeat('52',32),'hex'),transaction_timestamp()+interval '1 hour',1,1,'gateway-key-1','Ed25519',transaction_timestamp())`, pgx.QueryExecModeSimpleProtocol, o, w, e, device, enrollment, credential); err != nil {
			t.Fatal("gateway seed", err)
		}
		db := riskIngestDiagnosticDB{conn: gateway, t: t}
		repository, err := gatewaycontrol.NewPostgresRepository(db, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		evaluation := &gatewaycontrol.EvaluationEvidence{Version: 1, Action: "tool_execute", AgentID: "pid_f0771000-0000-4000-8000-000000000010", SessionID: "pid_f0771000-0000-4000-8000-000000000011", ContributingPolicyIDs: []string{"policy-risk"}, Risk: "high"}
		event := gatewaycontrol.DecisionEvent{CredentialID: credential, DeviceID: device, EventID: "pid_f0771000-0000-4000-8000-000000000020", ExpectedFloor: 0, NextFloor: 1, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", PolicyIDs: []string{"policy-risk"}, Classification: map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": "requested", "session_id": evaluation.SessionID}, OccurredAt: time.Now().UTC().Truncate(time.Second), Evaluation: evaluation}
		if err := repository.Record(ctx, event); err != nil {
			t.Fatal("actual annotated writer", err)
		}
		if err := repository.Record(ctx, event); err != nil {
			t.Fatal("exact annotated replay", err)
		}
		var got json.RawMessage
		var at time.Time
		var floor int64
		var digestOK bool
		if err := owner.QueryRow(ctx, `SELECT a.evaluation,v.occurred_at,d.replay_floor,v.request_digest=a.legacy_digest FROM zasp_temporal77.runtime_evaluations a JOIN zasp_runtime_gateway_events v USING(organization_id,workspace_id,environment_id,event_id) JOIN zasp_gateway_devices d ON(d.organization_id,d.workspace_id,d.environment_id,d.id)=(v.organization_id,v.workspace_id,v.environment_id,v.device_id) WHERE a.event_id=$1`, event.EventID).Scan(&got, &at, &floor, &digestOK); err != nil {
			t.Fatal("annotation readback", err)
		}
		want, _ := json.Marshal(evaluation)
		assertAutomaticRuleJSON(t, "runtime annotation", got, want)
		if !at.Equal(event.OccurredAt) || floor != 1 || !digestOK {
			t.Fatal("canonical event/floor changed", at, floor, digestOK)
		}
		if err := owner.QueryRow(ctx, `SELECT a.request_digest=digest(convert_to(jsonb_build_object('credential_id',v.credential_id,'device_id',v.device_id,'event_id',v.event_id,'expected_floor',0::bigint,'next_floor',v.sequence,'policy_version',v.policy_version,'decision',v.decision,'action_kind',v.action_kind,'classification',v.classification,'policy_ids',v.policy_ids,'occurred_at',to_char(v.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'evaluation',a.evaluation)::text,'UTF8'),'sha256') AND a.request_digest<>a.legacy_digest FROM zasp_temporal77.runtime_evaluations a JOIN zasp_runtime_gateway_events v USING(organization_id,workspace_id,environment_id,event_id) WHERE a.event_id=$1`, event.EventID).Scan(&digestOK); err != nil || !digestOK {
			t.Fatal("combined digest does not bind evaluation", digestOK, err)
		}
		evaluation.Risk = "critical"
		if repository.Record(ctx, event) == nil {
			t.Fatal("same event accepted changed evaluation")
		}
		evaluation.Risk = "high"
		legacy := event
		legacy.EventID = "pid_f0771000-0000-4000-8000-000000000021"
		legacy.ExpectedFloor = 1
		legacy.NextFloor = 2
		legacy.Evaluation = nil
		if err := repository.Record(ctx, legacy); err != nil {
			t.Fatal("legacy27 writer", err)
		}
		legacy.Evaluation = evaluation
		if repository.Record(ctx, legacy) == nil {
			t.Fatal("historical27 event acquired annotation")
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.runtime_evaluations WHERE event_id=$1`, legacy.EventID).Scan(&count); err != nil || count != 0 {
			t.Fatal("historical event annotated", count, err)
		}
		tx, err := gateway.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		transactionRepo, _ := gatewaycontrol.NewPostgresRepository(riskIngestDiagnosticDB{conn: tx, t: t}, 10*time.Second)
		rolled := event
		rolled.EventID = "pid_f0771000-0000-4000-8000-000000000022"
		rolled.ExpectedFloor = 2
		rolled.NextFloor = 3
		if err := transactionRepo.Record(ctx, rolled); err != nil {
			t.Fatal("transaction writer", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_gateway_events WHERE event_id=$1)+(SELECT count(*) FROM zasp_temporal77.runtime_evaluations WHERE event_id=$1)`, rolled.EventID).Scan(&count); err != nil || count != 0 {
			t.Fatal("rollback leaked event/annotation", count, err)
		}
		if err := owner.QueryRow(ctx, `SELECT replay_floor FROM zasp_gateway_devices WHERE id=$1`, device).Scan(&floor); err != nil || floor != 2 {
			t.Fatal("rollback advanced floor", floor, err)
		}
		// The public API role has no annotation writer authority.
		unauthorized, _ := gatewaycontrol.NewPostgresRepository(api, 10*time.Second)
		if unauthorized.Record(ctx, rolled) == nil {
			t.Fatal("API principal wrote gateway annotation")
		}
		// A credential from a different tenant cannot authenticate this device's
		// event, even though both credentials are individually current and valid.
		if _, err := owner.Exec(ctx, `
INSERT INTO zasp_organizations(id,name,domain) VALUES('pid_f0772000-0000-4000-8000-000000000001','Foreign risk tenant','risk77-foreign.invalid');
INSERT INTO zasp_workspaces(id,organization_id,name) VALUES('pid_f0772000-0000-4000-8000-000000000002','pid_f0772000-0000-4000-8000-000000000001','Security');
INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES('pid_f0772000-0000-4000-8000-000000000003','pid_f0772000-0000-4000-8000-000000000001','pid_f0772000-0000-4000-8000-000000000002','Production','production');
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES('pid_f0772000-0000-4000-8000-000000000001','pid_f0772000-0000-4000-8000-000000000002','pid_f0772000-0000-4000-8000-000000000003','pid_f0772000-0000-4000-8000-000000000004','Foreign gateway','active');
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,issued_at,expires_at,consumed_at,format_version,locator_digest,token_generation,device_version_at_issue,v15_issued_at)
SELECT 'pid_f0772000-0000-4000-8000-000000000001','pid_f0772000-0000-4000-8000-000000000002','pid_f0772000-0000-4000-8000-000000000003','pid_f0772000-0000-4000-8000-000000000005','pid_f0772000-0000-4000-8000-000000000004',audience,salt,digest(convert_to('foreign-risk77-token','UTF8'),'sha256'),issued_at,expires_at,consumed_at,format_version,digest(convert_to('foreign-risk77','UTF8'),'sha256'),token_generation,device_version_at_issue,v15_issued_at FROM zasp_gateway_enrollment_tokens WHERE id=$1;
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at)
SELECT 'pid_f0772000-0000-4000-8000-000000000001','pid_f0772000-0000-4000-8000-000000000002','pid_f0772000-0000-4000-8000-000000000003','pid_f0772000-0000-4000-8000-000000000006','pid_f0772000-0000-4000-8000-000000000004','pid_f0772000-0000-4000-8000-000000000005',enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at FROM zasp_gateway_credentials WHERE id=$2`, pgx.QueryExecModeSimpleProtocol, enrollment, credential); err != nil {
			t.Fatal("foreign authority seed", err)
		}
		foreign := rolled
		foreign.CredentialID = "pid_f0772000-0000-4000-8000-000000000006"
		if repository.Record(ctx, foreign) == nil {
			t.Fatal("foreign tenant credential authorized original device")
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_gateway_events WHERE event_id=$1)+(SELECT count(*) FROM zasp_temporal77.runtime_evaluations WHERE event_id=$1)`, rolled.EventID).Scan(&count); err != nil || count != 0 {
			t.Fatal("foreign credential leaked event", count, err)
		}
		// Corrupt only this disposable database's registered catalog, then restore
		// it. Annotated writes must fail even while their function/ACL still exist.
		if _, err := owner.Exec(ctx, `ALTER FUNCTION zasp_temporal77.evaluation_valid(jsonb,text,jsonb,jsonb) COST 123`); err != nil {
			t.Fatal(err)
		}
		if repository.Record(ctx, rolled) == nil {
			t.Fatal("invalid77 catalog accepted annotation")
		}
		if _, err := owner.Exec(ctx, `ALTER FUNCTION zasp_temporal77.evaluation_valid(jsonb,text,jsonb,jsonb) COST 100`); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal77.ready($1,$2) AND zasp_temporal76.ready($3,$4)`, migrations.ProductionTemporalAutomaticSources().Checksum(), migrations.TemporalAutomaticSourcesFingerprint(), migrations.ProductionTemporalHumanAdmission().Checksum(), migrations.TemporalHumanAdmissionFingerprint()).Scan(&runtimeReady); err != nil || !runtimeReady {
			t.Fatal("restored catalog not ready", runtimeReady, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=transaction_timestamp() WHERE id=$1`, credential); err != nil {
			t.Fatal(err)
		}
		if repository.Record(ctx, rolled) == nil {
			t.Fatal("revoked credential wrote event")
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_gateway_events WHERE event_id=$1`, rolled.EventID).Scan(&count); err != nil || count != 0 {
			t.Fatal("credential refusal leaked event", count, err)
		}
	})
}

type riskIngestDiagnosticDB struct {
	conn interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}
	t *testing.T
}

func (d riskIngestDiagnosticDB) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	return riskIngestDiagnosticRow{Row: d.conn.QueryRow(ctx, q, args...), t: d.t}
}

type riskIngestDiagnosticRow struct {
	pgx.Row
	t *testing.T
}

func (r riskIngestDiagnosticRow) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	if err != nil {
		r.t.Logf("actual gateway SQL: %v", err)
	}
	return err
}
