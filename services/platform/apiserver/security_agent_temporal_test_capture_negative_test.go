package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Synthetic negative evidence only. The fixed helper lets the registered API
// session reach the real65 trigger without granting any product table/core access.
func installTemporalTestCaptureNegative(t *testing.T, ctx context.Context, owner, api *pgx.Conn) {
	t.Helper()
	var login string
	if err := api.QueryRow(ctx, `SELECT session_user`).Scan(&login); err != nil {
		t.Fatal(err)
	}
	const fixture = `
CREATE SCHEMA test74_capture_fixture AUTHORIZATION zasp_discovery_authority;
CREATE FUNCTION test74_capture_fixture.non74_cancelled() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $fixture$
DECLARE src public.zasp_security_agent_request_receipts%ROWTYPE;ap public.zasp_security_agent_approvals%ROWTYPE;intent_value jsonb;identity_value constant text:='pid_f0740000-0000-4000-8000-000000000697';
BEGIN
 SELECT a.* INTO STRICT ap FROM public.zasp_security_agent_approvals a WHERE a.run_id='pid_f0740000-0000-4000-8000-000000000601' AND a.state='cancelled';
 SELECT rc.* INTO STRICT src FROM public.zasp_security_agent_request_receipts rc WHERE (rc.organization_id,rc.workspace_id,rc.environment_id,rc.resource_id,rc.operation)=(ap.organization_id,ap.workspace_id,ap.environment_id,ap.approval_id,'decideSecurityAgentApproval') AND rc.response->>'state'='cancelled';
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION 'fixture API/current catalog premise absent';END IF;
 intent_value:=jsonb_build_object('approval_id',identity_value,'expected_version',src.expected_version,'decision','cancelled');
 INSERT INTO public.zasp_security_agent_runs SELECT (jsonb_populate_record(NULL::public.zasp_security_agent_runs,to_jsonb(r)||jsonb_build_object('run_id',identity_value,'state','simulated'))).* FROM public.zasp_security_agent_runs r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(ap.organization_id,ap.workspace_id,ap.environment_id,ap.run_id);
 UPDATE public.zasp_security_agent_runs SET state='cancelled' WHERE run_id=identity_value;
 INSERT INTO public.zasp_security_agent_approvals SELECT (jsonb_populate_record(NULL::public.zasp_security_agent_approvals,to_jsonb(ap)||jsonb_build_object('run_id',identity_value,'approval_id',identity_value))).*;
 INSERT INTO public.zasp_security_agent_audit SELECT (jsonb_populate_record(NULL::public.zasp_security_agent_audit,to_jsonb(a)||jsonb_build_object('audit_id',identity_value,'correlation_id',identity_value,'run_id',identity_value,'approval_id',identity_value,'event_digest',digest(convert_to(intent_value::text,'UTF8'),'sha256'),'body',jsonb_build_object('approval_id',identity_value,'run_id',identity_value,'decision','cancelled','version',src.expected_version+1)))).* FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=(src.organization_id,src.workspace_id,src.environment_id,src.audit_id);
 INSERT INTO public.zasp_security_agent_request_receipts SELECT (jsonb_populate_record(NULL::public.zasp_security_agent_request_receipts,to_jsonb(src)||jsonb_build_object('idempotency_key','test74-capture-non74-cancelled','resource_id',identity_value,'intent',intent_value,'intent_digest',digest(convert_to(intent_value::text,'UTF8'),'sha256'),'audit_id',identity_value,'correlation_id',identity_value,'receipt_id',identity_value,'response',src.response||jsonb_build_object('id',identity_value,'run_id',identity_value,'audit_id',identity_value,'correlation_id',identity_value,'receipt_id',identity_value)))).*;
END $fixture$;
ALTER FUNCTION test74_capture_fixture.non74_cancelled() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION test74_capture_fixture.non74_cancelled() FROM PUBLIC;`
	if _, err := owner.Exec(ctx, fixture); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `GRANT USAGE ON SCHEMA test74_capture_fixture TO `+pgx.Identifier{login}.Sanitize()+`; GRANT EXECUTE ON FUNCTION test74_capture_fixture.non74_cancelled() TO `+pgx.Identifier{login}.Sanitize()); err != nil {
		t.Fatal(err)
	}
}

func assertTemporalTestCaptureNegative(t *testing.T, ctx context.Context, api *pgx.Conn) {
	t.Helper()
	if _, err := api.Exec(ctx, `SAVEPOINT capture_negative`); err != nil {
		t.Fatal(err)
	}
	_, err := api.Exec(ctx, `SELECT test74_capture_fixture.non74_cancelled()`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" || pgErr.Message != "outbox approval decision absent" {
		t.Fatal("non74 cancelled decision did not reach exact65 refusal", err)
	}
	if _, err := api.Exec(ctx, `ROLLBACK TO SAVEPOINT capture_negative`); err != nil {
		t.Fatal(err)
	}
}

func assertTemporalTestCaptureNoResidue(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	var absent bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_approvals WHERE approval_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE audit_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE receipt_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal65.commands WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.control_intents WHERE run_id=$1)`, "pid_f0740000-0000-4000-8000-000000000697").Scan(&absent); err != nil || !absent {
		t.Fatal("non74 trigger refusal left residue", absent, err)
	}
}
