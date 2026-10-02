package migrations

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func revisionTestFunction(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, "CREATE FUNCTION "+signature)
	if start < 0 {
		t.Fatalf("function %s missing", signature)
	}
	end := strings.Index(source[start:], "$body$;")
	if end < 0 {
		t.Fatalf("function %s terminator missing", signature)
	}
	return source[start : start+end+len("$body$;")]
}

func TestSingleTestRecoveryRevisionFencePostgres(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	admission := revisionTestSQL(t, "0080_temporal_single_recovery.admission.sql")
	human := revisionTestFunction(t, admission, "zasp_temporal_single_recovery.human(q jsonb,mutate boolean,current_version boolean,revision_delta bigint) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$")
	setup := `
CREATE SCHEMA zasp_authorization79;
CREATE SCHEMA zasp_authorization80;
CREATE SCHEMA zasp_temporal74;
CREATE SCHEMA zasp_temporal_single_recovery;
CREATE TABLE zasp_authorization79.organizations(organization_id text PRIMARY KEY,desired bigint NOT NULL,applied bigint NOT NULL,generation bigint NOT NULL,store_id text NOT NULL,model_id text NOT NULL);
CREATE TABLE public.zasp_security_agent_runs(organization_id text,workspace_id text,environment_id text,run_id text,version bigint,PRIMARY KEY(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE zasp_authorization80.fixture(singleton boolean PRIMARY KEY,p jsonb NOT NULL);
CREATE FUNCTION zasp_authorization80.context() RETURNS jsonb LANGUAGE sql STABLE AS $$SELECT p FROM zasp_authorization80.fixture WHERE singleton$$;
CREATE FUNCTION zasp_authorization80.read_request(text,text,text,text[],text,boolean,text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$SELECT true$$;
CREATE FUNCTION zasp_authorization80.allowed(text,text,text,text,text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$SELECT true$$;
CREATE FUNCTION zasp_authorization80.identity_fence(jsonb) RETURNS void LANGUAGE sql AS $$SELECT$$;
CREATE FUNCTION zasp_temporal74.manager(text,text,text,text) RETURNS void LANGUAGE sql AS $$SELECT$$;
CREATE FUNCTION public.zasp_security_agent_principal_ready(text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$SELECT true$$;
CREATE FUNCTION zasp_temporal_single_recovery.ready(text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$SELECT true$$;
INSERT INTO zasp_authorization79.organizations VALUES('org',10,9,3,'store','model');
INSERT INTO public.zasp_security_agent_runs VALUES('org','workspace','environment','run',7);
INSERT INTO zasp_authorization80.fixture VALUES(true,'{"collection":false,"path_parameters":{"id":"run"},"targets":[{"organization_id":"org","workspace_id":"workspace","environment_id":"environment","kind":"security_agent_run","id":"run","source_id":"run","version":7}],"allowed":[true],"revision":{"desired":10,"applied":9,"generation":3,"store_id":"store","model_id":"model"}}');
`
	assertions := `
DO $test$
DECLARE q jsonb:='{"organization_id":"org","workspace_id":"workspace","environment_id":"environment","run_id":"run","actor_id":"actor"}';state text;
BEGIN
 PERFORM zasp_temporal_single_recovery.human(q,true,true,0);
 UPDATE zasp_authorization79.organizations SET desired=14 WHERE organization_id='org';
 PERFORM zasp_temporal_single_recovery.human(q,true,true,4);
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,3);
  RAISE EXCEPTION 'short local delta accepted';
 EXCEPTION WHEN serialization_failure THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'40001' THEN RAISE;END IF;END;
 UPDATE zasp_authorization79.organizations SET desired=15 WHERE organization_id='org';
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,4);
  RAISE EXCEPTION 'unrelated revision accepted';
 EXCEPTION WHEN serialization_failure THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'40001' THEN RAISE;END IF;END;
 UPDATE zasp_authorization79.organizations SET desired=14,applied=10 WHERE organization_id='org';
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,4);
  RAISE EXCEPTION 'changed applied revision accepted';
 EXCEPTION WHEN serialization_failure THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'40001' THEN RAISE;END IF;END;
 UPDATE zasp_authorization79.organizations SET applied=9,generation=4 WHERE organization_id='org';
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,4);
  RAISE EXCEPTION 'changed generation accepted';
 EXCEPTION WHEN serialization_failure THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'40001' THEN RAISE;END IF;END;
 UPDATE zasp_authorization79.organizations SET generation=3,store_id='other-store' WHERE organization_id='org';
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,4);
  RAISE EXCEPTION 'changed store accepted';
 EXCEPTION WHEN serialization_failure THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'40001' THEN RAISE;END IF;END;
 UPDATE zasp_authorization79.organizations SET store_id='store',model_id='other-model' WHERE organization_id='org';
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,4);
  RAISE EXCEPTION 'changed model accepted';
 EXCEPTION WHEN serialization_failure THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'40001' THEN RAISE;END IF;END;
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,5);
  RAISE EXCEPTION 'out-of-range delta accepted';
 EXCEPTION WHEN invalid_transaction_state THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'25001' THEN RAISE;END IF;END;
 BEGIN
  PERFORM zasp_temporal_single_recovery.human(q,true,true,NULL);
  RAISE EXCEPTION 'null delta accepted';
 EXCEPTION WHEN invalid_transaction_state THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;IF state<>'25001' THEN RAISE;END IF;END;
END
$test$;`
	if _, err := tx.Exec(ctx, setup+human+assertions); err != nil {
		t.Fatal(err)
	}
}
