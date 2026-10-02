package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These installed-catalog probes catch a projection that also hides the new
// live trigger, or one that accidentally stops measuring retained immutability.
func assertWorkerRuntimeCatalog(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	assertWorkerRuntimeDirectMutationDenied(t, ctx, owner)
	if t.Failed() {
		return
	}
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND NOT zasp_authorization80_worker.runtime_ready()
 AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='zasp_authorization80_worker.runtime_associations'::regclass)
 AND NOT has_function_privilege('worker_test_executor','zasp_authorization80_worker.runtime_source(text,text,text,text)','EXECUTE')
 AND NOT has_function_privilege('worker_test_compensation','zasp_authorization80_worker.runtime_source(text,text,text,text)','EXECUTE')
 AND NOT has_function_privilege('worker_test_executor','zasp_authorization80_worker.runtime_capture(text,text,text,text)','EXECUTE')
 AND NOT has_function_privilege('worker_test_executor','zasp_authorization80_worker.runtime_occurrence_match(text,text,text,text,jsonb)','EXECUTE')
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['zasp_temporal_executor','zasp_temporal_compensation','zasp_red_team_adapter']) role_name CROSS JOIN unnest(ARRAY[
 'zasp_temporal74.context(text,text,text,text)','zasp_temporal74.context_parent(text,text,text,text,jsonb)',
 'zasp_temporal74.current_step(text,text,text,text,text)','zasp_temporal74.step_parent(text,text,text,text,text,jsonb)',
 'zasp_authorization80_worker.runtime_source_after_entry(text,text,text,text)',
 'zasp_authorization80_worker.runtime_trigger_inner(text,text,text,text,bigint,text,text,text,text,bigint)',
 'zasp_authorization80_worker.runtime_occurrence_match_inner(text,text,text,text,jsonb)',
 'zasp_authorization80_worker.test74_pricing_inner(text,text,jsonb)',
 'zasp_authorization80_worker.test74_context_inner(text,text,text,text)',
 'zasp_authorization80_worker.test74_context_parent_inner(text,text,text,text,jsonb)',
 'zasp_authorization80_worker.test74_authorize_inner(text,text,text,text,bigint)',
 'zasp_authorization80_worker.test74_service_current_inner(text,text,text,text,bigint)',
 'zasp_temporal74.load_plan(jsonb)',
 'zasp_authorization80_worker.test74_private_facts(boolean,jsonb,boolean,jsonb)']) signature
 WHERE has_function_privilege(role_name,signature,'EXECUTE'))`).Scan(&ready); err != nil || !ready {
		t.Fatal("runtime capture catalog/private-reader baseline", err)
	}
	for _, mutation := range []struct{ name, sql string }{
		{"evaluation capture", `ALTER TABLE zasp_temporal77.runtime_evaluations DISABLE TRIGGER zasp_authorization80_worker_runtime_capture`},
		{"evaluation truncate", `ALTER TABLE zasp_temporal77.runtime_evaluations DISABLE TRIGGER zasp_authorization80_worker_runtime_no_truncate`},
		{"source catch-up capture", `ALTER TABLE zasp_temporal77.source_events DISABLE TRIGGER zasp_authorization80_worker_runtime_capture`},
		{"source truncate", `ALTER TABLE zasp_temporal77.source_events DISABLE TRIGGER zasp_authorization80_worker_runtime_no_truncate`},
		{"retained evaluation immutable", `ALTER TABLE zasp_temporal77.runtime_evaluations DISABLE TRIGGER immutable`},
		{"retained source immutable", `ALTER TABLE zasp_temporal77.source_events DISABLE TRIGGER immutable`},
		{"runtime capture function", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.capture_runtime_source() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`},
		{"runtime capture ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.capture_runtime_source() TO PUBLIC`},
		{"source insertion body", `CREATE OR REPLACE FUNCTION zasp_temporal77.put_source(o text,w text,e text,k text,id_value text,v bigint,at_value timestamptz) RETURNS boolean LANGUAGE sql AS $$ SELECT false $$`},
		{"source insertion ACL", `GRANT EXECUTE ON FUNCTION zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamptz) TO PUBLIC`},
		{"effective76 projection body", `CREATE OR REPLACE FUNCTION zasp_temporal78.predecessor76_fingerprint() RETURNS text LANGUAGE sql AS $$ SELECT 'changed'::text $$`},
		{"effective76 projection ACL", `GRANT EXECUTE ON FUNCTION zasp_temporal78.predecessor76_fingerprint() TO PUBLIC`},
		{"projected74 entry ACL", `GRANT EXECUTE ON FUNCTION zasp_temporal74.context(text,text,text,text) TO PUBLIC`},
		{"runtime after-entry body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.runtime_source_after_entry(o text,w text,e text,r text) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"runtime after-entry ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_source_after_entry(text,text,text,text) TO PUBLIC`},
		{"runtime after-entry owner", `ALTER FUNCTION zasp_authorization80_worker.runtime_source_after_entry(text,text,text,text) OWNER TO zasp_temporal_executor`},
		{"runtime inner trigger body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.runtime_trigger_inner(o text,w text,e text,d text,v bigint,r text,k text,t text,s text,tv bigint) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"runtime inner trigger ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_trigger_inner(text,text,text,text,bigint,text,text,text,text,bigint) TO PUBLIC`},
		{"runtime inner matcher body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.runtime_occurrence_match_inner(o text,w text,e text,event_value text,b jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"runtime inner matcher ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_occurrence_match_inner(text,text,text,text,jsonb) TO PUBLIC`},
		{"test pricing inner body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_pricing_inner(checksum_value text,fingerprint_value text,q jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"test pricing inner ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_pricing_inner(text,text,jsonb) TO PUBLIC`},
		{"test pricing inner owner", `ALTER FUNCTION zasp_authorization80_worker.test74_pricing_inner(text,text,jsonb) OWNER TO zasp_temporal_executor`},
		{"test context inner body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_context_inner(o text,w text,e text,r text) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"test context inner ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_context_inner(text,text,text,text) TO PUBLIC`},
		{"test context inner owner", `ALTER FUNCTION zasp_authorization80_worker.test74_context_inner(text,text,text,text) OWNER TO zasp_temporal_executor`},
		{"test parent context inner body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_context_parent_inner(o text,w text,e text,r text,parent_value jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"test parent context inner ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_context_parent_inner(text,text,text,text,jsonb) TO PUBLIC`},
		{"test parent context inner owner", `ALTER FUNCTION zasp_authorization80_worker.test74_context_parent_inner(text,text,text,text,jsonb) OWNER TO zasp_temporal_executor`},
		{"test load projected live body", `CREATE OR REPLACE FUNCTION zasp_temporal74.load_plan(q jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"test load projected live ACL", `GRANT EXECUTE ON FUNCTION zasp_temporal74.load_plan(jsonb) TO PUBLIC`},
		{"test load projected live owner", `ALTER FUNCTION zasp_temporal74.load_plan(jsonb) OWNER TO zasp_temporal_executor`},
		{"test grant inner body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_authorize_inner(o text,w text,e text,d text,v bigint) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"test grant inner ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_authorize_inner(text,text,text,text,bigint) TO PUBLIC`},
		{"test grant inner owner", `ALTER FUNCTION zasp_authorization80_worker.test74_authorize_inner(text,text,text,text,bigint) OWNER TO zasp_temporal_executor`},
		{"test current grant inner body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_service_current_inner(o text,w text,e text,d text,v bigint) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"test current grant inner ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_service_current_inner(text,text,text,text,bigint) TO PUBLIC`},
		{"test current grant inner owner", `ALTER FUNCTION zasp_authorization80_worker.test74_service_current_inner(text,text,text,text,bigint) OWNER TO zasp_temporal_executor`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, mutation.sql); err != nil {
				t.Fatal("runtime catalog mutation setup", err)
			}
			var workerReady, temporalReady, composedReady, retainedMatch bool
			if err := tx.QueryRow(ctx, `SELECT coalesce(zasp_authorization80_worker.catalog_ready(),false),coalesce(zasp_temporal78.current_ready(),false),coalesce(zasp_authorization80_temporal.ready(),false),zasp_temporal77.fingerprint() IS NOT DISTINCT FROM(SELECT fingerprint FROM zasp_temporal77.registration)`).Scan(&workerReady, &temporalReady, &composedReady, &retainedMatch); err != nil {
				t.Fatal("runtime catalog mutation read", err)
			}
			retained := mutation.name == "retained evaluation immutable" || mutation.name == "retained source immutable"
			if temporalReady || composedReady || (!retained && workerReady) || (retained && retainedMatch) {
				t.Fatalf("runtime catalog mutation remained ready worker=%t temporal=%t composed=%t retained77Match=%t", workerReady, temporalReady, composedReady, retainedMatch)
			}
		})
		if t.Failed() {
			return
		}
	}
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("runtime catalog rollback did not restore exact baseline", err)
	}
}

// No service deletion path is added for derived summaries. Direct maintenance
// remains migration-owner work and must follow the documented org-first order.
// WHERE false still exercises PostgreSQL's actual command privilege check.
func assertWorkerRuntimeDirectMutationDenied(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	roles := []string{"zasp_discovery_api", "zasp_security_agent_api", "zasp_runtime_ingest", "zasp_runtime_coordinator", "zasp_runtime_archive_worker", "zasp_runtime_index_worker", "zasp_runtime_correlation_worker", "zasp_runtime_projection_worker", "source77_coordinator", "source77_projection"}
	for _, table := range []string{"zasp_runtime_session_events", "zasp_runtime_session_summaries"} {
		var protected bool
		if err := owner.QueryRow(ctx, `SELECT c.relrowsecurity AND c.relforcerowsecurity
 AND NOT EXISTS(SELECT 1 FROM unnest($2::text[]) r(name) WHERE has_table_privilege(r.name,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE'))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 AND a.privilege_type IN('INSERT','UPDATE','DELETE','TRUNCATE'))
 FROM pg_class c WHERE c.oid=$1::regclass`, "public."+table, roles).Scan(&protected); err != nil || !protected {
			t.Fatal("runtime derived-table write ACL/RLS baseline", table, err)
		}
		for _, role := range roles {
			for _, verb := range []string{"DELETE", "UPDATE"} {
				t.Run(table+"/"+role+"/"+verb, func(t *testing.T) {
					tx, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(context.Background())
					if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
						t.Fatal("installed runtime role setup", err)
					}
					statement := "DELETE FROM " + pgx.Identifier{"public", table}.Sanitize() + " WHERE false"
					if verb == "UPDATE" {
						statement = "UPDATE " + pgx.Identifier{"public", table}.Sanitize() + " SET organization_id=organization_id WHERE false"
					}
					_, err = tx.Exec(ctx, statement)
					var native *pgconn.PgError
					if !errors.As(err, &native) || native.Code != "42501" {
						t.Fatal("runtime service direct mutation did not refuse with insufficient privilege", err)
					}
				})
			}
		}
	}
}

// A dropped runtime source target must fail even when all four retained Test74
// target checks still pass. Expected identities come from the fixture's real
// projection and gateway writer, not from the returned metadata itself.
func assertWorkerRuntimeSourceFacts(t *testing.T, ctx context.Context, owner *pgx.Conn, executor *pgxpool.Pool, run, mode string, request json.RawMessage) {
	t.Helper()
	parent := ctx
	assertWorkerRuntimeMetadataLockOrder(t, ctx, owner, run, request)
	if t.Failed() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var raw json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning74_source('load',$1::jsonb)`, request).Scan(&raw); err != nil {
		t.Fatal("runtime current metadata consumer", err)
	}
	type check struct {
		Kind       string `json:"kind"`
		ID         string `json:"id"`
		Permission string `json:"permission"`
	}
	var facts struct {
		Protocol      string   `json:"runtime_protocol"`
		Digest        string   `json:"runtime_digest"`
		Session       string   `json:"source_session_id"`
		Agent         string   `json:"source_agent_id"`
		Devices       []string `json:"source_device_ids"`
		Checks        []check  `json:"checks"`
		FreshUntil    int64    `json:"fresh_until_ms"`
		DefinitionID  string   `json:"definition_id"`
		DefinitionVer int64    `json:"definition_version"`
	}
	protocol := "retained74-session-latest"
	version := int64(4)
	if mode == "runtime-configured" {
		protocol, version = "configured77-event-occurrence", 5
	}
	const session = "pid_96000007-0000-4000-8000-000000000007"
	const agent = "pid_89000011-0000-4000-8000-000000000001"
	device := automaticSourceID(40)
	if json.Unmarshal(raw, &facts) != nil || facts.Protocol != protocol || facts.Session != session || facts.Agent != agent || len(facts.Devices) != 1 || facts.Devices[0] != device || len(facts.Digest) != 64 || len(facts.Checks) != 7 || facts.DefinitionID != automaticSourceID(8740) || facts.DefinitionVer != version || facts.FreshUntil <= time.Now().UnixMilli() {
		t.Fatal("runtime metadata omitted exact protocol/ancestry/current lifetime")
	}
	for index, want := range []check{{"session", session, "investigate_sessions"}, {"agent", agent, "view"}, {"gateway_device", device, "view"}} {
		if facts.Checks[4+index] != want {
			t.Fatalf("runtime additional Check %d was not the actual captured target", index)
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("runtime metadata object")
	}
	for _, forbidden := range []string{"body", "context", "classification", "evaluation", "source_events", "match", "public_key", "key_reference", "credential_id", "endpoint"} {
		if _, present := fields[forbidden]; present {
			t.Fatalf("runtime metadata disclosed private field %s", forbidden)
		}
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(a.digest=$2 AND a.digest=encode(digest(convert_to(a.body::text,'UTF8'),'sha256'),'hex') AND a.body->>'runtime_protocol'=$3 AND a.body->>'source_session_id'=$4 AND a.body->>'source_agent_id'=$5 AND a.body->'source_device_ids'=jsonb_build_array($6::text) AND jsonb_array_length(a.body->'source_events')=1 AND (a.body->>'fresh_until_ms')::bigint=$7) FROM zasp_authorization80_worker.runtime_associations a WHERE a.run_id=$1`, run, facts.Digest, protocol, session, agent, device, facts.FreshUntil).Scan(&exact); err != nil || !exact {
		t.Fatal("runtime source facts do not match one immutable native capture", err)
	}
	assertWorkerRuntimeRetainedGuardRefusal(t, parent, owner, request)
}

// The baseline above consumed this exact captured run through the registered
// executor. Retained trigger drift must also refuse that real metadata entry.
func assertWorkerRuntimeRetainedGuardRefusal(t *testing.T, parent context.Context, owner *pgx.Conn, request json.RawMessage) {
	t.Helper()
	for _, table := range []string{"runtime_evaluations", "source_events"} {
		t.Run("retained guard entry/"+table, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(parent, 10*time.Second)
			defer cancel()
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, "ALTER TABLE "+pgx.Identifier{"zasp_temporal77", table}.Sanitize()+" DISABLE TRIGGER immutable"); err != nil {
				t.Fatal("retained immutable mutation", err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION worker_test_executor`); err != nil {
				t.Fatal("registered executor login", err)
			}
			var raw json.RawMessage
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning74_source('load',$1::jsonb)`, request).Scan(&raw)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("registered runtime metadata entry accepted retained guard drift", err)
			}
		})
	}
}
