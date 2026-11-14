package apiserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Section ws6_saas_sign_in of completion.sql against the released baseline:
// the section applies, a second run of it and of the saas section it builds
// on changes nothing, a saas integration may wait for its sign-in but cannot
// be authorized without a connection, a sign-in is taken once by the session
// that started it, and an API session reaches none of it outside a checked
// request.
func TestSaaSSignInSectionOnTheInstalledBaselinePostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	connection := installedBaselineConnection(t, ctx)

	definitions := func() string {
		t.Helper()
		var functions, constraints string
		if err := connection.QueryRow(ctx, `SELECT
 (SELECT md5(string_agg(pg_get_functiondef(p.oid)||COALESCE(p.proacl::text,''),'' ORDER BY p.oid::regprocedure::text)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind='f' AND (n.nspname LIKE 'zasp%' OR n.nspname='public')),
 (SELECT md5(string_agg(c.conrelid::regclass::text||c.conname||pg_get_constraintdef(c.oid),'' ORDER BY c.conrelid::regclass::text,c.conname)) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname LIKE 'zasp%' OR n.nspname='public')`).Scan(&functions, &constraints); err != nil {
			t.Fatal(err)
		}
		return functions + constraints
	}
	// The section builds on the saas provider section, which is a no-op on a
	// baseline that already serves saas.
	applyCompletionBlock(t, ctx, connection, "saas_generic_provider")
	before := definitions()
	var signInBefore bool
	if err := connection.QueryRow(ctx, `SELECT to_regclass('public.zasp_saas_sign_in_attempts') IS NOT NULL`).Scan(&signInBefore); err != nil {
		t.Fatal(err)
	}
	t.Logf("released baseline has the sign-in section: %t", signInBefore)
	applyCompletionBlock(t, ctx, connection, "ws6_saas_sign_in")
	after := definitions()
	if (after == before) != signInBefore {
		t.Fatalf("the section changed the catalog: %t, on a baseline that had it already: %t", after != before, signInBefore)
	}
	// A second run, and a second run of the section it builds on, change
	// nothing: the saas setup text section X3c wrote is still in place.
	applyCompletionBlock(t, ctx, connection, "ws6_saas_sign_in")
	applyCompletionBlock(t, ctx, connection, "saas_generic_provider")
	if definitions() != after {
		t.Fatal("a second run of the sections changed a function or a constraint")
	}

	check := func(expression string, want bool) {
		t.Helper()
		var got *bool
		if err := connection.QueryRow(ctx, "SELECT "+expression).Scan(&got); err != nil || got == nil || *got != want {
			t.Fatalf("%s = %v (%v), want %t", expression, got, err, want)
		}
	}
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	// A saas integration may be set up without a connection; it is then not
	// a configuration reference authorization accepts.
	for configuration, want := range map[string]bool{
		`{"platform":"servicenow","tenant_id":"acme"}`:                                                     true,
		`{"platform":"slack","tenant_id":"T024BE7LD"}`:                                                     true,
		`{"connection_reference":"` + reference + `","platform":"slack","tenant_id":"T024BE7LD"}`:          true,
		`{"platform":"servicenow"}`:                                                                        false,
		`{"tenant_id":"acme"}`:                                                                             false,
		`{"platform":"ServiceNow","tenant_id":"acme"}`:                                                     false,
		`{"platform":"servicenow","tenant_id":"a..b"}`:                                                     false,
		`{"platform":"servicenow","tenant_id":"a/b"}`:                                                      false,
		`{"platform":"servicenow","tenant_id":"acme","subdomain":"acme"}`:                                  false,
		`{"platform":"servicenow","tenant_id":"acme","connection_reference":"ref:nango/service-key-0001"}`: false,
		`{"platform":"servicenow","tenant_id":7}`:                                                          false,
	} {
		check(`COALESCE(zasp_authorization80.integration_setup_valid('saas','`+configuration+`'::jsonb),false)`, want)
	}
	check(`zasp_reference_authorization_configuration_valid('saas','{"platform":"servicenow","tenant_id":"acme"}'::jsonb)`, false)
	check(`zasp_reference_only('{"platform":"servicenow","tenant_id":"acme"}'::jsonb)`, true)
	// The other connectors' setup grammar is untouched.
	check(`COALESCE(zasp_authorization80.integration_setup_valid('github','{"platform":"servicenow","tenant_id":"acme"}'::jsonb),false)`, false)
	check(`COALESCE(zasp_authorization80.integration_setup_valid('github','{"authorization_mode":"github_app"}'::jsonb),false)`, true)

	identity := fixtureRequestIdentity(t)
	organizationID, workspaceID, environmentID, principalID := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	const (
		waiting    = "pid_7b000001-0000-4000-8000-000000000001"
		referenced = "pid_7b000002-0000-4000-8000-000000000002"
		github     = "pid_7b000003-0000-4000-8000-000000000003"
		otherScope = "pid_7b0000ee-0000-4000-8000-0000000000ee"
		otherActor = "pid_7b0000ff-0000-4000-8000-0000000000ff"
	)
	insertIntegration := func(id, connector, configuration, status string) {
		t.Helper()
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Fixture','connector_key',$5::text,'configuration',$6::jsonb,'status',$7::text))`,
			organizationID, workspaceID, environmentID, id, connector, configuration, status); err != nil {
			t.Fatalf("insert integration %s: %v", id, err)
		}
	}
	insertIntegration(waiting, "saas", `{"platform":"servicenow","tenant_id":"acme"}`, "pending_authorization")
	insertIntegration(referenced, "saas", `{"connection_reference":"`+reference+`","platform":"slack","tenant_id":"T024BE7LD"}`, "pending_authorization")
	insertIntegration(github, "github", `{"authorization_mode":"github_app"}`, "pending_authorization")

	scan := func(statement string, arguments ...any) (string, error) {
		t.Helper()
		var payload string
		err := connection.QueryRow(ctx, statement, arguments...).Scan(&payload)
		return payload, err
	}
	sqlState := func(err error) string {
		var native *pgconn.PgError
		if errors.As(err, &native) {
			return native.Code
		}
		return ""
	}
	digest := func(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }
	const integrationSQL = `SELECT zasp_authorization80.saas_sign_in_integration($1,$2,$3,$4,$5)::text`
	const startSQL = `SELECT zasp_authorization80.saas_sign_in_start($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)::text`
	const consumeSQL = `SELECT zasp_authorization80.saas_sign_in_consume($1,$2,$3,$4,$5,$6)::text`
	const finishSQL = `SELECT zasp_authorization80.saas_sign_in_finish($1,$2,$3,$4,$5,$6,$7)::text`

	// Only a saas integration that waits for its sign-in is one.
	if payload, err := scan(integrationSQL, organizationID, workspaceID, environmentID, principalID, waiting); err != nil || payload != `{"found": true, "status": "pending_authorization", "version": 1, "platform": "servicenow", "tenant_id": "acme"}` {
		t.Fatalf("waiting integration = %s, %v", payload, err)
	}
	for _, id := range []string{referenced, github, "pid_7b000009-0000-4000-8000-000000000009"} {
		if payload, err := scan(integrationSQL, organizationID, workspaceID, environmentID, principalID, id); err != nil || payload != `{"found": false}` {
			t.Fatalf("integration %s = %s, %v", id, payload, err)
		}
	}
	if payload, err := scan(integrationSQL, otherScope, workspaceID, environmentID, principalID, waiting); err != nil || payload != `{"found": false}` {
		t.Fatalf("integration of another organization = %s, %v", payload, err)
	}

	expires := time.Now().UTC().Add(9 * time.Minute)
	start := func(integration, attempt, session, state string, version int64, expiry time.Time) error {
		_, err := scan(startSQL, organizationID, workspaceID, environmentID, principalID, integration, attempt, digest(session), digest(state), expiry, version)
		return err
	}
	const first, second, third = "pid_7b000011-0000-4000-8000-000000000011", "pid_7b000012-0000-4000-8000-000000000012", "pid_7b000013-0000-4000-8000-000000000013"
	// What a sign-in cannot be started for.
	for name, test := range map[string]struct {
		err  error
		code string
	}{
		"an integration that names a connection": {start(referenced, first, "session", "state-x", 1, expires), "P0002"},
		"an integration of another connector":    {start(github, first, "session", "state-x", 1, expires), "P0002"},
		"an integration that does not exist":     {start(otherScope, first, "session", "state-x", 1, expires), "P0002"},
		"another version than the one read":      {start(waiting, first, "session", "state-x", 2, expires), "40001"},
		"an expiry beyond ten minutes":           {start(waiting, first, "session", "state-x", 1, time.Now().UTC().Add(11*time.Minute)), "22023"},
		"an expiry in the past":                  {start(waiting, first, "session", "state-x", 1, time.Now().UTC().Add(-time.Second)), "22023"},
	} {
		if sqlState(test.err) != test.code {
			t.Fatalf("%s: %v", name, test.err)
		}
	}
	if _, err := scan(startSQL, organizationID, workspaceID, environmentID, principalID, waiting, first, []byte("short"), digest("state-x"), expires, int64(1)); sqlState(err) != "22023" {
		t.Fatalf("a session digest of another length: %v", err)
	}
	if err := start(waiting, first, "session-a", "state-1", 1, expires); err != nil {
		t.Fatalf("start: %v", err)
	}
	// The same attempt or the same state cannot be recorded twice.
	if err := start(waiting, first, "session-a", "state-other", 1, expires); sqlState(err) != "23505" {
		t.Fatalf("the same attempt twice: %v", err)
	}
	if err := start(waiting, second, "session-a", "state-1", 1, expires); sqlState(err) != "23505" {
		t.Fatalf("the same state twice: %v", err)
	}
	status := func(attempt string) string {
		t.Helper()
		var value string
		if err := connection.QueryRow(ctx, `SELECT status||'/'||COALESCE(failure_code,'')||'/'||COALESCE(connection_reference,'') FROM zasp_saas_sign_in_attempts WHERE id=$1`, attempt).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	// A refused start changed nothing: the first sign-in is still open.
	if got := status(first); got != "pending//" {
		t.Fatalf("first attempt = %s", got)
	}
	// A newer sign-in of the same integration supersedes the open one.
	if err := start(waiting, second, "session-a", "state-2", 1, expires); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if got := status(first); got != "superseded//" {
		t.Fatalf("superseded attempt = %s", got)
	}

	consume := func(actor, state, session string) string {
		t.Helper()
		payload, err := scan(consumeSQL, organizationID, workspaceID, environmentID, actor, digest(state), digest(session))
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		return payload
	}
	// A state no sign-in of this scope has is not found; the caller serves
	// the callback another way.
	if payload := consume(principalID, "state-unknown", "session-a"); payload != `{"found": false}` {
		t.Fatalf("unknown state = %s", payload)
	}
	if payload, err := scan(consumeSQL, otherScope, workspaceID, environmentID, principalID, digest("state-2"), digest("session-a")); err != nil || payload != `{"found": false}` {
		t.Fatalf("a state of another organization = %s, %v", payload, err)
	}
	// A superseded sign-in is not taken.
	if payload := consume(principalID, "state-1", "session-a"); !strings.Contains(payload, `"accepted": false`) {
		t.Fatalf("superseded state = %s", payload)
	}
	// Another browser session presents the state: the sign-in ends.
	if payload := consume(principalID, "state-2", "session-b"); !strings.Contains(payload, `"accepted": false`) || status(second) != "failed/session_mismatch/" {
		t.Fatalf("another session = %s, attempt %s", payload, status(second))
	}
	// And the right session cannot take it afterwards.
	if payload := consume(principalID, "state-2", "session-a"); !strings.Contains(payload, `"accepted": false`) {
		t.Fatalf("a failed sign-in was taken: %s", payload)
	}
	// Another person presents the state.
	if err := start(waiting, third, "session-a", "state-3", 1, expires); err != nil {
		t.Fatal(err)
	}
	if payload := consume(otherActor, "state-3", "session-a"); !strings.Contains(payload, `"accepted": false`) || status(third) != "failed/session_mismatch/" {
		t.Fatalf("another person = %s, attempt %s", payload, status(third))
	}
	// The sign-in that completes.
	const fourth, fifth, sixth = "pid_7b000014-0000-4000-8000-000000000014", "pid_7b000015-0000-4000-8000-000000000015", "pid_7b000016-0000-4000-8000-000000000016"
	if err := start(waiting, fourth, "session-a", "state-4", 1, expires); err != nil {
		t.Fatal(err)
	}
	// A sign-in that was not taken cannot be finished.
	if _, err := scan(finishSQL, organizationID, workspaceID, environmentID, principalID, fourth, "completed", reference); sqlState(err) != "23505" {
		t.Fatalf("finish before the callback: %v", err)
	}
	if payload := consume(principalID, "state-4", "session-a"); payload != `{"id": "`+fourth+`", "found": true, "accepted": true, "platform": "servicenow", "tenant_id": "acme", "integration_id": "`+waiting+`"}` {
		t.Fatalf("taken sign-in = %s", payload)
	}
	// It is taken once.
	if payload := consume(principalID, "state-4", "session-a"); !strings.Contains(payload, `"accepted": false`) || status(fourth) != "consumed//" {
		t.Fatalf("second take = %s, attempt %s", payload, status(fourth))
	}
	for name, arguments := range map[string][]any{
		"a token where the reference belongs": {fourth, "completed", "nango-token-0001"},
		"a completion without a reference":    {fourth, "completed", ""},
		"a failure with a reference":          {fourth, "tenant_mismatch", reference},
		"a failure code that is free text":    {fourth, "The provider said no", ""},
	} {
		if _, err := scan(finishSQL, append([]any{organizationID, workspaceID, environmentID, principalID}, arguments...)...); sqlState(err) != "22023" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := scan(finishSQL, organizationID, workspaceID, environmentID, otherActor, fourth, "completed", reference); sqlState(err) != "23505" {
		t.Fatalf("finish by another person: %v", err)
	}
	if payload, err := scan(finishSQL, organizationID, workspaceID, environmentID, principalID, fourth, "completed", reference); err != nil || payload != `{"id": "`+fourth+`", "status": "completed", "integration_id": "`+waiting+`"}` || status(fourth) != "completed//"+reference {
		t.Fatalf("finish = %s, %v, attempt %s", payload, err, status(fourth))
	}
	if _, err := scan(finishSQL, organizationID, workspaceID, environmentID, principalID, fourth, "tenant_mismatch", ""); sqlState(err) != "23505" {
		t.Fatalf("finish twice: %v", err)
	}
	// The sign-in that fails after the callback.
	if err := start(waiting, fifth, "session-a", "state-5", 1, expires); err != nil {
		t.Fatal(err)
	}
	consume(principalID, "state-5", "session-a")
	if _, err := scan(finishSQL, organizationID, workspaceID, environmentID, principalID, fifth, "tenant_mismatch", ""); err != nil || status(fifth) != "failed/tenant_mismatch/" {
		t.Fatalf("failed sign-in: %v, attempt %s", err, status(fifth))
	}
	// A sign-in that expired before the callback.
	if err := start(waiting, sixth, "session-a", "state-6", 1, expires); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_saas_sign_in_attempts SET created_at=created_at-interval '20 minutes',expires_at=expires_at-interval '20 minutes' WHERE id=$1`, sixth); err != nil {
		t.Fatal(err)
	}
	if payload := consume(principalID, "state-6", "session-a"); !strings.Contains(payload, `"accepted": false`) || status(sixth) != "failed/expired/" {
		t.Fatalf("expired sign-in = %s, attempt %s", payload, status(sixth))
	}
	// A sign-in never touched the integration: it ends in a reference only.
	var integrationBody string
	if err := connection.QueryRow(ctx, `SELECT version::text||' '||(body->'configuration')::text FROM zasp_workflow_records WHERE id=$1`, waiting).Scan(&integrationBody); err != nil || integrationBody != `1 {"platform": "servicenow", "tenant_id": "acme"}` {
		t.Fatalf("integration after the sign-ins = %s, %v", integrationBody, err)
	}
	// Neither a state nor a session value is stored, only their digests.
	var stored string
	if err := connection.QueryRow(ctx, `SELECT string_agg(a::text,' ') FROM zasp_saas_sign_in_attempts a`).Scan(&stored); err != nil || strings.Contains(stored, "state-4") || strings.Contains(stored, "session-a") {
		t.Fatalf("stored attempts hold a state or session value: %v", err)
	}

	// An API session reaches the functions only inside a checked request,
	// and never the table or the guard.
	if _, err := connection.Exec(ctx, `CREATE ROLE ws6_sign_in_api LOGIN IN ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	// The baseline's own view of role membership is what direct_guard reads.
	check(`EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles l ON l.oid=m.member JOIN pg_roles g ON g.oid=m.roleid WHERE l.rolname='ws6_sign_in_api' AND g.rolname='zasp_discovery_api')`, true)
	for function, want := range map[string]bool{
		`zasp_authorization80.saas_sign_in_integration(text,text,text,text,text)`:                               true,
		`zasp_authorization80.saas_sign_in_start(text,text,text,text,text,text,bytea,bytea,timestamptz,bigint)`: true,
		`zasp_authorization80.saas_sign_in_consume(text,text,text,text,bytea,bytea)`:                            true,
		`zasp_authorization80.saas_sign_in_finish(text,text,text,text,text,text,text)`:                          true,
		`zasp_authorization80.saas_sign_in_guard(text,text,text,text,text,text)`:                                false,
	} {
		check(`has_function_privilege('ws6_sign_in_api','`+function+`','EXECUTE')`, want)
		check(`has_function_privilege('public','`+function+`','EXECUTE')`, false)
	}
	check(`has_table_privilege('ws6_sign_in_api','public.zasp_saas_sign_in_attempts','SELECT,INSERT,UPDATE,DELETE')`, false)
	check(`(SELECT relrowsecurity FROM pg_class WHERE oid='public.zasp_saas_sign_in_attempts'::regclass)`, true)
	config := connection.Config().Copy()
	config.User = "ws6_sign_in_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect as the API role: %v", err)
	}
	defer api.Close(context.Background())
	var sessionUser string
	if err := api.QueryRow(ctx, `SELECT session_user::text`).Scan(&sessionUser); err != nil || sessionUser != "ws6_sign_in_api" {
		t.Fatalf("API session user = %q, %v", sessionUser, err)
	}
	const seventh = "pid_7b000017-0000-4000-8000-000000000017"
	for name, call := range map[string]func() error{
		"read the integration": func() error {
			var payload string
			return api.QueryRow(ctx, integrationSQL, organizationID, workspaceID, environmentID, principalID, waiting).Scan(&payload)
		},
		"start a sign-in": func() error {
			var payload string
			return api.QueryRow(ctx, startSQL, organizationID, workspaceID, environmentID, principalID, waiting, seventh, digest("session-a"), digest("state-7"), expires, int64(1)).Scan(&payload)
		},
		"take a sign-in": func() error {
			var payload string
			return api.QueryRow(ctx, consumeSQL, organizationID, workspaceID, environmentID, principalID, digest("state-4"), digest("session-a")).Scan(&payload)
		},
		"finish a sign-in": func() error {
			var payload string
			return api.QueryRow(ctx, finishSQL, organizationID, workspaceID, environmentID, principalID, fifth, "completed", reference).Scan(&payload)
		},
		"read the attempts": func() error {
			var count int
			return api.QueryRow(ctx, `SELECT count(*) FROM public.zasp_saas_sign_in_attempts`).Scan(&count)
		},
	} {
		err := call()
		var native *pgconn.PgError
		// The functions are reached and refuse for want of a checked
		// request; the table is not reachable at all.
		wantMessage := "checked request required"
		if name == "read the attempts" {
			wantMessage = "permission denied for table zasp_saas_sign_in_attempts"
		}
		if !errors.As(err, &native) || native.Code != "42501" || native.Message != wantMessage {
			t.Fatalf("an API session outside a checked request could %s: %v", name, err)
		}
	}
	var attempts int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_saas_sign_in_attempts`).Scan(&attempts); err != nil || attempts != 6 {
		t.Fatalf("attempts after the refused API calls = %d, %v", attempts, err)
	}
}
