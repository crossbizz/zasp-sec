package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeSessionReadProjectionBackfillAuthorityAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, apply := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"session_coordinator", "session_archive", "session_index", "session_correlation", "session_projection", "session_gateway"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_register_principals(session_user,'session_coordinator','session_archive','session_index','session_correlation','session_projection','session_gateway')`); err != nil {
		t.Fatal(err)
	}
	connect := func(name string) *pgx.Conn {
		config := admin.Config().Copy()
		config.User = name
		c, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(context.Background()) })
		return c
	}
	coordinator, api := connect("session_coordinator"), connect("invocation_discovery_api")
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var result json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&result); err != nil {
		t.Fatal(err)
	}
	// Existing committed events must survive and receive summaries during upgrade.
	probe, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, migrations.ProductionRuntimeSessionReads().UpSQL()); err != nil {
		probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	err = probe.QueryRow(ctx, `SELECT zasp_production_runtime_session_reads_live_fingerprint()`).Scan(&fingerprint)
	probe.Rollback(ctx)
	if err != nil || fingerprint != migrations.ProductionRuntimeSessionReadsSemanticFingerprint() {
		t.Fatalf("candidate41 fingerprint=%s error=%v", fingerprint, err)
	}
	if err := runner.UpProductionRuntimeSessionReads(ctx); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	var apiSchema string
	if err := admin.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint(), migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint()).Scan(&apiSchema); err != nil || apiSchema != ProductionRecoverySchemaVersion {
		t.Fatalf("production API rejects installed schema41: schema=%s error=%v", apiSchema, err)
	}
	scope := identity.Scope
	org, workspace, environment, principal := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), identity.PrincipalID.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'runtime-read-organization','runtime-read-member','security_admin',true) ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='security_admin',active=true`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Runtime read proof','["view","investigate_sessions"]',true) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions='["view","investigate_sessions"]'`, org, workspace, environment, principal); err != nil {
		t.Fatal(err)
	}
	read := func(connection *pgx.Conn, organization, actor string) (json.RawMessage, error) {
		var value json.RawMessage
		err := connection.QueryRow(ctx, postgresRuntimeSessionPageSQL, organization, workspace, environment, actor, "", 101, "", nil, nil).Scan(&value)
		return value, err
	}
	payload, err := read(api, org, principal)
	var page struct {
		Items []struct {
			ID        string  `json:"id"`
			Kind      string  `json:"kind"`
			Count     int     `json:"event_count"`
			Agent     *string `json:"agent_id"`
			Principal *string `json:"principal_id"`
		} `json:"items"`
	}
	if err != nil || json.Unmarshal(payload, &page) != nil || len(page.Items) != 2 || page.Items[0].Count != 2 || page.Items[0].Kind != "runtime" || page.Items[0].Agent == nil || page.Items[0].Principal != nil || page.Items[1].ID != "unattributed" || page.Items[1].Kind != "unattributed" || page.Items[1].Count != 1 || page.Items[1].Agent != nil {
		t.Fatalf("runtime summaries=%s error=%v", payload, err)
	}
	before := string(payload)
	testRuntimeSessionReadHTTP(t, ctx, api, identity)
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&result); err != nil {
		t.Fatal(err)
	}
	if replay, err := read(api, org, principal); err != nil || string(replay) != before {
		t.Fatal("completion replay changed durable summary")
	}
	for _, bad := range []struct {
		connection *pgx.Conn
		org, actor string
	}{{coordinator, org, principal}, {api, "pid_99000001-0000-4000-8000-000000000001", principal}, {api, org, "pid_99000004-0000-4000-8000-000000000004"}} {
		if denied, err := read(bad.connection, bad.org, bad.actor); err == nil && len(denied) != 0 {
			t.Fatalf("unauthorized runtime read returned %s", denied)
		}
	}
	if _, err := api.Exec(ctx, `SELECT * FROM zasp_runtime_session_summaries`); err == nil {
		t.Fatal("API can bypass scoped reader")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, org, principal); err != nil {
		t.Fatal(err)
	}
	if denied, err := read(api, org, principal); err == nil && len(denied) != 0 {
		t.Fatal("role downgrade kept runtime reads through stale requested permissions")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE organization_id=$1 AND principal_id=$2`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, org, principal); err != nil {
		t.Fatal(err)
	}
	if denied, err := read(api, org, principal); err == nil && len(denied) != 0 {
		t.Fatal("deprovisioned identity kept runtime reads")
	}
	// Derived summaries can be rebuilt; rollback must preserve source events.
	for _, drift := range []string{
		`ALTER TABLE zasp_runtime_session_summaries DISABLE ROW LEVEL SECURITY`,
		`ALTER TABLE zasp_runtime_session_events DISABLE TRIGGER zasp_runtime_session_summary_projection`,
		`GRANT SELECT ON zasp_runtime_session_summaries TO zasp_discovery_api`,
		`GRANT EXECUTE ON FUNCTION zasp_runtime_session_get(text,text,text,text,text) TO PUBLIC`,
	} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, drift); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		var ready bool
		err = tx.QueryRow(ctx, `SELECT zasp_production_runtime_session_reads_readiness($1,$2)`, migrations.ProductionRuntimeSessionReads().Checksum(), migrations.ProductionRuntimeSessionReadsSemanticFingerprint()).Scan(&ready)
		_ = tx.Rollback(ctx)
		if err == nil && ready {
			t.Fatalf("runtime read readiness admitted drift: %s", drift)
		}
	}
	if err := runner.DownProductionRuntimeSessionReads(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_events`).Scan(&count); err != nil || count != 3 {
		t.Fatal("summary rollback removed source events")
	}
	if err := runner.UpProductionRuntimeSessionReads(ctx); err != nil {
		t.Fatal(err)
	}
	testRuntimeSessionSummaryConcurrency(t, ctx, admin)
}
