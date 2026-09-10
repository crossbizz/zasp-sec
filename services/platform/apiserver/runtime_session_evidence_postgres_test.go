package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeSessionEvidenceMigrationAndExactAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	probe, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, migrations.ProductionRuntimeSessionEvidence().UpSQL()); err != nil {
		probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	err = probe.QueryRow(ctx, `SELECT zasp_production_runtime_session_evidence_live_fingerprint()`).Scan(&fingerprint)
	probe.Rollback(ctx)
	if err != nil || fingerprint != migrations.ProductionRuntimeSessionEvidenceSemanticFingerprint() {
		t.Fatalf("candidate44 fingerprint=%s error=%v", fingerprint, err)
	}
	if err := runner.UpProductionRuntimeSessionEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"evidence_coordinator", "evidence_archive", "evidence_index", "evidence_correlation", "evidence_projection", "evidence_gateway"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_register_principals(session_user,'evidence_coordinator','evidence_archive','evidence_index','evidence_correlation','evidence_projection','evidence_gateway')`); err != nil {
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
	api, coordinator := connect("invocation_discovery_api"), connect("evidence_coordinator")
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	apiRepository, err := NewPostgresRepository(apiDatabase)
	if err != nil || apiRepository.Ready(ctx) != nil {
		t.Fatal("schema44 prevented API startup", err)
	}
	future, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := future.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(45,'future_release',repeat('0',64))`); err != nil {
		future.Rollback(ctx)
		t.Fatal(err)
	}
	var futureSchema string
	futureErr := future.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint()).Scan(&futureSchema)
	future.Rollback(ctx)
	if futureErr == nil {
		t.Fatal("API accepted unknown schema45")
	}
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var completed json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	org, workspace, environment, principal := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'evidence-org','evidence-member','security_admin',true) ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='security_admin',active=true`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Evidence read proof','["view","investigate_sessions"]',true) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions='["view","investigate_sessions"]'`, org, workspace, environment, principal); err != nil {
		t.Fatal(err)
	}
	var eventID, investigationID, evidenceID string
	if err := admin.QueryRow(ctx, `SELECT event_id,COALESCE(session_id,'unattributed'),evidence_id FROM zasp_runtime_session_events WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) ORDER BY event_id LIMIT 1`, org, workspace, environment).Scan(&eventID, &investigationID, &evidenceID); err != nil {
		t.Fatal(err)
	}
	read := func(actor, investigation, event string) (json.RawMessage, error) {
		var body json.RawMessage
		err := api.QueryRow(ctx, `SELECT zasp_runtime_session_event_get($1,$2,$3,$4,$5,$6)`, org, workspace, environment, actor, investigation, event).Scan(&body)
		return body, err
	}
	body, err := read(principal, investigationID, eventID)
	var value map[string]any
	if err != nil || json.Unmarshal(body, &value) != nil || value["id"] != eventID || value["evidence_id"] != evidenceID || len(value) != 11 {
		t.Fatalf("canonical evidence metadata=%s error=%v", body, err)
	}
	// Rolled-back component fixtures exercise the six-class SQL boundary. These
	// are not worker-composition or provider acceptance evidence.
	cloneSQL := `INSERT INTO zasp_runtime_session_events SELECT (jsonb_populate_record(NULL::zasp_runtime_session_events,to_jsonb(original)||jsonb_build_object('event_id',$1::text,'session_id',NULL,'agent_id',NULL,'confidence','unattributed','source',$2::text,'event_class',$3::text,'action',$4::text))).* FROM zasp_runtime_session_events original WHERE (organization_id,workspace_id,environment_id,event_id)=($5,$6,$7,$8)`
	for _, test := range []struct {
		source, class, action string
		valid                 bool
	}{
		{"otlp", "tool", "invoke", true}, {"tetragon", "process", "exec", true}, {"tetragon", "network", "connect", true}, {"tetragon", "file", "read", true}, {"otlp", "credential", "use", true}, {"otlp", "policy", "block", true},
		{"tetragon", "credential", "use", false}, {"tetragon", "policy", "block", false}, {"otlp", "file", "read", false}, {"otlp", "credential", "read", false}, {"otlp", "policy", "invoke", false},
	} {
		t.Run(test.source+"/"+test.class+"/"+test.action, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			newID := "pid_98000044-0000-4000-8000-000000000044"
			_, err = tx.Exec(ctx, cloneSQL, newID, test.source, test.class, test.action, org, workspace, environment, eventID)
			if !test.valid {
				if err == nil {
					t.Fatal("unsupported source/class/action accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("supported class rejected", err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION invocation_discovery_api`); err != nil {
				t.Fatal(err)
			}
			var body json.RawMessage
			if err := tx.QueryRow(ctx, `SELECT zasp_runtime_session_event_get($1,$2,$3,$4,'unattributed',$5)`, org, workspace, environment, principal, newID).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			expectedClass := test.class
			if expectedClass == "process" {
				expectedClass = "runtime"
			}
			if json.Unmarshal(body, &got) != nil || got["id"] != newID || got["class"] != expectedClass || got["action"] != test.action || got["source"] != test.source || got["evidence_id"] != evidenceID || got["confidence"] != "unattributed" || got["agent_id"] != nil || got["session_id"] != nil {
				t.Fatal("canonical class read altered evidence or attribution")
			}
		})
	}
	for _, target := range [][3]string{{"pid_99000001-0000-4000-8000-000000000001", investigationID, eventID}, {principal, "pid_99000002-0000-4000-8000-000000000002", eventID}, {principal, investigationID, "pid_99000003-0000-4000-8000-000000000003"}} {
		body, err := read(target[0], target[1], target[2])
		if err == nil && len(body) > 0 {
			t.Fatal("foreign/missing evidence target returned metadata")
		}
	}
	if _, err := api.Exec(ctx, `SELECT * FROM zasp_runtime_session_events`); err == nil {
		t.Fatal("evidence endpoint granted direct event-table access")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE (organization_id,principal_id)=($1,$2)`, org, principal); err != nil {
		t.Fatal(err)
	}
	if body, err := read(principal, investigationID, eventID); err == nil && len(body) > 0 {
		t.Fatal("revoked investigation permission retained evidence access")
	}
	if err := runner.DownProductionRuntimeSessionEvidence(ctx); err != nil {
		t.Fatal("old-class evidence prevented safe rollback", err)
	}
	if err := runner.UpProductionRuntimeSessionEvidence(ctx); err != nil {
		t.Fatal("reapply lost retained canonical evidence", err)
	}
	// Hold a new semantic row uncommitted while Down starts. Actual PostgreSQL
	// lock observation proves the guard serializes with inserts, not a sleep.
	writer := connect(admin.Config().User)
	write, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer write.Rollback(context.Background())
	newID := "pid_98000045-0000-4000-8000-000000000045"
	if _, err := write.Exec(ctx, cloneSQL, newID, "otlp", "credential", "use", org, workspace, environment, eventID); err != nil {
		t.Fatal(err)
	}
	downCtx, downCancel := context.WithTimeout(ctx, 10*time.Second)
	defer downCancel()
	done := make(chan error, 1)
	go func() { done <- runner.DownProductionRuntimeSessionEvidence(downCtx) }()
	observer := connect(admin.Config().User)
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		var blocked bool
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, admin.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			waiting = true
			break
		}
		select {
		case early := <-done:
			t.Fatalf("downgrade did not wait for semantic insert: %v", early)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !waiting {
		t.Fatal("downgrade lock competition not observed")
	}
	if err := write.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("downgrade accepted retained semantic event")
		}
	case <-downCtx.Done():
		t.Fatal("downgrade did not finish after insert committed")
	}
	var retained bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_runtime_session_events WHERE event_id=$1) AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=44)`, newID).Scan(&retained); err != nil || !retained {
		t.Fatal("refused downgrade lost semantic evidence or schema version", err)
	}
}
