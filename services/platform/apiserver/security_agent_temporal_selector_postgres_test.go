package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches missing installed selector authority, creator impersonation, stale
// configuration admission and a retained worker bypass of Temporal ownership.
func TestTemporalTestSelectorAdmissionPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		installTemporalTestExecutorFixture(t, ctx, owner)
		o2, w2, e2 := seedSelectorSecondTenant(t, ctx, owner, api, o, w, e, testID, actor)
		up, ok := any(precisionMigrationRunner(t, owner)).(interface{ UpProductionTemporalTestSelector(context.Context) error })
		if !ok {
			t.Fatal("versioned selector authority is absent")
		}
		if err := up.UpProductionTemporalTestSelector(ctx); err != nil {
			tx, txErr := owner.Begin(ctx)
			if txErr != nil {
				t.Fatal(txErr)
			}
			defer tx.Rollback(ctx)
			_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalTestSelector().UpSQL())
			var pin string
			pinErr := tx.QueryRow(ctx, `SELECT zasp_temporal75.fingerprint()`).Scan(&pin)
			t.Logf("independent75 compile DDL=%v pin_error=%v pin=%s", ddlErr, pinErr, pin)
			t.Fatal("install75", err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE selector_executor LOGIN; CREATE ROLE selector_compensation LOGIN; CREATE ROLE selector_unregistered LOGIN; SELECT zasp_temporal68.register_principals('selector_executor','selector_compensation')`); err != nil {
			t.Fatal(err)
		}
		connect := func(user string) *pgx.Conn {
			c := owner.Config().Copy()
			c.User = user
			conn, err := pgx.ConnectConfig(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close(context.Background()) })
			return conn
		}
		executor := connect("selector_executor")
		unregistered := connect("selector_unregistered")
		if _, err := unregistered.Exec(ctx, `SELECT zasp_temporal75.visible('a','b','c','d')`); err == nil {
			t.Fatal("unregistered schema access")
		}
		// Grant only temporary schema name resolution in this disposable DB to
		// test the public predicate itself, then restore the pinned catalog.
		if _, err := owner.Exec(ctx, `GRANT USAGE ON SCHEMA zasp_temporal75 TO selector_unregistered`); err != nil {
			t.Fatal(err)
		}
		var unknownVisible bool
		if err := unregistered.QueryRow(ctx, `SELECT zasp_temporal75.visible($1,$2,$3,'unknown-run')`, o, w, e).Scan(&unknownVisible); err != nil || unknownVisible {
			t.Fatal("unregistered predicate lookup", unknownVisible, err)
		}
		if _, err := unregistered.Exec(ctx, `SELECT * FROM zasp_security_agent_runs`); err == nil {
			t.Fatal("unregistered policy/table read")
		}
		if _, err := owner.Exec(ctx, `REVOKE USAGE ON SCHEMA zasp_temporal75 FROM selector_unregistered`); err != nil {
			t.Fatal(err)
		}
		worker = connect("security_agent_v33_worker_login")
		ref := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "definition_id": temporalTestLegacyProved}
		call := func(c *pgx.Conn, fn string, q any) (json.RawMessage, error) {
			b, _ := json.Marshal(q)
			var out json.RawMessage
			err := c.QueryRow(ctx, "SELECT zasp_temporal75."+fn+"($1::jsonb)", string(b)).Scan(&out)
			return out, err
		}
		q := map[string]any{"ref": ref, "revision": 1}
		if _, err := call(executor, "admit", q); err == nil {
			t.Fatal("missing desired configuration admitted")
		}
		for _, cadence := range []any{nil, 0, -1, 1.5, "1", 86401} {
			if _, err := call(owner, "configure", map[string]any{"revision": 1, "cadence_seconds": cadence, "enabled": true}); err == nil {
				t.Fatal("invalid cadence accepted", cadence)
			}
		}
		if _, err := call(owner, "configure", map[string]any{"revision": 1, "cadence_seconds": 1, "enabled": true}); err != nil {
			t.Fatal(err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		retained, err := NewSecurityAgentWorkerRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		if count, err := retained.ScheduleSecurityAgentTriggers(ctx, "selector-retained", 10); err != nil || count != 0 {
			t.Fatal("retained selector admitted specialized work", count, err)
		}
		var old []byte
		if err := worker.QueryRow(ctx, `SELECT zasp_temporal73.schedule($1,$2,$3,$4)`, existingTestReadPins([]any{"selector-old73", 10})...).Scan(&old); err != nil || string(old) != `{"created": 0}` {
			t.Fatal("old73 active-creator bypass", string(old), err)
		}
		apiDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		parse := func(s string) domain.ProductID {
			v, err := domain.ParseProductID(s)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		identity.Scope, err = domain.NewScope(parse(o), parse(w), parse(e))
		if err != nil {
			t.Fatal(err)
		}
		identity.PrincipalID = parse(actor)
		identity.CredentialKind = CredentialBrowserSession
		apiRepository := &PostgresRepository{database: apiDB, securityAgentExecution: true}
		manual := SecurityAgentRunRequest{DefinitionID: temporalTestLegacyProved, ExpectedVersion: 4, IdempotencyKey: "selector-manual-capacity", RunID: "pid_f0750000-0000-4000-8000-000000000021", AuditID: "pid_f0750000-0000-4000-8000-000000000022", CorrelationID: "pid_f0750000-0000-4000-8000-000000000023", ReceiptID: "pid_f0750000-0000-4000-8000-000000000024", TriggerKind: "manual"}
		if _, err := apiRepository.runSecurityAgentManual(ctx, identity, manual); err != nil {
			t.Fatal("registered manual occupancy", err)
		}
		if blocked, err := call(executor, "admit", q); err != nil || string(blocked) != `{"created": 0}` {
			t.Fatal("other-owner manual capacity", string(blocked), err)
		}
		if _, err := worker.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		claims, claimErr := retained.ClaimSecurityAgentRuns(ctx, "selector-manual-coexistence", "selector-manual-claim-proof-token", 30, 10)
		if _, err := worker.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if claimErr != nil || len(claims) != 1 || claims[0].RunID != manual.RunID {
			t.Fatal("unmarked manual retained claim compatibility", claims, claimErr)
		}
		if _, err := apiRepository.CancelSecurityAgentRun(ctx, identity, SecurityAgentCancelRequest{RunID: manual.RunID, ExpectedVersion: 1, IdempotencyKey: "selector-manual-cancel", AuditID: "pid_f0750000-0000-4000-8000-000000000025", CorrelationID: "pid_f0750000-0000-4000-8000-000000000026", ReceiptID: "pid_f0750000-0000-4000-8000-000000000027"}); err != nil {
			t.Fatal("registered manual capacity release", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		first, err := call(executor, "admit", q)
		if err != nil {
			t.Fatal("inactive creator prevented current service admission", err)
		}
		var result struct {
			Created int `json:"created"`
		}
		if json.Unmarshal(first, &result) != nil || result.Created != 1 {
			t.Fatal("current service admission", string(first))
		}
		duplicate, err := call(executor, "admit", q)
		if err != nil || string(duplicate) != `{"created": 0}` {
			t.Fatal("duplicate wake", string(duplicate), err)
		}
		var proof bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(r.requested_by=g.principal_id AND r.run_id=public.zasp_discovery_canonical_id(r.organization_id,r.workspace_id,r.environment_id,'security_agent_run',concat_ws(chr(31),r.definition_id,r.definition_version,tr.trigger_kind,tr.trigger_id,tr.trigger_version))) FROM zasp_temporal73.admissions a JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_trigger_receipts tr ON(tr.organization_id,tr.workspace_id,tr.environment_id,tr.definition_id,tr.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id,r.run_id) JOIN zasp_temporal73.commands c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) JOIN zasp_temporal74.service_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id,r.definition_version) WHERE a.definition_id=$1`, temporalTestLegacyProved).Scan(&proof); err != nil || !proof {
			t.Fatal("canonical service occurrence and atomic start", proof, err)
		}
		// No Temporal takeover has happened. A busy organization may keep the
		// start relay from taking ownership, but must never expose this admission
		// to the retained claim path. Keep the human active so that is not a fence.
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		if claims, err := retained.ClaimSecurityAgentRuns(ctx, "selector-retained", "selector-retained-claim-proof-token", 30, 10); err != nil || len(claims) != 0 {
			t.Fatalf("retained claim crossed pending Temporal admission: claims=%+v err=%v", claims, err)
		}
		for _, statement := range []string{`UPDATE zasp_security_agent_runs SET state='planning'`, `INSERT INTO zasp_temporal75.admissions SELECT * FROM zasp_temporal75.admissions`, `DELETE FROM zasp_temporal75.admissions`} {
			if _, err := worker.Exec(ctx, statement); err == nil {
				t.Fatal("direct retained mutation admitted", statement)
			}
		}
		// A different current source cannot use the slot hidden from retained
		// reads. This calls the admission boundary and its installed accounting.
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1 WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e); err != nil {
			t.Fatal(err)
		}
		if blocked, err := call(executor, "admit", q); err != nil || string(blocked) != `{"created": 0}` {
			t.Fatal("marked pending parent lost shared capacity", string(blocked), err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version-1 WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e); err != nil {
			t.Fatal(err)
		}
		var parent string
		if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal75.admissions WHERE organization_id=$1 AND configuration_revision=1`, o).Scan(&parent); err != nil {
			t.Fatal("atomic configuration ownership marker", err)
		}
		var takeover []byte
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, parent).Scan(&takeover); err != nil || string(takeover) == "null" {
			t.Fatal("registered takeover of marked parent", string(takeover), err)
		}
		for _, c := range []*pgx.Conn{executor, connect("selector_compensation")} {
			var state []byte
			body, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": parent, "definition_version": 4})
			if err := c.QueryRow(ctx, `SELECT zasp_temporal74.planning_state($1::jsonb)`, string(body)).Scan(&state); err != nil || string(state) != "null" {
				t.Fatal("registered marked-parent read", string(state), err)
			}
		}
		secondRef := map[string]any{"organization_id": o2, "workspace_id": w2, "environment_id": e2, "definition_id": temporalTestLegacyProved}
		if got, err := call(executor, "admit", map[string]any{"ref": secondRef, "revision": 1}); err != nil || string(got) != `{"created": 1}` {
			t.Fatal("same-name second tenant admission", string(got), err)
		}
		var parent2 string
		if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal75.admissions WHERE organization_id=$1`, o2).Scan(&parent2); err != nil || parent == parent2 {
			t.Fatal("tenant occurrence collision", parent2, err)
		}
		secondRef["workspace_id"] = w
		if _, err := call(executor, "admit", map[string]any{"ref": secondRef, "revision": 1}); err == nil {
			t.Fatal("cross-tenant composite admitted")
		}
		if _, err := apiRepository.GetSecurityAgentRun(ctx, identity, parent); err != nil {
			t.Fatal("marked run API read", err)
		}
		if _, err := apiRepository.GetSecurityAgentRun(ctx, identity, parent2); err == nil {
			t.Fatal("foreign marked run API read")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := call(owner, "configure", map[string]any{"revision": 2, "cadence_seconds": 2, "enabled": false}); err != nil {
			t.Fatal(err)
		}
		if _, err := call(executor, "admit", q); err == nil {
			t.Fatal("stale revision admitted")
		}
		q["revision"] = 2
		if _, err := call(executor, "admit", q); err == nil {
			t.Fatal("disabled selector admitted")
		}
		if _, err := call(owner, "configure", map[string]any{"revision": 3, "cadence_seconds": 1, "enabled": true}); err != nil {
			t.Fatal(err)
		}
		q["revision"] = 3
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal74.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id) VALUES($1,$2,$3,$4,4,$5,'pid_f0750000-0000-4000-8000-000000000001')`, o, w, e, temporalTestLegacyProved, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := call(executor, "admit", q); err == nil {
			t.Fatal("revoked current grant admitted")
		}
		if _, err := call(worker, "admit", q); err == nil {
			t.Fatal("retained worker invoked executor admission")
		}
		// The SQL entry itself must refuse75 catalog drift, even when a caller
		// bypasses the application's availability probe.
		if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_temporal75.admit(jsonb) TO PUBLIC`); err != nil {
			t.Fatal(err)
		}
		_, routeErr := retained.ScheduleSecurityAgentTriggers(ctx, "selector-drift", 10)
		directErr := worker.QueryRow(ctx, `SELECT zasp_temporal75.retained_schedule($1,$2,$3,$4)`, existingTestReadPins([]any{"selector-direct-drift", 10})...).Scan(&old)
		if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION zasp_temporal75.admit(jsonb) FROM PUBLIC`); err != nil {
			t.Fatal(err)
		}
		if routeErr == nil || directErr == nil {
			t.Fatal("75 catalog drift admitted retained route", routeErr, directErr, string(old))
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal74.current_ready() AND zasp_temporal73.current_ready() AND zasp_temporal75.current_ready()`).Scan(&proof); err != nil || !proof {
			t.Fatal("predecessor or successor catalog drift", proof, err)
		}
	})
}

func seedSelectorSecondTenant(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) (string, string, string) {
	t.Helper()
	o2, w2, e2 := worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 75)
	public62Seed(t, ctx, owner, o2, w2, e2, testID, actor)
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE organization_id=$1; UPDATE zasp_organizations SET name=(SELECT name FROM zasp_organizations WHERE id=$2) WHERE id=$1; UPDATE zasp_workspaces SET name=(SELECT name FROM zasp_workspaces WHERE id=$4) WHERE id=$3; UPDATE zasp_environments SET name=(SELECT name FROM zasp_environments WHERE id=$6) WHERE id=$5`, pgx.QueryExecModeSimpleProtocol, o2, o, w2, w, e2, e); err != nil {
		t.Fatal(err)
	}
	var draft, intent json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT body||jsonb_build_object('enabled',false,'environment_ids',jsonb_build_array($2::text)), jsonb_build_object('resource_id','','expected_version',0,'body',(body-'id')||jsonb_build_object('enabled',false,'environment_ids',jsonb_build_array($2::text))) FROM zasp_security_agent_definitions WHERE organization_id=$1 AND definition_id=$3`, o, e2, temporalTestLegacyProved).Scan(&draft, &intent); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := api.QueryRow(ctx, `SELECT zasp_temporal74.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, "create", temporalTestLegacyProved, o2, w2, e2, actor, "createSecurityAgent", "selector-second-create", int64(0), intent, draft, "pid_f0750000-0000-4000-8000-000000000011", "pid_f0750000-0000-4000-8000-000000000012", "pid_f0750000-0000-4000-8000-000000000013").Scan(&raw); err != nil {
		t.Fatal("registered second tenant create", err)
	}
	for i, activation := range []string{"validated", "supervised", "autonomous"} {
		var ids [3]string
		for j, kind := range []string{"audit", "correlation", "receipt"} {
			if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,$4,$5)`, o2, w2, e2, "selector-"+kind, activation).Scan(&ids[j]); err != nil {
				t.Fatal(err)
			}
		}
		if err := api.QueryRow(ctx, `SELECT zasp_temporal74.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, o2, w2, e2, temporalTestLegacyProved, actor, "selector-second-"+activation, int64(i+1), activation, time.Now().UTC().Add(4*time.Minute), ids[0], ids[1], ids[2]).Scan(&raw); err != nil {
			t.Fatal("registered second tenant activate", activation, err)
		}
	}
	return o2, w2, e2
}
