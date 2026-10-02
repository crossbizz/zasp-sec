package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentOrderedDeploymentPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		a, _ := orderedResourceGo(t, api, o, w, e, actor)
		db := a.repository.database.(*PostgresJSONDatabase)
		if err := db.VerifySecurityAgentOrderedHTTPRelease(ctx); err != ErrRepositoryUnavailable {
			t.Fatal("missing extension accepted", err)
		}
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := db.VerifySecurityAgentOrderedHTTPRelease(ctx); err != nil {
			t.Fatal("identity-free deployment readiness", err)
		}
		for _, q := range []string{`{"operation":"deployment_ready","actor_id":"` + actor + `"}`, `{"operation":"deployment_ready","organization_id":"` + o + `"}`, `{"operation":"deployment_ready","ready":true}`, `null`, `[]`} {
			if _, err := db.QueryJSON(ctx, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(q)); err == nil {
				t.Fatal("open deployment request", q)
			}
		}
		for _, args := range [][2]string{{"bad", migrations.SecurityAgentPublicFingerprint()}, {migrations.ProductionSecurityAgentPublic().Checksum(), "bad"}} {
			if _, err := db.QueryJSON(ctx, securityAgentPublicSQL, args[0], args[1], json.RawMessage(`{"operation":"deployment_ready"}`)); err == nil {
				t.Fatal("wrong release accepted")
			}
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo := &PostgresRepository{database: db, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		config := SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey}
		makeHandler := func(enabled bool) http.Handler {
			t.Helper()
			h, err := newSecurityAgentProductionHTTPHandler(ctx, repo, http.NotFoundHandler(), config, enabled)
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
		legacyID := "pid_ffffffff-ffff-4fff-8fff-fffffffffff1"
		triggerKeyLegacyFixture(t, ctx, owner, api, o, w, e, actor, legacyID, "production-legacy-trigger")
		_, id := orderedResourceGo(t, api, o, w, e, actor)
		id.FreshAuthenticated = true
		id.FreshAuthExpiresAt = time.Now().Add(4 * time.Minute)
		before := orderedHTTPCall(t, makeHandler(false), id, "getSecurityAgentRun", "pid_f2000001-0000-4000-8000-000000000001", "", "", 0, 200)
		enabled := makeHandler(true)
		after := orderedHTTPCall(t, enabled, id, "getSecurityAgentRun", "pid_f2000001-0000-4000-8000-000000000001", "", "", 0, 200)
		if before.Body.String() != after.Body.String() {
			t.Fatal("legacy run bytes changed")
		}
		oldActivation := orderedHTTPCall(t, makeHandler(false), id, "getSecurityAgentActivation", legacyID, "", "", 0, 503)
		newActivation := orderedHTTPCall(t, enabled, id, "getSecurityAgentActivation", legacyID, "", "", 0, 503)
		if oldActivation.Body.String() != newActivation.Body.String() {
			t.Fatal("legacy activation failure changed")
		}
		oldList := orderedListCall(t, makeHandler(false), id, "listSecurityAgentRuns", "agent_id="+legacyID+"&limit=1", 200)
		newList := orderedListCall(t, enabled, id, "listSecurityAgentRuns", "agent_id="+legacyID+"&limit=1", 200)
		if oldList.Body.String() != newList.Body.String() {
			t.Fatal("legacy list bytes changed")
		}
		orderedHTTPCall(t, enabled, id, "activateSecurityAgent", public62Definition, `{"activation":"supervised"}`, "production-ordered-activate", 1, 200)
		triggered := orderedHTTPCall(t, enabled, id, "runSecurityAgent", public62Definition, `{"environment_id":"`+e+`","trigger_kind":"finding","trigger_id":"`+public62Finding+`","trigger_version":1,"trigger_source":"credential"}`, "production-ordered-trigger", 2, 202)
		var run SecurityAgentRun
		if json.Unmarshal(triggered.Body.Bytes(), &run) != nil || run.ID == "" {
			t.Fatal(triggered.Body.String())
		}
		orderedHTTPCall(t, enabled, id, "getSecurityAgentRun", run.ID, "", "", 0, 200)
		orderedListCall(t, enabled, id, "listSecurityAgentRuns", "limit=10", 200)
		orderedListCall(t, enabled, id, "listSecurityAgentApprovals", "limit=10", 200)
		conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		restarted, _ := orderedResourceGo(t, conn, o, w, e, actor)
		repo.database = restarted.repository.database
		orderedHTTPCall(t, makeHandler(true), id, "getSecurityAgentRun", run.ID, "", "", 0, 200)
		snapshot := public62Snapshot(t, ctx, owner)
		rollback := makeHandler(false)
		rolled := orderedHTTPCall(t, rollback, id, "getSecurityAgentRun", "pid_f2000001-0000-4000-8000-000000000001", "", "", 0, 200)
		if rolled.Body.String() != before.Body.String() || public62Snapshot(t, ctx, owner) != snapshot {
			t.Fatal("rollback changed state or legacy bytes")
		}
		for name, drift := range map[string]string{
			"predecessor":          `UPDATE public.zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`,
			"missing-registration": `DELETE FROM zasp_ordered_public62.registration`,
			"registration":         `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64)`,
			"fingerprint":          `UPDATE zasp_ordered_public62.registration SET fingerprint=repeat('0',64)`,
			"acl":                  `GRANT EXECUTE ON FUNCTION zasp_ordered_public62.candidates(jsonb) TO zasp_security_agent_api`,
			"owner":                `ALTER FUNCTION zasp_ordered_public62.candidates(jsonb) OWNER TO CURRENT_USER`,
			"rls":                  `ALTER TABLE zasp_ordered_public62.registration DISABLE ROW LEVEL SECURITY`,
			"function":             `ALTER FUNCTION zasp_ordered_public62.candidates(jsonb) SET search_path TO pg_catalog`,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, "ROLLBACK")
				if _, err := owner.Exec(ctx, drift); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				// Use the owner transaction to see its uncommitted catalog drift.
				probe, _ := orderedResourceGo(t, owner, o, w, e, actor)
				if err := probe.repository.database.(*PostgresJSONDatabase).VerifySecurityAgentOrderedHTTPRelease(ctx); err != ErrRepositoryUnavailable {
					t.Fatal("drift accepted", err)
				}
			})
		}
		if err := db.VerifySecurityAgentOrderedHTTPRelease(ctx); err != nil {
			t.Fatal("drift rollback", err)
		}
		// The startup verifier must obey caller cancellation while waiting on
		// the same migration lock held by install/uninstall operations.
		if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			t.Fatal(err)
		}
		for _, canceled := range []bool{false, true} {
			probeConn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			probe, _ := orderedResourceGo(t, probeConn, o, w, e, actor)
			bounded, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
			if canceled {
				cancel()
			}
			started := time.Now()
			err = probe.repository.database.(*PostgresJSONDatabase).VerifySecurityAgentOrderedHTTPRelease(bounded)
			cancel()
			_ = probeConn.Close(ctx)
			if err != ErrRepositoryUnavailable || time.Since(started) > time.Second {
				t.Fatal("unbounded/canceled readiness", err)
			}
		}
		if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := newSecurityAgentProductionHTTPHandler(ctx, repo, http.NotFoundHandler(), config, true); err != ErrRepositoryUnavailable {
			t.Fatal("enabled downgrade after down", err)
		}
		makeHandler(false)
	})
}
