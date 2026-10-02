package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Each drift is fault injection only. Installation and readiness are exercised
// with real catalog definitions; no injected row is successful authority.
func TestSecurityAgentWorker63RegistrationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentWorker(ctx); err == nil {
			t.Fatal("missing public predecessor accepted")
		}
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		var before string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(zasp_sa_multistep_registered_live_fingerprint(),zasp_ordered_public62.fingerprint(),(SELECT jsonb_agg(to_jsonb(x) ORDER BY version) FROM zasp_schema_versions x),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_ordered_public62.registration x))::text`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		for _, pins := range [][2]string{{strings.Repeat("0", 64), worker63Fingerprint()}, {worker63Checksum(), strings.Repeat("0", 64)}} {
			var raw []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,'{"operation":"ready"}'::jsonb)`, pins[0], pins[1]).Scan(&raw); err == nil {
				t.Fatal("wrong request pin accepted")
			}
		}
		for _, sql := range []string{
			`GRANT EXECUTE ON FUNCTION zasp_ordered_worker63.dispatch(jsonb) TO zasp_security_agent_api`,
			`ALTER FUNCTION zasp_ordered_worker63.worker(text,text,jsonb) OWNER TO zasp_security_agent_worker`,
			`ALTER TABLE zasp_ordered_worker63.dispatch_leases NO FORCE ROW LEVEL SECURITY`,
			`DROP POLICY authority ON zasp_ordered_worker63.dispatch_leases`,
			`UPDATE zasp_ordered_worker63.registration SET checksum=repeat('0',64)`,
			`UPDATE zasp_ordered_public62.registration SET fingerprint=repeat('0',64)`,
			`UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`,
			`CREATE OR REPLACE FUNCTION zasp_ordered_worker63.pricing(o text,w text,e text,planner jsonb) RETURNS jsonb LANGUAGE sql SET search_path TO pg_catalog,public AS 'SELECT NULL::jsonb'`,
		} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, sql); err != nil {
				t.Fatal(sql, err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			callErr := tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,'{"operation":"ready"}'::jsonb)`, worker63Checksum(), worker63Fingerprint()).Scan(&raw)
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if callErr == nil {
				t.Fatal("catalog drift remained callable", sql)
			}
		}
		for _, role := range []string{"zasp_security_agent_api", "zasp_security_agent_action_worker", "zasp_policy_deployment_worker", "zasp_discovery_api", "zasp_discovery_worker", "zasp_red_team_worker"} {
			var allowed bool
			if err := owner.QueryRow(ctx, `SELECT has_schema_privilege($1,'zasp_ordered_worker63','USAGE') OR has_function_privilege($1,'zasp_ordered_worker63.worker(text,text,jsonb)','EXECUTE')`, role).Scan(&allowed); err != nil || allowed {
				t.Fatal("unauthorized principal", role, allowed, err)
			}
		}
		var allowed bool
		if err := owner.QueryRow(ctx, `SELECT has_table_privilege('zasp_security_agent_worker','zasp_ordered_worker63.dispatch_leases','SELECT') OR has_function_privilege('zasp_security_agent_worker','zasp_ordered_worker63.dispatch(jsonb)','EXECUTE')`).Scan(&allowed); err != nil || allowed {
			t.Fatal("worker got internals", allowed, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_ordered_worker63.registration SET checksum=checksum`); err == nil {
			t.Fatal("registration not immutable")
		}
		if err := runner.DownProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		var after string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(zasp_sa_multistep_registered_live_fingerprint(),zasp_ordered_public62.fingerprint(),(SELECT jsonb_agg(to_jsonb(x) ORDER BY version) FROM zasp_schema_versions x),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_ordered_public62.registration x))::text`).Scan(&after); err != nil || before != after {
			t.Fatal("predecessor bytes changed", err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2) AND zasp_ordered_public62.ready($3,$4)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("predecessor unready", err)
		}
	})
}

func TestSecurityAgentWorker63InputsAndHistoryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		created, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-history-trigger"})
		if err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		for _, mode := range []string{"disabled", "expired", "ambiguous", "wrong-credential"} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "wrong-credential" {
				var policyRaw []byte
				if err = tx.QueryRow(ctx, `SELECT policy FROM zasp_sa_multistep_prior.pricing_policies WHERE organization_id=$1 ORDER BY version DESC LIMIT 1`, o).Scan(&policyRaw); err != nil {
					t.Fatal(err)
				}
				var p map[string]any
				_ = json.Unmarshal(policyRaw, &p)
				q := orderedPricingAdminRequest(o, w, e, actor)
				q["policy"] = p
				q["idempotency_key"] = "worker63-price-" + mode
				q["expected_version"] = 1
				q["expected_account_version"] = 1
				switch mode {
				case "disabled":
					q["operation"] = "disable"
				case "expired":
					q["operation"] = "version"
					p["expires_at"] = time.Now().UTC().Add(3 * time.Second).Format("2006-01-02T15:04:05.000000Z")
				case "ambiguous":
					q["operation"] = "create"
					q["expected_version"] = 0
					q["expected_account_version"] = 0
					p["account_profile"] = "second-profile"
				}
				if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION security_agent_v33_discovery_api_login`); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(q)
				var response []byte
				if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.pricing_admin($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&response); err != nil {
					t.Fatal(mode, err)
				}
				if mode == "expired" {
					time.Sleep(3100 * time.Millisecond)
				}
			}
			if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			q := worker63ClaimRequest("worker63-price-refusal-token")
			if mode == "wrong-credential" {
				q["planner"].(map[string]any)["credential_digest"] = "sha256:" + strings.Repeat("ff", 32)
			}
			raw, _ := json.Marshal(q)
			var response []byte
			callErr := tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response)
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			_ = json.Unmarshal(response, &result)
			if callErr != nil || result["outcome"] != "empty" || result["item"] != nil {
				t.Fatal("ineligible pricing claimed or failed", mode, result, callErr)
			}
		}
		for _, fault := range []string{"scope", "run", "limit", "worker", "token", "seconds", "provider", "model", "policy", "tokens", "digest", "planner-extra"} {
			q := worker63ClaimRequest("worker63-input-token")
			p := q["planner"].(map[string]any)
			switch fault {
			case "scope":
				q["organization_id"] = o
			case "run":
				q["run_id"] = created.RunID
			case "limit":
				q["limit"] = 2
			case "worker":
				q["worker_id"] = "bad worker"
			case "token":
				q["lease_token"] = strings.Repeat("0", 32)
			case "seconds":
				q["lease_seconds"] = 301
			case "provider":
				p["provider"] = "other"
			case "model":
				p["model"] = "other"
			case "policy":
				p["request_policy_version"] = "other"
			case "tokens":
				p["request_token_limit"] = 4097
			case "digest":
				p["credential_digest"] = "raw-secret"
			case "planner-extra":
				p["raw_credential"] = "secret"
			}
			if _, err = worker63Call(ctx, worker, q); err == nil {
				t.Fatal("invalid request accepted", fault)
			}
		}
		for _, sql := range []string{
			`DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_public_triggered'`,
			`UPDATE zasp_security_agent_audit SET event_kind='relabelled' WHERE run_id=$1 AND event_kind='ordered_public_triggered'`,
			`DELETE FROM zasp_security_agent_trigger_receipts WHERE run_id=$1`,
			`DELETE FROM zasp_security_agent_definition_versions WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
			`UPDATE zasp_security_agent_runs SET version=2 WHERE run_id=$1`,
		} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, sql, created.RunID); err != nil {
				t.Fatal(sql, err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(worker63ClaimRequest("worker63-corruption-token"))
			var response []byte
			callErr := tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response)
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if callErr == nil {
				t.Fatal("corrupt ordered candidate skipped/claimed", sql)
			}
		}
		var fresh bool
		if err = owner.QueryRow(ctx, `SELECT state='queued' AND version=1 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1) FROM zasp_security_agent_runs WHERE run_id=$1`, created.RunID).Scan(&fresh); err != nil || !fresh {
			t.Fatal("refused requests mutated run", err)
		}
	})
}
