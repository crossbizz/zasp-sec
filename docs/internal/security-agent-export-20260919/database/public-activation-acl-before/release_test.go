package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Registered concrete logins can share the zasp_ prefix with authority roles.
// Self-membership must not count as a second authority, but direct or inherited
// foreign memberships must still block export API/worker calls.
func TestSecurityAgentExportPrefixedLoginsPostgres(t *testing.T) {
	runExportDefinitionFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, o, w, e, actor string) {
		if _, err := owner.Exec(ctx, `CREATE ROLE zasp_e2e_security_agent_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_security_agent_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_security_agent_action LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE export_login_bridge NOLOGIN INHERIT;
DELETE FROM zasp_security_agent_principal_bindings;
DELETE FROM zasp_security_agent_action_principal_bindings;
SELECT zasp_security_agent_register_principals(session_user,'zasp_e2e_security_agent_api','zasp_e2e_security_agent_worker');
SELECT zasp_security_agent_register_action_principal(session_user,'zasp_e2e_security_agent_action');`); err != nil {
			t.Fatal(err)
		}
		checksum, fp := migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
		t.Logf("release58 checksum=%s fingerprint=%s", checksum, fp)
		for _, item := range []struct {
			login, role, query string
			args               []any
		}{
			{"zasp_e2e_security_agent_api", "zasp_security_agent_api", `SELECT zasp_sa_export_definition_page($1,$2,$3,$4,'',20,$5,$6)`, []any{o, w, e, actor, checksum, fp}},
			{"zasp_e2e_security_agent_worker", "zasp_security_agent_worker", `SELECT zasp_sa_export_settlement_claim('prefixed-worker','prefixed-lease-token-0001',60,1,$1,$2)`, []any{checksum, fp}},
			{"zasp_e2e_security_agent_action", "zasp_security_agent_action_worker", `SELECT zasp_security_agent_claim_temporary_policy_effects('prefixed-action','prefixed-lease-token-0001',60,1)`, nil},
		} {
			t.Run(item.login, func(t *testing.T) {
				cfg := owner.Config().Copy()
				cfg.User = item.login
				conn, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(context.Background())
				var session string
				var self, expected bool
				if err = conn.QueryRow(ctx, `SELECT session_user,pg_has_role(session_user,session_user,'MEMBER'),pg_has_role(session_user,$1,'MEMBER')`, item.role).Scan(&session, &self, &expected); err != nil || session != item.login || !self || !expected {
					t.Fatalf("actual login=%s self=%v expected=%v error=%v", session, self, expected, err)
				}
				probe := func(want bool) {
					t.Helper()
					var raw []byte
					err := conn.QueryRow(ctx, item.query, item.args...).Scan(&raw)
					if want {
						if err != nil || !json.Valid(raw) {
							t.Errorf("registered %s refused: %s %v", item.login, raw, err)
						}
						return
					}
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || (pg.Code != "42501" && pg.Code != "22023") {
						t.Errorf("foreign authority accepted for %s: %s %v", item.login, raw, err)
					}
				}
				probe(true)
				if item.role == "zasp_security_agent_api" {
					var raw []byte
					if err = conn.QueryRow(ctx, `SELECT zasp_sa_export_controls($1,$2,$3,$4,$5,$6)`, o, w, e, actor, checksum, fp).Scan(&raw); err != nil {
						t.Errorf("prefixed API controls: %v", err)
					}
				}
				foreign := "zasp_discovery_api"
				if item.role == "zasp_security_agent_action_worker" {
					foreign = "zasp_security_agent_worker"
				}
				for _, inherited := range []bool{false, true} {
					grant := `GRANT ` + foreign + ` TO ` + item.login
					revoke := `REVOKE ` + foreign + ` FROM ` + item.login
					if inherited {
						grant = `GRANT ` + foreign + ` TO export_login_bridge; GRANT export_login_bridge TO ` + item.login
						revoke = `REVOKE export_login_bridge FROM ` + item.login + `; REVOKE ` + foreign + ` FROM export_login_bridge`
					}
					if _, err = owner.Exec(ctx, grant); err != nil {
						t.Fatal(err)
					}
					probe(false)
					if _, err = owner.Exec(ctx, revoke); err != nil {
						t.Fatal(err)
					}
					probe(true)
				}
				if item.role == "zasp_security_agent_action_worker" {
					var raw []byte
					err = conn.QueryRow(ctx, `SELECT zasp_sa_export_settlement_claim('prefixed-worker','prefixed-lease-token-0001',60,1,$1,$2)`, checksum, fp).Scan(&raw)
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != "42501" {
						t.Fatalf("action borrowed export worker authority: %v", err)
					}
				}
			})
		}
	})
}

func TestSecurityAgentExportMigrationIdentityPostgres(t *testing.T) {
	runExportDefinitionFixture(t, func(ctx context.Context, owner, api *pgx.Conn, _, _, _, _ string) {
		if _, err := owner.Exec(ctx, `CREATE ROLE export_unregistered_owner NOLOGIN`); err != nil {
			t.Fatal(err)
		}
		for _, signature := range []string{"public.zasp_workflow_mutate_v3(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text)", "public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)"} {
			var originalOwner, originalACL string
			if err := owner.QueryRow(ctx, `SELECT owner_name,acl::text FROM zasp_sa_export_prior.functions WHERE signature=$1`, signature).Scan(&originalOwner, &originalACL); err != nil {
				t.Fatal(err)
			}
			for _, drift := range []struct{ name, query string }{
				{"foreign_owner", `UPDATE zasp_sa_export_prior.functions SET owner_name=(SELECT principal_name FROM zasp_security_agent_principal_bindings WHERE authority_role='zasp_security_agent_api') WHERE signature=$1`},
				{"unregistered_owner", `UPDATE zasp_sa_export_prior.functions SET owner_name='export_unregistered_owner' WHERE signature=$1`},
				{"extra_acl", `UPDATE zasp_sa_export_prior.functions SET acl=acl||'[{"grantee":"zasp_security_agent_worker","grantable":false}]'::jsonb WHERE signature=$1`},
				{"grant_option", `UPDATE zasp_sa_export_prior.functions SET acl=(SELECT jsonb_agg(CASE WHEN a->>'grantee'=owner_name THEN jsonb_set(a,'{grantable}','true') ELSE a END ORDER BY n) FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)) WHERE signature=$1`},
			} {
				t.Run(signature+"/"+drift.name, func(t *testing.T) {
					if _, err := owner.Exec(ctx, drift.query, signature); err != nil {
						t.Fatal(err)
					}
					var actual string
					var ready bool
					if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_live_fingerprint(),zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&actual, &ready); err != nil || actual == migrations.SecurityAgentExportsFingerprint() || ready {
						t.Errorf("%s accepted catalog drift: fp=%s ready=%v error=%v", drift.name, actual, ready, err)
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_sa_export_prior.functions SET owner_name=$2,acl=$3::jsonb WHERE signature=$1`, signature, originalOwner, originalACL); err != nil {
						t.Fatal(err)
					}
					if err := api.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready {
						t.Fatalf("restored exact raw owner/ACL unavailable: %v %v", ready, err)
					}
				})
			}
		}
	})
}

func applyExport58(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentExports(ctx); err != nil {
		// A failed Runner transaction has rolled back. Inspect an isolated rollback-
		// only transaction to report the actual catalog pin or SQL diagnostic.
		tx, debugErr := owner.Begin(ctx)
		if debugErr != nil {
			t.Fatalf("Runner58=%v diagnostic=%v", err, debugErr)
		}
		defer tx.Rollback(context.Background())
		_, debugErr = tx.Exec(ctx, migrations.ProductionSecurityAgentExports().UpSQL())
		if debugErr != nil {
			t.Fatalf("Runner58=%v SQL diagnostic=%#v", err, debugErr)
		}
		var fp string
		debugErr = tx.QueryRow(ctx, `SELECT zasp_sa_export_live_fingerprint()`).Scan(&fp)
		t.Fatalf("Runner58=%v observed fingerprint=%s diagnostic=%v", err, fp, debugErr)
	}
}

// This catches loss of predecessor catalog/ACLs and destructive downgrade of
// disabled controls, which are still retained product history.
func TestSecurityAgentExportReleasePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		const catalog = `SELECT zasp_sa_attack_lab_live_fingerprint(),(SELECT jsonb_object_agg(oid::regprocedure::text,jsonb_build_object('owner',proowner::regrole::text,'acl',COALESCE(proacl::text,'')))::text FROM pg_proc WHERE pronamespace='public'::regnamespace)`
		var beforeFP, beforeACL string
		if err := owner.QueryRow(ctx, catalog).Scan(&beforeFP, &beforeACL); err != nil {
			t.Fatal(err)
		}
		if beforeFP != migrations.SecurityAgentAttackLabFingerprint() {
			t.Fatal("fixture57 catalog differs")
		}
		applyExport58(t, ctx, owner)
		var ready bool
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("registered58 readiness=%v error=%v", ready, err)
		}
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_workflow_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("installed workflow admission=%v %v", ready, err)
		}
		var closed bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.pronamespace='zasp_sa_export_prior'::regnamespace AND (has_function_privilege('zasp_security_agent_api',p.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE'))) AND NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_sa_export_workflow_readiness','zasp_sa_export_mutate_definition','zasp_sa_export_replay_definition','zasp_sa_export_activate','zasp_sa_export_controls','zasp_sa_export_set_control','zasp_sa_export_definition_value','zasp_sa_export_definition_detail','zasp_sa_export_definition_page') AND (p.proowner<>'zasp_discovery_authority'::regrole OR NOT p.prosecdef OR NOT has_function_privilege('zasp_security_agent_api',p.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE')))`).Scan(&closed); err != nil || !closed {
			t.Fatalf("public definition owner/ACL=%v %v", closed, err)
		}
		if _, err := owner.Exec(ctx, `BEGIN; GRANT EXECUTE ON FUNCTION zasp_sa_export_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text) TO zasp_security_agent_worker`); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_workflow_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("admission ACL drift accepted: %v %v", ready, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `BEGIN; ALTER TABLE zasp_sa_export_links ADD COLUMN unexpected text`); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("live column drift accepted: %v %v", ready, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK; CREATE ROLE export_release_executor LOGIN INHERIT; CREATE ROLE export_release_cleanup LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `BEGIN; CREATE FUNCTION public.export_fixture_unexpected_trigger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER export_fixture_unexpected BEFORE INSERT ON zasp_sa_export_links FOR EACH ROW EXECUTE FUNCTION public.export_fixture_unexpected_trigger()`); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || ready {
			t.Errorf("live trigger drift accepted: %v %v", ready, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if err := runner.RegisterComplianceWorkers(ctx, "export_release_executor", "export_release_cleanup"); err != nil {
			t.Fatalf("actual Runner registration58: %v", err)
		}
		if err := runner.DownProductionSecurityAgentExports(ctx); err != nil {
			t.Fatal(err)
		}
		var afterFP, afterACL string
		if err := owner.QueryRow(ctx, catalog).Scan(&afterFP, &afterACL); err != nil {
			t.Fatal(err)
		}
		if afterFP != beforeFP || afterACL != beforeACL {
			t.Fatalf("empty downgrade did not restore57: fingerprint %s -> %s; sameACL=%v", beforeFP, afterFP, beforeACL == afterACL)
		}
		applyExport58(t, ctx, owner)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'create_evidence_export',false,$4)`, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentExports(ctx); err == nil {
			t.Fatal("disabled export control history was destructively downgraded")
		}
		var version int64
		if err := owner.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&version); err != nil || version != 58 {
			t.Fatalf("refused downgrade changed registry: %d %v", version, err)
		}
	})
}
