package apiserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type auditProfileInstaller interface {
	UpProductionAuthorizationAuditProfile(context.Context) error
	UpProductionAuthorizationTemporalAuditProfile(context.Context) error
}

func TestP7AuditIsolationPostgres(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if output, err := exec.Command("go", "build", "-o", binary, "../agentsec-migrate").CombinedOutput(); err != nil {
		t.Fatalf("build guarded CLI: %v %s", err, output)
	}
	for _, profile := range []struct {
		name                   string
		composed, intermediate bool
	}{{"base", false, false}, {"base79", false, true}, {"composed", true, false}, {"composed79", true, true}} {
		composed := profile.composed
		t.Run(profile.name, func(t *testing.T) {
			multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, agentAPI *pgx.Conn, o, w, e, _, actor string) {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 6*time.Minute)
				defer cancel()
				db := &auditProfileMigrationDB{policyLineageDatabase: &policyLineageDatabase{connection: owner, t: t}}
				runner, _ := migrations.NewRunner(db)
				for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
					if err := up(ctx); err != nil {
						t.Fatal(err)
					}
				}
				var executor *pgx.Conn
				if composed {
					if _, err := owner.Exec(ctx, `CREATE ROLE auditprofile_scheduler LOGIN INHERIT; CREATE ROLE auditprofile_risk LOGIN INHERIT; CREATE ROLE auditprofile_graph LOGIN INHERIT; CREATE ROLE auditprofile_search LOGIN INHERIT; SELECT zasp_execution_register_principals(session_user,'auditprofile_scheduler','security_agent_v33_discovery_worker_login','auditprofile_risk','auditprofile_graph','auditprofile_search')`); err != nil {
						t.Fatal(err)
					}
					for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse} {
						if err := up(ctx); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := owner.Exec(ctx, `CREATE ROLE auditprofile_executor LOGIN INHERIT; CREATE ROLE auditprofile_compensation LOGIN INHERIT; SELECT zasp_temporal68.register_principals('auditprofile_executor','auditprofile_compensation')`); err != nil {
						t.Fatal(err)
					}
					executor = connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "auditprofile_executor")
					defer executor.Close(context.Background())
				}
				install := runner.UpProductionAuthorizationAuditProfile
				command := "up-authorization-audit-profile"
				if composed {
					install = runner.UpProductionAuthorizationTemporalAuditProfile
					command = "up-authorization-temporal-audit-profile"
				}
				if profile.intermediate {
					if err := runner.UpProductionAuthorizationProjection(ctx); err != nil {
						t.Fatal(err)
					}
				}
				var original57 string
				if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_sa_attack_lab_live_fingerprint()'::regprocedure)`).Scan(&original57); err != nil {
					t.Fatal(err)
				}
				db.fail = true
				if err := install(ctx); err == nil {
					t.Fatal("injected audit registration failure committed")
				}
				if !db.faultReached {
					t.Fatal("installer failed before selected registration fault")
				}
				var clean bool
				if err := owner.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80') IS NULL AND to_regnamespace('zasp_authorization80_audit') IS NULL AND to_regnamespace('zasp_authorization80_temporal') IS NULL AND(to_regnamespace('zasp_authorization79') IS NOT NULL)=$1 AND pg_get_functiondef('public.zasp_sa_attack_lab_live_fingerprint()'::regprocedure)=$2`, profile.intermediate, original57).Scan(&clean); err != nil || !clean {
					t.Fatalf("atomic rollback=%t %v", clean, err)
				}
				db.fail = false
				invoke := func(connection *pgx.Conn, principal string, want bool, args ...string) {
					t.Helper()
					config := connection.Config()
					dsn, err := url.Parse(config.ConnString())
					if err != nil {
						t.Fatal(err)
					}
					dsn.User = url.UserPassword(config.User, config.Password)
					cmd := exec.CommandContext(ctx, binary, args...)
					for _, value := range os.Environ() {
						if !strings.HasPrefix(value, "ZASP_") {
							cmd.Env = append(cmd.Env, value)
						}
					}
					cmd.Env = append(cmd.Env, "ZASP_POSTGRES_DSN="+dsn.String(), "ZASP_MIGRATION_DB_PRINCIPAL="+principal, "ZASP_MIGRATION_TIMEOUT=90s")
					output, err := cmd.CombinedOutput()
					if (err == nil) != want || (want && len(output) != 0) {
						t.Fatalf("guarded CLI want=%t error=%v output=%s", want, err, output)
					}
					t.Logf("guarded CLI command=%s registered_owner=%t success=%t", args[0], connection == owner, err == nil)
				}
				invoke(agentAPI, owner.Config().User, false, command)
				invoke(owner, "", false, command)
				invoke(owner, owner.Config().User, false, command, "extra")
				invoke(owner, owner.Config().User, true, command)
				invoke(owner, owner.Config().User, true, command)
				if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE audit_mode='source52-canonical61-audit-v1') AND zasp_authorization80_audit.guard_ready() AND zasp_authorization80_audit.catalog_ready() AND zasp_authorization80.ready($1)`, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&clean); err != nil || !clean {
					t.Fatalf("actual guarded selection/ready=%t %v", clean, err)
				}
				if composed {
					if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err == nil {
						t.Fatal("none command adopted guarded composed profile")
					}
				} else {
					if err := runner.UpProductionAuthorizationEnforcement(ctx); err == nil {
						t.Fatal("none command adopted guarded base profile")
					}
				}
				api := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "security_agent_v33_discovery_api_login")
				defer api.Close(context.Background())
				authorizationProfileReadPrincipal(t, ctx, api, true)
				read := authorizationProfileHumanRead(t, ctx, owner, api, o, w, e, actor)
				if err := read(ctx, true); err != nil {
					t.Fatal("initial signed read", err)
				}
				probe := func() error {
					if executor == nil {
						return nil
					}
					var body []byte
					return executor.QueryRow(ctx, `SELECT zasp_temporal78.pending()`).Scan(&body)
				}
				if err := probe(); err != nil {
					t.Fatal("registered native78 positive", err)
				}
				if profile.intermediate {
					return
				}
				const auditID = "pid_a0800000-0000-4000-8000-000000000001"
				if _, err := owner.Exec(ctx, `INSERT INTO public.zasp_admin_audit(id,organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,$4,$5,'workspace.create',$3,'succeeded','{}')`, auditID, o, w, e, actor); err != nil {
					t.Fatal("native owner seed", err)
				}
				for _, q := range []struct {
					name, sql string
					args      []any
				}{
					{"insert", `INSERT INTO public.zasp_admin_audit(id,organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome,metadata) VALUES('pid_a0800000-0000-4000-8000-000000000002',$1,$2,$3,$4,'workspace.create',$2,'succeeded','{}')`, []any{o, w, e, actor}},
					{"update", `UPDATE public.zasp_admin_audit SET actor_id=$1 WHERE id=$2`, []any{actor, auditID}},
					{"delete", `DELETE FROM public.zasp_admin_audit WHERE id=$1`, []any{auditID}},
					{"truncate", `TRUNCATE public.zasp_admin_audit`, nil},
				} {
					t.Run("raw "+q.name, func(t *testing.T) {
						tx, err := api.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer tx.Rollback(context.Background())
						_, err = tx.Exec(ctx, q.sql, q.args...)
						if err == nil {
							t.Error("raw registered API audit mutation accepted")
						}
					})
				}
				t.Run("constant57 independent entry", func(t *testing.T) {
					if err := read(ctx, true); err != nil {
						t.Fatal(err)
					}
					if err := probe(); err != nil {
						t.Fatal(err)
					}
					var original, value string
					if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_sa_attack_lab_live_fingerprint()'::regprocedure),public.zasp_sa_attack_lab_live_fingerprint()`).Scan(&original, &value); err != nil {
						t.Fatal(err)
					}
					t.Logf("accepted pre-mutation computed57=%s", value)
					defer func() {
						if _, err := owner.Exec(context.Background(), original); err != nil {
							t.Error(err)
						}
					}()
					if _, err := owner.Exec(ctx, fmt.Sprintf(`CREATE OR REPLACE FUNCTION public.zasp_sa_attack_lab_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT ''%s''::text'`, value)); err != nil {
						t.Fatal(err)
					}
					if err := read(ctx, false); err == nil {
						t.Error("constant57 bypassed signed API entry")
					}
					if composed {
						if err := probe(); err == nil {
							t.Error("constant57 bypassed registered native78 entry")
						}
						var ready bool
						if err := agentAPI.QueryRow(ctx, `SELECT zasp_temporal78.api_ready($1,$2)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()).Scan(&ready); err == nil && ready {
							t.Error("constant57 bypassed registered78 API readiness")
						}
					}
				})
				auditProfileCatalogDrifts(t, ctx, owner, agentAPI, read, probe, composed, install)
				if err := read(ctx, true); err != nil {
					t.Fatal("restored signed read", err)
				}
				if err := probe(); err != nil {
					t.Fatal("restored native78", err)
				}
			}, func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_e2e") })
		})
	}
}

type auditProfileMigrationDB struct {
	*policyLineageDatabase
	fail, faultReached bool
}

func (d *auditProfileMigrationDB) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.policyLineageDatabase.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &auditProfileMigrationTX{Transaction: tx, database: d}, nil
}

type auditProfileMigrationTX struct {
	migrations.Transaction
	database *auditProfileMigrationDB
}

func (t *auditProfileMigrationTX) Exec(ctx context.Context, q string, args ...any) error {
	if t.database.fail && strings.HasPrefix(q, "INSERT INTO zasp_authorization80_audit.registration") {
		t.database.faultReached = true
		return errors.New("owned audit registration fault")
	}
	return t.Transaction.Exec(ctx, q, args...)
}
