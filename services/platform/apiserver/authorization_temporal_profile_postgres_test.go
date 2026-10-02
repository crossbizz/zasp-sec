package apiserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type authorizationProfileInstaller interface {
	UpProductionAuthorizationTemporalProfile(context.Context) error
}

// A missing purpose profile, partial transaction, broadened trigger exclusion
// or unsigned API catalog repair must not turn a valid78 catalog into an allow.
func TestP7AuthorizationTemporalProfilePostgres(t *testing.T) {
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), time.Minute)
	defer cancelBuild()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if output, err := exec.CommandContext(buildCtx, "go", "build", "-o", binary, "../agentsec-migrate").CombinedOutput(); err != nil {
		t.Fatalf("build composed CLI: %v %s", err, output)
	}
	for _, intermediate := range []bool{false, true} {
		name := "atomic fresh install"
		if intermediate {
			name = "exact79 intermediate"
		}
		t.Run(name, func(t *testing.T) {
			multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, api *pgx.Conn, o, w, e, _, actor string) {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 6*time.Minute)
				defer cancel()
				db := &authorizationProfileMigrationDB{policyLineageDatabase: &policyLineageDatabase{connection: owner, t: t}}
				runner, _ := migrations.NewRunner(db)
				installer, ok := any(runner).(authorizationProfileInstaller)
				if !ok {
					t.Fatal("explicit composed installer missing")
				}
				for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
					if err := up(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if err := installer.UpProductionAuthorizationTemporalProfile(ctx); err == nil {
					t.Fatal("missing78 profile accepted")
				}
				if _, err := owner.Exec(ctx, `CREATE ROLE authprofile_scheduler LOGIN INHERIT; CREATE ROLE authprofile_risk LOGIN INHERIT; CREATE ROLE authprofile_graph LOGIN INHERIT; CREATE ROLE authprofile_search LOGIN INHERIT; SELECT zasp_execution_register_principals(session_user,'authprofile_scheduler','security_agent_v33_discovery_worker_login','authprofile_risk','authprofile_graph','authprofile_search')`); err != nil {
					t.Fatal(err)
				}
				for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse} {
					if err := up(ctx); err != nil {
						t.Fatal(err)
					}
				}
				humanAPI := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "security_agent_v33_discovery_api_login")
				defer humanAPI.Close(context.Background())
				if _, err := owner.Exec(ctx, `CREATE ROLE authprofile_executor LOGIN INHERIT; CREATE ROLE authprofile_compensation LOGIN INHERIT; SELECT zasp_temporal68.register_principals('authprofile_executor','authprofile_compensation')`); err != nil {
					t.Fatal("register native Temporal probe", err)
				}
				executor := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "authprofile_executor")
				defer executor.Close(context.Background())
				probe := func() error {
					var active bool
					if err := executor.QueryRow(ctx, `SELECT session_user=current_user AND session_user='authprofile_executor' AND pg_has_role(session_user,'zasp_temporal_executor','MEMBER') AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND rolinherit AND NOT(rolsuper OR rolbypassrls OR rolcreaterole))`).Scan(&active); err != nil || !active {
						return errors.New("native executor principal inactive")
					}
					var body []byte
					return executor.QueryRow(ctx, `SELECT zasp_temporal78.pending()`).Scan(&body)
				}
				authorizationProfileReadPrincipal(t, ctx, api, false)
				authorizationProfileReadPrincipal(t, ctx, humanAPI, true)
				if intermediate {
					if err := runner.UpProductionAuthorizationProjection(ctx); err != nil {
						t.Fatal(err)
					}
					if _, err := owner.Exec(ctx, `ALTER TABLE public.zasp_integrations DISABLE TRIGGER zasp_authorization79_capture`); err != nil {
						t.Fatal(err)
					}
					if err := installer.UpProductionAuthorizationTemporalProfile(ctx); err == nil {
						t.Fatal("invalid79 intermediate adopted")
					}
					if _, err := owner.Exec(ctx, `ALTER TABLE public.zasp_integrations ENABLE TRIGGER zasp_authorization79_capture`); err != nil {
						t.Fatal(err)
					}
				}
				db.failFinal = true
				if err := installer.UpProductionAuthorizationTemporalProfile(ctx); err == nil {
					t.Fatal("injected final registration failure committed")
				}
				var clean bool
				if err := owner.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_temporal') IS NULL AND to_regnamespace('zasp_authorization80') IS NULL AND (to_regnamespace('zasp_authorization79') IS NOT NULL)=$1`, intermediate).Scan(&clean); err != nil || !clean {
					t.Fatalf("partial composed state survived rollback: %t %v", clean, err)
				}
				db.failFinal = false
				invoke := func(connection *pgx.Conn, principal string, wantSuccess bool, args ...string) {
					t.Helper()
					config := connection.Config()
					dsn, parseErr := url.Parse(config.ConnString())
					if parseErr != nil {
						t.Fatal("owned CLI connection configuration", parseErr)
					}
					dsn.User = url.UserPassword(config.User, config.Password)
					command := exec.CommandContext(ctx, binary, args...)
					for _, value := range os.Environ() {
						if !strings.HasPrefix(value, "ZASP_") {
							command.Env = append(command.Env, value)
						}
					}
					command.Env = append(command.Env, "ZASP_POSTGRES_DSN="+dsn.String(), "ZASP_MIGRATION_DB_PRINCIPAL="+principal, "ZASP_MIGRATION_TIMEOUT=60s")
					output, err := command.CombinedOutput()
					if (err == nil) != wantSuccess || (wantSuccess && len(output) != 0) {
						t.Fatalf("actual composed CLI success=%t wanted=%t output=%s", err == nil, wantSuccess, output)
					}
					t.Logf("actual composed CLI args=%v registered_session=%t success=%t", args, connection == owner, err == nil)
				}
				invoke(api, owner.Config().User, false, "up-authorization-temporal-profile")
				invoke(owner, "", false, "up-authorization-temporal-profile")
				invoke(owner, owner.Config().User, false, "up-authorization-temporal-profile", "extra")
				invoke(owner, owner.Config().User, true, "up-authorization-temporal-profile")
				invoke(owner, owner.Config().User, true, "up-authorization-temporal-profile")
				var ready bool
				if err := api.QueryRow(ctx, `SELECT zasp_temporal78.api_ready($1,$2) AND zasp_authorization80.ready($3)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint(), migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready); err != nil || !ready {
					t.Fatalf("composed API readiness=%t %v", ready, err)
				}
				if rows := policyDomainRows(t, ctx, owner, "composed-profile"); len(rows) != 1204 {
					t.Fatalf("live retained domain lost rows: %d", len(rows))
				}
				if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_temporal.projected72()=$1 AND zasp_temporal72.fingerprint()=$1`, migrations.TemporalDiscoveryFingerprint()).Scan(&ready); err != nil || !ready {
					t.Fatalf("live projection differs from original72 pin: %t %v", ready, err)
				}
				authorizationProfileReadPrincipal(t, ctx, humanAPI, true)
				read := authorizationProfileHumanRead(t, ctx, owner, humanAPI, o, w, e, actor)
				if err := read(ctx, true); err != nil {
					t.Fatal("signed human read", err)
				}
				if intermediate {
					return
				}
				var originalWrapper, originalProjector, wrapper68, projector68, ready68, captureFunction, inventoryTrigger, syncTrigger, profileChecksum string
				for _, q := range []struct {
					sql string
					dst *string
				}{
					{`SELECT pg_get_functiondef('zasp_temporal72.fingerprint()'::regprocedure)`, &originalWrapper},
					{`SELECT pg_get_functiondef('zasp_authorization80_temporal.projected72()'::regprocedure)`, &originalProjector},
					{`SELECT pg_get_functiondef('zasp_temporal68.fingerprint()'::regprocedure)`, &wrapper68},
					{`SELECT pg_get_functiondef('zasp_authorization80_temporal.projected68()'::regprocedure)`, &projector68},
					{`SELECT pg_get_functiondef('zasp_temporal68.ready(text,text)'::regprocedure)`, &ready68},
					{`SELECT pg_get_functiondef('zasp_authorization79.capture()'::regprocedure)`, &captureFunction},
					{`SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid='zasp_inventory_entities'::regclass AND tgname='zasp_authorization79_capture'`, &inventoryTrigger},
					{`SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid='zasp_discovery_syncs'::regclass AND tgname='zasp_authorization79_capture'`, &syncTrigger},
					{`SELECT checksum FROM zasp_authorization80_temporal.registration`, &profileChecksum},
				} {
					if err := owner.QueryRow(ctx, q.sql).Scan(q.dst); err != nil {
						t.Fatal(err)
					}
				}
				for _, c := range []struct{ name, change, restore string }{
					{"constant72", `CREATE OR REPLACE FUNCTION zasp_temporal72.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT ''` + migrations.TemporalDiscoveryFingerprint() + `''::text'`, originalWrapper},
					{"constant68 fingerprint", `CREATE OR REPLACE FUNCTION zasp_temporal68.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT ''` + migrations.TemporalExecutorFingerprint() + `''::text'`, wrapper68},
					{"constant68 projector", `CREATE OR REPLACE FUNCTION zasp_authorization80_temporal.projected68() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT ''` + migrations.TemporalExecutorFingerprint() + `''::text'`, projector68},
					{"allow68 admission", `CREATE OR REPLACE FUNCTION zasp_temporal68.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT true'`, ready68},
					{"selector downgrade", `ALTER TABLE zasp_authorization80.runtime_profile DISABLE TRIGGER immutable; UPDATE zasp_authorization80.runtime_profile SET name='canonical61-authorization79-80-v1'; ALTER TABLE zasp_authorization80.runtime_profile ENABLE TRIGGER immutable`, `ALTER TABLE zasp_authorization80.runtime_profile DISABLE TRIGGER immutable; UPDATE zasp_authorization80.runtime_profile SET name='canonical61-temporal78-authorization79-80-v1'; ALTER TABLE zasp_authorization80.runtime_profile ENABLE TRIGGER immutable`},
					{"missing selector", `ALTER TABLE zasp_authorization80.runtime_profile DISABLE TRIGGER immutable; DELETE FROM zasp_authorization80.runtime_profile; ALTER TABLE zasp_authorization80.runtime_profile ENABLE TRIGGER immutable`, `ALTER TABLE zasp_authorization80.runtime_profile DISABLE TRIGGER immutable; INSERT INTO zasp_authorization80.runtime_profile(name) VALUES('canonical61-temporal78-authorization79-80-v1'); ALTER TABLE zasp_authorization80.runtime_profile ENABLE TRIGGER immutable`},
					{"selector guard disabled", `ALTER TABLE zasp_authorization80.runtime_profile DISABLE TRIGGER immutable`, `ALTER TABLE zasp_authorization80.runtime_profile ENABLE TRIGGER immutable`},
					{"missing profile", `ALTER SCHEMA zasp_authorization80_temporal RENAME TO authorization_profile_hidden`, `ALTER SCHEMA authorization_profile_hidden RENAME TO zasp_authorization80_temporal`},
					{"missing78", `ALTER SCHEMA zasp_temporal78 RENAME TO authorization78_hidden`, `ALTER SCHEMA authorization78_hidden RENAME TO zasp_temporal78`},
					{"disabled capture", `ALTER TABLE public.zasp_integrations DISABLE TRIGGER zasp_authorization79_capture`, `ALTER TABLE public.zasp_integrations ENABLE TRIGGER zasp_authorization79_capture`},
					{"missing capture", `DROP TRIGGER zasp_authorization79_capture ON public.zasp_discovery_syncs`, syncTrigger},
					{"old inventory args", `DROP TRIGGER zasp_authorization79_capture ON public.zasp_inventory_entities; CREATE TRIGGER zasp_authorization79_capture BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_inventory_entities FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,kind,id,state')`, `DROP TRIGGER zasp_authorization79_capture ON public.zasp_inventory_entities; ` + inventoryTrigger},
					{"capture ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization79.capture() TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION zasp_authorization79.capture() FROM PUBLIC`},
					{"capture security", `ALTER FUNCTION zasp_authorization79.capture() SECURITY INVOKER`, `ALTER FUNCTION zasp_authorization79.capture() SECURITY DEFINER`},
					{"capture config", `ALTER FUNCTION zasp_authorization79.capture() SET search_path=public`, `ALTER FUNCTION zasp_authorization79.capture() SET search_path=pg_catalog,public`},
					{"capture owner", `ALTER FUNCTION zasp_authorization79.capture() OWNER TO zasp_e2e`, `ALTER FUNCTION zasp_authorization79.capture() OWNER TO zasp_discovery_authority`},
					{"capture implementation", `CREATE OR REPLACE FUNCTION zasp_authorization79.capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS 'BEGIN RETURN NULL;END'`, captureFunction},
					{"wrong relation same trigger", `DROP TRIGGER zasp_authorization79_capture ON public.zasp_discovery_syncs; CREATE TABLE public.authorization_profile_wrong_relation(id text); CREATE TRIGGER zasp_authorization79_capture BEFORE INSERT OR UPDATE OR DELETE ON public.authorization_profile_wrong_relation FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,id,integration_id,principal_id,trigger_kind,state')`, `DROP TABLE public.authorization_profile_wrong_relation; ` + syncTrigger},
					{"unrelated extra trigger", `CREATE TRIGGER unexpected_authorization_capture BEFORE INSERT ON public.zasp_integrations FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,id')`, `DROP TRIGGER unexpected_authorization_capture ON public.zasp_integrations`},
					{"retained table RLS", `ALTER TABLE public.zasp_integrations DISABLE ROW LEVEL SECURITY`, `ALTER TABLE public.zasp_integrations ENABLE ROW LEVEL SECURITY`},
					{"wrapper source", `CREATE OR REPLACE FUNCTION zasp_temporal72.fingerprint() RETURNS text LANGUAGE sql STABLE AS 'SELECT NULL::text'`, originalWrapper},
					{"projector source", `CREATE OR REPLACE FUNCTION zasp_authorization80_temporal.projected72() RETURNS text LANGUAGE sql STABLE AS 'SELECT NULL::text'`, originalProjector},
					{"saved source", `ALTER TABLE zasp_authorization80_temporal.predecessor_functions DISABLE TRIGGER immutable; UPDATE zasp_authorization80_temporal.predecessor_functions SET definition=definition||' '`, `UPDATE zasp_authorization80_temporal.predecessor_functions SET definition=left(definition,length(definition)-1); ALTER TABLE zasp_authorization80_temporal.predecessor_functions ENABLE TRIGGER immutable`},
					{"old profile checksum", `ALTER TABLE zasp_authorization80_temporal.registration DISABLE TRIGGER immutable; UPDATE zasp_authorization80_temporal.registration SET checksum=repeat('0',64)`, `UPDATE zasp_authorization80_temporal.registration SET checksum='` + profileChecksum + `'; ALTER TABLE zasp_authorization80_temporal.registration ENABLE TRIGGER immutable`},
					{"invalid78", `ALTER TABLE zasp_temporal78.registration DISABLE TRIGGER immutable; UPDATE zasp_temporal78.registration SET checksum=repeat('0',64)`, `UPDATE zasp_temporal78.registration SET checksum='` + migrations.TemporalFindingResponseChecksum() + `'; ALTER TABLE zasp_temporal78.registration ENABLE TRIGGER immutable`},
				} {
					t.Run(c.name, func(t *testing.T) {
						// Committed drift is confined to this disposable cluster so the
						// real API session, not SET ROLE, observes each rejected catalog.
						if err := read(ctx, true); err != nil {
							t.Fatal("pre-drift signed read", err)
						}
						if err := probe(); err != nil {
							t.Fatal("pre-drift registered native Temporal probe", err)
						}
						if err := api.QueryRow(ctx, `SELECT zasp_temporal78.api_ready($1,$2)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()).Scan(&ready); err != nil || !ready {
							t.Fatal("pre-drift registered78 API readiness", err)
						}
						defer func() {
							if _, err := owner.Exec(context.Background(), c.restore); err != nil {
								t.Error("restore owned catalog", err)
							}
						}()
						if _, err := owner.Exec(ctx, c.change); err != nil {
							t.Fatal(err)
						}
						if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_temporal.ready()`).Scan(&ready); err == nil && ready {
							t.Fatal("catalog drift allowed composed profile")
						}
						if err := read(ctx, false); err == nil {
							t.Error("catalog drift allowed signed API fence/read")
						}
						if err := probe(); err == nil {
							t.Error("catalog drift allowed registered native Temporal pending read")
						}
						if err := api.QueryRow(ctx, `SELECT zasp_temporal78.api_ready($1,$2)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()).Scan(&ready); err == nil && ready {
							t.Error("catalog drift allowed registered78 API readiness")
						}
						if c.name == "old profile checksum" && installer.UpProductionAuthorizationTemporalProfile(ctx) == nil {
							t.Fatal("installer silently adopted obsolete profile")
						}
					})
				}
				if err := read(ctx, true); err != nil {
					t.Fatal("restored signed API read", err)
				}
				if err := probe(); err != nil {
					t.Fatal("restored registered native Temporal probe", err)
				}
				for _, connection := range []*pgx.Conn{owner, humanAPI, executor} {
					for _, q := range []string{`INSERT INTO zasp_authorization80.runtime_profile(name) VALUES('canonical61-authorization79-80-v1')`, `UPDATE zasp_authorization80.runtime_profile SET name='canonical61-authorization79-80-v1'`, `DELETE FROM zasp_authorization80.runtime_profile`, `TRUNCATE zasp_authorization80.runtime_profile`} {
						tx, err := connection.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						_, err = tx.Exec(ctx, q)
						_ = tx.Rollback(ctx)
						if err == nil {
							t.Fatal("registered selector mutation accepted", connection.Config().User, q)
						}
					}
				}
				for _, q := range []string{`SET ROLE zasp_discovery_authority`, `INSERT INTO zasp_authorization80_temporal.registration VALUES(true,'forged','forged')`} {
					tx, _ := api.Begin(ctx)
					_, err := tx.Exec(ctx, q)
					_ = tx.Rollback(ctx)
					if err == nil {
						t.Fatal("API gained profile authority", q)
					}
				}
			}, func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_e2e") })
		})
	}
	t.Run("standalone base remains valid", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		dsn := startDisposablePostgresAs(t, "zasp_e2e")
		owner, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close(context.Background())
		migrateP7Authorization(t, ctx, owner)
		api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
		defer api.Close(context.Background())
		authorizationProfileReadPrincipal(t, ctx, api, true)
		runner, _ := migrations.NewRunner(&integrationMigrationDatabase{connection: owner})
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err == nil {
			t.Fatal("base80 without78 silently adopted")
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80.ready($1) AND to_regnamespace('zasp_temporal78') IS NULL AND to_regnamespace('zasp_authorization80_temporal') IS NULL`, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready); err != nil || !ready {
			t.Fatalf("standalone base damaged: %t %v", ready, err)
		}
	})
}

func authorizationProfileReadPrincipal(t *testing.T, ctx context.Context, connection *pgx.Conn, wantSelect bool) {
	t.Helper()
	var session, current string
	var allowed bool
	if err := connection.QueryRow(ctx, `SELECT session_user,current_user,has_table_privilege(current_user,'public.zasp_risk_findings','SELECT')`).Scan(&session, &current, &allowed); err != nil || allowed != wantSelect || session != current || session != connection.Config().User {
		t.Fatalf("native read principal=%s/%s table_SELECT=%t expected=%t error=%v", session, current, allowed, wantSelect, err)
	}
	t.Logf("native read principal session_user=current_user=%s finding_SELECT=%t (existing registered role; no ACL mutation)", session, allowed)
}

type authorizationProfileMigrationDB struct {
	*policyLineageDatabase
	failFinal bool
}

func (d *authorizationProfileMigrationDB) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.policyLineageDatabase.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &authorizationProfileMigrationTX{Transaction: tx, fail: d.failFinal}, nil
}

type authorizationProfileMigrationTX struct {
	migrations.Transaction
	fail bool
}

func (t *authorizationProfileMigrationTX) Exec(ctx context.Context, q string, args ...any) error {
	if t.fail && strings.HasPrefix(q, "INSERT INTO zasp_authorization80_temporal.registration") {
		return errors.New("owned fixture final registration fault")
	}
	return t.Transaction.Exec(ctx, q, args...)
}

func authorizationProfileHumanRead(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) func(context.Context, bool) error {
	t.Helper()
	key := authorizationFixtureAttestor(t)
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier()); err != nil {
		t.Fatal(err)
	}
	const finding = "pid_f0800000-0000-4000-8000-000000000001"
	var priorMemberships int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_identity_memberships WHERE (principal_id,organization_id)=($1,$2)`, actor, o).Scan(&priorMemberships); err != nil || priorMemberships != 0 {
		t.Fatalf("versioned draft fixture identity assumption changed: memberships=%d %v", priorMemberships, err)
	}
	t.Log("versioned draft fixture actor had no current membership; seed exact active human membership and selected scope before signing")
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-profile','member-profile','security_engineer',true); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Profile','[]',true)`, pgx.QueryExecModeSimpleProtocol, actor, o, w, e); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$5,'posture','Profile read','low','open'); INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('authorization-profile-session','sha256'),'session-authorization-profile',$4,$1,$2,$3,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor, finding); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,'pid_f0800000-0000-4000-8000-000000000002')`, o, w, e, finding); err != nil {
		t.Fatal(err)
	}
	var seeded bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_identity_memberships WHERE(principal_id,organization_id)=($1,$2) AND active) AND EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes($1,$2) WHERE(workspace_id,environment_id)=($3,$4)) AND public.zasp_risk_finding_get($5,$2,$3,$4)->>'id'=$5`, actor, o, w, e, finding).Scan(&seeded); err != nil || !seeded {
		t.Fatalf("complete typed-read fixture: %t %v", seeded, err)
	}
	var outbox string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgxpool.ParseConfig(owner.Config().ConnString())
	cfg.ConnConfig.User = outbox
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	store, model := "01K00000000000000000000001", "01K00000000000000000000002"
	if _, err = owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model); err != nil {
		t.Fatal(err)
	}
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	if err = db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	resolver, _ := NewPostgresAuthorizationResolver(db)
	repository, err := NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	a := &OpenFGAAuthorizer{Reader: projection, Checker: authorizationDecisionFixture{allow: map[string]bool{finding: true}, model: model}, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: key}
	identity := automaticSourceIdentity(t, o, w, e, actor)
	identity.CSRFToken = strings.Repeat("x", 32)
	binding := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-authorization-profile", Digest: sha256.Sum256([]byte("authorization-profile-session"))}
	var grant RequestAuthorization
	return func(ctx context.Context, refresh bool) error {
		if refresh {
			var err error
			grant, err = a.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": finding}})
			if err != nil {
				return err
			}
		}
		result, err := repository.GetRiskFinding(context.WithValue(ctx, requestAuthorizationContextKey{}, grant), identity.Scope, finding)
		if err != nil {
			return err
		}
		if result.ID != finding {
			return errors.New("authorized finding missing")
		}
		return nil
	}
}
