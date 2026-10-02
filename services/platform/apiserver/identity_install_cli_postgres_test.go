package apiserver

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type identityInstallFaultDB struct {
	*policyLineageDatabase
	fail    bool
	reached bool
}

func (d *identityInstallFaultDB) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, e := d.policyLineageDatabase.Begin(ctx)
	if e != nil {
		return nil, e
	}
	return &identityInstallFaultTX{Transaction: tx, db: d}, nil
}

type identityInstallFaultTX struct {
	migrations.Transaction
	db *identityInstallFaultDB
}

func (tx *identityInstallFaultTX) Exec(ctx context.Context, q string, a ...any) error {
	if tx.db.fail && strings.HasPrefix(q, "INSERT INTO zasp_authorization80_identity.registration") {
		tx.db.reached = true
		return errors.New("owned fixture identity registration fault")
	}
	return tx.Transaction.Exec(ctx, q, a...)
}

func TestP7IdentityInstallCLIAndMaintenancePostgres(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if out, err := exec.Command("go", "build", "-o", binary, "../agentsec-migrate").CombinedOutput(); err != nil {
		t.Fatalf("build identity CLI: %v %s", err, out)
	}
	for _, composed := range []bool{false, true} {
		name := "base"
		if composed {
			name = "composed"
		}
		t.Run(name, func(t *testing.T) {
			multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, agentAPI *pgx.Conn, o, w, e, _, actor string) {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 6*time.Minute)
				defer cancel()
				db := &identityInstallFaultDB{policyLineageDatabase: &policyLineageDatabase{connection: owner, t: t}}
				runner, _ := migrations.NewRunner(db)
				for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
					if err := up(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if composed {
					if _, err := owner.Exec(ctx, `CREATE ROLE identityprofile_scheduler LOGIN INHERIT; CREATE ROLE identityprofile_risk LOGIN INHERIT; CREATE ROLE identityprofile_graph LOGIN INHERIT; CREATE ROLE identityprofile_search LOGIN INHERIT; SELECT zasp_execution_register_principals(session_user,'identityprofile_scheduler','security_agent_v33_discovery_worker_login','identityprofile_risk','identityprofile_graph','identityprofile_search')`); err != nil {
						t.Fatal(err)
					}
					for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse} {
						if err := up(ctx); err != nil {
							t.Fatal(err)
						}
					}
				}
				install := runner.UpProductionAuthorizationIdentityProfile
				command := "up-authorization-identity-profile"
				if composed {
					install = runner.UpProductionAuthorizationTemporalIdentityProfile
					command = "up-authorization-temporal-identity-profile"
				}
				db.fail = true
				if err := install(ctx); err == nil || !db.reached {
					t.Fatalf("identity atomic fault reached=%v error=%v", db.reached, err)
				}
				var ready bool
				if err := owner.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_identity') IS NULL AND to_regnamespace('zasp_authorization80') IS NULL AND to_regnamespace('zasp_authorization79') IS NULL AND public.zasp_identity_administration_live_fingerprint()=$1`, migrations.ProductionIdentityAdministrationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
					t.Fatalf("failed identity install retained effects: %v %v", ready, err)
				}
				db.fail = false
				seed := "identity-cli-fixture-seed-01234567890123456789"
				deployment := authorization.IdentityDeployment{PublicOrigin: "https://console.example", ProviderBaseURL: "https://test.stytch.com", ProjectID: "project-test-identity-cli", ConfiguredOrganization: "organization-identity-cli", Mode: "saas"}
				var apiPrincipal string
				if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_api'`).Scan(&apiPrincipal); err != nil {
					t.Fatal(err)
				}
				api := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), apiPrincipal)
				defer api.Close(context.Background())
				invoke := func(connection *pgx.Conn, want bool, args []string, overrides map[string]string) {
					t.Helper()
					config := connection.Config()
					dsn, err := url.Parse(config.ConnString())
					if err != nil {
						t.Fatal(err)
					}
					dsn.User = url.UserPassword(config.User, config.Password)
					env := map[string]string{"ZASP_POSTGRES_DSN": dsn.String(), "ZASP_MIGRATION_DB_PRINCIPAL": owner.Config().User, "ZASP_DISCOVERY_API_DB_PRINCIPAL": apiPrincipal, "ZASP_MIGRATION_TIMEOUT": "90s", "ZASP_WORKFLOW_SIGNING_KEY": seed, "ZASP_PUBLIC_ORIGIN": deployment.PublicOrigin, "ZASP_STYTCH_BASE_URL": deployment.ProviderBaseURL, "ZASP_STYTCH_PROJECT_ID": deployment.ProjectID, "ZASP_STYTCH_ORGANIZATION_ID": deployment.ConfiguredOrganization, "ZASP_DEPLOYMENT_MODE": deployment.Mode}
					for k, v := range overrides {
						env[k] = v
					}
					cmd := exec.CommandContext(ctx, binary, args...)
					for _, v := range os.Environ() {
						if !strings.HasPrefix(v, "ZASP_") {
							cmd.Env = append(cmd.Env, v)
						}
					}
					for k, v := range env {
						cmd.Env = append(cmd.Env, k+"="+v)
					}
					out, err := cmd.CombinedOutput()
					if strings.Contains(string(out), seed) || strings.Contains(string(out), dsn.String()) {
						t.Fatal("CLI disclosed private configuration")
					}
					if (err == nil) != want || want && len(out) != 0 {
						t.Fatalf("identity CLI %s wanted success=%v error=%v output=%s", args[0], want, err, out)
					}
					t.Logf("actual CLI %s registered_owner=%v success=%v", args[0], connection == owner, err == nil)
				}
				invoke(api, false, []string{command}, nil)
				invoke(owner, false, []string{command, "extra"}, nil)
				invoke(owner, true, []string{command}, nil)
				invoke(owner, true, []string{command}, nil)
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.structural_ready($1)`, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || !ready {
					t.Fatalf("empty-key structure: %v %v", ready, err)
				}
				var payload []byte
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.metadata()`).Scan(&payload); err == nil {
					t.Fatal("missing keys admitted")
				}
				for _, purpose := range []string{"session", "webhook"} {
					cmd := "register-identity-" + purpose + "-verifier"
					invoke(owner, false, []string{cmd}, map[string]string{"ZASP_WORKFLOW_SIGNING_KEY": "short"})
					invoke(owner, false, []string{cmd, "extra"}, nil)
					invoke(api, false, []string{cmd}, nil)
					invoke(owner, true, []string{cmd}, nil)
					invoke(owner, true, []string{cmd}, nil)
					if purpose == "session" {
						if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.metadata()`).Scan(&payload); err == nil {
							t.Fatal("one purpose admitted runtime")
						}
					}
				}
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.metadata()`).Scan(&payload); err != nil {
					t.Fatal(err)
				}
				if composed {
					if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_temporal.ready() AND zasp_authorization80_temporal.projected68()=$1 AND zasp_authorization80_temporal.projected72()=$2`, migrations.TemporalExecutorFingerprint(), migrations.TemporalDiscoveryFingerprint()).Scan(&ready); err != nil || !ready {
						t.Fatalf("composed68/72 catalog: %v %v", ready, err)
					}
				}
				state := strings.Repeat("k", 43)
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.begin_login($1,'/')`, state).Scan(&ready); err != nil || !ready {
					t.Fatal("native CLI-key state begin", err)
				}
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.consume_login($1)`, state).Scan(&payload); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_authorization80_identity.attempts(state_digest,attempt_id,return_path,consumed_at,expires_at,phase) SELECT digest('expired-owned-'||n,'sha256'),encode(digest('expired-attempt-'||n,'sha256'),'hex'),'/',clock_timestamp()-interval '3 days',clock_timestamp()-interval '2 days','consumed' FROM generate_series(1,1003)n`); err != nil {
					t.Fatal(err)
				}
				var count int
				const retainedAudit = "pid_98000001-0000-4000-8000-000000000299"
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,$4,$5,'identity.cleanup.fixture',$5,'succeeded','{}')`, o, w, e, retainedAudit, actor); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_webhook_events(project_id,event_id,organization_id,member_reference,event_kind,event_digest,audit_id,revoked_sessions,revoked_tokens) VALUES('project-test-cleanup','webhook-event-test-cleanup-retained',$1,'member-cleanup-retained','scim.member.delete',digest('cleanup-retained','sha256'),$2,0,0)`, o, retainedAudit); err != nil {
					t.Fatal(err)
				}
				retainedEvidence := func() string {
					t.Helper()
					var evidence string
					if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(a) ORDER BY organization_id,id) FROM zasp_admin_audit a),(SELECT jsonb_agg(to_jsonb(e) ORDER BY project_id,event_id) FROM zasp_identity_webhook_events e))::text`).Scan(&evidence); err != nil {
						t.Fatal(err)
					}
					return evidence
				}
				evidenceBefore := retainedEvidence()
				t.Run("NULL-maintenance-bound", func(t *testing.T) {
					requireIdentityRefusal(t, owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.cleanup_expired(NULL::integer)`).Scan(&count))
					if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization80_identity.attempts`).Scan(&count); err != nil || count != 1004 {
						t.Errorf("NULL cleanup changed1003 expired plus1 live attempts: count=%d error=%v", count, err)
					}
				})
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.cleanup_expired(2)`).Scan(&count); err == nil {
					t.Fatal("API performed maintenance")
				}
				for _, n := range []int{0, 1001} {
					if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.cleanup_expired($1)`, n).Scan(&count); err == nil {
						t.Fatal("unbounded maintenance accepted")
					}
				}
				if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.cleanup_expired(2)`).Scan(&count); err != nil || count != 2 {
					t.Fatalf("bounded maintenance count=%d error=%v", count, err)
				}
				if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization80_identity.attempts`).Scan(&count); err != nil || count != 1002 {
					t.Fatalf("maintenance erased live/extra attempt count=%d %v", count, err)
				}
				if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.cleanup_expired(1000)`).Scan(&count); err != nil || count != 1000 {
					t.Fatalf("maximum bounded maintenance count=%d error=%v", count, err)
				}
				if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization80_identity.attempts`).Scan(&count); err != nil || count != 2 {
					t.Fatalf("maximum cleanup erased extra/live attempts: count=%d error=%v", count, err)
				}
				if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_identity.attempts WHERE state_digest=digest($1,'sha256') AND expires_at>clock_timestamp())`, state).Scan(&ready); err != nil || !ready {
					t.Fatalf("cleanup erased live attempt: %v %v", ready, err)
				}
				if retainedEvidence() != evidenceBefore {
					t.Fatal("cleanup altered audit or webhook receipts")
				}
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.consume_login($1)`, state).Scan(&payload); err == nil {
					t.Fatal("cleanup revived consumed state")
				}
				invoke(owner, false, []string{"up-authorization-audit-profile"}, nil)
				t.Log("fresh and exact binary install, atomic rollback, both purpose commands, API/partial-key refusal, bounded owned maintenance; canonical number remains61")
			})
		})
	}
}
