package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type complianceFixFixture struct {
	t      *testing.T
	ctx    context.Context
	owner  *pgx.Conn
	dsn    string
	digest [32]byte
}

func withComplianceFixFixture(t *testing.T, fn func(*complianceFixFixture)) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		f := &complianceFixFixture{t: t, ctx: ctx, owner: owner, dsn: dsn, digest: sha256.Sum256([]byte("compliance-fix-session"))}
		f.exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'fix','fix','compliance_viewer');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'fix','["view","view_audit","view_compliance"]');
INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","view_audit","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp());
CREATE ROLE compliance_executor LOGIN INHERIT; CREATE ROLE compliance_cleanup LOGIN INHERIT;`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, f.digest[:])
		f.exec(`SELECT zasp_compliance_register_workers('compliance_executor','compliance_cleanup',$1,$2)`, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint())
		fn(f)
	})
}

func (f *complianceFixFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.owner.Exec(f.ctx, sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
		f.t.Fatal(err)
	}
}
func (f *complianceFixFixture) connect(user string) *pgx.Conn {
	f.t.Helper()
	cfg, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		f.t.Fatal(err)
	}
	cfg.User = user
	c, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}
func (f *complianceFixFixture) create(ctx context.Context, c *pgx.Conn, key string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.QueryRow(ctx, `SELECT zasp_compliance_export_create($1,$2,$3,$4,$5,$6,'{}',$7,$8)`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, f.digest[:], key, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
	return raw, err
}
func (f *complianceFixFixture) job(c *pgx.Conn, key string) string {
	f.t.Helper()
	raw, err := f.create(f.ctx, c, key)
	if err != nil {
		f.t.Fatal(err)
	}
	var v struct {
		ID string `json:"export_id"`
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.ID == "" {
		f.t.Fatalf("job: %s %v", raw, err)
	}
	return v.ID
}

// Observe a specific PostgreSQL blocker, then perform the competing change.
// The child query is bounded and joined on every path, including test failure.
func (f *complianceFixFixture) blocked(c *pgx.Conn, lockSQL string, lockArgs []any, call func(context.Context) (json.RawMessage, error), change func(context.Context)) (json.RawMessage, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	blocker, err := pgx.ConnectConfig(ctx, f.owner.Config().Copy())
	if err != nil {
		f.t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	tx, err := blocker.Begin(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	type result struct {
		raw json.RawMessage
		err error
	}
	done := make(chan result, 1)
	started, joined := false, false
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
		cancel()
		if started && !joined {
			select {
			case <-done:
			case <-cleanup.Done():
				f.t.Error("blocked query did not join")
			}
		}
	}()
	if _, err = tx.Exec(ctx, lockSQL, lockArgs...); err != nil {
		f.t.Fatal(err)
	}
	started = true
	go func() { raw, err := call(ctx); done <- result{raw, err} }()
	for {
		var waiting bool
		if err = f.owner.QueryRow(ctx, `SELECT $1::int=ANY(pg_blocking_pids($2::int))`, blocker.PgConn().PID(), c.PgConn().PID()).Scan(&waiting); err != nil {
			f.t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case r := <-done:
			joined = true
			f.t.Fatalf("query returned before observed lock: %s %v", r.raw, r.err)
		case <-ctx.Done():
			f.t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	change(ctx)
	if err = tx.Commit(ctx); err != nil {
		f.t.Fatal(err)
	}
	select {
	case r := <-done:
		joined = true
		return r.raw, r.err
	case <-ctx.Done():
		f.t.Fatal(ctx.Err())
	}
	return nil, ctx.Err()
}

func TestComplianceCreateFreshAfterWaitPostgres(t *testing.T) {
	withComplianceFixFixture(t, func(f *complianceFixFixture) {
		api := f.connect("security_agent_v33_discovery_api_login")
		f.exec(`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '15 minutes'+interval '2 seconds' WHERE token_digest=$1`, f.digest[:])
		raw, err := f.blocked(api, `SELECT 1 FROM zasp_compliance_export_policy FOR UPDATE`, nil, func(ctx context.Context) (json.RawMessage, error) { return f.create(ctx, api, "expired-during-lock") }, func(ctx context.Context) {
			if _, err := f.owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM authenticated_at+interval '15 minutes'-clock_timestamp()))+0.05) FROM zasp_product_sessions WHERE token_digest=$1`, f.digest[:]); err != nil {
				t.Fatal(err)
			}
		})
		if auditExportSQLState(err) != "28000" || len(raw) != 0 {
			t.Fatalf("stale fresh-auth admitted after policy wait: %s %v", raw, err)
		}
		var count int
		if err = f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_compliance_export_jobs`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("expired authentication left job: %d %v", count, err)
		}
	})
}

func TestComplianceGrantFreshAfterWaitPostgres(t *testing.T) {
	withComplianceFixFixture(t, func(f *complianceFixFixture) {
		api := f.connect("security_agent_v33_discovery_api_login")
		id := f.job(api, "grants")
		f.exec(`UPDATE zasp_compliance_export_jobs SET state='completed',phase='terminal',storage_state='verified',receipt_version='immutable-v1' WHERE export_id=$1`, id)
		for n, tc := range []struct {
			op        string
			grantLock bool
		}{{"issue", false}, {"read", false}, {"read", true}} {
			t.Run(fmt.Sprintf("%s_grant_lock_%v", tc.op, tc.grantLock), func(t *testing.T) {
				sub := *f
				sub.t = t
				f := &sub
				op := tc.op
				token := fmt.Sprintf("%064x", n+100)
				if op == "read" {
					f.exec(`INSERT INTO zasp_compliance_export_grants VALUES($1,$2,$3,$4,digest($5,'sha256'),$6,$7,'json',clock_timestamp()+interval '60 seconds',NULL,NULL)`, complianceOrg, complianceWorkspace, complianceEnvironment, id, token, compliancePrincipal, f.digest[:])
				}
				lockSQL, lockArgs := `SELECT 1 FROM zasp_compliance_export_jobs WHERE export_id=$1 FOR UPDATE`, []any{id}
				if tc.grantLock {
					lockSQL = `SELECT 1 FROM zasp_compliance_export_grants WHERE grant_digest=digest($1,'sha256') FOR UPDATE`
					lockArgs = []any{token}
				}
				raw, err := f.blocked(api, lockSQL, lockArgs, func(ctx context.Context) (json.RawMessage, error) {
					var raw json.RawMessage
					err := api.QueryRow(ctx, `SELECT zasp_compliance_export_grant($1,$2,$3,$4,$5,$6,$7,'json',$8,$9,$10)`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, f.digest[:], id, token, op, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
					return raw, err
				}, func(ctx context.Context) {
					if _, err := f.owner.Exec(ctx, `DELETE FROM zasp_authorized_scopes WHERE principal_id=$1`, compliancePrincipal); err != nil {
						t.Fatal(err)
					}
				})
				f.exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'restored','["view","view_audit","view_compliance"]')`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal)
				if auditExportSQLState(err) != "42501" || len(raw) != 0 {
					t.Errorf("revoked %s disclosed/mutated grant after job wait: %s %v", op, raw, err)
				}
				var count int
				if err = f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_compliance_export_grants WHERE grant_digest=digest($1,'sha256') AND ($2='issue' OR read_expires_at IS NOT NULL)`, token, op).Scan(&count); err != nil || count != 0 {
					t.Errorf("revoked %s persisted grant mutation: %d %v", op, count, err)
				}
			})
		}
	})
}

func TestComplianceWorkerReplayPostgres(t *testing.T) {
	withComplianceFixFixture(t, func(f *complianceFixFixture) {
		api := f.connect("security_agent_v33_discovery_api_login")
		id := f.job(api, "process-replay")
		child := func(mode string, extra ...string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/compliance-worker.test", "-test.run=^TestComplianceReplayRestartProcess$", "-test.v", "-test.timeout=13s")
			cmd.Env = append(os.Environ(), "ZASP_COMPLIANCE_WORKER_DSN="+f.dsn, "ZASP_COMPLIANCE_MODE="+mode, "ZASP_COMPLIANCE_ORG="+complianceOrg, "ZASP_COMPLIANCE_WORKSPACE="+complianceWorkspace, "ZASP_COMPLIANCE_ENV="+complianceEnvironment, "ZASP_COMPLIANCE_JOB="+id)
			cmd.Env = append(cmd.Env, extra...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("joined worker %s: %v %s", mode, err, output)
			}
			t.Logf("joined worker %s: %s", mode, output)
		}
		child("prepare")
		f.exec(`UPDATE zasp_compliance_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second',next_attempt_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
		worker := f.connect("compliance_executor")
		var raw json.RawMessage
		if err := worker.QueryRow(f.ctx, `SELECT zasp_compliance_export_claim($1,$2,$3,$4,'restart-worker',$5,'execute',$6,$7)`, complianceOrg, complianceWorkspace, complianceEnvironment, id, strings.Repeat("b", 64), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var lease struct {
			Generation int64 `json:"generation"`
			Attempt    int   `json:"attempt"`
		}
		if err := json.Unmarshal(raw, &lease); err != nil || lease.Generation != 2 || lease.Attempt != 2 {
			t.Fatalf("restart lease: %s %v", raw, err)
		}
		var expiry time.Time
		if err := f.owner.QueryRow(f.ctx, `UPDATE zasp_compliance_export_jobs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE export_id=$1 RETURNING lease_expires_at`, id).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		child("replay", "ZASP_COMPLIANCE_EXPIRY="+expiry.Format(time.RFC3339Nano), fmt.Sprintf("ZASP_COMPLIANCE_GENERATION=%d", lease.Generation), fmt.Sprintf("ZASP_COMPLIANCE_ATTEMPT=%d", lease.Attempt))
		var state, storage, version, body, revision string
		if err := f.owner.QueryRow(f.ctx, `SELECT state,storage_state,receipt_version,convert_from(package,'UTF8'),renderer_revision FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&state, &storage, &version, &body, &revision); err != nil || state != "completed" || storage != "verified" || version != "immutable-replay-v1" || body != "stored-v1-bytes-before-process-exit" || revision != "compliance-envelope-v1" {
			t.Fatalf("completed replay receipt: %s %s %s %q %s %v", state, storage, version, body, revision, err)
		}
	})
}
