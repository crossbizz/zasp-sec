package apiserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// These consumers must not turn an admission checked before a lock wait into
// effects or a successful replay after its proof, attempt or credential expires.
func exerciseIdentityExpiryAfterWait(t *testing.T, ctx context.Context, owner, api *pgx.Conn, provider *RepositoryIdentityProvider, repo *PostgresRepository, start func() string, key *authorization.IdentitySessionKey) {
	t.Helper()
	const org = "pid_98000001-0000-4000-8000-000000000001"
	const principal = "pid_98000001-0000-4000-8000-000000000004"
	const workspace = "pid_98000001-0000-4000-8000-000000000002"
	const environment = "pid_98000001-0000-4000-8000-000000000003"
	snapshot := func() string {
		t.Helper()
		var result string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(r) FROM zasp_authorization79.organizations r WHERE organization_id=$1),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY principal_id,group_reference) FROM zasp_identity_member_groups r WHERE organization_id=$1),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY session_id) FROM zasp_product_sessions r WHERE organization_id=$1),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM zasp_product_api_tokens r WHERE organization_id=$1),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM zasp_admin_audit r WHERE organization_id=$1),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY attempt_id) FROM zasp_authorization80_identity.attempts r),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY state_digest) FROM zasp_identity_states r)
 )::text`, org).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	blockedUntilExpired := func(t *testing.T, expires time.Time, lock string, lockArgs []any, query string, args ...any) {
		t.Helper()
		before := snapshot()
		holder, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Rollback(context.Background())
		if _, err := holder.Exec(ctx, lock, lockArgs...); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { var body []byte; done <- api.QueryRow(ctx, query, args...).Scan(&body) }()
		deadline := time.NewTimer(4 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		locked := false
		for !locked {
			select {
			case err := <-done:
				t.Fatalf("consumer never reached held lock: %v", err)
			case <-ticker.C:
				if err := holder.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, api.PgConn().PID()).Scan(&locked); err != nil {
					t.Fatal(err)
				}
			case <-deadline.C:
				t.Fatal("consumer did not wait at held identity boundary")
			}
		}
		var beforeExpiry bool
		if err := holder.QueryRow(ctx, `SELECT clock_timestamp()<$1`, expires).Scan(&beforeExpiry); err != nil || !beforeExpiry {
			t.Fatalf("held phase not observed before expiry: %v %v", beforeExpiry, err)
		}
		t.Log("observed native consumer blocked on unchanged held row before expiry")
		if _, err := holder.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM($1::timestamptz-clock_timestamp())))+0.05)`, expires); err != nil {
			t.Fatal(err)
		}
		if err := holder.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		requireIdentityRefusal(t, <-done)
		if after := snapshot(); before != after {
			t.Error("expired blocked consumer committed identity effects")
		}
	}
	grant, err := provider.Complete(ctx, "one", start())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateSession(ctx, grant); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"fresh-external", "replay-proof", "fresh-attempt", "verifier-proof", "verifier-external"} {
		t.Run(kind, func(t *testing.T) {
			prepared := freshIdentityPrepared(t, ctx, provider, start)
			expires := time.Now().Add(2 * time.Second).UTC().Truncate(time.Millisecond)
			envelope := identityFixtureEnvelope(t, prepared.envelope, key.Verifier(), func(b map[string]any) {
				if kind == "fresh-external" || kind == "verifier-external" {
					b["external_expires_at"] = expires.UnixMilli()
					b["groups"] = []string{"scim-group-test-afterwait"}
				}
				if kind == "replay-proof" || kind == "verifier-proof" {
					b["expires_at"] = expires.UnixMilli()
				}
			}, false)
			lock := `SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`
			lockArgs := []any{org}
			if kind == "replay-proof" {
				var body []byte
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, envelope).Scan(&body); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "fresh-attempt" {
				if _, err := owner.Exec(ctx, `UPDATE zasp_authorization80_identity.attempts SET expires_at=$1 WHERE attempt_id=(convert_from(decode(($2::jsonb)->>'body','base64'),'UTF8')::jsonb)->>'attempt_id'`, expires, envelope); err != nil {
					t.Fatal(err)
				}
				lock = `SELECT 1 FROM zasp_identity_memberships WHERE organization_id=$1 FOR UPDATE`
			}
			if kind == "verifier-proof" || kind == "verifier-external" {
				lock = `SELECT 1 FROM zasp_authorization80_identity.verifiers WHERE purpose='session' FOR UPDATE`
				lockArgs = nil
			}
			blockedUntilExpired(t, expires, lock, lockArgs, `SELECT zasp_authorization80_identity.resolve_login($1)`, envelope)
		})
	}
	t.Run("consume-state", func(t *testing.T) {
		state := start()
		expires := time.Now().Add(2 * time.Second).UTC().Truncate(time.Millisecond)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_states SET expires_at=$1 WHERE state_digest=digest($2,'sha256')`, expires, state); err != nil {
			t.Fatal(err)
		}
		blockedUntilExpired(t, expires, `SELECT 1 FROM zasp_identity_states WHERE state_digest=digest($1,'sha256') FOR UPDATE`, []any{state}, `SELECT zasp_authorization80_identity.consume_login($1)`, state)
	})
	t.Run("issue-attempt", func(t *testing.T) {
		g, err := provider.Complete(ctx, "one", start())
		if err != nil {
			t.Fatal(err)
		}
		p := g.nativeAdmission
		expires := time.Now().Add(2 * time.Second).UTC().Truncate(time.Millisecond)
		if _, err := owner.Exec(ctx, `UPDATE zasp_authorization80_identity.attempts SET expires_at=$1 WHERE attempt_id=(convert_from(decode(($2::jsonb)->>'body','base64'),'UTF8')::jsonb)->>'attempt_id'`, expires, string(p.envelope)); err != nil {
			t.Fatal(err)
		}
		blockedUntilExpired(t, expires, `SELECT 1 FROM zasp_identity_memberships WHERE organization_id=$1 FOR UPDATE`, []any{org}, `SELECT zasp_authorization80_identity.issue_login($1,$2,$3)`, string(p.envelope), p.token, p.csrf)
	})
	for n, kind := range []string{"PAT", "logout", "switch"} {
		t.Run(kind, func(t *testing.T) {
			raw := fmt.Sprintf("identity-expiry-wait-%s-012345678901234567890123456789", kind)
			csrf := "identity-expiry-csrf-012345678901234567890123456789"
			expires := time.Now().Add(2 * time.Second).UTC().Truncate(time.Millisecond)
			var lock, query string
			var args []any
			if kind == "PAT" {
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest($1,'sha256'),$2,'Expiry wait',$3,$4,$5,$6,'["view"]',$7)`, raw, fmt.Sprintf("pid_98000001-0000-4000-8000-%012d", 200+n), principal, org, workspace, environment, expires); err != nil {
					t.Fatal(err)
				}
				lock = `SELECT 1 FROM zasp_product_api_tokens WHERE token_digest=digest($1,'sha256') FOR UPDATE`
				query = `SELECT zasp_authorization80_identity.authenticate_pat($1)`
				args = []any{raw}
			} else {
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at) VALUES(digest($1,'sha256'),$2,$3,$4,$5,'[]',$6,$7)`, raw, principal, org, workspace, environment, csrf, expires); err != nil {
					t.Fatal(err)
				}
				lock = `SELECT 1 FROM zasp_product_sessions WHERE token_digest=digest($1,'sha256') FOR UPDATE`
				query = `SELECT zasp_authorization80_identity.logout($1,$2,$3,$4)`
				args = []any{raw, csrf, org, principal}
				if kind == "switch" {
					query = `SELECT zasp_authorization80_identity.switch_scope($1,$2,$3,$4,$5,$6)`
					args = append(args, workspace, environment)
				}
			}
			blockedUntilExpired(t, expires, lock, []any{raw}, query, args...)
		})
	}
}
