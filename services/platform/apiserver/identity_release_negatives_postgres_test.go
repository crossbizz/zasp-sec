package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func freshIdentityPrepared(t *testing.T, ctx context.Context, provider *RepositoryIdentityProvider, start func() string) *preparedIdentitySession {
	t.Helper()
	a, err := provider.identityIssuer.repository.consumeIdentityAttempt(ctx, start())
	if err != nil {
		t.Fatal(err)
	}
	e, err := provider.authenticator.Authenticate(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider.identityIssuer.prepare(ctx, e, a)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func requireIdentityRefusal(t *testing.T, err error) {
	t.Helper()
	var p *pgconn.PgError
	if !errors.As(err, &p) || p.Code != "42501" {
		t.Errorf("expected native42501, got %v", err)
	}
}

func rawIdentityFixtureEnvelope(t *testing.T, source []byte, key []byte, change func([]byte) []byte) string {
	t.Helper()
	var outer struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}
	if err := json.Unmarshal(source, &outer); err != nil {
		t.Fatal(err)
	}
	outer.Body = change(outer.Body)
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte("zasp-identity-session-attestation-v1\x00"))
	_, _ = m.Write(outer.Body)
	outer.MAC = hex.EncodeToString(m.Sum(nil))
	b, _ := json.Marshal(outer)
	return string(b)
}

func exerciseIdentityReleaseNegatives(t *testing.T, ctx context.Context, owner, api *pgx.Conn, provider *RepositoryIdentityProvider, repo *PostgresRepository, start func() string, sk *authorization.IdentitySessionKey) {
	t.Helper()
	t.Run("fresh-consumed-parser-refusal", func(t *testing.T) {
		for _, c := range []struct {
			name   string
			change func([]byte) []byte
		}{
			{"invalid-UTF8", func([]byte) []byte { return []byte{'{', '"', 'x', '"', ':', '"', 255, '"', '}'} }},
			{"body-over64KiB", func([]byte) []byte { return []byte(`{"x":"` + strings.Repeat("x", 65536) + `"}`) }},
			{"deep-json", func([]byte) []byte {
				return []byte(`{"x":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`)
			}},
			{"duplicate-key", func(b []byte) []byte { return append([]byte(`{"epoch":1,`), b[1:]...) }},
			{"unknown-field", func(b []byte) []byte { return append([]byte(`{"permission":"manage_identity",`), b[1:]...) }},
			{"numeric-string", func(b []byte) []byte {
				var x map[string]any
				_ = json.Unmarshal(b, &x)
				x["epoch"] = "1"
				v, _ := json.Marshal(x)
				return v
			}},
			{"missing-field", func(b []byte) []byte {
				var x map[string]any
				_ = json.Unmarshal(b, &x)
				delete(x, "token_digest")
				v, _ := json.Marshal(x)
				return v
			}},
		} {
			t.Run(c.name, func(t *testing.T) {
				p := freshIdentityPrepared(t, ctx, provider, start)
				var body []byte
				err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, rawIdentityFixtureEnvelope(t, p.envelope, sk.Verifier(), c.change)).Scan(&body)
				requireIdentityRefusal(t, err)
				// No resolved proof digest exists yet. Rejection cannot be masked by
				// replay mismatch, and the unchanged valid envelope remains usable.
				var untouched bool
				if err := owner.QueryRow(ctx, `SELECT phase='consumed' AND proof_digest IS NULL AND snapshot IS NULL FROM zasp_authorization80_identity.attempts WHERE attempt_id=(convert_from(decode(($1::jsonb)->>'body','base64'),'UTF8')::jsonb)->>'attempt_id'`, string(p.envelope)).Scan(&untouched); err != nil || !untouched {
					t.Fatalf("consumed attempt changed=%v error=%v", !untouched, err)
				}
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, string(p.envelope)).Scan(&body); err != nil {
					t.Fatalf("valid fresh proof failed: %v", err)
				}
			})
		}
	})
	t.Run("raw-token-and-CSRF-digest-binding", func(t *testing.T) {
		g, err := provider.Complete(ctx, "one", start())
		if err != nil {
			t.Fatal(err)
		}
		p := g.nativeAdmission
		for _, args := range [][]any{{string(p.envelope), p.token + "x", p.csrf}, {string(p.envelope), p.token, p.csrf + "x"}} {
			var b []byte
			requireIdentityRefusal(t, api.QueryRow(ctx, `SELECT zasp_authorization80_identity.issue_login($1,$2,$3)`, args...).Scan(&b))
		}
		token, err := repo.CreateSession(ctx, g)
		if err != nil {
			t.Fatal(err)
		}
		i, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token})
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*RequestIdentity){func(v *RequestIdentity) { v.CSRFToken = "" }, func(v *RequestIdentity) {
			v.PrincipalID, _ = domain.ParseProductID("pid_98000002-0000-4000-8000-000000000004")
		}, func(v *RequestIdentity) { v.CredentialKind = CredentialBearerToken }} {
			bad := i
			change(&bad)
			if err := repo.Revoke(ctx, bad, token); err == nil {
				t.Error("foreign/missing-CSRF/PAT self logout accepted")
			}
		}
		if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token}); err != nil {
			t.Fatalf("denied logout changed credential: %v", err)
		}
	})
	t.Run("outer-envelope-and-unsigned-fields", func(t *testing.T) {
		for _, kind := range []string{"over96KiB", "parallel-token", "bad-MAC", "unknown-version"} {
			t.Run(kind, func(t *testing.T) {
				p := freshIdentityPrepared(t, ctx, provider, start)
				var outer map[string]any
				if err := json.Unmarshal(p.envelope, &outer); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "parallel-token":
					outer["token_digest"] = strings.Repeat("a", 64)
				case "bad-MAC":
					outer["mac"] = strings.Repeat("0", 64)
				case "unknown-version":
					outer["version"] = strings.Repeat("0", 64)
				}
				b, _ := json.Marshal(outer)
				envelope := string(b)
				if kind == "over96KiB" {
					envelope += strings.Repeat(" ", 98305)
				}
				var result []byte
				requireIdentityRefusal(t, api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, envelope).Scan(&result))
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, string(p.envelope)).Scan(&result); err != nil {
					t.Fatalf("valid original rejected: %v", err)
				}
			})
		}
	})
	t.Run("state-expiry-and-concurrent-consume", func(t *testing.T) {
		state := start()
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_states SET expires_at=clock_timestamp()-interval '1 second' WHERE state_digest=digest($1,'sha256')`, state); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.consumeIdentityAttempt(ctx, state); err == nil {
			t.Error("expired state consumed")
		}
		state = start()
		other := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "auth80_api")
		defer other.Close(context.Background())
		begin := make(chan struct{})
		results := make(chan error, 2)
		for _, conn := range []*pgx.Conn{api, other} {
			go func(c *pgx.Conn) {
				<-begin
				var b []byte
				results <- c.QueryRow(ctx, `SELECT zasp_authorization80_identity.consume_login($1)`, state).Scan(&b)
			}(conn)
		}
		close(begin)
		wins := 0
		for range 2 {
			err := <-results
			if err == nil {
				wins++
			} else {
				requireIdentityRefusal(t, err)
			}
		}
		if wins != 1 {
			t.Errorf("consume winners=%d", wins)
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization80_identity.attempts WHERE state_digest=digest($1,'sha256')`, state).Scan(&count); err != nil || count != 1 {
			t.Errorf("attempt count=%d error=%v", count, err)
		}
	})
	t.Run("private-record-and-worker-isolation", func(t *testing.T) {
		p := freshIdentityPrepared(t, ctx, provider, start)
		for _, role := range []string{"auth80_api", "auth80_discovery", "auth80_ingest", "auth80_runtime", "auth80_outbox", "auth80_gateway"} {
			t.Run(role, func(t *testing.T) {
				conn := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), role)
				defer conn.Close(context.Background())
				for _, q := range []string{`SELECT key FROM zasp_authorization80_identity.verifiers`, `INSERT INTO zasp_authorization80_identity.permits VALUES(pg_backend_pid(),pg_current_xact_id(),session_user,'{"purpose":"issue"}')`, `INSERT INTO zasp_authorization80_identity.attempts(state_digest,attempt_id,return_path,consumed_at,expires_at,phase) VALUES(digest('forged','sha256'),repeat('a',64),'/',clock_timestamp(),clock_timestamp()+interval '1 minute','consumed')`, `SELECT zasp_authorization80_identity.set_permit('{"purpose":"issue"}')`, `SELECT zasp_authorization80_identity.register_session(repeat('a',64),decode(repeat('b',64),'hex'),repeat('c',64),'project-test-identity80','auth80_api','')`, `SET ROLE zasp_discovery_authority`} {
					_, err := conn.Exec(ctx, q)
					requireIdentityRefusal(t, err)
				}
				if role != "auth80_api" {
					var b []byte
					requireIdentityRefusal(t, conn.QueryRow(ctx, `SELECT zasp_authorization80_identity.resolve_login($1)`, string(p.envelope)).Scan(&b))
					_, err := conn.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE false`)
					requireIdentityRefusal(t, err)
				}
			})
		}
	})
	t.Run("allow-valued-catalog-gate-refused", func(t *testing.T) {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `CREATE OR REPLACE FUNCTION zasp_authorization80_identity.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT true $$`); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_identity.structural_ready($1)`, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || ready {
			t.Errorf("allow-valued gate accepted=%v error=%v", ready, err)
		}
	})
}
