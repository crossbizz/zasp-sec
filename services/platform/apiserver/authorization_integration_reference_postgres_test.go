package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestP7IntegrationReferenceCanonicalConnectionPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	f.freshReferenceSession(t)
	id, _ := f.createReference(t, "aws", "reference-canonical-create")
	i := f.browser
	g, err := f.authorizer.Authorize(f.ctx, i, i.credentialBinding, RoutedOperation{OperationID: "authorizeIntegrationReference", PathParameters: map[string]string{"id": id}})
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := authorizationProofJSON(g)
	args := f.referenceNativeArgs(id, "reference-canonical-complete", 1)
	args[6] = "pid_78200299-0000-4000-8000-000000000099"
	before := f.referenceEffects(t)
	tx, err := f.api.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof))
	var raw []byte
	if err == nil {
		err = tx.QueryRow(f.ctx, postgresCurrentReferenceCompleteSQL, args...).Scan(&raw)
	}
	_ = tx.Rollback(f.ctx)
	var native *pgconn.PgError
	if !errors.As(err, &native) || native.Code != "22023" {
		t.Errorf("noncanonical unused valid connection accepted: %v", err)
	}
	if f.referenceEffects(t) != before {
		t.Fatal("noncanonical completion left partial effects")
	}
	r := f.invokeReference(t, i, id, "reference-canonical-positive", 1)
	if r.Code != 200 {
		t.Fatalf("canonical completion=%d %s", r.Code, r.Body)
	}
	var canonical string
	if err := f.owner.QueryRow(f.ctx, `SELECT id FROM zasp_integration_connections WHERE integration_id=$1`, id).Scan(&canonical); err != nil || canonical != referenceConnectionID(i.Scope, id, "aws") {
		t.Fatalf("canonical identity=%s %v", canonical, err)
	}
}

func (f *integrationClientFixture) referenceRouter(t *testing.T) http.Handler {
	t.Helper()
	handler, err := NewReferenceAuthorizationHTTPHandler(ReferenceAuthorizationHTTPConfig{Repository: &ReferenceAuthorizationRepository{database: f.repo.database}, Workflows: f.repo, Registry: f.references})
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := authorization.LookupOperation("authorizeIntegrationReference")
	router, err := NewRouter([]Operation{{Method: policy.Method, Pattern: policy.Path, OperationID: "authorizeIntegrationReference", Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, RequireFreshAuth: true, Handler: handler}})
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = f.authorizer
	if f.referenceAuthorizer != nil {
		router.(*operationRouter).authorizer = f.referenceAuthorizer
	}
	return router
}

type referenceHookProbe struct {
	delegate *ReferenceConnectorRegistry
	hook     func()
}

func (p referenceHookProbe) ProbeReferenceAuthorization(ctx context.Context, target ReferenceAuthorizationTarget) (ReferenceAuthorizationSubject, error) {
	subject, err := p.delegate.Probe(ctx, target)
	if err == nil && p.hook != nil {
		p.hook()
	}
	return subject, err
}

func TestP7IntegrationReferenceSecurityPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	f.freshReferenceSession(t)
	id, _ := f.createReference(t, "aws", "reference-security-create")
	t.Run("http_refusals_before_provider", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			identity RequestIdentity
			alter    func(*http.Request)
			want     int
		}{
			{"pat", f.pat, nil, 401},
			{"csrf", f.browser, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "incorrect") }, 403},
			{"scope_header", f.browser, func(r *http.Request) { r.Header.Set(expectedScopeHeader, "other") }, 409},
			{"fresh_header", f.browser, func(r *http.Request) { r.Header.Del("X-Zasp-Fresh-Auth") }, 400},
			{"nonempty_body", f.browser, func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"provider":"aws"}`)) }, 400},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before, calls := f.referenceEffects(t), f.providerCalls.Load()
				var opts []func(*http.Request)
				if tc.alter != nil {
					opts = append(opts, tc.alter)
				}
				r := f.invokeReference(t, tc.identity, id, "reference-denied-"+tc.name, 1, opts...)
				if r.Code != tc.want || f.providerCalls.Load() != calls || f.referenceEffects(t) != before {
					t.Fatalf("refusal=%d want=%d %s", r.Code, tc.want, r.Body)
				}
			})
		}
	})
	t.Run("provider_return_cannot_extend_authority", func(t *testing.T) {
		for _, name := range []string{"revoked", "scope", "fresh_age", "membership", "typed_version", "verifier_key", "current_source"} {
			t.Run(name, func(t *testing.T) {
				original := f.references
				t.Cleanup(func() { f.references = original; f.reconcile() })
				var after string
				hook := func() {
					switch name {
					case "verifier_key":
						old := authorizationFixtureAttestor(t)
						t.Cleanup(func() { f.exec(`SELECT zasp_authorization80.register_verifier($1,$2)`, old.Version(), old.Verifier()) })
						next, err := authorization.NewAttestationKey(bytes.Repeat([]byte{0x37}, 32))
						if err != nil {
							t.Fatal(err)
						}
						f.exec(`SELECT zasp_authorization80.register_verifier($1,$2)`, next.Version(), next.Verifier())
					case "current_source":
						var checksum string
						if err := f.owner.QueryRow(f.ctx, `SELECT checksum FROM zasp_authorization80.registration`).Scan(&checksum); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { f.exec(`UPDATE zasp_authorization80.registration SET checksum=$1`, checksum) })
						f.exec(`UPDATE zasp_authorization80.registration SET checksum=repeat('0',64)`)
					case "revoked":
						t.Cleanup(func() { f.exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-client80'`) })
						f.exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-client80'`)
					case "scope":
						t.Cleanup(func() {
							f.exec(`UPDATE zasp_product_sessions SET environment_id=$1 WHERE session_id='session-client80'`, f.browser.Scope.EnvironmentID().String())
						})
						f.exec(`UPDATE zasp_product_sessions SET environment_id='pid_78200073-0000-4000-8000-000000000073' WHERE session_id='session-client80'`)
					case "fresh_age":
						t.Cleanup(func() {
							f.exec(`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp() WHERE session_id='session-client80'`)
						})
						f.exec(`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE session_id='session-client80'`)
					case "membership":
						t.Cleanup(func() {
							f.exec(`UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, f.browser.PrincipalID.String())
							f.reconcile()
						})
						f.exec(`UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, f.browser.PrincipalID.String())
					case "typed_version":
						t.Cleanup(func() { f.reconcile() })
						var raw []byte
						err := f.owner.QueryRow(f.ctx, `SELECT zasp_discovery_transition_integration($1,$2,$3,$4,1,'authorizing')`, f.browser.Scope.OrganizationID().String(), f.browser.Scope.WorkspaceID().String(), f.browser.Scope.EnvironmentID().String(), id).Scan(&raw)
						if err != nil {
							t.Fatal(err)
						}
					}
					after = f.referenceEffects(t)
				}
				var err error
				f.references, err = NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": referenceHookProbe{original, hook}}, map[string]ConnectorCapabilityCheck{"aws": func(context.Context) error { return nil }})
				if err != nil {
					t.Fatal(err)
				}
				r := f.invokeReference(t, f.browser, id, "reference-changed-"+name, 1)
				want := 409
				if name == "verifier_key" || name == "current_source" {
					want = 503
				}
				if r.Code != want || after == "" || f.referenceEffects(t) != after {
					t.Fatalf("postprovider %s=%d %s after_present=%t", name, r.Code, r.Body, after != "")
				}
			})
		}
	})
	t.Run("native_wrong_purpose_actor_scope_and_isolation", func(t *testing.T) {
		i := f.browser
		o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
		for _, operation := range []string{"getIntegration", "updateIntegration", "authorizeIntegrationReference"} {
			g, err := f.authorizer.Authorize(f.ctx, i, i.credentialBinding, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": id}})
			if err != nil {
				t.Fatal(err)
			}
			proof, _ := authorizationProofJSON(g)
			for _, q := range []string{postgresCurrentReferenceValueSQL, postgresCurrentReferenceReplaySQL, postgresCurrentReferenceCompleteSQL} {
				for _, variant := range []string{"purpose", "actor", "scope", "repeatable"} {
					if operation != "authorizeIntegrationReference" && variant != "purpose" || operation == "authorizeIntegrationReference" && variant == "purpose" {
						continue
					}
					before := f.referenceEffects(t)
					args := []any{o, w, e, id}
					if q == postgresCurrentReferenceReplaySQL {
						args = []any{o, w, e, i.PrincipalID.String(), id, "reference-native-replay", int64(1)}
					}
					if q == postgresCurrentReferenceCompleteSQL {
						args = f.referenceNativeArgs(id, "reference-native-complete", 1)
					}
					if variant == "scope" {
						args[1] = o
					}
					if variant == "actor" {
						if q == postgresCurrentReferenceValueSQL {
							continue
						}
						args[3] = id
					}
					options := pgx.TxOptions{}
					if variant == "repeatable" {
						options.IsoLevel = pgx.RepeatableRead
					}
					tx, err := f.api.BeginTx(f.ctx, options)
					if err != nil {
						t.Fatal(err)
					}
					_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof))
					var raw []byte
					if err == nil {
						err = tx.QueryRow(f.ctx, q, args...).Scan(&raw)
					}
					_ = tx.Rollback(f.ctx)
					var native *pgconn.PgError
					if !errors.As(err, &native) || native.Code != "42501" && native.Code != "55000" || f.referenceEffects(t) != before {
						t.Fatalf("%s %s %s: %v", operation, q, variant, err)
					}
				}
			}
		}
	})
}

func (f *integrationClientFixture) referenceNativeArgs(id, key string, version int64) []any {
	i := f.browser
	config := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	return []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), id, "aws", referenceConnectionID(i.Scope, id, "aws"), "ref:aws/external-id/customer-0001", key, version, config, referenceAuthorizationIntent(i, id, "aws", key, version, config), "pid_78200071-0000-4000-8000-000000000071", integrationClientCorrelation(key), "pid_78200072-0000-4000-8000-000000000072", "aws_account", "123456789012"}
}

type shortReferenceAuthorizer struct {
	real *OpenFGAAuthorizer
	t    *testing.T
}

func (a shortReferenceAuthorizer) Authorize(ctx context.Context, i RequestIdentity, c CredentialBinding, r RoutedOperation) (RequestAuthorization, error) {
	g, err := a.real.Authorize(ctx, i, c, r)
	if err != nil {
		return g, err
	}
	return attestAuthorization(g, authorizationFixtureAttestor(a.t), time.Now().Add(-58*time.Second))
}

func TestP7IntegrationReferenceAtomicityPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	f.freshReferenceSession(t)
	id, _ := f.createReference(t, "aws", "reference-atomic-create")
	for _, mode := range []string{"error-after-mutation", "panic-after-mutation", "before-commit", "lost-response"} {
		t.Run(mode, func(t *testing.T) {
			before := f.referenceEffects(t)
			calls := f.providerCalls.Load()
			key := "reference-fault-" + mode
			t.Cleanup(func() { f.driver.mode = "" })
			f.driver.mode = mode
			panicked := false
			var r *httptest.ResponseRecorder
			func() {
				defer func() { panicked = recover() != nil }()
				r = f.invokeReference(t, f.browser, id, key, 1)
			}()
			f.driver.mode = ""
			if mode == "panic-after-mutation" {
				if !panicked {
					t.Fatal("expected postwrite panic")
				}
			} else if r == nil || r.Code != 503 {
				t.Fatalf("fault result=%v", r)
			}
			if mode != "lost-response" {
				if f.referenceEffects(t) != before {
					t.Fatal("fault persisted partial rows/revision")
				}
				return
			}
			f.reconcile()
			after := f.referenceEffects(t)
			retry := f.invokeReference(t, f.browser, id, key, 1)
			if retry.Code != 200 || f.referenceEffects(t) != after || f.providerCalls.Load() != calls+1 {
				t.Fatalf("lost response replay=%d %s calls=%d", retry.Code, retry.Body, f.providerCalls.Load()-calls)
			}
		})
	}
	t.Run("actual_subject_bind_conflict_rolls_back_prior_workflow_and_connection_writes", func(t *testing.T) {
		id, _ := f.createReference(t, "aws", "reference-bind-fault-create")
		i := f.browser
		o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
		connection := referenceConnectionID(i.Scope, id, "aws")
		var raw []byte
		if err := f.api.QueryRow(f.ctx, `SELECT zasp_discovery_put_connection($1,$2,$3,$4,$5,'aws','ref:aws/external-id/customer-0001')`, o, w, e, connection, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		// A valid-shaped but newer retained subject forces the real binding function
		// to fail after its workflow, receipt, typed and connection writes.
		f.exec(`INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source) SELECT organization_id,workspace_id,environment_id,id,$2,'aws','aws_account','123456789012',99,digest(convert_to(configuration::text,'UTF8'),'sha256'),'reference' FROM zasp_integrations WHERE id=$1`, id, connection)
		f.reconcile()
		before := f.referenceEffects(t)
		r := f.invokeReference(t, i, id, "reference-bind-native-conflict", 1)
		if r.Code != 409 || f.referenceEffects(t) != before {
			t.Fatalf("subject native conflict=%d %s", r.Code, r.Body)
		}
	})
	t.Run("provider_wait_expires_original_proof", func(t *testing.T) {
		id, _ := f.createReference(t, "aws", "reference-provider-expiry")
		original := f.references
		t.Cleanup(func() { f.references = original; f.referenceAuthorizer = nil })
		f.referenceAuthorizer = shortReferenceAuthorizer{f.authorizer, t}
		f.references, _ = NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": referenceHookProbe{original, func() { time.Sleep(2100 * time.Millisecond) }}}, map[string]ConnectorCapabilityCheck{"aws": func(context.Context) error { return nil }})
		before, calls := f.referenceEffects(t), f.providerCalls.Load()
		r := f.invokeReference(t, f.browser, id, "reference-provider-expired-proof", 1)
		if r.Code != 503 || f.providerCalls.Load() != calls+1 || f.referenceEffects(t) != before {
			t.Fatalf("expired original proof=%d %s", r.Code, r.Body)
		}
	})
	t.Run("audit_lock_wait_expires_credential_and_rolls_back", func(t *testing.T) {
		id, _ := f.createReference(t, "aws", "reference-native-wait-expiry")
		t.Cleanup(func() {
			f.exec(`UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE session_id='session-client80'`)
		})
		f.exec(`UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '7 seconds' WHERE session_id='session-client80'`)
		before := f.referenceEffects(t)
		blocker, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(context.Background())
		if _, err := blocker.Exec(f.ctx, `LOCK TABLE zasp_workflow_audit IN SHARE MODE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- f.invokeReference(t, f.browser, id, "reference-audit-wait-expiry", 1) }()
		waitIntegrationClientLock(t, f, blocker, int(f.api.PgConn().PID()))
		for {
			var expired bool
			if err := blocker.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM zasp_product_sessions WHERE session_id='session-client80'`).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if expired {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		_ = blocker.Rollback(f.ctx)
		select {
		case r := <-done:
			if r.Code != 409 {
				t.Fatalf("expired credential=%d %s", r.Code, r.Body)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("reference request did not join")
		}
		if f.referenceEffects(t) != before {
			t.Fatal("reference audit wait left partial effects")
		}
	})
}

func TestP7IntegrationReferenceConcurrentPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	f.freshReferenceSession(t)
	id, _ := f.createReference(t, "aws", "reference-concurrent-create")
	second := connectRuntimeDataPlanePrincipal(t, f.ctx, f.dsn, "auth80_api")
	defer second.Close(context.Background())
	g, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "authorizeIntegrationReference", PathParameters: map[string]string{"id": id}})
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := authorizationProofJSON(g)
	const key = "reference-same-key-racing"
	args := f.referenceNativeArgs(id, key, 1)
	type outcome struct {
		raw []byte
		err error
	}
	done := make(chan outcome, 2)
	start := make(chan struct{})
	for _, conn := range []*pgx.Conn{f.api, second} {
		go func(c *pgx.Conn) {
			<-start
			tx, err := c.Begin(f.ctx)
			if err != nil {
				done <- outcome{err: err}
				return
			}
			defer tx.Rollback(context.Background())
			_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof))
			var raw []byte
			if err == nil {
				err = tx.QueryRow(f.ctx, postgresCurrentReferenceCompleteSQL, args...).Scan(&raw)
			}
			if err == nil {
				err = tx.Commit(f.ctx)
			}
			done <- outcome{raw, err}
		}(conn)
	}
	close(start)
	success, conflict := 0, 0
	for range 2 {
		r := <-done
		if r.err == nil {
			success++
		} else {
			var p *pgconn.PgError
			if errors.As(r.err, &p) && (p.Code == "40001" || p.Code == "40P01") {
				conflict++
			} else {
				t.Fatal(r.err)
			}
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("committed=%d conflicted=%d", success, conflict)
	}
	f.reconcile()
	before, calls := f.referenceEffects(t), f.providerCalls.Load()
	retry := f.invokeReference(t, f.browser, id, key, 1)
	if retry.Code != 200 || retry.Header().Get("ETag") != `"2"` || f.referenceEffects(t) != before || f.providerCalls.Load() != calls {
		t.Fatalf("fresh request replay=%d %s", retry.Code, retry.Body)
	}
	var callable bool
	if err := f.api.QueryRow(f.ctx, `SELECT has_function_privilege(current_user,'zasp_authorization80.integration_reference_native_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','EXECUTE') OR has_function_privilege(current_user,'zasp_authorization80.integration_reference_execution_complete(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text)','EXECUTE')`).Scan(&callable); err != nil || callable {
		t.Fatalf("private dependency callable=%t %v", callable, err)
	}
	var raw []byte
	err = f.api.QueryRow(f.ctx, postgresCurrentReferenceReplaySQL, args[0], args[1], args[2], args[3], id, key, int64(1)).Scan(&raw)
	var native *pgconn.PgError
	if !errors.As(err, &native) || native.Code != "42501" {
		t.Fatalf("proofless reference=%v", err)
	}
}

func (f *integrationClientFixture) invokeReference(t *testing.T, identity RequestIdentity, id, key string, version int64, alter ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/integrations/"+id+"/reference/authorize", strings.NewReader(`{}`))
	policy, _ := authorization.LookupOperation("authorizeIntegrationReference")
	r.URL.Path = strings.ReplaceAll(policy.Path, "{id}", id)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("If-Match", fmt.Sprintf(`"%d"`, version))
	r.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
	r.Header.Set("Origin", "https://console.example")
	r.Header.Set("X-CSRF-Token", identity.CSRFToken)
	r.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "client80-session"})
	ctx := context.WithValue(f.ctx, identityContextKey{}, identity)
	ctx = context.WithValue(ctx, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
	ctx = context.WithValue(ctx, correlationContextKey{}, integrationClientCorrelation(key))
	for _, change := range alter {
		change(r)
	}
	result := httptest.NewRecorder()
	f.referenceRouter(t).ServeHTTP(result, r.WithContext(ctx))
	return result
}

// A missing checked replay/preparation/completion route must fail this mounted
// success assertion, even when a private native clone would work as its owner.
func TestP7IntegrationReferencePostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	f.freshReferenceSession(t)
	for _, provider := range []string{"aws", "kubernetes"} {
		t.Run(provider, func(t *testing.T) {
			id, body := f.createReference(t, provider, "reference-create-"+provider)
			beforeRevision := f.referenceRevision(t)
			key := "reference-complete-" + provider
			completed := f.invokeReference(t, f.browser, id, key, 1)
			if completed.Code != 200 {
				t.Fatalf("mounted complete=%d %s", completed.Code, completed.Body)
			}
			f.assertReference(t, id, key, provider, 2, 2, 2, beforeRevision+2, completed)
			f.reconcile()
			before, calls := f.referenceEffects(t), f.providerCalls.Load()
			replay := f.invokeReference(t, f.browser, id, key, 1)
			if replay.Code != 200 || replay.Body.String() != completed.Body.String() || replay.Header().Get("X-Mutation-Receipt-ID") != completed.Header().Get("X-Mutation-Receipt-ID") || f.referenceEffects(t) != before || f.providerCalls.Load() != calls {
				t.Fatalf("replay=%d %s", replay.Code, replay.Body)
			}
			got := f.invoke(f.browser, "getIntegration", id, "", "", 0)
			if got.Code != 200 || got.Header().Get("ETag") != `"2"` {
				t.Fatalf("GET=%d %s", got.Code, got.Body)
			}
			updated := f.invoke(f.browser, "updateIntegration", id, "reference-update-"+provider, body, 2)
			if updated.Code != 200 || updated.Header().Get("ETag") != `"3"` {
				t.Fatalf("update=%d %s", updated.Code, updated.Body)
			}
			f.assertEffects(t, f.browser, "updateIntegration", "reference-update-"+provider, id, 3, updated)
			f.reconcile()
			before = f.referenceEffects(t)
			replay = f.invokeReference(t, f.browser, id, key, 1)
			if replay.Code != 200 || replay.Header().Get("ETag") != `"2"` || replay.Body.String() != completed.Body.String() || f.referenceEffects(t) != before || f.providerCalls.Load() != calls {
				t.Fatalf("historical replay=%d %s", replay.Code, replay.Body)
			}
		})
	}
	t.Run("legitimate_independent_typed_and_connection_versions", func(t *testing.T) {
		id, _ := f.createReference(t, "aws", "reference-divergent")
		i := f.browser
		o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
		connection := referenceConnectionID(i.Scope, id, "aws")
		var raw []byte
		for _, call := range []struct {
			q    string
			args []any
		}{
			{`SELECT zasp_discovery_put_connection($1,$2,$3,$4,$5,'aws','ref:aws/external-id/customer-0001')`, []any{o, w, e, connection, id}},
			{`SELECT zasp_discovery_transition_connection($1,$2,$3,$4,$5,1,'invalid')`, []any{o, w, e, connection, id}},
			{`SELECT zasp_discovery_transition_connection($1,$2,$3,$4,$5,2,'pending')`, []any{o, w, e, connection, id}},
			{`SELECT zasp_discovery_transition_integration($1,$2,$3,$4,1,'authorizing')`, []any{o, w, e, id}},
		} {
			if err := f.api.QueryRow(f.ctx, call.q, call.args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
		f.reconcile()
		revision := f.referenceRevision(t)
		r := f.invokeReference(t, i, id, "reference-divergent-complete", 1)
		if r.Code != 200 {
			t.Fatalf("W1 T2 C3 completion=%d %s", r.Code, r.Body)
		}
		f.assertReference(t, id, "reference-divergent-complete", "aws", 2, 3, 4, revision+3, r)
		f.reconcile()
		// This retained native consumer snapshots T and C independently. It
		// does not claim the still-unimplemented checked public sync route.
		digest := sha256.Sum256([]byte("reference independent native sync"))
		if err := f.api.QueryRow(f.ctx, `SELECT zasp_execution_public_request_sync($1,$2,$3,$4,$5,'reference-native-independent-sync',3,'pid_78200081-0000-4000-8000-000000000081','pid_78200082-0000-4000-8000-000000000082','pid_78200083-0000-4000-8000-000000000083',$6,'parser_v1','tool_v1','pid_78200084-0000-4000-8000-000000000084','pid_78200085-0000-4000-8000-000000000085','pid_78200086-0000-4000-8000-000000000086')`, o, w, e, i.PrincipalID.String(), id, digest[:]).Scan(&raw); err != nil {
			t.Fatal("retained native independent T/C sync", err)
		}
		var snapT, snapC int64
		if err := f.owner.QueryRow(f.ctx, `SELECT integration_version,connection_version FROM zasp_discovery_job_authorities WHERE job_id='pid_78200082-0000-4000-8000-000000000082'`).Scan(&snapT, &snapC); err != nil || snapT != 3 || snapC != 4 {
			t.Fatalf("native independent snapshots T/C=%d/%d %v", snapT, snapC, err)
		}
		// A degraded public body is the retained source13 upgrade shape. The
		// independently advanced T below comes from the actual source10 API.
		if err := f.api.QueryRow(f.ctx, `SELECT zasp_discovery_transition_integration($1,$2,$3,$4,3,'degraded')`, o, w, e, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		f.exec(`UPDATE zasp_workflow_records SET body=jsonb_set(body,'{status}','"degraded"'),version=version+1 WHERE id=$1`, id)
		f.reconcile()
		revision = f.referenceRevision(t)
		r = f.invokeReference(t, i, id, "reference-degraded-complete", 3)
		if r.Code != 200 {
			t.Fatalf("degraded W3 T4 C4 completion=%d %s", r.Code, r.Body)
		}
		f.assertReference(t, id, "reference-degraded-complete", "aws", 4, 5, 5, revision+4, r)
		f.reconcile()
	})
}

func (f *integrationClientFixture) freshReferenceSession(t *testing.T) {
	t.Helper()
	f.exec(`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp() WHERE session_id='session-client80'`)
	var err error
	f.browser, err = f.repo.Authenticate(f.ctx, Credential{Kind: CredentialBrowserSession, Value: "client80-session"})
	if err != nil || !f.browser.FreshAuthenticated {
		t.Fatalf("fresh session=%t %v", f.browser.FreshAuthenticated, err)
	}
}

func (f *integrationClientFixture) createReference(t *testing.T, provider, key string) (string, string) {
	t.Helper()
	config := `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`
	if provider == "kubernetes" {
		config = `{"connection_reference":"ref:kubernetes/connection/customer-0001"}`
	}
	body := fmt.Sprintf(`{"name":"Reference","connector_key":%q,"configuration":%s}`, provider, config)
	created := f.invoke(f.browser, "createIntegration", "", key, body, 0)
	if created.Code != 201 {
		t.Fatalf("create=%d %s", created.Code, created.Body)
	}
	var value struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &value)
	f.reconcile()
	return value.ID, body
}

func (f *integrationClientFixture) referenceRevision(t *testing.T) int64 {
	t.Helper()
	var v int64
	if err := f.owner.QueryRow(f.ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, f.browser.Scope.OrganizationID().String()).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
func (f *integrationClientFixture) referenceEffects(t *testing.T) string {
	t.Helper()
	var value string
	if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM zasp_integration_connections c),(SELECT jsonb_agg(to_jsonb(s) ORDER BY connection_id) FROM zasp_discovery_connection_subjects s))::text`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return f.effects(t) + value
}
func (f *integrationClientFixture) assertReference(t *testing.T, id, key, provider string, wantW, wantT, wantC, wantRevision int64, r *httptest.ResponseRecorder) {
	t.Helper()
	var good bool
	err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_workflow_records w JOIN zasp_integrations i ON(i.organization_id,i.workspace_id,i.environment_id,i.id)=(w.organization_id,w.workspace_id,w.environment_id,w.id)
 JOIN zasp_integration_connections c ON(c.organization_id,c.workspace_id,c.environment_id,c.integration_id)=(i.organization_id,i.workspace_id,i.environment_id,i.id)
 JOIN zasp_discovery_connection_subjects s ON(s.organization_id,s.workspace_id,s.environment_id,s.integration_id,s.connection_id)=(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.id)
 JOIN zasp_workflow_audit a ON(a.organization_id,a.resource_id,a.operation,a.resource_version)=(w.organization_id,w.id,'completeIntegrationReferenceAuthorization',w.version)
 JOIN zasp_workflow_idempotency k ON(k.organization_id,k.workspace_id,k.environment_id,k.principal_id,k.operation,k.idempotency_key)=(w.organization_id,w.workspace_id,w.environment_id,$8,'completeIntegrationReferenceAuthorization',$2)
 JOIN zasp_workflow_receipts q ON(q.organization_id,q.receipt_id,q.resource_version,q.audit_id,q.operation)=(w.organization_id,$10,$4,a.audit_id,'completeIntegrationReferenceAuthorization')
 WHERE w.id=$1 AND w.kind='integration' AND (w.version,i.version,c.version)=($4,$5,$6) AND w.body->>'status'='active' AND i.state='active' AND c.state='verified' AND s.source='reference'
 AND c.provider=$3 AND s.provider=$3 AND s.connection_version=$6 AND s.configuration_digest=digest(convert_to(i.configuration::text,'UTF8'),'sha256')
 AND s.subject_kind=CASE $3 WHEN 'aws' THEN 'aws_account' ELSE 'kubernetes_cluster' END AND s.subject_id=CASE $3 WHEN 'aws' THEN '123456789012' ELSE 'cluster.example.test/cluster-01' END
 AND a.audit_id=$9 AND a.correlation_id=$11 AND k.response->>'audit_id'=$9 AND k.response->>'receipt_id'=$10 AND k.response->'body'=w.body AND q.result=w.body AND q.intent->>'integration_id'=$1 AND (q.intent->>'expected_version')::bigint=$4-1
 AND EXISTS(SELECT 1 FROM zasp_authorization79.organizations x WHERE x.organization_id=w.organization_id AND x.desired=$7))`, id, key, provider, wantW, wantT, wantC, wantRevision, f.browser.PrincipalID.String(), r.Header().Get("X-Audit-ID"), r.Header().Get("X-Mutation-Receipt-ID"), integrationClientCorrelation(key)).Scan(&good)
	if err != nil || !good || r.Header().Get("ETag") != fmt.Sprintf(`"%d"`, wantW) {
		t.Fatalf("reference exact W/T/C=%d/%d/%d revision=%d all effects=%t %v body=%s", wantW, wantT, wantC, wantRevision, good, err, r.Body)
	}
	t.Logf("actual reference %s W/T/C=%d/%d/%d exact desired=%d", provider, wantW, wantT, wantC, wantRevision)
}
