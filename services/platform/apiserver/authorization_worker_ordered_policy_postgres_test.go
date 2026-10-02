package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Missing the native effect proof fence makes this fail after real admission,
// authenticated current80 approval and official OpenFGA authorization succeed.
func TestP7WorkerOrdered68PolicyBoundary(t *testing.T) {
	runOrdered68PolicyBoundary(t, false, false, false)
}

// Catalog capture is a distinct setup checkpoint, never approval/effect proof.
func TestP7Ordered62InstalledCatalog(t *testing.T) {
	runOrdered68PolicyBoundary(t, true, false, false)
}

func TestP7Ordered68InstalledWriterCatalog(t *testing.T) {
	runOrdered68PolicyBoundary(t, true, false, true)
}

func TestP7Ordered62CurrentApproval(t *testing.T) {
	runOrdered68PolicyBoundary(t, false, true, false)
}

type ordered69ApprovalConsumer func(*testing.T, context.Context, *pgx.Conn, json.RawMessage, string)

// ordered68CatalogCapture is an explicitly named, catalog-only observation
// seam for reviewed native packets. A nil callback preserves the historical
// installed-body capture path byte-for-byte.
type ordered68CatalogCapture func(*testing.T, context.Context, *pgx.Conn) bool

func ordered68RunCatalogCaptureBoundary(t *testing.T, ctx context.Context, owner *pgx.Conn, capture ordered68CatalogCapture) bool {
	t.Helper()
	if capture == nil {
		return false
	}
	return capture(t, ctx, owner)
}

func ordered68CatalogCaptureOptionsValid(catalogOnly, approvalOnly, writerCatalog bool, capture ordered68CatalogCapture, acceptance *ordered68PolicyAcceptance, lifecycle []ordered69LifecycleConsumer) bool {
	return capture == nil || !(catalogOnly || approvalOnly || writerCatalog || acceptance != nil || len(lifecycle) != 0)
}

// ordered68ConsumeCatalogCapture is the one post-install consumer used by the
// real fixture. A selected callback never falls through, including when it
// refuses; nil runs exactly the historical default capture body.
func ordered68ConsumeCatalogCapture(t *testing.T, ctx context.Context, owner *pgx.Conn, capture ordered68CatalogCapture, defaultCapture func()) (captured, defaultRan bool) {
	t.Helper()
	if capture != nil {
		return ordered68RunCatalogCaptureBoundary(t, ctx, owner, capture), false
	}
	if defaultCapture == nil {
		t.Fatal("catalog capture default consumer missing")
	}
	defaultCapture()
	return false, true
}

type ordered69LifecycleConsumer struct {
	phase       string
	consume     ordered69ApprovalConsumer
	application func(ordered68TestFlowContext)
	// Only downstream application consumers may reuse separately verified
	// negative controls; actual admission and all producer operations still run.
	connectedConsumer bool
}

func (c ordered69LifecycleConsumer) valid() bool {
	if c.connectedConsumer && c.phase != "application-complete" {
		return false
	}
	switch c.phase {
	case "approval", "block-reserved", "block-started":
		return c.consume != nil && c.application == nil
	case "application-complete":
		return c.consume == nil && c.application != nil
	default:
		return false
	}
}

func runOrdered68PolicyBoundary(t *testing.T, catalogOnly, approvalOnly, writerCatalog bool, lifecycle ...ordered69LifecycleConsumer) {
	runOrdered68PolicyAcceptance(t, catalogOnly, approvalOnly, writerCatalog, nil, lifecycle...)
}

func ordered68PolicyOptionsValid(catalogOnly, approvalOnly, writerCatalog bool, acceptance *ordered68PolicyAcceptance, lifecycle ...ordered69LifecycleConsumer) bool {
	if acceptance != nil && (catalogOnly || approvalOnly || writerCatalog || len(lifecycle) != 0 || acceptance.consume == nil) {
		return false
	}
	if len(lifecycle) > 1 || len(lifecycle) == 1 && (catalogOnly || writerCatalog || !lifecycle[0].valid() || approvalOnly && lifecycle[0].phase != "approval") {
		return false
	}
	return true
}

func runOrdered68PolicyAcceptance(t *testing.T, catalogOnly, approvalOnly, writerCatalog bool, acceptance *ordered68PolicyAcceptance, lifecycle ...ordered69LifecycleConsumer) {
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, catalogOnly, approvalOnly, writerCatalog, nil, acceptance, lifecycle...)
}

func runOrdered68PolicyAcceptanceWithCatalogCapture(t *testing.T, catalogOnly, approvalOnly, writerCatalog bool, capture ordered68CatalogCapture, acceptance *ordered68PolicyAcceptance, lifecycle ...ordered69LifecycleConsumer) {
	t.Helper()
	if !ordered68CatalogCaptureOptionsValid(catalogOnly, approvalOnly, writerCatalog, capture, acceptance, lifecycle) {
		t.Fatal("catalog-only capture callback requires the direct acceptance path")
	}
	if !ordered68PolicyOptionsValid(catalogOnly, approvalOnly, writerCatalog, acceptance, lifecycle...) {
		t.Fatal("invalid ordered policy acceptance or lifecycle consumer")
	}
	predecessorCapture, err := orderedPredecessorCatalogPreflight(catalogOnly, approvalOnly, writerCatalog, acceptance != nil, len(lifecycle))
	if err != nil {
		t.Fatal(err)
	}
	if predecessorCapture.enabled {
		t.Cleanup(func() {
			if !t.Failed() && (!predecessorCapture.reached || !predecessorCapture.completed) {
				t.Error("standalone predecessor catalog capture did not complete")
			}
		})
	}
	connectedConsumer := len(lifecycle) == 1 && lifecycle[0].connectedConsumer
	consumed := false
	runTemporalExecutorPolicyFixtureWithHook(t, false, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, actor string, keys policy.GatewayPolicyKeys, private ed25519.PrivateKey) bool {
		consumed = true
		fixtureBudget := 5 * time.Minute
		if !catalogOnly && !approvalOnly {
			fixtureBudget = 10 * time.Minute
		}
		if acceptance != nil && acceptance.capacity {
			fixtureBudget = 65 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fixtureBudget)
		defer cancel()
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		if predecessorCapture.enabled || len(lifecycle) == 1 && lifecycle[0].phase == "application-complete" {
			installOrderedRunnerAdapterPrincipals(t, ctx, owner)
		}
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalFindingResponse(ctx); err != nil {
			t.Fatal("ordered predecessor", err)
		}
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal("ordered authorization", err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal("ordered worker", err)
		}
		if captured, err := predecessorCapture.run(func(destination string) {
			captureOrdered69PredecessorCatalog(t, ctx, owner, destination)
		}); err != nil {
			t.Fatal(err)
		} else if captured {
			t.Log("standalone predecessor catalog capture reached/completed; no durable product-flow claim")
			return true
		}
		if catalogOnly {
			retirementMode, valid := ordered69RetirementCatalogMode(os.Getenv("ZASP_P7_ORDERED69_RETIREMENT_ACL"), os.Getenv("ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION"), os.Getenv("ZASP_ORDERED_READINESS_ATTRIBUTION"), os.Getenv("ZASP_ORDERED_READINESS_CAPTURE"))
			if !valid {
				t.Fatal("invalid or overlapping raw69 retirement catalog mode")
			}
			if captureOrderedReadinessClosure(t, ctx, owner) {
				if retirementMode == 2 {
					t.Log("combined retirement: synchronous attribution completed")
					if !assertOrdered69InstalledRetirementIfRequested(t, ctx, owner, executor) {
						t.Fatal("combined retirement skipped ACL assertions")
					}
				}
				return true
			}
			if retirementMode == 2 {
				t.Fatal("combined retirement skipped attribution")
			}
			if assertOrdered69InstalledRetirementIfRequested(t, ctx, owner, executor) {
				return true
			}
			assertOrderedTestInstalledCatalog(t, ctx, owner, executor)
			if writerCatalog {
				captureOrdered68InstalledWriters(t, ctx, owner)
			} else {
				captureOrdered62InstalledBodies(t, ctx, owner)
			}
			return true
		}
		captured, defaultRan := ordered68ConsumeCatalogCapture(t, ctx, owner, capture, func() {
			captureOrdered68InstalledBodies(t, ctx, owner)
		})
		if captured {
			// The named callback is a catalog-only boundary. It must not fall
			// through into approval, OpenFGA, or product-flow setup.
			return true
		}
		if capture != nil {
			t.Fatal("direct catalog capture did not reach/complete")
		}
		if !defaultRan {
			t.Fatal("default catalog capture did not run")
		}
		if acceptance != nil && acceptance.prepare != nil {
			acceptance.prepare(t, ctx, owner, o, w, e)
		}
		var identity json.RawMessage
		var step, approval string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'run_id',r.run_id,'definition_version',r.definition_version,'input_digest',c.input_digest),s.step_id,a.approval_id FROM zasp_security_agent_runs r JOIN zasp_temporal65.commands c USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE r.run_id=$1 AND c.kind='start' AND s.step_index=0 AND s.state='waiting_approval' AND a.state='pending'`, run).Scan(&identity, &step, &approval); err != nil {
			t.Fatal("actual pending Block approval", err)
		}
		if _, err := executor.Exec(ctx, `SELECT zasp_authorization80_worker.prepare_ordered68($1::jsonb)`, identity); err != nil {
			t.Fatal("actual ordered authority capture", err)
		}
		if !connectedConsumer {
			assertOrdered62CatalogRefusal(t, ctx, owner, api.Config().User)
			assertOrdered62InnerBoundaries(t, ctx, owner, api)
			assertOrdered68SigningInnerBoundaries(t, ctx, owner, executor)
			assertWorkerReadinessGraphEquivalence(t, ctx, owner)
			for _, operation := range []string{"classify", "decide_resource", "decide"} {
				q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": orderedProgressionApprover, "operation": operation}
				if operation == "classify" {
					q["resource_kind"], q["resource_id"] = "approval", approval
				} else {
					q["approval_id"], q["approval_version"], q["decision"], q["fresh_auth_at"], q["idempotency_key"] = approval, 1, "approved", time.Now().UTC().Format(time.RFC3339Nano), "ordered62-unsigned-decision"
					if operation == "decide" {
						q["run_id"], q["run_version"] = run, 2
					}
				}
				raw, _ := json.Marshal(q)
				var result json.RawMessage
				err := api.QueryRow(ctx, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), raw).Scan(&result)
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != "42501" {
					t.Fatal("unsigned actual62 approval not refused", operation, err)
				}
			}
		}
		client, pins := newAuthorizationProjectionFGA(t)
		checker, err := authorization.NewOpenFGA(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := authorization.NewOpenFGATupleWriter(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		var projector string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&projector); err != nil {
			t.Fatal(err)
		}
		cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User, cfg.MaxConns = projector, 2
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		projection, err := authorization.NewPostgresProjectionRepository(pool)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID); err != nil {
			t.Fatal(err)
		}
		human := authorizationFixtureAttestor(t)
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, human.Version(), human.Verifier()); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('ordered68-owned-approval-session','sha256'),'session-ordered68-owned-approval',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, orderedProgressionApprover, o, w, e); err != nil {
			t.Fatal(err)
		}
		functionTiming := os.Getenv("ZASP_ORDERED62_FUNCTION_TIMING") == "1"
		if functionTiming {
			api = ordered62FunctionTimingConnection(t, ctx, owner, api)
		}
		db, err := NewPostgresJSONDatabase(&ordered62TraceDriver{authorizationConnectionDriver: &authorizationConnectionDriver{conn: api}, t: t})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		repo, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal("actual current security-agent repository", err)
		}
		// Authentication belongs to the registered discovery API authority;
		// the dedicated security-agent API only owns the checked public62 call.
		var authenticationLogin string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_api'`).Scan(&authenticationLogin); err != nil {
			t.Fatal(err)
		}
		authenticationConfig := owner.Config().Copy()
		authenticationConfig.User = authenticationLogin
		authenticationConnection, err := pgx.ConnectConfig(ctx, authenticationConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = authenticationConnection.Close(cleanup)
		}()
		authenticationDB, err := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: authenticationConnection})
		if err != nil {
			t.Fatal(err)
		}
		if err := authenticationDB.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		authenticationRepository, err := NewPostgresRepository(authenticationDB)
		if err != nil {
			t.Fatal(err)
		}
		browser, err := authenticationRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "ordered68-owned-approval-session"})
		if err != nil || !browser.FreshAuthenticated {
			t.Fatal("actual current browser authentication", err)
		}
		handler, err := newSecurityAgentProductionHTTPHandler(ctx, repo, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: bytes.Repeat([]byte{17}, 32)}, true)
		if err != nil {
			t.Fatal(err)
		}
		resolver, err := NewPostgresAuthorizationResolver(db)
		if err != nil {
			t.Fatal(err)
		}
		operation, _ := authorization.LookupOperation("decideSecurityAgentApproval")
		router, err := NewRouter([]Operation{{Method: operation.Method, Pattern: operation.Path, OperationID: operation.ID, Permission: operation.Permission, Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, RequireFreshAuth: operation.FreshAuth, Handler: handler}})
		if err != nil {
			t.Fatal(err)
		}
		authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: human}
		router.(*operationRouter).authorizer = authorizer
		if result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
			t.Fatal("actual approval projection", err)
		}
		call := func(version, fresh, key string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/security-agent-approvals/"+approval+"/decision", strings.NewReader(`{"decision":"approved"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("If-Match", version)
			r.Header.Set("Idempotency-Key", key)
			r.Header.Set("X-Zasp-Fresh-Auth", fresh)
			r.Header.Set(expectedScopeHeader, expectedScopeValue(browser.Scope))
			r.Header.Set("Origin", "https://console.example")
			r.Header.Set("X-CSRF-Token", browser.CSRFToken)
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "ordered68-owned-approval-session"})
			c := context.WithValue(ctx, identityContextKey{}, browser)
			c = context.WithValue(c, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
			c = context.WithValue(c, correlationContextKey{}, integrationClientCorrelation(key))
			out := httptest.NewRecorder()
			router.ServeHTTP(out, r.WithContext(c))
			return out
		}
		membership := func(active bool) {
			t.Helper()
			if tag, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=$3 WHERE organization_id=$1 AND principal_id=$2`, o, orderedProgressionApprover, active); err != nil || tag.RowsAffected() != 1 {
				t.Fatal("approval membership control", err)
			}
			if result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
				t.Fatal("approval membership projection", err)
			}
		}
		if !connectedConsumer {
			membership(false)
			if denied := call(`"1"`, "confirmed", "ordered68-fga-denied"); denied.Code != http.StatusForbidden {
				t.Fatal("actual FGA denial before approval", denied.Code)
			}
			membership(true)
		}
		desired := func() int64 {
			t.Helper()
			var revision int64
			if err := owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&revision); err != nil {
				t.Fatal("approval revision", err)
			}
			return revision
		}
		beforeDecision := desired()
		if !connectedConsumer {
			assertOrdered62ProofWait(t, ctx, owner, api, authorizer, browser, human, approval, run)
			if desired() != beforeDecision {
				t.Fatal("expired proof changed native revision")
			}
			for _, control := range []struct {
				name, version, fresh string
				status               int
			}{{"version", `"2"`, "confirmed", http.StatusConflict}, {"fresh", `"1"`, "", http.StatusUnauthorized}} {
				if got := call(control.version, control.fresh, "ordered68-denied-"+control.name); got.Code != control.status {
					t.Fatal("actual approval negative accepted", control.name, got.Code)
				}
				var pending bool
				if err := owner.QueryRow(ctx, `SELECT state='pending' AND version=1 FROM zasp_security_agent_approvals WHERE approval_id=$1`, approval).Scan(&pending); err != nil || !pending {
					t.Fatal("denied approval mutated", err)
				}
				if desired() != beforeDecision {
					t.Fatal("refused approval changed revision")
				}
			}
		}
		if functionTiming {
			if _, err := api.Exec(ctx, `SELECT pg_stat_force_next_flush()`); err != nil {
				t.Fatal("flush prior diagnostic function counters", err)
			}
			if _, err := owner.Exec(ctx, `SELECT pg_stat_reset()`); err != nil {
				t.Fatal("owned function counters reset", err)
			}
		}
		got := call(`"1"`, "confirmed", "ordered68-actual-approved")
		if functionTiming {
			ordered62ReportFunctionTiming(t, ctx, owner, api)
		}
		if got.Code != http.StatusOK {
			t.Fatal("actual current authorized approval", got.Code, "revision_delta", desired()-beforeDecision)
		}
		if desired() != beforeDecision+2 {
			t.Fatal("decision did not produce exact two native revision captures")
		}
		if functionTiming {
			t.Log("approval function diagnostic only; connected effect flow not executed")
			return true
		}
		immutable := func() []byte {
			t.Helper()
			var raw []byte
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE run_id=$1),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY receipt_id) FROM zasp_security_agent_request_receipts r WHERE resource_id=$1),'approvals',(SELECT jsonb_agg(to_jsonb(a) ORDER BY approval_id) FROM zasp_security_agent_approvals a WHERE run_id=$1),'steps',(SELECT jsonb_agg(to_jsonb(s) ORDER BY step_id) FROM zasp_security_agent_steps s WHERE run_id=$1))`, run).Scan(&raw); err != nil {
				t.Fatal("approval immutable evidence", err)
			}
			return raw
		}
		original := immutable()
		if result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
			t.Fatal("approval own-revision projection", err)
		}
		if replay := call(`"1"`, "confirmed", "ordered68-actual-approved"); replay.Code != http.StatusOK {
			t.Fatal("actual approval idempotency", replay.Code)
		}
		if desired() != beforeDecision+2 || !bytes.Equal(original, immutable()) {
			t.Fatal("approval replay changed revision or immutable evidence")
		}
		if !connectedConsumer {
			membership(false)
			if denied := call(`"1"`, "confirmed", "ordered68-actual-approved"); denied.Code != http.StatusForbidden {
				t.Fatal("revoked approval replay bypassed current FGA", denied.Code)
			}
			membership(true)
		}
		var approved bool
		if err := owner.QueryRow(ctx, `SELECT s.state='authorized' AND a.state='approved' AND a.version=2 FROM zasp_security_agent_steps s JOIN zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE s.run_id=$1 AND s.step_id=$2`, run, step).Scan(&approved); err != nil || !approved {
			t.Fatal("actual approval did not authorize Block", err)
		}
		if len(lifecycle) == 1 && lifecycle[0].phase == "approval" {
			lifecycle[0].consume(t, ctx, owner, identity, step)
			return true
		}
		if approvalOnly {
			return true
		}
		if !connectedConsumer {
			q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}})
			tx, err := executor.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			err = tx.QueryRow(ctx, `SELECT zasp_temporal68.effect($1::jsonb)`, q).Scan(&raw)
			rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			rollbackErr := tx.Rollback(rollbackCtx)
			rollbackCancel()
			if rollbackErr != nil {
				t.Fatal("unsigned effect rollback", rollbackErr)
			}
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Error("unsigned current-profile Block reservation was not refused", err)
			}
		}
		if !t.Failed() {
			projectionAttempt := func(attemptCtx context.Context) (authorization.ProjectionReceipt, error) {
				r, err := authorization.Reconcile(attemptCtx, projection, writer, o, pins.StoreID, pins.ModelID)
				if errors.Is(err, authorization.ErrConflict) {
					t.Logf("ordered capture projection conflict desired=%d applied=%d generation=%d", r.Revision.Desired, r.Revision.Applied, r.Revision.Generation)
				}
				return r, err
			}
			reconcile := func() {
				if result, err := projectionAttempt(ctx); err != nil || !result.Applied {
					t.Fatal("ordered policy projection", err)
				}
			}
			var afterEffect []ordered69EffectConsumer
			if acceptance != nil {
				acceptance.consume(ordered68PolicyAcceptanceContext{t: t, ctx: ctx, owner: owner, o: o, w: w, e: e, run: run, step: step, actor: actor, login: executor.Config().User, store: pins.StoreID, model: pins.ModelID, keys: keys, private: private, checker: checker, reconcile: reconcile, projectionAttempt: projectionAttempt, config: pins})
				return true
			}
			if len(lifecycle) == 1 {
				if lifecycle[0].phase == "application-complete" {
					afterEffect = append(afterEffect, ordered69EffectConsumer{phase: "application-complete", application: func(forward, compensation *authorization.WorkerExecutor) {
						lifecycle[0].application(ordered68TestFlowContext{t: t, ctx: ctx, owner: owner, identity: identity, forward: forward, compensation: compensation, checker: checker, config: pins, storeID: pins.StoreID, modelID: pins.ModelID, forwardLogin: executor.Config().User, actor: actor, reconcile: reconcile, policyKeys: keys, policySigner: func(signCtx context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
							if err := signCtx.Err(); err != nil {
								return policy.GatewayPolicyEnvelope{}, err
							}
							return policy.SignGatewayPolicyEnvelope(input, private)
						}, approve: func(testApproval string, version int64) *httptest.ResponseRecorder {
							original := approval
							approval = testApproval
							defer func() { approval = original }()
							return call(fmt.Sprintf(`"%d"`, version), "confirmed", "ordered68-actual-test-approved")
						}})
					}})
				} else {
					afterEffect = append(afterEffect, ordered69EffectConsumer{phase: lifecycle[0].phase, consume: func() { lifecycle[0].consume(t, ctx, owner, identity, step) }})
				}
			}
			assertOrdered68SignedPolicyFlow(t, ctx, owner, executor.Config().User, o, w, e, run, step, actor, keys, private, checker, pins.StoreID, pins.ModelID, reconcile, projectionAttempt, afterEffect...)
		}
		return true
	})
	if !t.Failed() && !consumed {
		t.Fatal("actual admitted policy hook did not run")
	}
}

// A missing exact62 rule rejects the shipped ordered approval before its
// native fence. A broad SQL rule would let that proof cross actor/target/pins.
func TestP7Ordered62ApprovalCheckedStatements(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	i.FreshAuthenticated = true
	i.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const id = "pid_88006801-0000-4000-8000-000000000001"
	const foreign = "pid_88006802-0000-4000-8000-000000000002"
	for _, op := range []string{"classify", "decide_resource"} {
		for _, mutation := range []string{"exact", "organization", "workspace", "environment", "actor", "target", "operation", "pins", "fingerprint", "unknown", "extra-field", "missing-field", "null-field", "duplicate-field", "malformed", "wrong-json-type", "extra-argument", "missing-argument", "credential", "no-fresh", "collection", "no-allow", "grant-operation", "route", "target-kind", "target-source", "multiple-targets"} {
			t.Run(op+"/"+mutation, func(t *testing.T) {
				target := AuthorizationTarget{Scope: i.Scope, Kind: "security_agent_approval", ID: id, SourceID: id, Version: 1}
				grant := RequestAuthorization{OperationID: "decideSecurityAgentApproval", Identity: i, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "session-ordered-contract", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, Targets: []AuthorizationTarget{target}, Allowed: []AuthorizationTarget{target}, PathParameters: map[string]string{"id": id}}
				q := map[string]any{"operation": op, "organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": p}
				if op == "classify" {
					q["resource_kind"], q["resource_id"] = "approval", id
				} else {
					q["approval_id"], q["approval_version"], q["decision"], q["idempotency_key"], q["fresh_auth_at"] = id, 1, "approved", "ordered-contract-decision", i.FreshAuthExpiresAt.Add(-5*time.Minute).Format(time.RFC3339Nano)
				}
				query, checksum, fingerprint := securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()
				switch mutation {
				case "organization", "workspace", "environment":
					q[mutation+"_id"] = foreign
				case "actor":
					q["actor_id"] = foreign
				case "target":
					if op == "classify" {
						q["resource_id"] = foreign
					} else {
						q["approval_id"] = foreign
					}
				case "operation":
					q["operation"] = "deployment_ready"
				case "pins":
					checksum = "wrong"
				case "fingerprint":
					fingerprint = "wrong"
				case "unknown":
					query += " "
				case "extra-field":
					q["unsigned"] = true
				case "missing-field":
					delete(q, "actor_id")
				case "null-field":
					q["actor_id"] = nil
				case "credential":
					grant.Identity.CredentialKind = CredentialBearerToken
					grant.Credential.Kind = CredentialBearerToken
				case "no-fresh":
					grant.Identity.FreshAuthenticated = false
				case "collection":
					grant.Collection = true
				case "no-allow":
					grant.Allowed = nil
				case "grant-operation":
					grant.OperationID = "getSecurityAgentApproval"
				case "route":
					grant.PathParameters["id"] = foreign
				case "target-kind":
					grant.Targets[0].Kind, grant.Allowed[0].Kind = "security_agent_run", "security_agent_run"
				case "target-source":
					grant.Targets[0].SourceID, grant.Allowed[0].SourceID = foreign, foreign
				case "multiple-targets":
					other := target
					other.ID, other.SourceID = foreign, foreign
					grant.Targets, grant.Allowed = append(grant.Targets, other), append(grant.Allowed, other)
				}
				raw, _ := json.Marshal(q)
				switch mutation {
				case "duplicate-field":
					raw = append([]byte(`{"actor_id":"`+p+`",`), raw[1:]...)
				case "malformed":
					raw = []byte(`{`)
				case "wrong-json-type":
					raw = []byte(`[]`)
				}
				grant, err := attestAuthorization(grant, authorizationFixtureAttestor(t), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				tx := &authorizationTxFixture{}
				driver := &authorizationDriverFixture{tx: tx}
				db, _ := NewPostgresJSONDatabase(driver)
				args := []any{checksum, fingerprint, json.RawMessage(raw)}
				if mutation == "extra-argument" {
					args = append(args, true)
				} else if mutation == "missing-argument" {
					args = args[:2]
				}
				body, err := db.QueryJSON(context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant), query, args...)
				if mutation == "exact" {
					if err != nil || string(body) != `{"ok":true}` {
						t.Fatalf("exact current62 contract refused: %v", err)
					}
				} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 || driver.direct {
					t.Fatalf("unbound current62 statement reached SQL: %v", err)
				}
			})
		}
	}
}

// This fixture-only wrapper preserves the real transaction and row methods.
// Diagnostics expose only fixed phase names, elapsed time and safe error class.
type ordered62TraceDriver struct {
	*authorizationConnectionDriver
	t *testing.T
}

func (d *ordered62TraceDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.authorizationConnectionDriver.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &ordered62TraceTx{Tx: tx, t: d.t}, nil
}

type ordered62TraceTx struct {
	pgx.Tx
	t *testing.T
}

func (x *ordered62TraceTx) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	start := time.Now()
	tag, err := x.Tx.Exec(ctx, q, args...)
	phase := "exec"
	if q == `SELECT zasp_authorization80.fence($1::text)` {
		phase = "human-fence"
	}
	x.t.Log("ordered62 SQL", phase, "elapsed_ms", time.Since(start).Milliseconds(), "class", ordered62TraceClass(err))
	return tag, err
}

func (x *ordered62TraceTx) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	phase := "query"
	if q == securityAgentPublicSQL {
		phase = "public62"
		if len(args) == 3 {
			if raw, ok := args[2].(json.RawMessage); ok {
				var value struct {
					Operation string `json:"operation"`
				}
				if json.Unmarshal(raw, &value) == nil && (value.Operation == "classify" || value.Operation == "decide_resource") {
					phase = value.Operation
				}
			}
		}
	}
	start := time.Now()
	return ordered62TraceRow{Row: x.Tx.QueryRow(ctx, q, args...), t: x.t, phase: phase, start: start}
}

func (x *ordered62TraceTx) Commit(ctx context.Context) error {
	start := time.Now()
	err := x.Tx.Commit(ctx)
	x.t.Log("ordered62 SQL", "commit", "elapsed_ms", time.Since(start).Milliseconds(), "class", ordered62TraceClass(err))
	return err
}

type ordered62TraceRow struct {
	pgx.Row
	t     *testing.T
	phase string
	start time.Time
}

func (r ordered62TraceRow) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	r.t.Log("ordered62 SQL", r.phase, "elapsed_ms", time.Since(r.start).Milliseconds(), "class", ordered62TraceClass(err))
	return err
}

func ordered62TraceClass(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var native *pgconn.PgError
	if errors.As(err, &native) {
		return "sqlstate-" + native.Code
	}
	return "other"
}

func assertOrdered62CatalogRefusal(t *testing.T, ctx context.Context, owner *pgx.Conn, principal string) {
	t.Helper()
	for _, control := range []string{"unchanged", "body", "acl"} {
		t.Run("catalog-"+control, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				if err := tx.Rollback(cleanup); err != nil {
					t.Error("catalog rollback", err)
				}
			}()
			if control == "body" {
				var definition string
				if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_ordered_public62.api(text,text,jsonb)'::regprocedure)`).Scan(&definition); err != nil {
					t.Fatal(err)
				}
				if strings.Count(definition, "BEGIN\n") != 1 {
					t.Fatal("catalog body control anchor")
				}
				if _, err := tx.Exec(ctx, strings.Replace(definition, "BEGIN\n", "BEGIN\n PERFORM 1;\n", 1)); err != nil {
					t.Fatal(err)
				}
			} else if control == "acl" {
				if _, err := tx.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_ordered_public62.mutate(text,text,jsonb) TO zasp_security_agent_api`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{principal}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			var result json.RawMessage
			err = tx.QueryRow(ctx, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(`{"operation":"deployment_ready"}`)).Scan(&result)
			if control == "unchanged" {
				if err != nil || !bytes.Contains(result, []byte(`"ready": true`)) {
					t.Fatal("original62 readiness", err)
				}
			} else {
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != "55000" {
					t.Fatal("native catalog drift not refused", err)
				}
			}
		})
	}
}

func assertOrdered62ProofWait(t *testing.T, ctx context.Context, owner, api *pgx.Conn, authorizer *OpenFGAAuthorizer, browser RequestIdentity, key *authorization.AttestationKey, approval, run string) {
	t.Helper()
	for _, control := range []string{"proof", "credential"} {
		if !t.Run(control+"-expires-after-wait", func(t *testing.T) {
			assertOrdered62AuthorityWait(t, ctx, owner, api, authorizer, browser, key, approval, run, control)
		}) {
			t.Fatal("approval authority wait control failed")
		}
	}
}

func assertOrdered62AuthorityWait(t *testing.T, ctx context.Context, owner, api *pgx.Conn, authorizer *OpenFGAAuthorizer, browser RequestIdentity, key *authorization.AttestationKey, approval, run, control string) {
	t.Helper()
	var credentialExpiry time.Time
	if control == "credential" {
		if err := owner.QueryRow(ctx, `SELECT expires_at FROM zasp_product_sessions WHERE session_id='session-ordered68-owned-approval'`).Scan(&credentialExpiry); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if _, err := owner.Exec(cleanup, `UPDATE zasp_product_sessions SET expires_at=$1 WHERE session_id='session-ordered68-owned-approval'`, credentialExpiry); err != nil {
				t.Error("owned session expiry restore", err)
			}
		}()
	}
	binding := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-ordered68-owned-approval", Digest: sha256.Sum256([]byte("ordered68-owned-approval-session"))}
	grant, err := authorizer.Authorize(ctx, browser, binding, RoutedOperation{OperationID: "decideSecurityAgentApproval", PathParameters: map[string]string{"id": approval}})
	if err != nil {
		t.Fatal("actual wait authorization", err)
	}
	// Shorten only the validity of this actual Check's signed decision. No
	// allowed target, revision, actor or permission is fabricated or replaced.
	expires := time.Now().Add(8 * time.Second)
	issued := expires.Add(-time.Minute)
	if control == "credential" {
		issued = time.Now()
		if _, err := owner.Exec(ctx, `UPDATE zasp_product_sessions SET expires_at=$1 WHERE session_id='session-ordered68-owned-approval'`, expires); err != nil {
			t.Fatal(err)
		}
	}
	grant, err = attestAuthorization(grant, key, issued)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rollback := func(tx pgx.Tx) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("proof wait rollback", err)
		}
	}
	defer rollback(lock)
	if _, err := lock.Exec(ctx, `SELECT 1 FROM zasp_security_agent_org_admissions WHERE organization_id=$1 FOR UPDATE`, browser.Scope.OrganizationID().String()); err != nil {
		t.Fatal(err)
	}
	tx, err := api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
		t.Fatal("initial valid native proof", err)
	}
	q, _ := json.Marshal(map[string]any{"organization_id": browser.Scope.OrganizationID().String(), "workspace_id": browser.Scope.WorkspaceID().String(), "environment_id": browser.Scope.EnvironmentID().String(), "actor_id": browser.PrincipalID.String(), "operation": "decide_resource", "approval_id": approval, "approval_version": 1, "decision": "approved", "fresh_auth_at": browser.FreshAuthExpiresAt.Add(-5 * time.Minute).Format(time.RFC3339Nano), "idempotency_key": "ordered62-expired-after-wait"})
	joined := make(chan error, 1)
	go func() {
		var result json.RawMessage
		joined <- tx.QueryRow(ctx, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), q).Scan(&result)
	}()
	waitCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	waiting := false
	for waitCtx.Err() == nil {
		var blocked bool
		if err := lock.QueryRow(waitCtx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, api.PgConn().PID()).Scan(&blocked); err != nil {
			break
		}
		if blocked {
			waiting = true
			break
		}
		select {
		case <-waitCtx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if waiting {
		delay := time.Until(expires.Add(100 * time.Millisecond))
		if delay > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(delay):
			}
		}
	}
	rollback(lock)
	callErr := <-joined
	rollback(tx)
	if !waiting {
		t.Fatal("approval did not reach observed admission lock wait", callErr)
	}
	var native *pgconn.PgError
	if !errors.As(callErr, &native) || (native.Code != "42501" && native.Code != "40001") {
		t.Fatal("expired approval proof survived observed wait", callErr)
	}
	var unchanged bool
	if err := owner.QueryRow(ctx, `SELECT a.state='pending' AND a.version=1 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE idempotency_key='ordered62-expired-after-wait') FROM zasp_security_agent_approvals a WHERE a.approval_id=$1 AND a.run_id=$2`, approval, run).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("expired approval wrote native evidence", err)
	}
}

func captureOrdered68InstalledBodies(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	signatures := []string{"zasp_temporal68.effect(jsonb)", "zasp_temporal68.application(jsonb)", "zasp_temporal68.delivery(jsonb)", "zasp_temporal68.cleanup(jsonb)", "zasp_temporal68.current_plan(text,text,text,text,boolean)", "zasp_sa_multistep_prior.application_current(text,text,text,text,text)", "zasp_sa_multistep_prior.deployment_composition(text,text,text,text)", "zasp_temporal68.cleanup_current(text,text,text,text,text)", "zasp_temporal69.inspect(jsonb)", "zasp_temporal69.stop(jsonb)"}
	var raw []byte
	if err := owner.QueryRow(ctx, `SELECT jsonb_object_agg(s,jsonb_build_object('definition',pg_get_functiondef(p.oid),'owner',p.proowner::regrole::text,'acl',p.proacl::text)) FROM unnest($1::text[]) s JOIN pg_proc p ON p.oid=s::regprocedure`, signatures).Scan(&raw); err != nil {
		t.Fatal("installed ordered bodies", err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || len(value) != len(signatures) {
		t.Fatal("installed ordered body count")
	}
	writeOrderedInstalledBodies(t, value)
}

// Read-only static catalog evidence, before any new capture trigger is
// installed. Includes direct target/delivery writers and their one-hop callers
// so private helpers are not mistaken for the entire reachable entry boundary.
func captureOrdered68InstalledWriters(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	var raw []byte
	if err := owner.QueryRow(ctx, `WITH functions AS MATERIALIZED(
 SELECT p.oid,p.proname,p.prosrc,pg_get_functiondef(p.oid) definition,p.proowner::regrole::text owner,p.proacl::text acl
 FROM pg_proc p WHERE p.prokind='f' AND p.pronamespace IN('public'::regnamespace,'zasp_sa_multistep_prior'::regnamespace,'zasp_temporal68'::regnamespace)),
 writers AS(SELECT * FROM functions WHERE prosrc~*'(INSERT INTO|UPDATE|DELETE FROM)[[:space:]]+(public\.)?(zasp_security_agent_temporary_policy_targets|zasp_temporal68\.deliveries)')
 SELECT jsonb_build_object('direct_writers',(SELECT jsonb_object_agg(oid::regprocedure::text,jsonb_build_object('definition',definition,'owner',owner,'acl',acl)) FROM writers),
 'callers',(SELECT jsonb_object_agg(f.oid::regprocedure::text,jsonb_build_object('definition',f.definition,'owner',f.owner,'acl',f.acl)) FROM functions f WHERE EXISTS(SELECT 1 FROM writers w WHERE f.oid<>w.oid AND strpos(f.prosrc,w.proname||'(')>0)),
 'organization_lock',(SELECT pg_get_functiondef('zasp_sa_multistep_prior.application_lock(text,text,text,text,text)'::regprocedure)),
 'existing_triggers',(SELECT jsonb_agg(jsonb_build_object('relation',t.tgrelid::regclass::text,'name',t.tgname,'definition',pg_get_triggerdef(t.oid),'enabled',t.tgenabled) ORDER BY t.tgrelid::regclass::text,t.tgname) FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid IN('public.zasp_security_agent_temporary_policy_targets'::regclass,'zasp_temporal68.deliveries'::regclass,'public.zasp_workflow_records'::regclass)))`).Scan(&raw); err != nil {
		t.Fatal("installed ordered writer catalog", err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || len(value) != 4 || value["direct_writers"] == nil || value["callers"] == nil {
		t.Fatal("installed ordered writer catalog shape")
	}
	writeOrderedInstalledBodies(t, value)
}

func captureOrdered62InstalledBodies(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	var raw []byte
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('functions',(SELECT jsonb_object_agg(p.oid::regprocedure::text,jsonb_build_object('definition',pg_get_functiondef(p.oid),'owner',p.proowner::regrole::text,'acl',p.proacl::text)) FROM pg_proc p WHERE p.pronamespace='zasp_ordered_public62'::regnamespace OR p.oid IN('zasp_sa_multistep_prior.transition(text,text,jsonb)'::regprocedure,'zasp_sa_multistep_prior.transition_current(text,text,text,text,boolean)'::regprocedure,'zasp_sa_multistep_prior.transition_lock(text,text,text,text)'::regprocedure,'zasp_sa_multistep_prior.context(text,text,text,text)'::regprocedure,'zasp_sa_multistep_prior.lock_scope(text,text,text,text)'::regprocedure,'zasp_authorization79.capture()'::regprocedure,'zasp_authorization79.touch(text)'::regprocedure,'zasp_authorization80_worker.capture_ordered_run()'::regprocedure)), 'triggers',(SELECT jsonb_agg(jsonb_build_object('relation',t.tgrelid::regclass::text,'name',t.tgname,'definition',pg_get_triggerdef(t.oid),'enabled',t.tgenabled,'function',t.tgfoid::regprocedure::text,'arguments',encode(t.tgargs,'escape')) ORDER BY t.tgrelid::regclass::text,t.tgname) FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_steps'::regclass,'public.zasp_security_agent_approvals'::regclass,'public.zasp_security_agent_request_receipts'::regclass,'public.zasp_security_agent_audit'::regclass,'zasp_authorization80_worker.ordered_state'::regclass)))`).Scan(&raw); err != nil {
		t.Fatal("installed62 catalog capture", err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || len(value) != 2 {
		t.Fatal("installed62 catalog shape")
	}
	writeOrderedInstalledBodies(t, value)
}

func writeOrderedInstalledBodies(t *testing.T, value map[string]any) {
	t.Helper()
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("ZASP_P7_ORDERED_BODY_CAPTURE")
	if path == "" {
		path = filepath.Join(t.TempDir(), "ordered68-installed-bodies.json")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("absolute owned body output required")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("exclusive body artifact", err)
	}
	_, writeErr := file.Write(formatted)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("body artifact write", writeErr, closeErr)
	}
	t.Log("installed ordered static catalog", len(value), fmt.Sprintf("%x", sha256.Sum256(formatted)), path)
}
