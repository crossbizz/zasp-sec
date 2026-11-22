package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/providerhooks"
)

// Exercise the public provider wire through a newly constructed hook on each
// delivery. The scoped PAT, current authorization fence, policy snapshots and
// retry/outcome receipts use the installed PostgreSQL functions.
func TestClaudeEnterpriseHookOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	// Cancellation can discard a pgx connection. Use the production pool
	// behavior so an exact delivery retry exercises fresh authorization.
	poolConfig, err := pgxpool.ParseConfig(os.Getenv("ZASP_BASELINE_RELEASE_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.User = "zasp_svc_api"
	poolConfig.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(b.ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	b.product, err = NewPostgresJSONDatabase(&singleRecoveryNativePoolDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	b.authorizer.Resolver, err = NewPostgresAuthorizationResolverWithSecurityAgent(b.product, b.agents)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, tokens := installedWorkloadTokenIssuer(t, b, repo, admin)
	pat := issue("Claude provider", `["decide_actions"]`)
	service := &workloadActionHandler{database: b.product, newProductID: newWorkflowProductID}
	target := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		service.serve(w, r, op)
	})
	route, err := NewRouter([]Operation{{Method: "POST", Pattern: "/api/v1/runtime/action-decisions", OperationID: "createWorkloadActionDecision", Permission: "decide_actions", Security: []CredentialKind{CredentialBearerToken}, Handler: target}})
	if err != nil {
		t.Fatal(err)
	}
	route.(*operationRouter).authorizer = b.authorizer
	product, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://test.invalid", MaximumBodyBytes: 16384, Authenticate: repo.Authenticate, GenerateCorrelationID: func() string { return guardrailTestDecisionID }}, route)
	if err != nil {
		t.Fatal(err)
	}
	type traceKey struct{}
	type admissionTiming struct {
		status  int
		code    string
		elapsed time.Duration
	}
	tracedProduct := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		observed := httptest.NewRecorder()
		product.ServeHTTP(observed, r)
		for name, values := range observed.Header() {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.WriteHeader(observed.Code)
		_, _ = w.Write(observed.Body.Bytes())
		channel, _ := r.Context().Value(traceKey{}).(chan admissionTiming)
		if channel != nil {
			var reason struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(observed.Body.Bytes(), &reason)
			channel <- admissionTiming{observed.Code, reason.Code, time.Since(start)}
		}
	})
	admit, err := providerhooks.ProductAdmitter(tracedProduct, tokens["Claude provider"])
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{12}, 32)
	cfg := providerhooks.Config{Integration: b.id(), Tenant: "enterprise-fixture", Secret: "whsec_" + base64.StdEncoding.EncodeToString(key), ReferenceKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{41}, 32)), Scope: providerhooks.Scope{Organization: b.o, Workspace: b.w, Environment: b.e, Credential: pat.binding.ID}}
	policy := sampleToolPolicy("enforced", "resource", "claude.prompt")
	policy.Trigger = "runtime"
	rawPolicy, _ := json.Marshal(policy)
	b.seed(func() {
		b.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,$5::jsonb)`, b.o, b.w, b.e, policy.ID, rawPolicy)
	})
	send := func(c providerhooks.Config, raw, id string, expectedInner ...int) *httptest.ResponseRecorder {
		t.Helper()
		h, err := providerhooks.NewClaude(c, admit)
		if err != nil {
			t.Fatal(err)
		}
		stamp := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id + "." + stamp + "." + raw))
		// Keep timestamp, signature, delivery ID and body byte-for-byte across
		// these bounded client retries. Every individual call retains its deadline.
		for attempt := 0; ; attempt++ {
			req := httptest.NewRequest("POST", providerhooks.ClaudePath+c.Integration, strings.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("webhook-id", id)
			req.Header.Set("webhook-timestamp", stamp)
			req.Header.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
			w := httptest.NewRecorder()
			trace := make(chan admissionTiming, 1)
			start := time.Now()
			h.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), traceKey{}, trace)))
			elapsed := time.Since(start)
			timedOut := w.Code == 504 || (w.Code == 503 && strings.Contains(w.Body.String(), "<h1>Timeout</h1>"))
			if timedOut && attempt < 2 {
				t.Logf("signed frame timed out after %v, retrying identical delivery (attempt %d)", elapsed, attempt+1)
				time.Sleep(time.Duration(attempt+1) * 75 * time.Millisecond)
				continue
			}
			select {
			case inner := <-trace:
				t.Logf("signed frame returned %d in %v (product admission %d %q in %v)", w.Code, elapsed, inner.status, inner.code, inner.elapsed)
				if len(expectedInner) > 0 && inner.status != expectedInner[0] {
					t.Fatalf("expected internal status %d, received %d %q", expectedInner[0], inner.status, inner.code)
				}
			default:
				t.Logf("signed frame returned %d in %v before product admission completed", w.Code, elapsed)
				if len(expectedInner) > 0 {
					t.Fatal("missing underlying authorization result")
				}
			}
			return w
		}
	}
	const prompt = `{"type":"prompt","request_id":"fixture-prompt","tenant_id":"enterprise-fixture","messages":[{"role":"user","content":"private example"}]}`
	const tool = `{"type":"tool_call","request_id":"fixture-tool","tenant_id":"enterprise-fixture","messages":[{"role":"assistant","content":[{"type":"tool_use","tool_info":{"type":"platform"}}]}]}`
	wrong := cfg
	wrong.Scope.Environment = b.id()
	if w := send(wrong, prompt, "fixture-prompt", http.StatusForbidden); w.Code != 503 {
		t.Fatalf("wrong mapping %d %s", w.Code, w.Body)
	}
	first := send(cfg, prompt, "fixture-prompt")
	if first.Code != 200 || !strings.Contains(first.Body.String(), `"action":"deny"`) {
		t.Fatalf("prompt: %d %s", first.Code, first.Body)
	}
	if w := send(cfg, prompt, "fixture-prompt"); w.Code != 200 || w.Body.String() != first.Body.String() {
		t.Fatalf("new receiver replay: %d %s", w.Code, w.Body)
	}
	if w := send(cfg, strings.Replace(prompt, "private example", "unrelated example", 1), "fixture-prompt"); w.Code != 409 {
		t.Fatalf("conflict: %d %s", w.Code, w.Body)
	}
	if w := send(cfg, tool, "fixture-tool"); w.Code != 200 || !strings.Contains(w.Body.String(), `"action":"allow"`) {
		t.Fatalf("tool: %d %s", w.Code, w.Body)
	}
	var raw, id, decision string
	if err = b.admin.QueryRow(b.ctx, `SELECT request::text,action_id,receipt->>'decision_id' FROM public.zasp_workload_actions WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND credential_id=$4 AND request->>'action_kind'='provider_prompt'`, b.o, b.w, b.e, pat.binding.ID).Scan(&raw, &id, &decision); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "private example") || strings.Contains(raw, "enterprise-fixture") {
		t.Fatal("provider content retained")
	}
	if w := b.serve(target, pat, "createWorkloadActionDecision", "POST", "/api/v1/runtime/action-decisions", nil, raw, map[string]string{"Idempotency-Key": id}); w.Code != 403 {
		t.Fatalf("native PAT impersonated provider: %d", w.Code)
	}
	out := workloadOutcome{SchemaVersion: "action-outcome.v1", ActionID: id, DecisionID: decision, Status: "returned"}
	payload, _ := json.Marshal(out)
	if w := b.serve(target, pat, "recordWorkloadActionOutcome", "POST", "/api/v1/runtime/actions/"+id+"/outcomes", map[string]string{"actionId": id}, string(payload), map[string]string{"Idempotency-Key": id + "-outcome"}); w.Code != 404 {
		t.Fatalf("provider execution evidence: %d", w.Code)
	}
	revoke := administrationMutation{Operation: "revokeAPIToken", ID: pat.binding.ID, ExpectedVersion: 1, AuditID: b.id()}
	checked, err := b.checked(admin, RoutedOperation{OperationID: revoke.Operation, PathParameters: map[string]string{"id": revoke.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.MutateAdministration(checked, admin.identity, revoke); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range []string{"fixture-prompt", "revoked-prompt"} {
		if w := send(cfg, strings.Replace(prompt, "fixture-prompt", delivery, 1), delivery, http.StatusUnauthorized); w.Code != 503 {
			t.Fatalf("revoked source obtained a provider verdict: %d", w.Code)
		}
	}
	count := b.text(`SELECT count(*)::text FROM public.zasp_workload_actions WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND credential_id=$4`, b.o, b.w, b.e, pat.binding.ID)
	if count != "2" {
		t.Fatalf("expected exactly two original decisions after retry and revocation, found %s", count)
	}

}

func TestClaudeHookDoesNotTreatServicePrincipalAsClaudeUser(t *testing.T) {
	identity := newGuardrailFixture(t, CredentialBearerToken).secondary.identity
	handler := workloadActionHandler{newProductID: func() (string, error) { return guardrailTestDecisionID, nil }}
	action := workloadActionRequest{ActionID: "fixture", ActionKind: "provider_prompt", Operation: "claude.prompt"}
	action.Resource.Kind = "claude_enterprise"
	action.Resource.Classification = "claude.prompt"
	p := sampleToolPolicy("enforced", "principal_id", identity.PrincipalID.String())
	p.Trigger = "runtime"
	raw, _ := json.Marshal(p)
	_, err := handler.evaluate(context.Background(), identity, action, workloadAdmission{Revision: "sha256:" + strings.Repeat("a", 64), Policies: []workloadPolicy{{p.ID, 1, raw}}})
	if !errors.Is(err, errUnsupportedWorkloadContext) {
		t.Fatalf("service principal satisfied a Claude user policy: %v", err)
	}
}

func TestClaudeMixedFrameAppliesAnyMatchingToolOrigin(t *testing.T) {
	identity := newGuardrailFixture(t, CredentialBearerToken).secondary.identity
	handler := workloadActionHandler{newProductID: func() (string, error) { return guardrailTestDecisionID, nil }}
	a := workloadActionRequest{ActionKind: "provider_tool_frame", ActionID: "fixture", Operation: "claude.tool_frame"}
	a.Resource.Kind = "claude_enterprise"
	a.Resource.Classification = "claude.tool_frame.mixed.platform.third_party"
	for cls, want := range map[string]string{"claude.tool_frame.third_party": "block", "claude.tool_frame.platform": "block", "claude.tool_frame.mixed": "block", "claude.tool_frame.client": "allow"} {
		p := sampleToolPolicy("enforced", "resource", cls)
		raw, _ := json.Marshal(p)
		r, err := handler.evaluate(context.Background(), identity, a, workloadAdmission{Revision: "sha256:" + strings.Repeat("a", 64), Policies: []workloadPolicy{{p.ID, 1, raw}}})
		if err != nil || r.Verdict != want {
			t.Fatalf("class %s expected %s: %+v %v", cls, want, r, err)
		}
	}
}
