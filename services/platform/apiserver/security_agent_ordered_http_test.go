package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func orderedHTTPRequest(id RequestIdentity, operation, method, resource, body string) *http.Request {
	r := httptest.NewRequest(method, "/api/v1/security-agent/"+resource, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "ordered-http-key-01")
	r.Header.Set("If-Match", `"1"`)
	r.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	ctx := context.WithValue(r.Context(), identityContextKey{}, id)
	ctx = context.WithValue(ctx, routedOperationContextKey{}, RoutedOperation{operation, map[string]string{"id": resource}})
	return r.WithContext(ctx)
}

func orderedHTTPAuthority(t *testing.T, family string, response any, failure error) (*SecurityAgentOrderedResourceAuthority, *orderedPublicDB) {
	t.Helper()
	db := &orderedPublicDB{query: func(_ context.Context, _ string, args ...any) (json.RawMessage, error) {
		var q map[string]any
		if json.Unmarshal(args[2].(json.RawMessage), &q) != nil {
			t.Fatal("bad SQL request")
		}
		if failure != nil {
			return nil, failure
		}
		switch q["operation"] {
		case "classify_trigger_key":
			return json.Marshal(map[string]any{"contract_version": 62, "definition_id": q["definition_id"], "idempotency_key": q["idempotency_key"], "family": family})
		case "classify":
			return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": q["resource_kind"], "resource_id": q["resource_id"], "family": family})
		case "classify_mutation":
			return json.Marshal(map[string]any{"contract_version": 62, "mutation_kind": q["mutation_kind"], "definition_id": q["definition_id"], "idempotency_key": q["idempotency_key"], "trigger": q["trigger"], "family": family})
		}
		return json.Marshal(response)
	}}
	a, err := NewSecurityAgentOrderedResourceAuthority(db)
	if err != nil {
		t.Fatal(err)
	}
	return a, db
}

func orderedHTTPHandler(t *testing.T, a *SecurityAgentOrderedResourceAuthority, legacy http.Handler) http.Handler {
	t.Helper()
	h, err := newSecurityAgentOrderedHTTPHandler(a, &orderedListLegacy{}, func() (http.Handler, error) { return legacy, nil }, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSecurityAgentOrderedHTTPRead(t *testing.T) {
	id := orderedPublicIdentity()
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued", true: "admitted"}[admitted], func(t *testing.T) {
			a, _ := orderedHTTPAuthority(t, "ordered_release61", orderedResourceFixture(id, public62Definition, admitted), nil)
			h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("ordered fell through") }))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, orderedHTTPRequest(id, "getSecurityAgentRun", "GET", public62Definition, ""))
			if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("ETag") == "" {
				t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body.String())
			}
			var got struct {
				SecurityAgentRunDetail
				Ordered struct {
					ContractVersion int                       `json:"contract_version"`
					Steps           []SecurityAgentPublicStep `json:"steps"`
				} `json:"ordered"`
			}
			if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Run.ID != public62Definition || got.Ordered.ContractVersion != 62 || len(got.Ordered.Steps) != map[bool]int{false: 0, true: 2}[admitted] {
				t.Fatal(w.Body.String())
			}
			if admitted && (!got.Ordered.Steps[1].Dependency.Blocked || got.Ordered.Steps[1].Action != "run_test") {
				t.Fatal(w.Body.String())
			}
			for _, private := range []string{"organization_id", "actor_id", "lease_token", "worker_id", "credential", "provider_payload"} {
				if strings.Contains(w.Body.String(), private) {
					t.Fatal(private, w.Body.String())
				}
			}
		})
	}
}

func TestSecurityAgentOrderedHTTPLegacyPreservesRequest(t *testing.T) {
	id := orderedPublicIdentity()
	for _, op := range []string{"getSecurityAgentActivation", "activateSecurityAgent", "runSecurityAgent", "getSecurityAgentRun", "cancelSecurityAgentRun", "getSecurityAgentApproval", "decideSecurityAgentApproval"} {
		t.Run(op, func(t *testing.T) {
			a, _ := orderedHTTPAuthority(t, "legacy_or_missing", nil, nil)
			method, body := "GET", ""
			if op == "activateSecurityAgent" {
				method, body = "POST", ` { "activation" : "autonomous" } `
			}
			if op == "decideSecurityAgentApproval" {
				method, body = "POST", ` { "decision" : "cancelled" } `
			}
			if op == "cancelSecurityAgentRun" {
				method = "POST"
			}
			if op == "runSecurityAgent" {
				method, body = "POST", ` {"environment_id":"`+id.Scope.EnvironmentID().String()+`","trigger_kind":"finding","trigger_id":"`+public62Finding+`"} `
			}
			r := orderedHTTPRequest(id, op, method, public62Definition, body)
			header := r.Header.Clone()
			ctx := r.Context()
			calls := 0
			h := orderedHTTPHandler(t, a, http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
				calls++
				b, e := io.ReadAll(got.Body)
				if e != nil || string(b) != body || got.Method != method || got.URL.String() != r.URL.String() || got.Context() != ctx || !reflect.DeepEqual(got.Header, header) {
					t.Fatal("changed delegated request")
				}
				w.WriteHeader(202)
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if calls != 1 || w.Code != 202 {
				t.Fatal(calls, w.Code, w.Body.String())
			}
		})
	}
}

func TestSecurityAgentOrderedHTTPActivation(t *testing.T) {
	id := public62FreshIdentity()
	audit, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1factivate_resource\x1fordered-http-key-01")
	receipt, _ := CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1factivate_resource\x1fordered-http-key-01")
	a, _ := orderedHTTPAuthority(t, "ordered_release61", map[string]any{"contract_version": 62, "id": public62Definition, "activation": "supervised", "enabled": true, "version": 2, "audit_id": audit, "correlation_id": audit, "receipt_id": receipt, "replayed": false}, nil)
	h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("ordered delegated") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, orderedHTTPRequest(id, "activateSecurityAgent", "POST", public62Definition, `{"activation":"supervised"}`))
	if w.Code != 200 || w.Header().Get("ETag") != `"2"` || w.Header().Get("X-Audit-ID") != audit || w.Header().Get("X-Mutation-Receipt-ID") != receipt || w.Body.String() != `{"id":"`+public62Definition+`","activation":"supervised","enabled":true,"version":2}`+"\n" {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
}

func TestSecurityAgentOrderedHTTPIncompleteTriggerRefuses(t *testing.T) {
	// Key-only classification establishes ownership, never the missing version.
	id := orderedPublicIdentity()
	a, db := orderedHTTPAuthority(t, "ordered_release61", nil, nil)
	h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("incomplete trigger delegated") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, orderedHTTPRequest(id, "runSecurityAgent", "POST", public62Definition, `{"environment_id":"`+id.Scope.EnvironmentID().String()+`","trigger_kind":"finding","trigger_id":"`+public62Finding+`"}`))
	if w.Code != 400 || db.calls != 1 {
		t.Fatal(w.Code, db.calls, w.Body.String())
	}
}

func TestSecurityAgentOrderedHTTPBearerAndBadBodies(t *testing.T) {
	for _, op := range []string{"getSecurityAgentActivation", "activateSecurityAgent", "runSecurityAgent", "getSecurityAgentRun", "cancelSecurityAgentRun", "getSecurityAgentApproval", "decideSecurityAgentApproval"} {
		id := public62FreshIdentity()
		id.CredentialKind = CredentialBearerToken
		body, method := "", "GET"
		switch op {
		case "activateSecurityAgent":
			body, method = `{"activation":"supervised"}`, "POST"
		case "runSecurityAgent":
			body, method = `{"environment_id":"`+id.Scope.EnvironmentID().String()+`","trigger_kind":"finding","trigger_id":"`+public62Finding+`","trigger_version":1,"trigger_source":"credential"}`, "POST"
		case "cancelSecurityAgentRun":
			method = "POST"
		case "decideSecurityAgentApproval":
			body, method = `{"decision":"approved"}`, "POST"
		}
		a, db := orderedHTTPAuthority(t, "ordered_release61", nil, nil)
		h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("bearer delegated") }))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, orderedHTTPRequest(id, op, method, public62Definition, body))
		if w.Code != 400 || db.calls != 1 {
			t.Fatal(op, w.Code, db.calls, w.Body.String())
		}
	}
	for _, body := range []string{`{`, strings.Repeat("x", 16385), `{"activation":"supervised","activation":"autonomous"}`, `{"activation":"supervised","worker_id":"private"}`} {
		a, db := orderedHTTPAuthority(t, "legacy_or_missing", nil, nil)
		h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("malformed delegated") }))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, orderedHTTPRequest(public62FreshIdentity(), "activateSecurityAgent", "POST", public62Definition, body))
		if w.Code != 400 || db.calls != 0 {
			t.Fatal(w.Code, db.calls, w.Body.String())
		}
	}
}

func TestSecurityAgentOrderedHTTPRefusesErrorsAndDelegatesUnintercepted(t *testing.T) {
	for _, op := range []string{"getSecurityAgentRun", "listSecurityAgents", "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "getSecurityAgentExecutionControls", "setSecurityAgentExecutionControl", "simulateSecurityAgent", "getSecurityAgent", "listSecurityAgentActivity"} {
		a, db := orderedHTTPAuthority(t, "ordered_release61", nil, errors.New("private SQL failure"))
		h := orderedHTTPHandler(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if op == "getSecurityAgentRun" {
				t.Fatal("classification error delegated")
			}
			w.WriteHeader(218)
			_, _ = w.Write([]byte("legacy response"))
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, orderedHTTPRequest(orderedPublicIdentity(), op, "GET", public62Definition, ""))
		if op == "getSecurityAgentRun" && (w.Code != 503 || strings.Contains(w.Body.String(), "private SQL")) {
			t.Fatal(op, w.Code, w.Body.String())
		}
		if op != "getSecurityAgentRun" && (db.calls != 0 || w.Code != 218 || w.Body.String() != "legacy response") {
			t.Fatal("unintercepted operation changed", op, db.calls, w.Code, w.Body.String())
		}
	}
}

func TestSecurityAgentOrderedHTTPConstruction(t *testing.T) {
	a, _ := orderedHTTPAuthority(t, "legacy_or_missing", nil, nil)
	for _, factory := range []func() (http.Handler, error){nil, func() (http.Handler, error) { panic("private") }, func() (http.Handler, error) { return nil, nil }, func() (http.Handler, error) { return http.HandlerFunc(nil), nil }, func() (http.Handler, error) { return http.NotFoundHandler(), errors.New("failed") }} {
		h, err := newSecurityAgentOrderedHTTPHandler(a, &orderedListLegacy{}, factory, []byte(strings.Repeat("k", 32)))
		if h != nil || err != ErrRepositoryConfiguration {
			t.Fatal(h, err)
		}
	}
	for _, a := range []*SecurityAgentOrderedResourceAuthority{nil, {}} {
		h, err := newSecurityAgentOrderedHTTPHandler(a, &orderedListLegacy{}, func() (http.Handler, error) { return http.NotFoundHandler(), nil }, []byte(strings.Repeat("k", 32)))
		if h != nil || err != ErrRepositoryConfiguration {
			t.Fatal(h, err)
		}
	}
}

func TestSecurityAgentOrderedHTTPGatedProductionComposition(t *testing.T) {
	// Only the readiness-gated composition helper may construct the router.
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := file.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if (ident.Name == "newSecurityAgentOrderedHTTPHandler" || ident.Name == "securityAgentOrderedHTTPHandler") && name != "security_agent_ordered_http.go" && name != "security_agent_ordered_list.go" && name != "security_agent_ordered_production.go" {
				t.Errorf("router referenced outside gated composition %s", name)
			}
			return true
		})
		if name == "security_agent_ordered_http.go" {
			for _, decl := range parsed.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && ast.IsExported(fn.Name.Name) {
					t.Errorf("exported dormant constructor/function %s", fn.Name.Name)
				}
			}
		}
	}
}

func TestSecurityAgentOrderedHTTPErrorIsolation(t *testing.T) {
	id := public62FreshIdentity()
	for _, op := range []string{"getSecurityAgentActivation", "activateSecurityAgent", "runSecurityAgent", "getSecurityAgentRun", "cancelSecurityAgentRun", "getSecurityAgentApproval", "decideSecurityAgentApproval"} {
		for _, stage := range []string{"classification", "lifecycle", "decode", "wrapped-not-owned"} {
			t.Run(op+"/"+stage, func(t *testing.T) {
				db := &orderedPublicDB{query: func(_ context.Context, _ string, args ...any) (json.RawMessage, error) {
					var q map[string]any
					_ = json.Unmarshal(args[2].(json.RawMessage), &q)
					if stage == "classification" {
						return nil, errors.New("private SQL tenant secret")
					}
					if stage == "wrapped-not-owned" {
						return nil, fmt.Errorf("private: %w", ErrSecurityAgentNotOwned)
					}
					if q["operation"] == "classify" {
						return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": q["resource_kind"], "resource_id": q["resource_id"], "family": "ordered_release61"})
					}
					if q["operation"] == "classify_mutation" {
						return json.Marshal(map[string]any{"contract_version": 62, "mutation_kind": q["mutation_kind"], "definition_id": q["definition_id"], "idempotency_key": q["idempotency_key"], "trigger": q["trigger"], "family": "ordered_release61"})
					}
					if stage == "decode" {
						return json.RawMessage(`{"contract_version":62,"private_payload":"secret"}`), nil
					}
					return nil, ErrRepositoryConflict
				}}
				a, _ := NewSecurityAgentOrderedResourceAuthority(db)
				h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("error delegated") }))
				method, body := "GET", ""
				switch op {
				case "activateSecurityAgent":
					method, body = "POST", `{"activation":"supervised"}`
				case "runSecurityAgent":
					method, body = "POST", `{"environment_id":"`+id.Scope.EnvironmentID().String()+`","trigger_kind":"finding","trigger_id":"`+public62Finding+`","trigger_version":1,"trigger_source":"credential"}`
				case "cancelSecurityAgentRun":
					method = "POST"
				case "decideSecurityAgentApproval":
					method, body = "POST", `{"decision":"approved"}`
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, orderedHTTPRequest(id, op, method, public62Definition, body))
				want := 503
				if stage == "lifecycle" && (op == "activateSecurityAgent" || op == "runSecurityAgent" || op == "decideSecurityAgentApproval") {
					want = 409
				}
				if w.Code != want || w.Header().Get("X-Audit-ID") != "" || w.Header().Get("X-Mutation-Receipt-ID") != "" || strings.Contains(w.Body.String(), "secret") {
					t.Fatal(w.Code, w.Header(), w.Body.String())
				}
			})
		}
	}
}

func TestSecurityAgentOrderedHTTPRequestValidation(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-identity": func(r *http.Request) {
			*r = *r.WithContext(context.WithValue(r.Context(), identityContextKey{}, RequestIdentity{}))
		},
		"version":           func(r *http.Request) { r.Header.Set("If-Match", `"0"`) },
		"duplicate-version": func(r *http.Request) { r.Header.Add("If-Match", `"1"`) },
		"key":               func(r *http.Request) { r.Header.Set("Idempotency-Key", "bad") },
		"duplicate-key":     func(r *http.Request) { r.Header.Add("Idempotency-Key", "ordered-http-key-02") },
		"query":             func(r *http.Request) { r.URL.RawQuery = "unexpected=1" },
		"method":            func(r *http.Request) { r.Method = "PUT" },
		"content-type":      func(r *http.Request) { r.Header.Add("Content-Type", "application/json") },
		"cancelled-context": func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, db := orderedHTTPAuthority(t, "ordered_release61", nil, nil)
			h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid input delegated") }))
			r := orderedHTTPRequest(public62FreshIdentity(), "activateSecurityAgent", "POST", public62Definition, `{"activation":"supervised"}`)
			change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 || db.calls != 0 {
				t.Fatal(w.Code, db.calls, w.Body.String())
			}
		})
	}
	for _, op := range []string{"activateSecurityAgent", "decideSecurityAgentApproval"} {
		for _, mode := range []string{"expired", "missing-confirmation", "not-fresh"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				id := public62FreshIdentity()
				if mode == "expired" {
					id.FreshAuthExpiresAt = time.Now().UTC().Add(-time.Minute)
				}
				if mode == "not-fresh" {
					id.FreshAuthenticated = false
				}
				body := `{"activation":"supervised"}`
				if op == "decideSecurityAgentApproval" {
					body = `{"decision":"approved"}`
				}
				a, db := orderedHTTPAuthority(t, "ordered_release61", nil, nil)
				h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("auth failure delegated") }))
				r := orderedHTTPRequest(id, op, "POST", public62Definition, body)
				if mode == "missing-confirmation" {
					r.Header.Del("X-Zasp-Fresh-Auth")
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 401 || db.calls != 1 {
					t.Fatal(w.Code, db.calls, w.Body.String())
				}
			})
		}
	}
}
