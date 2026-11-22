package providerhooks

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
	"strconv"
	"strings"
	"testing"
	"time"
)

const pid = "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func hookConfig() Config {
	return Config{Integration: pid, Tenant: "org-test", Secret: "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{231}, 32)), ReferenceKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{22}, 32)), Scope: Scope{pid, pid, pid, pid}}
}
func hookRequest(raw, id string, delta int64) *http.Request {
	stamp := strconv.FormatInt(time.Now().Unix()+delta, 10)
	m := hmac.New(sha256.New, bytes.Repeat([]byte{231}, 32))
	m.Write([]byte(id + "." + stamp + "." + raw))
	r := httptest.NewRequest("POST", ClaudePath+pid, strings.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("webhook-id", id)
	r.Header.Set("webhook-timestamp", stamp)
	r.Header.Set("webhook-signature", "v0,unused v1,"+base64.StdEncoding.EncodeToString(m.Sum(nil)))
	return r
}
func call(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestClaudeVerifiedFrames(t *testing.T) {
	const prompt = `{"type":"prompt","request_id":"d1","tenant_id":"org-test","actor":{"email":"private@example.invalid"},"session_id":"private-session","source":{"application":"code"},"messages":[{"role":"user","content":"private transcript"}]}`
	const tool = `{"type":"tool_call","request_id":"d2","tenant_id":"org-test","messages":[{"role":"assistant","content":[{"type":"tool_use","name":"private-tool","input":{"private":"secret"},"tool_info":{"type":"platform"}},{"type":"tool_use","tool_info":{"type":"third_party"}}]}]}`
	var actions []Action
	h, err := NewClaude(hookConfig(), func(ctx context.Context, a Action) (Decision, error) {
		scope, ok := Binding(ctx)
		if !ok || scope != hookConfig().Scope {
			t.Error("missing verified scope")
		}
		actions = append(actions, a)
		verdict := "allow"
		if a.Kind == "provider_tool_frame" {
			verdict = "block"
		}
		return Decision{a.ID, pid, "enforce", verdict}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ body, id, class, expected string }{{prompt, "d1", "claude.prompt", `"action":"allow"`}, {tool, "d2", "claude.tool_frame.mixed.platform.third_party", `"action":"deny"`}, {`{"type":"prompt","request_id":"d3","tenant_id":null,"source":{"application":"config-test"},"messages":[]}`, "d3", "claude.prompt", `"action":"allow"`}} {
		w := call(h, hookRequest(tc.body, tc.id, 0))
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.expected) {
			t.Fatal(w.Code, w.Body)
		}
		a := actions[len(actions)-1]
		if a.Resource.Classification != tc.class {
			t.Fatal(a)
		}
		encoded, _ := json.Marshal(a)
		if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "org-test") {
			t.Fatal("private fields forwarded")
		}
	}
	first := actions[0]
	w := call(h, hookRequest(prompt, "d1", 0))
	if w.Code != 200 || actions[len(actions)-1] != first {
		t.Fatal("unstable retry")
	}
	call(h, hookRequest(strings.Replace(prompt, "private transcript", "changed", 1), "d1", 0))
	changed := actions[len(actions)-1]
	if changed.ID != first.ID || changed.Call == first.Call {
		t.Fatal("changed body not detectable")
	}
	before := len(actions)
	for _, tc := range []struct {
		body, id string
		delta    int64
		status   int
	}{
		{prompt, "d1", -301, 401}, {prompt, "d1", 302, 401}, {prompt, "wrong", 0, 400}, {strings.Replace(prompt, "org-test", "other", 1), "d1", 0, 403},
		{`{"type":"prompt","request_id":"d1"}`, "d1", 0, 403}, {strings.Replace(tool, "tool_use", "ignore", 2), "d2", 0, 400}, {strings.Replace(prompt, `"type":"prompt"`, `"type":"future"`, 1), "d1", 0, 200},
	} {
		if w := call(h, hookRequest(tc.body, tc.id, tc.delta)); w.Code != tc.status {
			t.Fatalf("want %d got %d", tc.status, w.Code)
		}
	}
	r := hookRequest(prompt, "d1", 0)
	r.Header.Add("webhook-id", "d1")
	if call(h, r).Code != 401 {
		t.Fatal("duplicate id")
	}
	r = hookRequest(prompt, "d1", 0)
	r.Header.Set("webhook-signature", "v1,unverified")
	if call(h, r).Code != 401 {
		t.Fatal("invalid signature")
	}
	r = hookRequest(prompt, "d1", 0)
	r.ContentLength = maxFrame + 1
	if call(h, r).Code != 413 {
		t.Fatal("oversize accepted")
	}
	if len(actions) != before {
		t.Fatal("unverified/unknown frame reached product admission")
	}
}
func TestClaudeUncertainDecisionsAndDeadline(t *testing.T) {
	const prompt = `{"type":"prompt","request_id":"d","tenant_id":"org-test","messages":[]}`
	for _, tc := range []struct {
		err    error
		status int
	}{{ErrConflict, 409}, {ErrIncompatible, 422}, {errors.New("unavailable"), 503}, {nil, 503}} {
		h, _ := NewClaude(hookConfig(), func(context.Context, Action) (Decision, error) { return Decision{}, tc.err })
		if w := call(h, hookRequest(prompt, "d", 0)); w.Code != tc.status {
			t.Fatalf("want %d got %d", tc.status, w.Code)
		}
	}
	release := make(chan struct{})
	defer close(release)
	h, _ := NewClaude(hookConfig(), func(context.Context, Action) (Decision, error) { <-release; return Decision{}, nil })
	start := time.Now()
	w := call(h, hookRequest(prompt, "d", 0))
	if w.Code != 503 && w.Code != 504 || time.Since(start) > 800*time.Millisecond {
		t.Fatalf("deadline: status=%d elapsed=%v", w.Code, time.Since(start))
	}
}

func TestClaudeTypedFailuresKeepFramePrivate(t *testing.T) {
	const frame = `{"type":"prompt","request_id":"opaque-private-id","tenant_id":"org-test","messages":[]}`
	for _, tc := range []struct {
		status  int
		code    string
		failure error
	}{
		{401, "authentication_required", nil}, {413, "request_too_large", nil},
		{409, "action_id_conflict", ErrConflict}, {422, "policy_context_unavailable", ErrIncompatible},
	} {
		h, err := NewClaude(hookConfig(), func(context.Context, Action) (Decision, error) { return Decision{}, tc.failure })
		if err != nil {
			t.Fatal(err)
		}
		r := hookRequest(frame, "opaque-private-id", 0)
		if tc.status == 401 {
			r.Header.Del("webhook-signature")
		}
		if tc.status == 413 {
			r.ContentLength = maxFrame + 1
		}
		w := call(h, r)
		var response struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			ID        string `json:"correlation_id"`
			Retryable *bool  `json:"retryable"`
		}
		if w.Code != tc.status || w.Header().Get("Content-Type") != "application/json" || json.Unmarshal(w.Body.Bytes(), &response) != nil ||
			response.Code != tc.code || response.Message == "" || !productID.MatchString(response.ID) || response.Retryable == nil || *response.Retryable ||
			strings.Contains(w.Body.String(), "opaque-private-id") {
			t.Fatalf("incorrect typed HTTP %d error: %s", tc.status, w.Body)
		}
	}
}
