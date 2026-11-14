package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Only a provider answer that proves the request was refused before any
// generation is a definite rejection. Everything else stays unknown.
func TestClassifyPlannerProviderRejection(t *testing.T) {
	const credits = `{"error":{"message":"Insufficient credits. This account never purchased credits.","code":402,"metadata":{"limit_source":"openrouter_credits"}}}`
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"insufficient credits": {402, credits},
		"invalid credentials":  {401, `{"error":{"message":"No auth credentials found","code":401}}`},
		"rate limited":         {429, `{"error":{"message":"Rate limit exceeded","code":429,"metadata":{"headers":{}}},"user_id":"user_1"}`},
	} {
		rejection := classifyPlannerProviderRejection(tc.status, []byte(tc.body))
		if rejection == nil || rejection.Status != tc.status || string(rejection.Body) != tc.body {
			t.Fatalf("%s was not a definite rejection: %+v", name, rejection)
		}
		payload, err := json.Marshal(rejection.payload())
		want, _ := json.Marshal(map[string]any{"rejected": map[string]any{"status": tc.status, "raw": tc.body}})
		if err != nil || string(payload) != string(want) {
			t.Fatalf("%s payload = %s", name, payload)
		}
	}
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"a moderation block":             {403, `{"error":{"message":"flagged","code":403,"metadata":{"reasons":["x"]}}}`},
		"a bad request":                  {400, `{"error":{"message":"bad","code":400}}`},
		"a timeout":                      {408, `{"error":{"message":"timeout","code":408}}`},
		"a model failure":                {502, `{"error":{"message":"down","code":502}}`},
		"no provider":                    {503, `{"error":{"message":"none","code":503}}`},
		"a success status":               {200, credits},
		"another code than the status":   {402, `{"error":{"message":"x","code":429}}`},
		"a code as text":                 {402, `{"error":{"message":"x","code":"402"}}`},
		"no code":                        {402, `{"error":{"message":"x"}}`},
		"no error":                       {402, `{"message":"x","code":402}`},
		"an error that is not an object": {402, `{"error":"Insufficient credits"}`},
		"usage":                          {402, `{"error":{"code":402},"usage":{"total_tokens":10}}`},
		"choices":                        {402, `{"error":{"code":402},"choices":[]}`},
		"a response identifier":          {402, `{"error":{"code":402},"id":"gen-1"}`},
		"a repeated key":                 {402, `{"error":{"code":402},"error":{"code":402}}`},
		"not JSON":                       {402, `<html>Payment Required</html>`},
		"JSON null":                      {402, `null`},
		"an array":                       {402, `[{"error":{"code":402}}]`},
		"an empty body":                  {402, ``},
		"invalid text":                   {402, "{\"error\":{\"code\":402,\"message\":\"\xff\"}}"},
		"a body that is too large":       {402, `{"error":{"code":402,"message":"` + strings.Repeat("x", securityAgentPlannerRejectionLimit) + `"}}`},
	} {
		if rejection := classifyPlannerProviderRejection(tc.status, []byte(tc.body)); rejection != nil {
			t.Fatalf("%s was classified as a definite rejection", name)
		}
	}
}

func TestPlannerRejectionFromSendError(t *testing.T) {
	rejection := classifyPlannerProviderRejection(402, []byte(`{"error":{"code":402}}`))
	if rejection == nil || plannerRejectionFrom(rejection) != rejection || plannerRejectionFrom(errors.Join(errWorkerExecution, rejection)) != rejection {
		t.Fatal("a definite rejection was not recognised")
	}
	if plannerRejectionFrom(errWorkerExecution) != nil || plannerRejectionFrom(nil) != nil || plannerRejectionFrom((*plannerProviderRejection)(nil)) != nil {
		t.Fatal("an unknown outcome was read as a rejection")
	}
	// The planning database refuses evidence that does not prove a rejection
	// before it asks PostgreSQL anything.
	database := &workerFindingPlanningDatabase{}
	if err := database.RecoverRejectedPlanning(context.Background(), json.RawMessage(`{}`), &plannerProviderRejection{Status: 403, Body: []byte(`{"error":{"code":403}}`)}); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("unproven evidence: err=%v", err)
	}
	if err := database.RecoverRejectedPlanning(context.Background(), json.RawMessage(`{}`), nil); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("no evidence: err=%v", err)
	}
	ordered := &workerFindingPlanningDatabase{family: workerPlanningOrdered68}
	if err := ordered.RecoverRejectedPlanning(context.Background(), json.RawMessage(`{}`), rejection); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("ordered release: err=%v", err)
	}
}

// A step is decided again only for a pending projection or a moved revision.
func TestRetryWorkerAuthorization(t *testing.T) {
	calls := 0
	if err := retryWorkerAuthorization(context.Background(), func() error {
		calls++
		if calls < 3 {
			return authorization.ErrPending
		}
		return nil
	}); err != nil || calls != 3 {
		t.Fatalf("pending step: err=%v calls=%d", err, calls)
	}
	calls = 0
	if err := retryWorkerAuthorization(context.Background(), func() error { calls++; return authorization.ErrDenied }); !errors.Is(err, authorization.ErrDenied) || calls != 1 {
		t.Fatalf("denied step: err=%v calls=%d", err, calls)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if err := retryWorkerAuthorization(cancelled, func() error { calls++; return authorization.ErrConflict }); !errors.Is(err, authorization.ErrConflict) || calls != 1 {
		t.Fatalf("cancelled step: err=%v calls=%d", err, calls)
	}
}
