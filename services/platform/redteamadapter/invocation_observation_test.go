package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Local TLS responses exercise the actual invoker. No persistence or live
// customer-target acceptance is claimed by these component tests.
func TestHTTPSInvokerProducesRedactedCuratedObservation(t *testing.T) {
	for _, category := range []string{"prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information"} {
		for _, unsafe := range []bool{false, true} {
			t.Run(category+map[bool]string{false: "_protected", true: "_unsafe"}[unsafe], func(t *testing.T) {
				output := "Customer confidential response"
				if unsafe {
					output += " ZASP_RED_TEAM_" + strings.ToUpper(category)
				}
				body, _ := json.Marshal(Response{Output: output})
				var calls atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(body)
				}))
				defer server.Close()
				resolver := &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}
				invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, resolver, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				request := Invocation{Scope: testScope(t), RunID: testRunID, Category: category, Input: curatedInputs[category], Binding: TargetBinding{TargetID: testTargetID, TargetKind: "agent_endpoint", Endpoint: "https://adapter.customer.example/v1/evaluate", CredentialReference: "ref:red-team/target-0001", Version: 7}}
				actual, observation, err := invoker.InvokeObserved(context.Background(), request)
				raw, _ := json.Marshal(observation)
				var receipt struct {
					HTTPStatus     int    `json:"http_status"`
					ResponseDigest string `json:"response_digest"`
					Protected      *bool  `json:"protected"`
				}
				digest := sha256.Sum256(body)
				if err != nil || actual != output || json.Unmarshal(raw, &receipt) != nil || receipt.HTTPStatus != 200 || receipt.ResponseDigest != hex.EncodeToString(digest[:]) || receipt.Protected == nil || *receipt.Protected == unsafe || calls.Load() != 1 || strings.Contains(string(raw), "Customer confidential") {
					t.Fatalf("observation=%s err=%v calls=%d", raw, err, calls.Load())
				}
			})
		}
	}
}
