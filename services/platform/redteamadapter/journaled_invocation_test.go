package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// This controlled journal models commit/lost-ack boundaries. It is not database
// durability evidence; the target path uses the actual HTTPS invoker over TLS.
type journalFixture struct {
	started       bool
	terminal      *InvocationObservation
	lostAck       bool
	requestDigest string
	binding       TargetBinding
	startHook     func(InvocationReceipt) InvocationReceipt
	lostStartAck  bool
	completions   int
	effectKey     string
}

func (j *journalFixture) Start(_ context.Context, r JournalRequest) (InvocationReceipt, error) {
	if j.terminal != nil {
		return InvocationReceipt{TargetComparison: targetComparisonFixture(r), TargetBinding: j.binding, State: "completed", Attempt: 1, RequestDigest: j.requestDigest, Observation: j.terminal, EffectKey: j.effectKey}, nil
	}
	if j.started {
		return InvocationReceipt{}, ErrAdapter
	}
	j.started = true
	j.requestDigest = r.RequestDigest
	j.binding = r.Invocation.Binding
	if j.lostStartAck {
		return InvocationReceipt{}, ErrAdapter
	}
	receipt := InvocationReceipt{TargetComparison: targetComparisonFixture(r), TargetBinding: r.Invocation.Binding, State: "started", Attempt: 1, RequestDigest: r.RequestDigest, EffectKey: j.effectKey}
	if j.startHook != nil {
		receipt = j.startHook(receipt)
	}
	return receipt, nil
}
func (j *journalFixture) Complete(_ context.Context, _ JournalRequest, _ int, o InvocationObservation) error {
	j.completions++
	j.terminal = &o
	if j.lostAck {
		return ErrAdapter
	}
	return nil
}

func TestJournaledInvocationCommitsBeforeSendAndReplaysAfterLostAck(t *testing.T) {
	journal := &journalFixture{lostAck: true}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !journal.started {
			t.Error("request reached target before durable start")
		}
		body, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		if journal.requestDigest != hex.EncodeToString(digest[:]) || r.Header.Get("X-Zasp-Payload-Digest") != "sha256:"+journal.requestDigest {
			t.Error("durable digest differs from signed request body")
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":"Protected response"}`))
	}))
	defer server.Close()
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := JournalRequest{Invocation: Invocation{Scope: testScope(t), RunID: testRunID, Category: "prompt_injection", Input: curatedInputs["prompt_injection"], Binding: TargetBinding{TargetID: testTargetID, TargetKind: "agent_endpoint", Endpoint: "https://adapter.customer.example/v1/evaluate", CredentialReference: "ref:red-team/target-0001", Version: 7}}, LeaseToken: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if _, err := invoker.InvokeJournaled(context.Background(), request, journal); err == nil {
		t.Fatal("lost completion acknowledgement reported success")
	}
	if calls.Load() != 1 || journal.terminal == nil {
		t.Fatalf("no durable observation after target response: calls=%d", calls.Load())
	}
	changed := request
	changed.Invocation.Binding.Endpoint = "https://other.customer.example/v1/evaluate"
	if result, err := invoker.InvokeJournaled(context.Background(), changed, journal); err == nil || result.Protected != nil || calls.Load() != 1 {
		t.Fatalf("replay accepted substituted endpoint: %#v %v calls=%d", result, err, calls.Load())
	}
	result, err := invoker.InvokeJournaled(context.Background(), request, journal)
	if err != nil || result.Protected == nil || !*result.Protected || calls.Load() != 1 {
		t.Fatalf("replay caused resend or lost observation: %#v %v calls=%d", result, err, calls.Load())
	}
	*result.Protected = false
	if !*journal.terminal.Protected {
		t.Fatal("replayed observation aliases durable receipt")
	}
	result.TargetComparison.Categories[0] = "tool_abuse"
	if journal.terminal.TargetComparison.Categories[0] != "prompt_injection" {
		t.Fatal("replayed comparison aliases durable receipt")
	}
	journal.terminal = nil // Model a crash after start, before terminal persistence.
	if _, err := invoker.InvokeJournaled(context.Background(), request, journal); err == nil || calls.Load() != 1 {
		t.Fatalf("unknown outcome retried: %v calls=%d", err, calls.Load())
	}
}

func TestJournaledInvocationRejectsInvalidAdmissionBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":"ok"}`))
	}))
	defer server.Close()
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := JournalRequest{Invocation: Invocation{Scope: testScope(t), RunID: testRunID, Category: "prompt_injection", Input: curatedInputs["prompt_injection"], Binding: TargetBinding{TargetID: testTargetID, TargetKind: "agent_endpoint", Endpoint: "https://adapter.customer.example/v1/evaluate", CredentialReference: "ref:red-team/target-0001", Version: 7}}, LeaseToken: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, mode := range []string{"endpoint", "credential", "target", "kind", "version", "missing_binding", "replay_binding", "digest", "attempt", "state", "missing_receipt", "invalid_receipt", "started_with_receipt", "cancelled", "lost_start_ack", "supplied_digest"} {
		t.Run(mode, func(t *testing.T) {
			calls.Store(0)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			journal := &journalFixture{startHook: func(r InvocationReceipt) InvocationReceipt {
				switch mode {
				case "endpoint":
					r.TargetBinding.Endpoint = "https://other.customer.example/v1/evaluate"
				case "credential":
					r.TargetBinding.CredentialReference = "ref:red-team/other-0001"
				case "target":
					r.TargetBinding.TargetID = testRunID
				case "kind":
					r.TargetBinding.TargetKind = "mcp_server"
				case "version":
					r.TargetBinding.Version++
				case "missing_binding":
					r.TargetBinding = TargetBinding{}
				case "replay_binding":
					r.TargetBinding.Version++
					r.State = "completed"
					protected := true
					r.Observation = &InvocationObservation{HTTPStatus: 200, ResponseDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Protected: &protected}
				case "digest":
					r.RequestDigest = "wrong"
				case "attempt":
					r.Attempt = 6
				case "state":
					r.State = "unknown"
				case "missing_receipt":
					r.State = "completed"
				case "invalid_receipt":
					r.State = "completed"
					r.Observation = &InvocationObservation{HTTPStatus: 500}
				case "started_with_receipt":
					r.Observation = &InvocationObservation{}
				case "cancelled":
					cancel()
				}
				return r
			}}
			journal.lostStartAck = mode == "lost_start_ack"
			candidate := request
			if mode == "supplied_digest" {
				candidate.RequestDigest = "wrong"
			}
			if result, err := invoker.InvokeJournaled(ctx, candidate, journal); err == nil || result.Protected != nil || calls.Load() != 0 {
				t.Fatalf("invalid admission sent request: %#v %v calls=%d", result, err, calls.Load())
			}
		})
	}
}

func TestJournaledInvocationRejectsUnboundEffectReceipt(t *testing.T) {
	journal := &journalFixture{}
	handler, calls, resolver := linkedHandlerFixture(t, journal, `{"output":"Protected response"}`)
	effectHandler, err := NewEffectJournaledHandler(handler.config, resolver, handler.journaledInvoker, journal)
	if err != nil {
		t.Fatal(err)
	}
	r := linkedRequest(t)
	r.URL.Path = "/v1/effects/evaluate"
	r.Header.Del("X-Zasp-Run-Lease")
	r.Header.Set("X-Zasp-Effect-Key", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	response := httptest.NewRecorder()
	effectHandler.ServeHTTP(response, r)
	if response.Code == http.StatusOK || calls.Load() != 0 {
		t.Fatalf("receipt without exact effect binding sent provider request: status=%d calls=%d", response.Code, calls.Load())
	}
}

func TestJournaledInvocationPersistsUnsafeButNotInvalidResponses(t *testing.T) {
	for _, body := range []string{`{"output":"ZASP_RED_TEAM_PROMPT_INJECTION"}`, `{"output":null}`, "transport_closed"} {
		t.Run(body, func(t *testing.T) {
			journal := &journalFixture{}
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if body == "transport_closed" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			request := JournalRequest{Invocation: Invocation{Scope: testScope(t), RunID: testRunID, Category: "prompt_injection", Input: curatedInputs["prompt_injection"], Binding: TargetBinding{TargetID: testTargetID, TargetKind: "agent_endpoint", Endpoint: "https://adapter.customer.example/v1/evaluate", CredentialReference: "ref:red-team/target-0001", Version: 7}}, LeaseToken: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			result, err := invoker.InvokeJournaled(context.Background(), request, journal)
			if body == `{"output":null}` || body == "transport_closed" {
				if err == nil || result.Protected != nil || journal.completions != 0 {
					t.Fatalf("invalid response persisted: %#v %v", result, err)
				}
				if _, err := invoker.InvokeJournaled(context.Background(), request, journal); err == nil || calls.Load() != 1 {
					t.Fatal("invalid response caused retry")
				}
			} else if err != nil || result.Protected == nil || *result.Protected || journal.completions != 1 || journal.terminal == nil || *journal.terminal.Protected {
				t.Fatalf("unsafe response not preserved: %#v %v", result, err)
			}
		})
	}
}
