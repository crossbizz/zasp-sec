package optionalegress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testIntent() Intent {
	return Intent{OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", ActorID: "pid_44444444-4444-4444-8444-444444444444", FindingID: "pid_55555555-5555-4555-8555-555555555555", FindingVersion: 1, IdempotencyKey: "finding-explanation-intent-0001", Purpose: Purpose}
}

var ownedTestNow = time.Now().UTC().Truncate(time.Second)

func testClock() time.Time { return ownedTestNow }
func testToken() []byte    { return []byte(strings.Repeat("X", 48)) }
func testSource(t *testing.T) Source {
	t.Helper()
	i := testIntent()
	p := Profile{ProfileID: "pid_66666666-6666-4666-8666-666666666666", ProfileVersion: 1, Provider: "openrouter", Purpose: Purpose, Model: "openai/gpt-5-mini", Backend: "OpenAI", AccountID: "controlled-test-account", CredentialReference: "secret_ref_ai/" + i.OrganizationID + "/" + i.WorkspaceID + "/" + i.EnvironmentID + "/provider", CredentialDigest: digest(testToken()), CapabilityDigest: digest([]byte("controlled-capability-receipt")), PricingDigest: digest([]byte("controlled-price-receipt")), EffectiveAt: testClock().Add(-time.Hour).Format(TimeFormat), ExpiresAt: testClock().Add(time.Hour).Format(TimeFormat), InputTokenBound: 100000, OutputTokenCap: 512, PromptPriceNanoCreditsPerMillion: 1000000000, CompletionPriceNanoCreditsPerMillion: 2000000000, CostCeilingNanoCredits: 200000000, MaximumOutstandingNanoCredits: 500000000, MaximumConcurrency: 2, TimeoutMilliseconds: 10000, PolicyVersion: "finding-explanation-v1"}
	var e error
	p.ProfileDigest, e = ProfileDigest(p)
	if e != nil {
		t.Fatal(e)
	}
	summary := Summary{FindingID: i.FindingID, Version: i.FindingVersion, Rule: "ownerless_agent", Severity: "high", EvidenceCount: 3}
	summary.SourceDigest, e = SourceDigest(summary)
	if e != nil {
		t.Fatal(e)
	}
	return Source{Summary: summary, Profile: p}
}
func testPrepared(t *testing.T) *Prepared {
	t.Helper()
	p, e := Prepare(testIntent(), testSource(t), "pid_77777777-7777-4777-8777-777777777777", testClock())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestGovernedPreparationPrivacyAndBounds(t *testing.T) {
	p := testPrepared(t)
	if bytes.Contains(p.body, []byte(testIntent().FindingID)) || bytes.Contains(p.body, []byte(testIntent().OrganizationID)) || bytes.Contains(p.body, []byte("credential_reference")) {
		t.Fatal("private identifiers reached provider body")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(p.body, &body) != nil || len(body) != 6 {
		t.Fatal("unexpected body")
	}
	var provider map[string]json.RawMessage
	_ = json.Unmarshal(body["provider"], &provider)
	for _, k := range []string{"zdr", "require_parameters"} {
		if string(provider[k]) != "true" {
			t.Fatal("privacy constraint missing", k)
		}
	}
	if string(provider["allow_fallbacks"]) != "false" || string(provider["data_collection"]) != `"deny"` || string(provider["only"]) != `["OpenAI"]` {
		t.Fatal("provider constraints differ")
	}
	if p.binding.CostCeilingNanoCredits != 101024000 {
		t.Fatal("wrong exact ceiling", p.binding.CostCeilingNanoCredits)
	}
	for _, name := range []string{"unknown rule", "bad summary pin", "profile drift", "expired profile", "over cost", "foreign credential", "too many tokens", "too large price"} {
		t.Run(name, func(t *testing.T) {
			s := testSource(t)
			switch name {
			case "unknown rule":
				s.Summary.Rule = "user medical record"
			case "bad summary pin":
				s.Summary.EvidenceCount++
			case "profile drift":
				s.Profile.Model = "other/model"
			case "expired profile":
				s.Profile.ExpiresAt = testClock().Add(-time.Second).Format(TimeFormat)
			case "over cost":
				s.Profile.CostCeilingNanoCredits = 1
			case "foreign credential":
				s.Profile.CredentialReference = strings.Replace(s.Profile.CredentialReference, testIntent().OrganizationID, testIntent().ActorID, 1)
			case "too many tokens":
				s.Profile.InputTokenBound = 1000001
			case "too large price":
				s.Profile.PromptPriceNanoCreditsPerMillion = 1000000000001
			}
			if name != "profile drift" {
				s.Profile.ProfileDigest, _ = ProfileDigest(s.Profile)
			}
			if _, e := Prepare(testIntent(), s, p.binding.RequestID, testClock()); e == nil {
				t.Fatal("unsafe preparation accepted")
			}
		})
	}
	if _, e := priceCeiling(9223372036854775807, 9223372036854775807, 9223372036854775807, 9223372036854775807); e == nil {
		t.Fatal("overflow accepted")
	}
	for _, value := range []string{"1e999999999", "-1", "999999999999999999999999", "null"} {
		if _, e := nanoCost(json.Number(value)); e == nil {
			t.Fatal("unsafe numeric usage", value)
		}
	}
	if got, e := nanoCost(json.Number("1")); e != nil || got != 1000000000 || decimalPrice(1000000000) != "1.000000000" {
		t.Fatal("USD/nanoUSD conversion differs", got, e)
	}
	if got, e := nanoCost(json.Number("0.0000000001")); e != nil || got != 1 {
		t.Fatal("fractional ceiling", got, e)
	}
}

type testAuthorizer struct {
	mu     sync.Mutex
	phases []Phase
	deny   Phase
}

func (a *testAuthorizer) Authorize(_ context.Context, _ Intent, p Phase) (Proof, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.phases = append(a.phases, p)
	if p == a.deny {
		return nil, errors.New("denied")
	}
	return Proof(`{"controlled":"fresh"}`), nil
}

type testStore struct {
	mu            sync.Mutex
	source        Source
	receipt       *Receipt
	disable       bool
	dispatchError bool
	settleError   bool
	settlements   []Settlement
	startOffset   time.Duration
}

func (s *testStore) Replay(_ context.Context, i Intent, _ Proof) (ReplayResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receipt != nil {
		r := *s.receipt
		if r.Binding.Intent != i {
			return ReplayResult{}, ErrInvalid
		}
		return ReplayResult{Found: true, Receipt: &r}, nil
	}
	return ReplayResult{}, nil
}
func (s *testStore) Source(context.Context, Intent, Proof) (Source, error) { return s.source, nil }
func (s *testStore) Reserve(_ context.Context, b Binding, _ Proof) (Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receipt != nil {
		return Reservation{Receipt: *s.receipt}, nil
	}
	r := Receipt{Binding: b, State: Reserved}
	s.receipt = &r
	return Reservation{Receipt: r, NewlyReserved: true}, nil
}
func (s *testStore) Dispatch(_ context.Context, b Binding, _ Proof) (DispatchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disable {
		return DispatchResult{}, ErrUnavailable
	}
	if s.receipt == nil || s.receipt.Binding != b {
		return DispatchResult{}, ErrInvalid
	}
	if s.receipt.State != Reserved {
		return DispatchResult{Receipt: *s.receipt}, nil
	}
	s.receipt.State = Started
	if s.dispatchError {
		return DispatchResult{}, ErrUnknown
	}
	return DispatchResult{Receipt: *s.receipt, NewlyStarted: true, Nonce: strings.Repeat("a", 64), StartedAt: testClock().Add(s.startOffset).Format(TimeFormat)}, nil
}
func (s *testStore) Settle(_ context.Context, q Settlement) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settlements = append(s.settlements, q)
	if s.settleError {
		return Receipt{}, ErrUnknown
	}
	if s.receipt == nil || s.receipt.Binding != q.Binding || s.receipt.State != Started {
		return Receipt{}, ErrInvalid
	}
	r := Receipt{Binding: q.Binding, State: q.State, ResultDigest: q.ResultDigest, FailureCode: q.FailureCode, Usage: q.Usage}
	s.receipt = &r
	return r, nil
}

type testSender struct {
	calls   atomic.Int64
	outcome SendOutcome
	after   func()
}

func (s *testSender) Send(context.Context, *Prepared, Claim) SendOutcome {
	s.calls.Add(1)
	if s.after != nil {
		s.after()
	}
	return s.outcome
}
func completeOutcome() SendOutcome {
	return SendOutcome{State: Complete, Result: &TransientExplanation{Explanation: "Review the missing owner.", Recommendation: "Assign a security owner."}, ResultDigest: digest([]byte("controlled-response")), Usage: &Usage{InputTokens: 10, OutputTokens: 20, CostNanoCredits: 50000}}
}
func testService(t *testing.T, store *testStore, auth *testAuthorizer, sender Sender) *Service {
	t.Helper()
	s, e := New(Config{Store: store, Authorizer: auth, Sender: sender, Now: testClock, NewRequestID: func() (string, error) { return "pid_77777777-7777-4777-8777-777777777777", nil }})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestDurableServiceDispatchReplayAndUncertainty(t *testing.T) {
	t.Run("one first result then metadata replay", func(t *testing.T) {
		store := &testStore{source: testSource(t)}
		auth := &testAuthorizer{}
		sender := &testSender{outcome: completeOutcome()}
		service := testService(t, store, auth, sender)
		result, e := service.Generate(context.Background(), testIntent())
		if e != nil || result.Explanation == nil || result.Receipt.State != Complete {
			t.Fatal("first generation", e)
		}
		encoded, _ := json.Marshal(store.settlements)
		if bytes.Contains(encoded, []byte("Review the missing owner")) || bytes.Contains(encoded, []byte("Assign a security owner")) {
			t.Fatal("model text persisted")
		}
		replay, e := service.Generate(context.Background(), testIntent())
		if e != nil || !replay.Replayed || replay.Explanation != nil || sender.calls.Load() != 1 {
			t.Fatal("paid effect replayed", e)
		}
		want := []Phase{ReplayPhase, SourcePhase, ReservePhase, DispatchPhase, ReplayPhase}
		if len(auth.phases) != len(want) {
			t.Fatal("missing fresh phases", auth.phases)
		}
		for n, p := range want {
			if auth.phases[n] != p {
				t.Fatal("phase order")
			}
		}
		auth.deny = ReplayPhase
		if _, e := service.Generate(context.Background(), testIntent()); e == nil || sender.calls.Load() != 1 {
			t.Fatal("revoked replay passed")
		}
	})
	for _, scenario := range []string{"dispatch commit lost", "disabled before dispatch", "revoked before dispatch", "provider unknown", "settlement reply lost"} {
		t.Run(scenario, func(t *testing.T) {
			store := &testStore{source: testSource(t)}
			auth := &testAuthorizer{}
			sender := &testSender{outcome: completeOutcome()}
			switch scenario {
			case "dispatch commit lost":
				store.dispatchError = true
			case "disabled before dispatch":
				store.disable = true
			case "revoked before dispatch":
				auth.deny = DispatchPhase
			case "provider unknown":
				sender.outcome = SendOutcome{State: Unknown, FailureCode: "provider_transport"}
			case "settlement reply lost":
				store.settleError = true
			}
			service := testService(t, store, auth, sender)
			if _, e := service.Generate(context.Background(), testIntent()); e == nil {
				t.Fatal("uncertain operation succeeded")
			}
			calls := sender.calls.Load()
			if (scenario == "dispatch commit lost" || scenario == "disabled before dispatch" || scenario == "revoked before dispatch") && calls != 0 {
				t.Fatal("unauthorized send")
			}
			if _, e := service.Generate(context.Background(), testIntent()); e != nil {
				t.Fatal("safe metadata replay", e)
			}
			if sender.calls.Load() != calls {
				t.Fatal("retry resent paid request")
			}
		})
	}
	t.Run("captured settlement after cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		store := &testStore{source: testSource(t)}
		sender := &testSender{outcome: SendOutcome{State: Unknown, FailureCode: "provider_transport"}, after: cancel}
		service := testService(t, store, &testAuthorizer{}, sender)
		_, _ = service.Generate(ctx, testIntent())
		if len(store.settlements) != 1 || store.receipt.State != Unknown {
			t.Fatal("captured result not settled")
		}
	})
	t.Run("database clock owns admission timestamp", func(t *testing.T) {
		store := &testStore{source: testSource(t), startOffset: 3 * time.Millisecond}
		sender := &testSender{outcome: completeOutcome()}
		service := testService(t, store, &testAuthorizer{}, sender)
		if result, e := service.Generate(context.Background(), testIntent()); e != nil || result.Receipt.State != Complete || sender.calls.Load() != 1 {
			t.Fatal("valid SQL admission rejected for local clock skew", e)
		}
	})
	t.Run("concurrent same intent", func(t *testing.T) {
		store := &testStore{source: testSource(t)}
		sender := &testSender{outcome: completeOutcome()}
		service := testService(t, store, &testAuthorizer{}, sender)
		var group sync.WaitGroup
		for n := 0; n < 12; n++ {
			group.Add(1)
			go func() { defer group.Done(); _, _ = service.Generate(context.Background(), testIntent()) }()
		}
		group.Wait()
		if sender.calls.Load() != 1 {
			t.Fatal("same intent sent more than once", sender.calls.Load())
		}
	})
}

type testResolver struct {
	calls atomic.Int64
	token []byte
}

func (r *testResolver) ResolveOptionalCredential(context.Context, Binding, Profile) ([]byte, error) {
	r.calls.Add(1)
	return bytes.Clone(r.token), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func responseJSON(t *testing.T) []byte {
	t.Helper()
	result, _ := json.Marshal(TransientExplanation{Explanation: "Review the canonical rule.", Recommendation: "Assign an owner."})
	v, _ := json.Marshal(map[string]any{"id": "gen-controlled-1", "provider": "OpenAI", "model": "openai/gpt-5-mini", "object": "chat.completion", "openrouter_metadata": map[string]any{"attempts": []any{map[string]any{"model": "openai/gpt-5-mini", "provider": "OpenAI", "status": 200}}}, "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(result)}}}, "usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30, "cost": json.Number("0.00005")}})
	return v
}
func TestOpenRouterActualHTTPBoundary(t *testing.T) {
	for _, scenario := range []string{"complete", "no optional provider", "missing provider identity", "extra routing attempt", "wrong model", "wrong backend", "duplicate result key", "over usage", "missing cost", "oversize", "redirect", "transport lost", "wrong credential"} {
		t.Run(scenario, func(t *testing.T) {
			prepared := testPrepared(t)
			resolver := &testResolver{token: testToken()}
			var calls atomic.Int64
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if r.URL.String() != openRouterEndpoint || r.Method != http.MethodPost || (r.Header.Get("Authorization") != "Bearer "+string(testToken()) || r.Header.Get("X-OpenRouter-Metadata") != "enabled") {
					t.Fatal("request identity differs")
				}
				b, e := io.ReadAll(r.Body)
				if e != nil || !bytes.Equal(b, prepared.body) {
					t.Fatal("body differs")
				}
				if scenario == "transport lost" {
					return nil, errors.New("controlled response lost")
				}
				raw := responseJSON(t)
				code := http.StatusOK
				switch scenario {
				case "no optional provider":
					var m map[string]json.RawMessage
					_ = json.Unmarshal(raw, &m)
					delete(m, "provider")
					raw, _ = json.Marshal(m)
				case "missing provider identity":
					var m map[string]json.RawMessage
					_ = json.Unmarshal(raw, &m)
					delete(m, "openrouter_metadata")
					raw, _ = json.Marshal(m)
				case "extra routing attempt":
					var m map[string]json.RawMessage
					_ = json.Unmarshal(raw, &m)
					m["openrouter_metadata"] = json.RawMessage(`{"attempts":[{"model":"openai/gpt-5-mini","provider":"OpenAI","status":200},{"model":"openai/gpt-5-mini","provider":"OpenAI","status":200}]}`)
					raw, _ = json.Marshal(m)
				case "wrong model":
					raw = bytes.ReplaceAll(raw, []byte("openai/gpt-5-mini"), []byte("other/model"))
				case "wrong backend":
					raw = bytes.ReplaceAll(raw, []byte("OpenAI"), []byte("other"))
				case "duplicate result key":
					raw = bytes.Replace(raw, []byte(`"provider":"OpenAI"`), []byte(`"provider":"OpenAI","provider":"other"`), 1)
				case "over usage":
					raw = bytes.Replace(raw, []byte(`"prompt_tokens":10`), []byte(`"prompt_tokens":100001`), 1)
				case "missing cost":
					raw = bytes.Replace(raw, []byte(`"cost":0.00005,`), nil, 1)
				case "oversize":
					raw = bytes.Repeat([]byte("x"), maximumResponseBytes+1)
				case "redirect":
					code = http.StatusTemporaryRedirect
				}
				return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}, "Location": []string{"https://example.invalid/"}}, Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
			})
			if scenario == "wrong credential" {
				resolver.token = []byte(strings.Repeat("Y", 48))
			}
			sender, e := NewOpenRouterSender(SenderConfig{Resolver: resolver, Transport: transport, Now: testClock})
			if e != nil {
				t.Fatal(e)
			}
			claim := Claim{Binding: prepared.binding, Nonce: strings.Repeat("a", 64)}
			out := sender.Send(context.Background(), prepared, claim)
			if scenario == "complete" || scenario == "no optional provider" {
				if out.State != Complete || out.Result == nil || out.Usage == nil {
					t.Fatal("valid controlled response rejected", out.FailureCode)
				}
			} else if out.State != Unknown || out.Result != nil {
				t.Fatal("unsafe response succeeded")
			}
			expected := int64(1)
			if scenario == "wrong credential" {
				expected = 0
			}
			if calls.Load() != expected {
				t.Fatal("unexpected HTTP attempts", calls.Load())
			}
			_ = sender.Send(context.Background(), prepared, claim)
			if calls.Load() != expected {
				t.Fatal("prepared request resent")
			}
		})
	}
}

type ownedTransportObserver struct {
	requests atomic.Int64
	closes   atomic.Int64
}

func (o *ownedTransportObserver) RoundTrip(*http.Request) (*http.Response, error) {
	o.requests.Add(1)
	return nil, ErrUnavailable
}
func (o *ownedTransportObserver) CloseIdleConnections() { o.closes.Add(1) }
func TestSenderCloseRejectsNewWorkWithoutClosingInjectedTransport(t *testing.T) {
	resolver := &testResolver{token: testToken()}
	transport := &ownedTransportObserver{}
	sender, e := NewOpenRouterSender(SenderConfig{Resolver: resolver, Transport: transport, Now: testClock})
	if e != nil {
		t.Fatal(e)
	}
	if sender.Close() != nil || sender.Close() != nil {
		t.Fatal("idempotent close failed")
	}
	p := testPrepared(t)
	out := sender.Send(context.Background(), p, Claim{Binding: p.Binding(), Nonce: strings.Repeat("a", 64)})
	if out.State != Unknown || out.Result != nil || transport.requests.Load() != 0 || resolver.calls.Load() != 0 || transport.closes.Load() != 0 {
		t.Fatal("closed sender admitted work or closed shared transport")
	}
	owned, e := NewOpenRouterSender(SenderConfig{Resolver: resolver, Now: testClock})
	if e != nil || owned.owned == nil {
		t.Fatal("default transport not owned")
	}
	if owned.Close() != nil || owned.Close() != nil {
		t.Fatal("owned close failed")
	}
}
