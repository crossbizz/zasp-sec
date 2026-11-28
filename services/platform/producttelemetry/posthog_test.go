package producttelemetry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const testProjectKey = "phc_test_project"

func TestPostHogRequiresProjectTokenAndHTTPSOrigin(t *testing.T) {
	for _, endpoint := range []string{"", "http://host", "https://", "https://user:pw@host", "https://host/path", "https://host/?q", "https://host?#", "https://host/#fragment", "https://host:0", "https://host:65536"} {
		if p, err := NewPostHog(endpoint, testProjectKey); p != nil || err != ErrConfiguration {
			t.Errorf("accepted invalid origin %q", endpoint)
		}
	}
	for _, key := range []string{"", "phx_personal_key", "phc_", "phc_new\nline", "phc_contains spaces"} {
		if err := ValidatePostHogConfig("https://us.i.posthog.com", key); err != ErrConfiguration {
			t.Errorf("invalid project token did not return the fixed configuration error")
		}
	}
	for _, host := range []string{"https://us.i.posthog.com", "https://self-hosted.example:444/"} {
		p, err := NewPostHog(host, testProjectKey)
		if err != nil || p.captureURL != strings.TrimSuffix(host, "/")+"/i/v0/e/" {
			t.Errorf("unexpected ingest target for %s", host)
		}
	}
}

func TestPostHogEmitsOnlyExplicitWorkflowProperties(t *testing.T) {
	received := make(chan map[string]any, 32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/i/v0/e/" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("invalid capture request")
		}
		for _, key := range []string{"Cookie", "Authorization", "X-Forwarded-For", "Referer"} {
			if r.Header.Get(key) != "" {
				t.Errorf("unexpected request header %s", key)
			}
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	p, err := NewPostHog(server.URL, testProjectKey)
	if err != nil {
		t.Fatal(err)
	}
	p.client.Transport = server.Client().Transport

	scope := telemetryTestScope(t)
	event := func(kind EventName, source string, success bool) Event {
		return Event{Name: kind, Fields: []Field{TextField("source", source), BooleanField("success", success)}}
	}
	valid := event(WorkflowUsage, AuditLogRead, true)
	p.TryTrack(domain.Scope{}, valid)
	p.TryTrack(scope, exactEvent(true))
	p.TryTrack(scope, event("unreviewed", HomeSummaryRead, true))
	p.TryTrack(scope, event(WorkflowAction, AuditLogRead, true))
	p.TryTrack(scope, event(WorkflowUsage, "sensitive-bounded-slug", true))
	p.TryTrack(scope, Event{Name: WorkflowUsage, Fields: append(valid.Fields, TextField("raw_evidence", "sensitive"))})
	p.TryTrack(scope, valid)
	valid.Fields[0] = TextField("source", "caller-mutation-after-return")
	p.TryTrack(scope, event(WorkflowAction, PolicyCreated, false))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p.TryTrack(scope, event(WorkflowUsage, FindingDetailRead, true))
	p.Close()
	close(received)

	seen := map[EventName]bool{}
	mac := hmac.New(sha256.New, []byte(testProjectKey))
	mac.Write([]byte(scope.OrganizationID().String()))
	wantDistinctID := hex.EncodeToString(mac.Sum(nil))
	for body := range received {
		name, _ := body["event"].(string)
		kind := EventName(name)
		source, success := AuditLogRead, true
		if kind == WorkflowAction {
			source, success = PolicyCreated, false
		}
		want := map[string]any{
			"api_key": testProjectKey,
			"event":   name,
			"properties": map[string]any{
				"source": source, "success": success, "distinct_id": wantDistinctID,
				"$geoip_disable": true, "$process_person_profile": false,
			},
		}
		if seen[kind] || !reflect.DeepEqual(body, want) {
			t.Fatalf("unexpected capture document %#v", body)
		}
		seen[kind] = true
	}
	if len(seen) != 2 || !seen[WorkflowAction] || !seen[WorkflowUsage] {
		t.Fatalf("unexpected event families %v", seen)
	}
}

func TestPostHogDropsOverflowAndNeverFollowsRedirects(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	var redirected atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/i/v0/e/" {
			redirected.Store(true)
			return
		}
		io.Copy(io.Discard, r.Body)
		calls.Add(1)
		<-release
		http.Redirect(w, r, "/another-destination", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	p, err := NewPostHog(server.URL, testProjectKey)
	if err != nil {
		t.Fatal(err)
	}
	p.client.Transport = server.Client().Transport
	scope := telemetryTestScope(t)
	for range postHogMaxInFlight * 2 {
		p.TryTrack(scope, Event{Name: WorkflowUsage, Fields: []Field{BooleanField("success", true), TextField("source", HomeSummaryRead)}})
	}
	close(release)
	p.Close()
	if int(calls.Load()) != postHogMaxInFlight || redirected.Load() {
		t.Fatalf("capture requests=%d redirect followed=%v", calls.Load(), redirected.Load())
	}
}

type stalledIngest func(*http.Request) (*http.Response, error)

func (s stalledIngest) RoundTrip(r *http.Request) (*http.Response, error) { return s(r) }

func TestPostHogTimesOutAnUnavailableProviderWithoutRetry(t *testing.T) {
	p, err := NewPostHog("https://unavailable.example", testProjectKey)
	if err != nil {
		t.Fatal(err)
	}
	if p.client.Timeout <= 0 || p.client.Timeout > 2*time.Second {
		t.Fatal("capture timeout must bound the duration of shutdown")
	}
	p.client.Timeout = 20 * time.Millisecond
	var attempts atomic.Int32
	p.client.Transport = stalledIngest(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	p.TryTrack(telemetryTestScope(t), Event{Name: WorkflowUsage, Fields: []Field{TextField("source", AuditLogRead), BooleanField("success", true)}})
	if err := p.Close(); err != nil || attempts.Load() != 1 {
		t.Fatalf("provider timeout: attempts %d, close error %v", attempts.Load(), err)
	}
}
