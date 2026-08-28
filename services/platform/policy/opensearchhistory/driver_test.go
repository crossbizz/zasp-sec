package opensearchhistory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestDriverSearchesOnlyBoundedTenantTriggerHistory(t *testing.T) {
	scope := historyScope(t)
	doer := historyDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/zasp-runtime-events-v1/_search" || request.URL.Query().Get("filter_path") != "hits.hits._id,hits.hits._source,hits.hits.sort,timed_out" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Authorization") != "signed" {
			t.Fatalf("request=%s %s headers=%v", request.Method, request.URL.String(), request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		var query map[string]any
		if json.Unmarshal(body, &query) != nil || query["size"] != float64(25) || query["track_total_hits"] != false {
			t.Fatalf("query=%s", body)
		}
		expected := []string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "tool"}
		for _, value := range expected {
			if !strings.Contains(string(body), value) {
				t.Fatalf("query missing %q: %s", value, body)
			}
		}
		response := historyResponse(http.StatusOK, `{"timed_out":false,"hits":{"hits":[{"_id":"evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sort":["2026-08-28T12:00:00.000Z","evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"_source":{"organization_id":"`+scope.OrganizationID().String()+`","workspace_id":"`+scope.WorkspaceID().String()+`","environment_id":"`+scope.EnvironmentID().String()+`","record_type":"runtime_event","event_id":"`+historyID(t).String()+`","event_class":"tool","action":"invoke","agent_id":"pid_70000001-0000-4000-8000-000000000001","session_id":"pid_70000002-0000-4000-8000-000000000002","tool_id":"shell","source_event_id":"source-1","event_time":"2026-08-28T12:00:00.000Z"}}]}}`)
		response.Header.Set("Content-Type", "application/json; charset=UTF-8")
		return response, nil
	})
	driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, doer, historyReady{}, func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	values, err := driver.SearchPolicyActions(context.Background(), scope, "tool", 25)
	if err != nil || len(values) != 1 || values[0].PrincipalID != values[0].AgentID || values[0].Resource != "shell" || values[0].Metadata["action"] != "invoke" || values[0].EnvironmentID != scope.EnvironmentID().String() {
		t.Fatalf("values=%#v err=%v", values, err)
	}
}

func TestDriverFailsClosedOnForeignMalformedOrUnboundedHistory(t *testing.T) {
	scope := historyScope(t)
	foreign := historyScope(t)
	tests := map[string]string{
		"foreign scope": `{"timed_out":false,"hits":{"hits":[{"_id":"evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sort":["2026-08-28T12:00:00.000Z","evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"_source":{"organization_id":"` + foreign.OrganizationID().String() + `","workspace_id":"` + scope.WorkspaceID().String() + `","environment_id":"` + scope.EnvironmentID().String() + `","record_type":"runtime_event","event_id":"` + historyID(t).String() + `","event_class":"tool","action":"invoke","agent_id":"pid_70000001-0000-4000-8000-000000000001","session_id":"pid_70000002-0000-4000-8000-000000000002","tool_id":"shell","source_event_id":"source-1","event_time":"2026-08-28T12:00:00.000Z"}}]}}`,
		"timed out":     `{"timed_out":true,"hits":{"hits":[]}}`,
		"unknown field": `{"timed_out":false,"secret":"provider-body","hits":{"hits":[]}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, historyDoerFunc(func(*http.Request) (*http.Response, error) { return historyResponse(http.StatusOK, body), nil }), historyReady{}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if values, err := driver.SearchPolicyActions(context.Background(), scope, "tool", 100); err == nil || values != nil {
				t.Fatalf("values=%#v err=%v", values, err)
			}
		})
	}
}

func TestDriverReadinessRequiresExactSchemaAuthority(t *testing.T) {
	ready := &historyReadyStub{err: ErrHistory}
	driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, historyDoerFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected search"); return nil, nil }), ready, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Ready(context.Background()); err == nil || ready.calls != 1 {
		t.Fatalf("ready err=%v calls=%d", err, ready.calls)
	}
}

func TestDriverAllowsLoopbackOnlyThroughExplicitTestAuthority(t *testing.T) {
	base := Config{Endpoint: "http://127.0.0.1:19092", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}
	client := historyDoerFunc(func(*http.Request) (*http.Response, error) { return nil, ErrHistory })
	if driver, err := newWithClient(base, historyCredentials{}, historySigner{}, client, historyReady{}, time.Now); err == nil || driver != nil {
		t.Fatalf("loopback accepted without test authority: %#v %v", driver, err)
	}
	base.AllowTestLoopback = true
	if driver, err := newWithClient(base, historyCredentials{}, historySigner{}, client, historyReady{}, time.Now); err != nil || driver == nil {
		t.Fatalf("explicit test loopback rejected: %#v %v", driver, err)
	}
	base.Endpoint = "http://10.0.0.1:19092"
	if driver, err := newWithClient(base, historyCredentials{}, historySigner{}, client, historyReady{}, time.Now); err == nil || driver != nil {
		t.Fatalf("non-loopback test authority accepted: %#v %v", driver, err)
	}
}

type historyCredentials struct{}

func (historyCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "token"}, nil
}

type historySigner struct{}

func (historySigner) SignHTTP(_ context.Context, _ aws.Credentials, request *http.Request, _ string, service, region string, _ time.Time, _ ...func(*SignerOptions)) error {
	if service != "es" || region != "us-west-2" {
		return ErrHistory
	}
	request.Header.Set("Authorization", "signed")
	return nil
}

type historyDoerFunc func(*http.Request) (*http.Response, error)

func (function historyDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type historyReady struct{}

func (historyReady) Ready(context.Context) error { return nil }

type historyReadyStub struct {
	err   error
	calls int
}

func (stub *historyReadyStub) Ready(context.Context) error { stub.calls++; return stub.err }

func historyResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func historyScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(historyID(t), historyID(t), historyID(t))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func historyID(t *testing.T) domain.ProductID {
	t.Helper()
	value, err := domain.NewProductID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
