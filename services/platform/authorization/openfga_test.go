package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

const storeID = "01K00000000000000000000001"
const modelID = "01K00000000000000000000002"

func testConfig(url string) runtimeservices.Config {
	return runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-dev", TaskQueue: "zasp-security", DiscoveryTaskQueue: "zasp-discovery", FGAURL: url, StoreID: storeID, ModelID: modelID, FGATokenFile: "/test/token", Timeout: time.Second}
}

// Exercises our SDK boundary against HTTP responses: wrong model/store or
// consistency must never get an allow; service errors cannot leak response data.
func TestOpenFGACheck(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		allowed    bool
		wantErr    error
	}{
		{"allow", `{"allowed":true}`, 200, true, nil}, {"deny", `{"allowed":false}`, 200, false, nil},
		{"outage", `{"message":"secret response"}`, 503, false, ErrUnavailable},
		{"malformed", `not-json`, 200, false, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Model       string                                  `json:"authorization_model_id"`
					Consistency string                                  `json:"consistency"`
					Tuple       struct{ User, Relation, Object string } `json:"tuple_key"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if r.URL.Path != "/stores/"+storeID+"/check" || body.Model != modelID || body.Consistency != "HIGHER_CONSISTENCY" || body.Tuple.User != "user:"+principal || body.Tuple.Relation != "view" {
					t.Errorf("wrong authorization boundary: %s %#v", r.URL.Path, body)
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: server.URL, StoreId: "01K00000000000000000000003", AuthorizationModelId: "01K00000000000000000000004"})
			if err != nil {
				t.Fatal(err)
			}
			checker, err := NewOpenFGA(client, testConfig(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := checker.Check(context.Background(), exampleRequest())
			if decision.Allowed != tc.allowed || decision.ModelID != modelID || !errors.Is(err, tc.wantErr) {
				t.Fatalf("decision %#v error %v", decision, err)
			}
		})
	}
}

func TestOpenFGARejectsUntrustedInput(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; t.Error("invalid input reached dependency") }))
	defer server.Close()
	client, _ := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: server.URL})
	checker, err := NewOpenFGA(client, testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	r := exampleRequest()
	r.Permission = "organization_admin"
	d, err := checker.Check(context.Background(), r)
	if d.Allowed || !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid relation: %#v %v", d, err)
	}
	d, err = checker.Check(nil, exampleRequest())
	if d.Allowed || !errors.Is(err, ErrInvalid) || calls != 0 {
		t.Fatalf("nil context: %#v %v calls=%d", d, err, calls)
	}
	if _, err := NewOpenFGA(nil, testConfig(server.URL)); err == nil {
		t.Fatal("nil client accepted")
	}
	config := testConfig(server.URL)
	config.ModelID = ""
	if _, err := NewOpenFGA(client, config); err == nil {
		t.Fatal("unpinned model accepted")
	}
}
