package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The wrapper deliberately exposes only JSONDatabase, like production tracing.
// It cannot gain finding routing through an optional capability assertion.
type findingRouteDatabase struct {
	JSONDatabase
	present, ready, family string
	calls                  []string
}

func (d *findingRouteDatabase) QueryJSON(_ context.Context, q string, _ ...any) (json.RawMessage, error) {
	d.calls = append(d.calls, q)
	switch {
	case strings.Contains(q, "to_regnamespace"):
		return json.RawMessage(d.present), nil
	case strings.Contains(q, "api_ready"):
		return json.RawMessage(d.ready), nil
	case strings.Contains(q, ".family("):
		return json.RawMessage(d.family), nil
	default:
		return nil, errors.New("unexpected finding route query")
	}
}

func TestTemporalFindingResponseHTTPFamilyRouting(t *testing.T) {
	for _, tc := range []struct {
		name, present, ready, family string
		status                       int
		calls                        int
	}{
		{"absent retains ordered", "false", "", "", http.StatusNoContent, 1},
		{"malformed presence denies", "null", "", "", http.StatusServiceUnavailable, 1},
		{"installed invalid denies", "true", "false", "", http.StatusServiceUnavailable, 2},
		{"malformed ready denies", "true", "null", "", http.StatusServiceUnavailable, 2},
		{"other family retains ordered", "true", "true", "false", http.StatusNoContent, 3},
		{"finding chooses strict source handler", "true", "true", "true", http.StatusAccepted, 3},
		{"malformed family denies", "true", "true", "{}", http.StatusServiceUnavailable, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &findingRouteDatabase{present: tc.present, ready: tc.ready, family: tc.family}
			h := &securityAgentHumanHTTPHandler{findingDatabase: db, next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), legacy: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })}
			r := workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "runSecurityAgent", map[string]string{"id": public62Definition}, http.MethodPost, "/api/v1/security-agents/"+public62Definition+"/runs", "{}")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, r)
			if response.Code != tc.status || len(db.calls) != tc.calls {
				t.Fatalf("status=%d calls=%d", response.Code, len(db.calls))
			}
		})
	}
}
