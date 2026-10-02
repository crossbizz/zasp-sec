package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestPolicyRiskPublicBody(t *testing.T) {
	base := `{"id":"policy-risk","name":"Risk","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"invoke"}],"action":"block","rollout":"draft","failure_mode":"closed"`
	for _, tc := range []struct {
		name, suffix string
		valid        bool
	}{
		{"omitted", `}`, true}, {"known", `,"risk":"high"}`, true},
		{"unknown", `,"risk":"severe"}`, false}, {"null", `,"risk":null}`, false}, {"empty", `,"risk":""}`, false},
		{"duplicate", `,"risk":"low","risk":"high"}`, false}, {"case", `,"Risk":"high"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := base + tc.suffix
			r := &workflowRepositoryStub{}
			h, err := newWorkflowHTTPHandler(r, securityAgentTestSigningKey, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			req := workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "createPolicy", nil, http.MethodPost, "/api/v1/policies", raw)
			req.Header.Set("Idempotency-Key", "automatic77-policy-risk")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			want := 400
			if tc.valid {
				want = 201
			}
			if response.Code != want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
			var value policy.Policy
			if (decodePolicyValue(json.RawMessage(raw), "policy-risk", &value) == nil) != tc.valid {
				t.Fatal("typed policy readback differs from input contract")
			}
			if tc.valid && tc.name == "known" {
				var got map[string]any
				json.Unmarshal(r.mutation.Body, &got)
				if got["risk"] != "high" {
					t.Fatal("canonical mutation lost risk", got)
				}
			}
		})
	}
}
