package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSecurityAgentCostConfigurationPublicError(t *testing.T) {
	for _, tc := range []struct{ message, code string }{
		{"security agent cost budget configuration required", "cost_budget_required"},
		{"other invalid input with private details", "invalid_request"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			err := discoveryProviderError(classifyPostgresError(&pgconn.PgError{Code: "22023", Message: tc.message, Detail: "private provider detail"}))
			response := httptest.NewRecorder()
			writeProductionError(response, httptest.NewRequest(http.MethodPost, "/", nil), err)
			var body struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				Retryable bool   `json:"retryable"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusBadRequest || body.Code != tc.code || body.Retryable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if tc.code == "cost_budget_required" && body.Message != "Configure and save an explicit AI cost budget before enabling execution" {
				t.Fatalf("message=%q", body.Message)
			}
			if tc.code == "invalid_request" && body.Message != "Request rejected" {
				t.Fatalf("private error exposed: %q", body.Message)
			}
		})
	}
}
