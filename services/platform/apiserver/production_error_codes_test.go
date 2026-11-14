package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Two database refusals have their own product error instead of the generic,
// non-retryable operation_conflict:
//   - a checked statement whose proof went stale between the request's check
//     and the statement (the projection moved, for example while Security
//     Agent runs are processed) is retryable, like the router's own answer;
//   - a run requested on a finding of another rule names the cause.
func TestDatabaseRefusalsWithANamedProductError(t *testing.T) {
	for _, test := range []struct {
		name, state, message string
		wrap                 func(error) error
		status               int
		code                 string
		retryable            bool
	}{
		{"stale proof", "40001", "authorization changed; retry from Check", nil, http.StatusConflict, "authorization_changed", true},
		{"stale proof through a repository", "40001", "authorization changed; retry from Check", discoveryProviderError, http.StatusConflict, "authorization_changed", true},
		{"trigger source mismatch", "40001", "security agent trigger source mismatch", discoveryProviderError, http.StatusConflict, "trigger_source_mismatch", false},
		{"any other serialization failure", "40001", "finding human source changed", nil, http.StatusConflict, "operation_conflict", false},
		{"a unique violation", "23505", "discovery schedule exists", nil, http.StatusConflict, "operation_conflict", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := classifyPostgresError(&pgconn.PgError{Code: test.state, Message: test.message})
			if !errors.Is(err, ErrRepositoryConflict) {
				t.Fatalf("not a conflict: %v", err)
			}
			if test.wrap != nil {
				err = test.wrap(err)
			}
			recorder := httptest.NewRecorder()
			writeProductionError(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/security-agent-runs", nil), err)
			var body struct {
				Code      string `json:"code"`
				Retryable bool   `json:"retryable"`
			}
			if json.Unmarshal(recorder.Body.Bytes(), &body) != nil || recorder.Code != test.status || body.Code != test.code || body.Retryable != test.retryable {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
