package providerhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var errAdmissionUnavailable = errors.New("product admission unavailable")

// ProductAdmitter calls the deployed workload decision API in-process, through
// its normal PAT authentication, authorization and scoped SQL fencing.
func ProductAdmitter(product http.Handler, token string) (Admit, error) {
	if product == nil || len(token) < 32 || len(token) > 4096 || strings.IndexFunc(token, func(c rune) bool { return c < 33 || c > 126 }) >= 0 {
		return nil, errAdmissionUnavailable
	}
	return func(ctx context.Context, a Action) (Decision, error) {
		raw, err := json.Marshal(a)
		if err != nil {
			return Decision{}, errAdmissionUnavailable
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/runtime/action-decisions", bytes.NewReader(raw))
		if err != nil {
			return Decision{}, errAdmissionUnavailable
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", a.ID)
		response := decisionResponse{header: make(http.Header)}
		product.ServeHTTP(&response, req)
		if response.overflow {
			return Decision{}, errAdmissionUnavailable
		}
		var body struct {
			Code       string `json:"code"`
			DecisionID string `json:"decision_id"`
			ActionID   string `json:"action_id"`
			Mode       string `json:"mode"`
			Verdict    string `json:"verdict"`
		}
		if json.Unmarshal(response.body.Bytes(), &body) != nil {
			return Decision{}, errAdmissionUnavailable
		}
		switch {
		case response.status == 200:
			return Decision{ActionID: body.ActionID, DecisionID: body.DecisionID, Mode: body.Mode, Verdict: body.Verdict}, nil
		case response.status == 409 && body.Code == "action_id_conflict":
			return Decision{}, ErrConflict
		case response.status == 422:
			return Decision{}, ErrIncompatible
		default:
			return Decision{}, errAdmissionUnavailable
		}
	}, nil
}

type decisionResponse struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func (w *decisionResponse) Header() http.Header { return w.header }
func (w *decisionResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *decisionResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if len(p) > 8192-w.body.Len() {
		w.overflow = true
		return 0, errAdmissionUnavailable
	}
	return w.body.Write(p)
}
