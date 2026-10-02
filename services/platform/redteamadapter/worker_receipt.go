package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const completedRequestFields = "organization_id workspace_id environment_id parent_run_id test_run_id step_id effect_key generation category input_digest request_digest"
const completedReceiptFields = completedRequestFields + " attempt state response_digest http_status protected credential_version_digest completed_at captured_resolution_digest"

// CompletedReceiptRequest identifies captured evidence, not a new invocation.
type CompletedReceiptRequest struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	ParentRunID    string `json:"parent_run_id"`
	TestRunID      string `json:"test_run_id"`
	StepID         string `json:"step_id"`
	EffectKey      string `json:"effect_key"`
	Generation     int    `json:"generation"`
	Category       string `json:"category"`
	InputDigest    string `json:"input_digest"`
	RequestDigest  string `json:"request_digest"`
}

type CompletedReceipt struct {
	CompletedReceiptRequest
	Attempt                  int    `json:"attempt"`
	State                    string `json:"state"`
	ResponseDigest           string `json:"response_digest"`
	HTTPStatus               int    `json:"http_status"`
	Protected                *bool  `json:"protected"`
	CredentialVersionDigest  string `json:"credential_version_digest"`
	CompletedAt              string `json:"completed_at"`
	CapturedResolutionDigest string `json:"captured_resolution_digest"`
}

func validCompletedRequest(q CompletedReceiptRequest) bool {
	for _, id := range []string{q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.ParentRunID, q.TestRunID, q.StepID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return false
		}
	}
	_, category := curatedInputs[q.Category]
	identity := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.ParentRunID, q.StepID, "1"}, "\x1f")))
	return category && q.Generation == 1 && q.EffectKey == hex.EncodeToString(identity[:]) && releaseDigestPattern.MatchString(q.InputDigest) && releaseDigestPattern.MatchString(q.RequestDigest)
}

func decodeCompletedRequest(raw []byte) (CompletedReceiptRequest, error) {
	var q CompletedReceiptRequest
	fields, err := exactJournalObject(raw, completedRequestFields)
	if len(raw) > 4096 || err != nil || len(fields) != 11 || json.Unmarshal(raw, &q) != nil || !validCompletedRequest(q) {
		return CompletedReceiptRequest{}, ErrAdapter
	}
	return q, nil
}

func decodeCompletedReceipt(raw []byte, q CompletedReceiptRequest) (CompletedReceipt, error) {
	var r CompletedReceipt
	fields, err := exactJournalObject(raw, completedReceiptFields)
	if len(raw) > 8192 || err != nil || len(fields) != 19 || !validCompletedRequest(q) || json.Unmarshal(raw, &r) != nil || r.CompletedReceiptRequest != q {
		return CompletedReceipt{}, ErrAdapter
	}
	for _, value := range fields {
		if string(value) == "null" {
			return CompletedReceipt{}, ErrAdapter
		}
	}
	stamp, err := time.Parse("2006-01-02T15:04:05.000000Z", r.CompletedAt)
	if r.Attempt != 1 || r.State != "completed" || r.HTTPStatus != 200 || r.Protected == nil || !releaseDigestPattern.MatchString(r.ResponseDigest) || !validCredentialVersionDigest(r.CredentialVersionDigest) || !releaseDigestPattern.MatchString(r.CapturedResolutionDigest) || err != nil || stamp.IsZero() || stamp.Format("2006-01-02T15:04:05.000000Z") != r.CompletedAt {
		return CompletedReceipt{}, ErrAdapter
	}
	return r, nil
}

// CompletedReceipt has no resolver, credential, invocation or forward fallback.
func (j *TemporalPostgresJournal) CompletedReceipt(ctx context.Context, q CompletedReceiptRequest) (CompletedReceipt, error) {
	if j == nil || j.workerFamily != workerJournalSingle74 || j.compensation == nil || j.forward == nil || ctx == nil || !validCompletedRequest(q) {
		return CompletedReceipt{}, ErrAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := json.Marshal(q)
	if err != nil {
		return CompletedReceipt{}, ErrAdapter
	}
	decision, err := j.compensation.Authorize(ctx, "test74.adapter.receipt", raw)
	if err != nil {
		return CompletedReceipt{}, ErrAdapter
	}
	result, err := j.compensation.Execute(ctx, decision)
	if err != nil {
		return CompletedReceipt{}, ErrAdapter
	}
	return decodeCompletedReceipt(result, q)
}

// NewWorkerEffectJournaledHandler explicitly enables the private receipt route.
// The full production profile remains gated independently of this staged seam.
func NewWorkerEffectJournaledHandler(config Config, resolver TargetResolver, invoker *HTTPSInvoker, journal InvocationJournal, reader *TemporalPostgresJournal) (*Handler, error) {
	if reader == nil || reader.workerFamily != workerJournalSingle74 || reader.forward == nil || reader.compensation == nil {
		return nil, ErrAdapter
	}
	h, err := NewEffectJournaledHandler(config, resolver, invoker, journal)
	if err != nil {
		return nil, err
	}
	h.completedReader = reader
	return h, nil
}

func (h *Handler) serveCompletedReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path || r.Header.Get("Content-Type") != "application/json" || r.ContentLength > h.config.MaximumRequestBytes {
		writeError(w, http.StatusBadRequest)
		return
	}
	scope, child, ok := requestScope(r)
	effect, effectOK := exactHeader(r, "X-Zasp-Effect-Key")
	if !ok || !effectOK || !ValidEffectKey(effect) || len(r.Header.Values("X-Zasp-Run-Lease")) != 0 {
		writeError(w, http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.config.MaximumRequestBytes))
	q, decodeErr := decodeCompletedRequest(raw)
	if err != nil || decodeErr != nil || q.OrganizationID != scope.OrganizationID().String() || q.WorkspaceID != scope.WorkspaceID().String() || q.EnvironmentID != scope.EnvironmentID().String() || q.TestRunID != child || q.EffectKey != effect {
		writeError(w, http.StatusBadRequest)
		return
	}
	receipt, err := h.completedReader.CompletedReceipt(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipt)
}
