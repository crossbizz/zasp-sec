package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
)

// Admission authenticates before reading a large body. Recording must separately
// authenticate under the original sensor locks and return only a confirmed-commit
// receipt. Admission does not grant authority to a later transaction.
type PrivateNodeCoverageHeartbeatAuthority interface {
	AuthenticateNodeCoverage(context.Context, *TokenCredential) error
	RecordAuthenticatedNodeCoverage(context.Context, *TokenCredential, []byte) (nodecoveragewire.Receipt, error)
}
type privateNodeCoverageHeartbeatHandler struct {
	authority PrivateNodeCoverageHeartbeatAuthority
	clock     func() time.Time
	timeout   time.Duration
	permit    chan struct{}
}

func NewPrivateNodeCoverageHeartbeatHandler(authority PrivateNodeCoverageHeartbeatAuthority, clock func() time.Time, operationTimeout time.Duration) (http.Handler, error) {
	if authority == nil || clock == nil || operationTimeout < time.Second || operationTimeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &privateNodeCoverageHeartbeatHandler{authority: authority, clock: clock, timeout: operationTimeout, permit: make(chan struct{}, 1)}, nil
}
func (h *privateNodeCoverageHeartbeatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if h == nil || h.authority == nil || r == nil || r.URL == nil {
		writePrivateHeartbeatError(w, http.StatusServiceUnavailable, "unavailable", true)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != PrivateHeartbeatPath || r.URL.EscapedPath() != PrivateHeartbeatPath {
		writePrivateHeartbeatError(w, http.StatusNotFound, "not_found", false)
		return
	}
	if r.URL.RawQuery != "" || hasPrivateScopeAuthority(r.Header) || !exactHeader(r.Header, "Content-Type", PrivateHeartbeatMediaType) || !exactHeader(r.Header, PrivateHeartbeatSchemaHeader, nodecoveragewire.HeartbeatSchema) || len(r.Header.Values("Content-Encoding")) != 0 || r.ContentLength > nodecoveragewire.MaxEnvelopeBytes || r.Body == nil {
		writePrivateHeartbeatError(w, http.StatusBadRequest, "invalid_request", false)
		return
	}
	credential, err := privateHeartbeatCredential(r.Header)
	if err != nil {
		writePrivateHeartbeatError(w, http.StatusUnauthorized, "unauthorized", false)
		return
	}
	defer credential.Destroy()
	select {
	case h.permit <- struct{}{}:
		defer func() { <-h.permit }()
	default:
		w.Header().Set("Retry-After", "1")
		writePrivateHeartbeatError(w, http.StatusServiceUnavailable, "unavailable", true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	if err = safeNodeCoverageAdmission(ctx, h.authority, credential); err != nil || ctx.Err() != nil {
		writeNodeCoverageError(w, err)
		return
	}
	// The real server's deadline bounds socket reads. Closing the request body on
	// cancellation also interrupts ordinary HTTP bodies; no body-reader goroutine
	// is detached or treated as joined by this handler.
	deadline, _ := ctx.Deadline()
	_ = http.NewResponseController(w).SetReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
	defer stop()
	raw, err := io.ReadAll(io.LimitReader(r.Body, nodecoveragewire.MaxEnvelopeBytes+1))
	defer clear(raw)
	if err != nil || ctx.Err() != nil {
		writePrivateHeartbeatError(w, http.StatusServiceUnavailable, "unavailable", true)
		return
	}
	envelope, err := nodecoveragewire.ParseEnvelope(raw)
	if err != nil {
		writePrivateHeartbeatError(w, http.StatusBadRequest, "invalid_request", false)
		return
	}
	receipt, err := safeNodeCoverageRecord(ctx, h.authority, credential, raw)
	if err != nil || ctx.Err() != nil {
		writeNodeCoverageError(w, err)
		return
	}
	encoded, err := nodecoveragewire.MarshalReceipt(receipt)
	sum := sha256.Sum256(raw)
	now, clockOK := safeNodeCoverageClock(h.clock)
	if err != nil || !clockOK || receipt.Sequence != envelope.Sequence || receipt.RequestDigest != hex.EncodeToString(sum[:]) || !receipt.SourceObservedAt.Equal(envelope.SourceObservedAt) || !receipt.ExpiresAt.Equal(envelope.SourceObservedAt.Add(time.Duration(envelope.TTLSeconds)*time.Second)) || receipt.ResolvedAt.After(now.Add(5*time.Second)) {
		writePrivateHeartbeatError(w, http.StatusServiceUnavailable, "unavailable", true)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}
func writeNodeCoverageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound):
		writePrivateHeartbeatError(w, http.StatusUnauthorized, "unauthorized", false)
	case errors.Is(err, ErrConflict):
		writePrivateHeartbeatError(w, http.StatusConflict, "conflict", false)
	default:
		writePrivateHeartbeatError(w, http.StatusServiceUnavailable, "unavailable", true)
	}
}
func safeNodeCoverageAdmission(ctx context.Context, a PrivateNodeCoverageHeartbeatAuthority, c *TokenCredential) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return a.AuthenticateNodeCoverage(ctx, c)
}
func safeNodeCoverageRecord(ctx context.Context, a PrivateNodeCoverageHeartbeatAuthority, c *TokenCredential, raw []byte) (receipt nodecoveragewire.Receipt, err error) {
	defer func() {
		if recover() != nil {
			receipt = nodecoveragewire.Receipt{}
			err = ErrUnavailable
		}
	}()
	if ctx.Err() != nil {
		return receipt, ErrUnavailable
	}
	return a.RecordAuthenticatedNodeCoverage(ctx, c, raw)
}
func safeNodeCoverageClock(clock func() time.Time) (now time.Time, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	now = clock()
	return now, !now.IsZero()
}
