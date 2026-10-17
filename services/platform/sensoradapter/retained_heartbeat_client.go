package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// SendRetainedHeartbeat sends already-durable original bytes. It intentionally
// permits structurally valid expired observations for durable negative resolution;
// the server alone authenticates, serializes and confirms the terminal outcome.
func (c *ProductionClient) SendRetainedHeartbeat(ctx context.Context, wire []byte) (nodecoveragewire.Receipt, error) {
	var zero nodecoveragewire.Receipt
	if c == nil || !c.nodeCoverageRetention || c.enrollment == "" {
		return zero, ErrClient
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, ErrClientRetryable
	}
	env, err := nodecoveragewire.ParseEnvelope(wire)
	if err != nil || env.Selection.EnrollmentBinding != c.enrollment {
		return zero, ErrClient
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	token, err := safeToken(c.token)
	if err != nil || len(token) == 0 {
		clear(token)
		return zero, ErrClientDenied
	}
	defer clear(token)
	credential, err := sensor.ParseTokenCredential(string(token))
	if err != nil {
		return zero, ErrClientDenied
	}
	secret, err := credential.Wire()
	credential.Destroy()
	if err != nil {
		return zero, ErrClientDenied
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+heartbeatPath, bytes.NewReader(wire))
	if err != nil {
		return zero, ErrClient
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Content-Type", heartbeatMediaType)
	request.Header.Set("X-Zasp-Schema-Version", nodecoveragewire.HeartbeatSchema)
	response, err := safeDo(c.do, request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.Body == nil {
		return zero, ErrClientRetryable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	defer clear(raw)
	if err != nil || ctx.Err() != nil || len(raw) > 16384 {
		return zero, ErrClientRetryable
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return zero, ErrClientDenied
	}
	if response.StatusCode != http.StatusOK || !retainedResponseHeader(response.Header, "Cache-Control", "no-store") || !retainedResponseHeader(response.Header, "Content-Type", "application/json") {
		return zero, ErrClientRetryable
	}
	receipt, err := nodecoveragewire.ParseReceipt(raw)
	sum := sha256.Sum256(wire)
	if err != nil || receipt.SensorID != c.sensorID || receipt.Sequence != env.Sequence || receipt.RequestDigest != hex.EncodeToString(sum[:]) || !receipt.SourceObservedAt.Equal(env.SourceObservedAt) || !receipt.ExpiresAt.Equal(env.SourceObservedAt.Add(time.Duration(env.TTLSeconds)*time.Second)) {
		return zero, ErrClientRetryable
	}
	return receipt, nil
}
func retainedResponseHeader(h http.Header, name, value string) bool {
	values := h.Values(name)
	return len(values) == 1 && values[0] == value
}
