package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// This fixture loses only the first committed success. Until the owner joins
// the old daemon and explicitly opens replay, retries cannot reach the handler.
// It never stores credential text. The real database proof supplies handler.
type sensorDaemonReplayTrace struct {
	mu            sync.Mutex
	handler       http.Handler
	claimed       bool
	inFlight      bool
	replayAllowed bool
	entries       []daemonReplayHTTPEntry
}

type daemonReplayHTTPEntry struct {
	installedChunkHTTPEntry
	batchID string
}

func (trace *sensorDaemonReplayTrace) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	trace.mu.Lock()
	if trace.inFlight || trace.claimed && !trace.replayAllowed || len(trace.entries) >= 8 {
		trace.mu.Unlock()
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	trace.inFlight = true
	first := !trace.claimed
	trace.mu.Unlock()
	defer func() {
		trace.mu.Lock()
		trace.inFlight = false
		trace.mu.Unlock()
	}()
	// Keep evidence polling independent of slow sockets or database work. Only
	// one request can enter the real handler, which may own a pgx connection.
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	deadline, _ := ctx.Deadline()
	controller := http.NewResponseController(writer)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	trace.mu.Lock()
	trace.claimed = true
	trace.mu.Unlock()
	request.Body = io.NopCloser(bytes.NewReader(body))
	response := httptest.NewRecorder()
	trace.handler.ServeHTTP(response, request)
	var receipt struct {
		BatchID string `json:"batch_id"`
	}
	if response.Body.Len() <= 64<<10 {
		_ = json.Unmarshal(response.Body.Bytes(), &receipt)
	}
	trace.mu.Lock()
	trace.entries = append(trace.entries, daemonReplayHTTPEntry{installedChunkHTTPEntry: installedChunkHTTPEntry{
		body: bytes.Clone(body), key: request.Header.Get("Idempotency-Key"),
		authDigest: sha256.Sum256([]byte(request.Header.Get("Authorization"))), status: response.Code,
	}, batchID: receipt.BatchID})
	trace.mu.Unlock()
	if first && response.Code == http.StatusAccepted {
		// net/http aborts the connection without response headers or a panic log.
		panic(http.ErrAbortHandler)
	}
	for key, values := range response.Header() {
		writer.Header()[key] = append([]string(nil), values...)
	}
	writer.WriteHeader(response.Code)
	_, _ = writer.Write(response.Body.Bytes())
}

func (trace *sensorDaemonReplayTrace) allowReplay() bool {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if trace.inFlight || len(trace.entries) == 0 || trace.entries[0].status != http.StatusAccepted {
		return false
	}
	trace.replayAllowed = true
	return true
}

func (trace *sensorDaemonReplayTrace) snapshot() []daemonReplayHTTPEntry {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	entries := append([]daemonReplayHTTPEntry(nil), trace.entries...)
	for index := range entries {
		entries[index].body = bytes.Clone(entries[index].body)
	}
	return entries
}
