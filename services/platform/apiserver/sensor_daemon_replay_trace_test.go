package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSensorDaemonReplayTraceDropsSuccessAndGatesRetries(t *testing.T) {
	var calls atomic.Int32
	trace := &sensorDaemonReplayTrace{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"batch_id":"accepted-fixture"}`)
	})}
	if trace.allowReplay() {
		t.Fatal("replay armed before an accepted request")
	}
	server := httptest.NewTLSServer(trace)
	defer server.Close()
	server.Client().Timeout = 2 * time.Second
	body := []byte(`{"fixture":"one immutable request"}`)
	post := func(credential string) (*http.Response, error) {
		request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Idempotency-Key", "daemon-replay-fixture")
		request.Header.Set("Authorization", credential)
		return server.Client().Do(request)
	}
	response, err := post("fixture-original-identity")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || response != nil || calls.Load() != 1 {
		t.Fatal("first committed success reached the client", err, calls.Load())
	}
	for attempt := 0; attempt < 3; attempt++ {
		response, err = post("fixture-original-identity")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusServiceUnavailable || calls.Load() != 1 {
			t.Fatal("closed replay gate reached the handler", response.StatusCode, calls.Load())
		}
	}
	if !trace.allowReplay() {
		t.Fatal("accepted first request couldn't arm replay")
	}
	response, err = post("fixture-replacement-identity")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusAccepted || calls.Load() != 2 || string(raw) != `{"batch_id":"accepted-fixture"}` {
		t.Fatal("authorized replay response wasn't forwarded", err, calls.Load())
	}
	entries := trace.snapshot()
	if len(entries) != 2 || !bytes.Equal(entries[0].body, body) || !bytes.Equal(entries[1].body, body) || entries[0].key != "daemon-replay-fixture" || entries[1].key != entries[0].key || entries[0].status != http.StatusAccepted || entries[1].status != http.StatusAccepted || entries[0].authDigest != sha256.Sum256([]byte("fixture-original-identity")) || entries[1].authDigest != sha256.Sum256([]byte("fixture-replacement-identity")) {
		t.Fatal("trace lost exact body, key or credential digest")
	}
	entries[0].body[0] = '!'
	if entries[0].batchID != "accepted-fixture" || entries[1].batchID != "accepted-fixture" {
		t.Fatal("trace lost response batch identity")
	}
	if !bytes.Equal(trace.snapshot()[0].body, body) {
		t.Fatal("trace snapshot allowed mutation of retained evidence")
	}
}

func TestSensorDaemonReplayTracePollingDoesNotWaitForHandler(t *testing.T) {
	entered := make(chan struct{})
	trace := &sensorDaemonReplayTrace{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		w.WriteHeader(http.StatusGatewayTimeout)
	})}
	server := httptest.NewTLSServer(trace)
	defer server.Close()
	server.Client().Timeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, bytes.NewReader([]byte("fixture")))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if response, _ := server.Client().Do(request); response != nil {
			response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("stalled handler didn't start")
	}
	polled := make(chan bool, 1)
	go func() { polled <- len(trace.snapshot()) == 0 && !trace.allowReplay() }()
	blocked := false
	select {
	case valid := <-polled:
		if !valid {
			cancel()
			<-done
			t.Fatal("in-flight handler exposed acceptance")
		}
	case <-time.After(100 * time.Millisecond):
		blocked = true
	}
	cancel()
	<-done
	if blocked {
		select {
		case <-polled:
		case <-time.After(time.Second):
			t.Fatal("polling remained blocked after cancellation")
		}
		t.Fatal("evidence polling waited for the stalled handler")
	}
}

func TestSensorDaemonReplayTraceRejectsOversizeAndDoesNotHideFailure(t *testing.T) {
	var calls atomic.Int32
	trace := &sensorDaemonReplayTrace{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Fixture-Result", "rejected")
		http.Error(w, "fixture denial", http.StatusForbidden)
	})}
	oversize := httptest.NewRecorder()
	trace.ServeHTTP(oversize, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte{'x'}, (1<<20)+1))))
	if oversize.Code != http.StatusRequestEntityTooLarge || calls.Load() != 0 || len(trace.snapshot()) != 0 || trace.allowReplay() {
		t.Fatal("oversize request reached handler or admitted replay")
	}
	denied := httptest.NewRecorder()
	trace.ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("fixture"))))
	if denied.Code != http.StatusForbidden || denied.Header().Get("X-Fixture-Result") != "rejected" || denied.Body.String() != "fixture denial\n" || calls.Load() != 1 || trace.allowReplay() {
		t.Fatal("first handler denial was hidden or armed replay")
	}
	blocked := httptest.NewRecorder()
	trace.ServeHTTP(blocked, httptest.NewRequest(http.MethodPost, "/", nil))
	if blocked.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatal("denied first request admitted a later attempt")
	}
}

func TestSensorDaemonReplayTraceBoundsRetainedAttempts(t *testing.T) {
	var calls atomic.Int32
	trace := &sensorDaemonReplayTrace{claimed: true, replayAllowed: true, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	})}
	for attempt := 0; attempt < 10; attempt++ {
		response := httptest.NewRecorder()
		trace.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("fixture"))))
		want := http.StatusAccepted
		if attempt >= 8 {
			want = http.StatusServiceUnavailable
		}
		if response.Code != want {
			t.Fatal("unexpected bounded trace response", attempt, response.Code)
		}
	}
	if calls.Load() != 8 || len(trace.snapshot()) != 8 {
		t.Fatal("trace exceeded its fixed attempt budget")
	}
}
