package sensor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
)

// This group exercises admission and exact terminal receipts through the actual
// new HTTP handler. The authority is controlled; it proves no database commit.
func TestPrivateNodeCoverageHeartbeatAdmissionAndReceipt(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	wire := retainedHandlerFixture(t, now, 1)
	token := fixtureV15TokenWire(t)
	request := func(body io.ReadCloser) *http.Request {
		r := httptest.NewRequest(http.MethodPost, PrivateHeartbeatPath, nil)
		r.Body, r.ContentLength = body, -1
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", PrivateHeartbeatMediaType)
		r.Header.Set(PrivateHeartbeatSchemaHeader, nodecoveragewire.HeartbeatSchema)
		return r
	}
	handler := func(a *retainedHeartbeatAuthorityFixture) http.Handler {
		h, err := NewPrivateNodeCoverageHeartbeatHandler(a, func() time.Time { return now }, time.Second)
		if err != nil {
			t.Fatal("retained constructor refused")
		}
		return h
	}
	t.Run("authenticated_exact_bytes_and_both_terminal_dispositions", func(t *testing.T) {
		for _, disposition := range []string{"accepted", "expired_not_committed"} {
			a := &retainedHeartbeatAuthorityFixture{}
			a.record = func(ctx context.Context, c *TokenCredential, raw []byte) (nodecoveragewire.Receipt, error) {
				if !bytes.Equal(raw, wire) || a.admissions.Load() != 1 {
					t.Error("record lost original bytes or admission")
				}
				if _, _, err := c.Parts(); err != nil {
					t.Error("record credential destroyed early")
				}
				return retainedHandlerReceipt(wire, now, disposition), nil
			}
			h := handler(a)
			out := httptest.NewRecorder()
			h.ServeHTTP(out, request(io.NopCloser(bytes.NewReader(wire))))
			var got nodecoveragewire.Receipt
			if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &got) != nil || got.Disposition != disposition || out.Header().Get("Cache-Control") != "no-store" || out.Header().Get("Content-Type") != "application/json" || a.records.Load() != 1 {
				t.Fatal("missing typed terminal200 receipt")
			}
			if _, _, err := a.credential.Parts(); err == nil {
				t.Fatal("credential retained after response")
			}
		}
	})
	t.Run("headers_size_and_credentials_refused_before_body_read", func(t *testing.T) {
		for _, mutate := range []func(*http.Request){
			func(r *http.Request) { r.Header.Del("Authorization") },
			func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+token) },
			func(r *http.Request) { r.Header.Set("X-Zasp-Scope", "foreign") },
			func(r *http.Request) { r.URL.RawQuery = "scope=foreign" },
			func(r *http.Request) { r.Header.Add(PrivateHeartbeatSchemaHeader, nodecoveragewire.HeartbeatSchema) },
			func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
			func(r *http.Request) { r.ContentLength = nodecoveragewire.MaxEnvelopeBytes + 1 },
		} {
			a := &retainedHeartbeatAuthorityFixture{}
			b := &retainedCountingBody{Reader: bytes.NewReader(wire)}
			r := request(b)
			mutate(r)
			out := httptest.NewRecorder()
			handler(a).ServeHTTP(out, r)
			if out.Code < 400 || b.reads.Load() != 0 || a.records.Load() != 0 || strings.Contains(out.Body.String(), token) {
				t.Fatal("invalid admission read body or exposed token")
			}
		}
		a := &retainedHeartbeatAuthorityFixture{admit: func(context.Context, *TokenCredential) error { return ErrForbidden }}
		b := &retainedCountingBody{Reader: bytes.NewReader(wire)}
		out := httptest.NewRecorder()
		handler(a).ServeHTTP(out, request(b))
		if out.Code != http.StatusUnauthorized || b.reads.Load() != 0 || a.records.Load() != 0 {
			t.Fatal("actual credential admission followed body allocation")
		}
	})
	t.Run("single_inflight_permit_and_canceled_admission_release", func(t *testing.T) {
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		a := &retainedHeartbeatAuthorityFixture{admit: func(ctx context.Context, _ *TokenCredential) error {
			close(entered)
			select {
			case <-release:
				return ErrForbidden
			case <-ctx.Done():
				return ErrUnavailable
			}
		}}
		h := handler(a)
		go func() {
			defer close(done)
			h.ServeHTTP(httptest.NewRecorder(), request(io.NopCloser(bytes.NewReader(wire))))
		}()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("first admission never started")
		}
		b := &retainedCountingBody{Reader: bytes.NewReader(wire)}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, request(b))
		close(release)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("first admission did not join")
		}
		if out.Code != http.StatusServiceUnavailable || b.reads.Load() != 0 || a.admissions.Load() != 1 {
			t.Fatal("concurrent request escaped single permit")
		}
		a.admit = nil
		out = httptest.NewRecorder()
		h.ServeHTTP(out, request(io.NopCloser(bytes.NewReader(wire))))
		if out.Code != http.StatusOK {
			t.Fatal("permit leaked after rejected admission")
		}
	})
	t.Run("bounded_unknown_length_and_legacy_limit_preserved", func(t *testing.T) {
		large := retainedHandlerFixture(t, now, 1000)
		if len(large) <= maximumPrivateHeartbeatBytes {
			t.Fatal("fixture did not exceed original limit")
		}
		a := &retainedHeartbeatAuthorityFixture{}
		out := httptest.NewRecorder()
		handler(a).ServeHTTP(out, request(io.NopCloser(bytes.NewReader(large))))
		if out.Code != http.StatusOK || a.records.Load() != 1 {
			t.Fatal("full selected1000 observation was truncated or refused")
		}
		old, _ := NewPrivateHeartbeatHandler(&heartbeatAuthorityStub{})
		out = httptest.NewRecorder()
		r := request(io.NopCloser(bytes.NewReader(large)))
		r.Header.Set(PrivateHeartbeatSchemaHeader, PrivateHeartbeatSchemaVersion)
		old.ServeHTTP(out, r)
		if out.Code < 400 {
			t.Fatal("legacy16KiB path widened")
		}
		over := &retainedCountingBody{Reader: io.LimitReader(retainedByteReader{}, nodecoveragewire.MaxEnvelopeBytes+2)}
		a = &retainedHeartbeatAuthorityFixture{}
		out = httptest.NewRecorder()
		handler(a).ServeHTTP(out, request(over))
		if out.Code < 400 || a.records.Load() != 0 || over.bytes.Load() > nodecoveragewire.MaxEnvelopeBytes+1 {
			t.Fatal("unknown-length body exceeded fixed16MiB+1 read bound")
		}
	})
	t.Run("invalid_or_unknown_commit_never_acknowledged", func(t *testing.T) {
		for _, mode := range []string{"error", "digest", "sequence", "time", "panic"} {
			a := &retainedHeartbeatAuthorityFixture{record: func(_ context.Context, _ *TokenCredential, raw []byte) (nodecoveragewire.Receipt, error) {
				rec := retainedHandlerReceipt(raw, now, "accepted")
				switch mode {
				case "error":
					return rec, ErrUnavailable
				case "digest":
					rec.RequestDigest = strings.Repeat("0", 64)
				case "sequence":
					rec.Sequence++
				case "time":
					rec.ExpiresAt = rec.ExpiresAt.Add(time.Second)
				case "panic":
					panic("controlled authority panic")
				}
				return rec, nil
			}}
			out := httptest.NewRecorder()
			handler(a).ServeHTTP(out, request(io.NopCloser(bytes.NewReader(wire))))
			if out.Code < 400 || strings.Contains(out.Body.String(), token) {
				t.Fatal("unconfirmed or mismatched receipt acknowledged")
			}
		}
	})
	t.Run("operation_deadline_cancels_admission_and_preserves_permit", func(t *testing.T) {
		a := &retainedHeartbeatAuthorityFixture{admit: func(ctx context.Context, _ *TokenCredential) error {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("missing operation deadline")
			}
			<-ctx.Done()
			return ErrUnavailable
		}}
		h := handler(a)
		b := &retainedCountingBody{Reader: bytes.NewReader(wire)}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, request(b))
		if out.Code != http.StatusServiceUnavailable || b.reads.Load() != 0 || a.records.Load() != 0 {
			t.Fatal("expired admission read or acknowledged payload")
		}
		a.admit = nil
		out = httptest.NewRecorder()
		h.ServeHTTP(out, request(io.NopCloser(bytes.NewReader(wire))))
		if out.Code != http.StatusOK {
			t.Fatal("deadline leaked in-flight permit")
		}
	})
}

type retainedHeartbeatAuthorityFixture struct {
	admit               func(context.Context, *TokenCredential) error
	record              func(context.Context, *TokenCredential, []byte) (nodecoveragewire.Receipt, error)
	admissions, records atomic.Int64
	credential          *TokenCredential
}

func (a *retainedHeartbeatAuthorityFixture) AuthenticateNodeCoverage(ctx context.Context, c *TokenCredential) error {
	a.admissions.Add(1)
	a.credential = c
	if a.admit != nil {
		return a.admit(ctx, c)
	}
	return nil
}
func (a *retainedHeartbeatAuthorityFixture) RecordAuthenticatedNodeCoverage(ctx context.Context, c *TokenCredential, b []byte) (nodecoveragewire.Receipt, error) {
	a.records.Add(1)
	a.credential = c
	if a.record != nil {
		return a.record(ctx, c, b)
	}
	var v nodecoveragewire.Envelope
	if json.Unmarshal(b, &v) != nil {
		return nodecoveragewire.Receipt{}, ErrInvalid
	}
	return retainedHandlerReceipt(b, v.InventoryObservedAt, "accepted"), nil
}

type retainedCountingBody struct {
	io.Reader
	reads, bytes atomic.Int64
}

func (b *retainedCountingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	n, e := b.Reader.Read(p)
	b.bytes.Add(int64(n))
	return n, e
}
func (*retainedCountingBody) Close() error { return nil }

type retainedByteReader struct{}

func (retainedByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}
func retainedHandlerReceipt(raw []byte, now time.Time, disposition string) nodecoveragewire.Receipt {
	var v nodecoveragewire.Envelope
	_ = json.Unmarshal(raw, &v)
	sum := sha256.Sum256(raw)
	return nodecoveragewire.Receipt{SensorID: "pid_10000001-0000-4000-8000-000000000001", Sequence: v.Sequence, RequestDigest: hex.EncodeToString(sum[:]), Disposition: disposition, ResolvedAt: now, SourceObservedAt: v.SourceObservedAt, ExpiresAt: v.SourceObservedAt.Add(time.Duration(v.TTLSeconds) * time.Second)}
}
func retainedHandlerFixture(t *testing.T, now time.Time, count int) []byte {
	t.Helper()
	target := nodecoveragewire.CoverageTarget{Namespace: "sensor", Name: "agent", Release: "zasp", ReleaseNamespace: "sensor", Image: "example/sensor@sha256:" + strings.Repeat("b", 64), ServiceAccount: "agent", Container: "agent"}
	other := target
	other.Name = "tetragon"
	v := nodecoveragewire.Envelope{Heartbeat: nodecoveragewire.Heartbeat{Sequence: 7, Status: "degraded", Capabilities: []string{"process"}, Kernel: "unknown", BTF: false}, CoverageSchema: nodecoveragewire.CoverageSchema, StateUID: "11111111-1111-4111-8111-111111111111", StorageEpoch: 1, Selection: nodecoveragewire.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: "22222222-2222-4222-8222-222222222222", EnrollmentBinding: strings.Repeat("a", 64), MatchLabels: map[string]string{"group": "selected"}, Sensor: target, Tetragon: other}, TargetDigest: strings.Repeat("c", 64), InventoryObservedAt: now.Add(-time.Minute), SourceObservedAt: now.Add(-time.Minute), TTLSeconds: 30, SensorDaemonSetUID: "33333333-3333-4333-8333-333333333333", TetragonDaemonSetUID: "44444444-4444-4444-8444-444444444444", SelectedNodes: []nodecoveragewire.SelectedNode{}, Reports: []nodecoveragewire.NodeCoverageV2{}}
	for i := 1; i <= count; i++ {
		id := retainedFixtureID(i)
		v.SelectedNodes = append(v.SelectedNodes, nodecoveragewire.SelectedNode{NodeName: "node-" + id[:8], NodeUID: id, BootID: id})
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal("fixture encoding refused")
	}
	return b
}
func retainedFixtureID(i int) string {
	const digits = "0123456789abcdef"
	b := []byte("00000000-0000-4000-8000-000000000001")
	for p := 7; p >= 0; p-- {
		b[p] = digits[i&15]
		i >>= 4
	}
	return string(b)
}
