package collection

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type effectTransportFunc func(*http.Request) (*http.Response, error)

func (f effectTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type effectRequestBody struct{ closed bool }

func (*effectRequestBody) Read([]byte) (int, error) {
	return 0, errors.New("must not read rejected request")
}
func (b *effectRequestBody) Close() error { b.closed = true; return nil }

func TestProductEffectTransportClosesRejectedBody(t *testing.T) {
	ctx, cancel, err := WithProductEffect(context.Background(), strings.Repeat("a", 64), time.Now().Add(time.Minute), func(context.Context) error { return errors.New("revoked") })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	body := &effectRequestBody{}
	request, _ := http.NewRequestWithContext(ctx, "POST", "https://provider.example.test", body)
	transport := EffectTransport{Next: effectTransportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("rejected send reached provider")
		return nil, nil
	})}
	if _, err := transport.RoundTrip(request); err == nil || !body.closed {
		t.Fatal("rejected body retained", body.closed, err)
	}
}

func TestProductEffectTransportChecksEverySend(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	revoked := false
	checks, sends := 0, 0
	ctx, cancel, err := WithProductEffect(context.Background(), strings.Repeat("a", 64), deadline, func(context.Context) error {
		checks++
		if revoked {
			return errors.New("revoked")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	transport := EffectTransport{Next: effectTransportFunc(func(r *http.Request) (*http.Response, error) {
		sends++
		got, ok := r.Context().Deadline()
		if !ok || got.After(deadline) {
			t.Fatal("missing original budget")
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})}
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://provider.example.test", nil)
	if _, err = transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	revoked = true
	if _, err = transport.RoundTrip(request); err == nil {
		t.Fatal("revoked send allowed")
	}
	if checks != 2 || sends != 1 {
		t.Fatalf("checks=%d sends=%d", checks, sends)
	}
	cancel()
	if _, err = transport.RoundTrip(request); err == nil {
		t.Fatal("cancelled send allowed")
	}
	if checks != 2 || sends != 1 {
		t.Fatal("cancelled boundary reached IO")
	}
	if err = RequireProductEffect(ctx, strings.Repeat("b", 64)); err == nil {
		t.Fatal("foreign effect context accepted")
	}
	if err = RequireProductEffect(context.Background(), strings.Repeat("a", 64)); err == nil {
		t.Fatal("unguarded product request accepted")
	}
}
