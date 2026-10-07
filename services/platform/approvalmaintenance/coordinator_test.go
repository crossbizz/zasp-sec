package approvalmaintenance

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// These are own protocol doubles, not native proofs, SQL or provider evidence.
type fixture struct {
	calls       []string
	deny        Phase
	secretErr   error
	providerErr error
	beginErr    error
	cancel      context.CancelFunc
	cancelAt    string
	secret      []byte
}

func (f *fixture) mark(s string) {
	f.calls = append(f.calls, s)
	if f.cancelAt == s {
		f.cancel()
	}
}
func (f *fixture) Reserve(context.Context) (Reservation, bool, error) {
	f.mark("reserve")
	return Reservation{"synthetic-reference", time.Now().Add(30 * time.Second)}, true, nil
}
func (f *fixture) PauseDenied(context.Context, Reservation) error { f.mark("pause"); return nil }
func (f *fixture) ReleaseUnattempted(context.Context, Reservation) error {
	f.mark("release")
	return nil
}
func (f *fixture) BeginAttempt(ctx context.Context, r Reservation, k AttemptKind, p []byte) (Attempt, error) {
	if ctx.Err() != nil {
		return Attempt{}, ErrUnavailable
	}
	if k == SecretFailureAttempt {
		f.mark("begin-secret-failure")
	} else {
		f.mark("begin-delivery")
	}
	if f.beginErr != nil {
		return Attempt{}, f.beginErr
	}
	return Attempt{[]byte("SYNTHETIC-ATTEMPT")}, nil
}
func (f *fixture) Complete(ctx context.Context, r Reservation, a Attempt) error {
	if ctx.Err() != nil || len(a.CapturedProof) == 0 {
		return ErrUnavailable
	}
	f.mark("complete")
	return nil
}
func (f *fixture) Fail(ctx context.Context, r Reservation, a Attempt) error {
	if ctx.Err() != nil || len(a.CapturedProof) == 0 {
		return ErrUnavailable
	}
	f.mark("fail")
	return nil
}
func (f *fixture) Authorize(ctx context.Context, r Reservation, p Phase) ([]byte, error) {
	names := map[Phase]string{BeforeSecrets: "gate-secret", BeforeDelivery: "gate-delivery", BeforeSecretFailure: "gate-failure"}
	f.mark(names[p])
	if f.deny == p {
		return nil, ErrDenied
	}
	return []byte("SYNTHETIC-FORWARD"), nil
}
func (f *fixture) Resolve(context.Context, Reservation) ([]byte, error) {
	f.mark("secret")
	f.secret = make([]byte, 32)
	for i := range f.secret {
		f.secret[i] = 0xa5
	}
	return f.secret, f.secretErr
}
func (f *fixture) Deliver(context.Context, Reservation, []byte) error {
	for _, b := range f.secret {
		if b != 0xa5 {
			return ErrUnavailable
		}
	}
	f.mark("send")
	return f.providerErr
}
func (f *fixture) coordinator() Coordinator { return Coordinator{f, f, f, f, time.Now} }
func want(t *testing.T, f *fixture, calls ...string) {
	t.Helper()
	if !reflect.DeepEqual(f.calls, calls) {
		t.Fatalf("protocol sequence=%v want=%v", f.calls, calls)
	}
}

func TestDeniedAuthorityDoesNotConsumeDeliveryAttempts(t *testing.T) {
	for _, p := range []Phase{BeforeSecrets, BeforeDelivery, BeforeSecretFailure} {
		t.Run(map[Phase]string{BeforeSecrets: "before-secret", BeforeDelivery: "before-send", BeforeSecretFailure: "failed-secret"}[p], func(t *testing.T) {
			f := &fixture{deny: p}
			if p == BeforeSecretFailure {
				f.secretErr = ErrUnavailable
			}
			if !errors.Is(f.coordinator().RunOnce(context.Background()), ErrDenied) {
				t.Fatal("denial was not preserved")
			}
			if p == BeforeSecrets {
				want(t, f, "reserve", "gate-secret", "pause")
			} else if p == BeforeDelivery {
				want(t, f, "reserve", "gate-secret", "secret", "gate-delivery", "pause")
			} else {
				want(t, f, "reserve", "gate-secret", "secret", "gate-failure", "pause")
			}
		})
	}
}
func TestAuthorizedSecretFailureRetainsFailureAttempt(t *testing.T) {
	f := &fixture{secretErr: ErrUnavailable}
	if f.coordinator().RunOnce(context.Background()) != nil {
		t.Fatal("failure settlement")
	}
	want(t, f, "reserve", "gate-secret", "secret", "gate-failure", "begin-secret-failure", "fail")
}
func TestSuccessfulDeliveryUsesBothGatesAndCapturedCompletion(t *testing.T) {
	f := &fixture{}
	if f.coordinator().RunOnce(context.Background()) != nil {
		t.Fatal("delivery")
	}
	want(t, f, "reserve", "gate-secret", "secret", "gate-delivery", "begin-delivery", "send", "complete")
	for _, b := range f.secret {
		if b != 0 {
			t.Fatal("secret not cleared")
		}
	}
}
func TestAttemptedProviderFailureUsesCapturedSettlement(t *testing.T) {
	f := &fixture{providerErr: ErrUnavailable}
	if f.coordinator().RunOnce(context.Background()) != nil {
		t.Fatal("failure settlement")
	}
	want(t, f, "reserve", "gate-secret", "secret", "gate-delivery", "begin-delivery", "send", "fail")
}
func TestCancellationBeforeAttemptReleasesWithoutBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fixture{cancel: cancel, cancelAt: "secret"}
	if !errors.Is(f.coordinator().RunOnce(ctx), ErrUnavailable) {
		t.Fatal("cancellation")
	}
	want(t, f, "reserve", "gate-secret", "secret", "release")
}
func TestAmbiguousAttemptStartNeverReleasesOrSends(t *testing.T) {
	f := &fixture{beginErr: ErrUnavailable}
	if !errors.Is(f.coordinator().RunOnce(context.Background()), ErrUnavailable) {
		t.Fatal("ambiguity")
	}
	want(t, f, "reserve", "gate-secret", "secret", "gate-delivery", "begin-delivery")
}
func TestInvalidCoordinatorDoesNotReserve(t *testing.T) {
	f := &fixture{}
	c := f.coordinator()
	c.Gate = nil
	if !errors.Is(c.RunOnce(context.Background()), ErrConfiguration) {
		t.Fatal("missing gate")
	}
	if len(f.calls) != 0 {
		t.Fatal("unconfigured reserve")
	}
	var typedNil *fixture
	c = f.coordinator()
	c.Repository = typedNil
	if !errors.Is(c.RunOnce(context.Background()), ErrConfiguration) {
		t.Fatal("typed nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(f.coordinator().RunOnce(ctx), ErrUnavailable) {
		t.Fatal("canceled")
	}
	if len(f.calls) != 0 {
		t.Fatal("canceled reserve")
	}
}

func TestAuthorityDenialDuringSecretBoundaryDoesNotBecomeFailureAttempt(t *testing.T) {
	f := &fixture{secretErr: ErrDenied}
	if !errors.Is(f.coordinator().RunOnce(context.Background()), ErrDenied) {
		t.Fatal("fresh authority denial was lost")
	}
	want(t, f, "reserve", "gate-secret", "secret", "pause")
	for _, b := range f.secret {
		if b != 0 {
			t.Fatal("nonzero secret survived authority denial")
		}
	}
}
