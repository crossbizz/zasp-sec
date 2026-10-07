// Package approvaldelivery is a private application protocol candidate. It does
// not issue authority. A native adapter must validate every opaque proof and
// durable transition; test doubles establish orchestration behavior only.
package approvalmaintenance

import (
	"context"
	"errors"
	"reflect"
	"time"
)

var (
	ErrDenied        = errors.New("delivery authority denied")
	ErrUnavailable   = errors.New("delivery unavailable")
	ErrConfiguration = errors.New("delivery configuration refused")
)

type Phase uint8

const (
	BeforeSecrets Phase = iota + 1
	BeforeDelivery
	BeforeSecretFailure
)

type AttemptKind uint8

const (
	DeliveryAttempt AttemptKind = iota + 1
	SecretFailureAttempt
)

// Reservation is an exact native source/lease reference. Scope and source
// provenance, payload, destination, idempotency and token are validated by the
// adapter. A bare reference or foreign lease must never pass native admission.
type Reservation struct {
	Reference string
	ExpiresAt time.Time
}
type Attempt struct{ CapturedProof []byte }
type Repository interface {
	Reserve(context.Context) (Reservation, bool, error)
	PauseDenied(context.Context, Reservation) error
	ReleaseUnattempted(context.Context, Reservation) error
	// BeginAttempt persists an idempotent exact attempt receipt. On an ambiguous
	// response callers stop; a native receipt recovery protocol owns recovery.
	BeginAttempt(context.Context, Reservation, AttemptKind, []byte) (Attempt, error)
	Complete(context.Context, Reservation, Attempt) error
	Fail(context.Context, Reservation, Attempt) error
}
type Gate interface {
	Authorize(context.Context, Reservation, Phase) ([]byte, error)
}
type Secrets interface {
	Resolve(context.Context, Reservation) ([]byte, error)
}
type Provider interface {
	Deliver(context.Context, Reservation, []byte) error
}
type Coordinator struct {
	Repository Repository
	Gate       Gate
	Secrets    Secrets
	Provider   Provider
	Now        func() time.Time
}

func (c Coordinator) RunOnce(ctx context.Context) error {
	if ctx == nil || missing(c.Repository) || missing(c.Gate) || missing(c.Secrets) || missing(c.Provider) || c.Now == nil {
		return ErrConfiguration
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	r, found, err := c.Repository.Reserve(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if !found {
		if r != (Reservation{}) {
			return ErrUnavailable
		}
		return nil
	}
	if r.Reference == "" || !r.ExpiresAt.Add(-2*time.Second).After(c.Now()) {
		return ErrUnavailable
	}
	providerCtx, cancel := context.WithDeadline(ctx, r.ExpiresAt.Add(-2*time.Second))
	defer cancel()
	settleCtx, settleCancel := context.WithDeadline(context.WithoutCancel(ctx), r.ExpiresAt.Add(-100*time.Millisecond))
	defer settleCancel()
	stop := func(cause error) error {
		if errors.Is(cause, ErrDenied) {
			if c.Repository.PauseDenied(settleCtx, r) != nil {
				return ErrUnavailable
			}
			return ErrDenied
		}
		if c.Repository.ReleaseUnattempted(settleCtx, r) != nil {
			return ErrUnavailable
		}
		return ErrUnavailable
	}
	authorize := func(phase Phase) ([]byte, error) {
		if providerCtx.Err() != nil {
			return nil, ErrUnavailable
		}
		proof, e := c.Gate.Authorize(providerCtx, r, phase)
		if e != nil {
			return nil, e
		}
		if providerCtx.Err() != nil || len(proof) == 0 {
			return nil, ErrUnavailable
		}
		return proof, nil
	}
	if _, err = authorize(BeforeSecrets); err != nil {
		return stop(err)
	}
	secret, secretErr := c.Secrets.Resolve(providerCtx, r)
	defer clear(secret)
	if errors.Is(secretErr, ErrDenied) {
		return stop(ErrDenied)
	}
	if providerCtx.Err() != nil {
		return stop(ErrUnavailable)
	}
	kind, phase := DeliveryAttempt, BeforeDelivery
	if secretErr != nil || len(secret) < 32 || len(secret) > 4096 {
		kind, phase = SecretFailureAttempt, BeforeSecretFailure
	}
	proof, err := authorize(phase)
	if err != nil {
		return stop(err)
	}
	if providerCtx.Err() != nil {
		return stop(ErrUnavailable)
	}
	attempt, err := c.Repository.BeginAttempt(providerCtx, r, kind, proof)
	if err != nil || len(attempt.CapturedProof) == 0 {
		// Never release or retry after an ambiguous durable attempt start.
		return ErrUnavailable
	}
	if kind == SecretFailureAttempt {
		if c.Repository.Fail(settleCtx, r, attempt) != nil {
			return ErrUnavailable
		}
		return nil
	}
	if providerCtx.Err() != nil || safelyDeliver(c.Provider, providerCtx, r, secret) != nil {
		if c.Repository.Fail(settleCtx, r, attempt) != nil {
			return ErrUnavailable
		}
		return nil
	}
	if c.Repository.Complete(settleCtx, r, attempt) != nil {
		return ErrUnavailable
	}
	return nil
}

func safelyDeliver(p Provider, ctx context.Context, r Reservation, secret []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	return p.Deliver(ctx, r, secret)
}

func missing(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}
