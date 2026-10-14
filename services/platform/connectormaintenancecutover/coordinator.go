// Package connectormaintenancecutover implements only controlled-owned local cutover.
package connectormaintenancecutover

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrRefused = errors.New("connector controlled cutover refused")

// Neither observations nor permits are accepted as operator-supplied JSON/hashes.
type identity struct {
	pid                int
	start              string
	dev, ino           uint64
	executable, sha256 string
}
type evidence interface {
	oldModel(context.Context) error
	oldUnauthorized(context.Context) error
	newModel(context.Context) error
	live(context.Context, int) (identity, error)
	absent(context.Context, identity) error
}
type activation interface {
	activate(context.Context, string, identity, func(context.Context) error) error
}
type Coordinator struct {
	mu           sync.Mutex
	observations evidence
	sql          activation
	ttl          time.Duration
}
type Permit struct {
	owner        *Coordinator
	organization string
	writer       identity
	expires      time.Time
	state        *permitState
}

type permitState struct{ spent bool }

func (c *Coordinator) Prepare(ctx context.Context, organization string, oldWriterPID int) (*Permit, error) {
	if c == nil || c.observations == nil || c.sql == nil || ctx == nil || ctx.Err() != nil || organization == "" || oldWriterPID <= 0 || c.ttl <= 0 || c.ttl > 30*time.Second {
		return nil, prepareRefused(ctx, "invalid")
	}
	expires := time.Now().Add(c.ttl)
	if parent, ok := ctx.Deadline(); ok && parent.Before(expires) {
		expires = parent
	}
	bounded, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	ctx = bounded
	// Authentic old credential and a live exact writer are mandatory, not optional.
	before, err := c.observations.live(ctx, oldWriterPID)
	if err != nil {
		return nil, prepareRefused(ctx, "live-before")
	}
	if c.observations.oldModel(ctx) != nil {
		return nil, prepareRefused(ctx, "model-read")
	}
	after, err := c.observations.live(ctx, oldWriterPID)
	if err != nil || before != after || ctx.Err() != nil {
		return nil, prepareRefused(ctx, "live-after")
	}
	return &Permit{owner: c, organization: organization, writer: after, expires: expires, state: &permitState{}}, nil
}

func (c *Coordinator) Activate(ctx context.Context, p *Permit) error {
	if c == nil || ctx == nil {
		return ErrRefused
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p == nil || p.owner != c || p.state == nil || p.state.spent || !time.Now().Before(p.expires) || ctx.Err() != nil {
		return ErrRefused
	}
	// Consume before any fallible effect. An uncertain SQL result cannot be resent.
	p.state.spent = true
	bounded, cancel := context.WithDeadline(ctx, p.expires)
	defer cancel()
	verify := func(check context.Context) error {
		if check.Err() != nil || !time.Now().Before(p.expires) || c.observations.oldUnauthorized(check) != nil || c.observations.absent(check, p.writer) != nil || c.observations.newModel(check) != nil || check.Err() != nil {
			return ErrRefused
		}
		return nil
	}
	// Concrete SQL adapter must call verify after original79 organization lock,
	// before fixed operator-only activation, in the same bounded transaction.
	if verify(bounded) != nil || c.sql.activate(bounded, p.organization, p.writer, verify) != nil || bounded.Err() != nil {
		return ErrRefused
	}
	return nil
}

// PrepareRefusalStage returns only a fixed diagnostic stage, without exposing
// process identity, credentials, model contents or dependency errors.
func PrepareRefusalStage(err error) string {
	var refusal *prepareRefusal
	if !errors.As(err, &refusal) || refusal == nil {
		return "unknown"
	}
	switch refusal.stage {
	case "invalid", "live-before", "model-read", "live-after", "deadline":
		return refusal.stage
	default:
		return "unknown"
	}
}

type prepareRefusal struct{ stage string }

func (*prepareRefusal) Error() string { return ErrRefused.Error() }
func (*prepareRefusal) Unwrap() error { return ErrRefused }
func prepareRefused(ctx context.Context, stage string) error {
	if ctx != nil && ctx.Err() != nil {
		stage = "deadline"
	}
	return &prepareRefusal{stage: stage}
}
