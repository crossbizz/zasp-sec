package main

import (
	"context"
	"errors"
	"testing"
)

type outboxProcessorFixture struct {
	calls int
	err   error
}

func (p *outboxProcessorFixture) RunOnce(context.Context) error { p.calls++; return p.err }
func TestTemporalRelayIndependentOfLegacyFailure(t *testing.T) {
	legacy := &outboxProcessorFixture{err: errors.New("legacy unavailable")}
	relay := &outboxProcessorFixture{}
	p := temporalOutboxProcessor{legacy: legacy, relay: relay}
	if err := p.RunOnce(context.Background()); err == nil || relay.calls != 1 || legacy.calls != 1 {
		t.Fatal("legacy failure prevented delivery", err)
	}
	legacy.err = nil
	relay.err = errors.New("Temporal unavailable")
	if err := p.RunOnce(context.Background()); err == nil || legacy.calls != 2 {
		t.Fatal("delivery failure prevented legacy owner", err)
	}
}
