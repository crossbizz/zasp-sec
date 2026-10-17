package runtimeindex

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type journalBoundaryFixture struct {
	reserve, claim, append int
	failure                string
}

func (g *journalBoundaryFixture) BeginRetainedExecution(context.Context, RetainedExecutionInput) (RetainedExecutionJournal, error) {
	return g, nil
}
func (g *journalBoundaryFixture) VisibleEvents(context.Context, domain.Scope, []string) (map[string]bool, error) {
	return nil, errors.New("not used")
}
func (g *journalBoundaryFixture) RecordRetainedWrite(context.Context, RetainedWriteReceipt) error {
	return errors.New("not used")
}
func (g *journalBoundaryFixture) ReserveRequest(context.Context, RetainedRequestDescriptor) error {
	g.reserve++
	if g.failure == "reserve" {
		return ErrUnknownOutcome
	}
	return nil
}
func (g *journalBoundaryFixture) ClaimSend(context.Context) (bool, error) {
	g.claim++
	if g.failure == "unknown commit" {
		return true, ErrUnknownOutcome
	}
	return g.failure != "replay", nil
}
func (g *journalBoundaryFixture) AppendTerminal(context.Context, int, []byte) error {
	g.append++
	return nil
}
func TestRetainedJournalClaimCrashAndOneUseBoundaries(t *testing.T) {
	for _, failure := range []string{"reserve", "unknown commit", "replay", "confirmed"} {
		t.Run(failure, func(t *testing.T) {
			g := &journalBoundaryFixture{failure: failure}
			ctx, err := BeginRetainedJournal(context.Background(), g, RetainedExecutionInput{})
			if err != nil {
				t.Fatal("fixture begin refused")
			}
			ctx = WithRetainedBulkItems(ctx, []string{"document"}, []string{"event"})
			permit, err := PrepareRetainedBulk(ctx, RetainedRequestDescriptor{})
			if failure != "confirmed" {
				if err == nil || permit != nil || ConsumeRetainedSendPermit(ctx, permit) == nil {
					t.Fatal("unconfirmed durable claim issued transport capability")
				}
			} else {
				other, otherErr := BeginRetainedJournal(context.Background(), g, RetainedExecutionInput{})
				if otherErr != nil || ConsumeRetainedSendPermit(other, permit) == nil {
					t.Fatal("volatile permit crossed private execution context")
				}
				if err != nil || ConsumeRetainedSendPermit(ctx, permit) != nil || ConsumeRetainedSendPermit(ctx, permit) == nil {
					t.Fatal("confirmed claim was missing or reusable")
				}
			}
			if _, err := PrepareRetainedBulk(ctx, RetainedRequestDescriptor{}); err == nil {
				t.Fatal("same execution reserved a second bulk")
			}
			if g.reserve != 1 || g.claim > 1 {
				t.Fatal("crash/status path reconstructed a dispatch")
			}
		})
	}
}
