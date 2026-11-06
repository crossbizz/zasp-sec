package runtimeindex

import (
	"context"
	"crypto/sha256"
	"sync/atomic"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// RetainedExecutionInput contains source identities only, never lease secrets.
type RetainedExecutionInput struct {
	Kind                  string
	Scope                 domain.Scope
	BatchID               string
	Generation            int64
	InputDigest           [sha256.Size]byte
	DocumentIDs, EventIDs []string
}

// RetainedRequestDescriptor describes the actual serialized request. No request
// payload, authorization header, private capability or lease token is retained.
type RetainedRequestDescriptor struct {
	Ordinal           int      `json:"ordinal"`
	Method            string   `json:"method"`
	Target            string   `json:"target"`
	Path              string   `json:"path"`
	Query             string   `json:"query"`
	MediaType         string   `json:"media_type"`
	BodySHA256        string   `json:"body_sha256"`
	BodyLength        int      `json:"body_length"`
	DocumentIDs       []string `json:"document_ids"`
	EventIDs          []string `json:"event_ids"`
	SerializerProfile string   `json:"serializer_profile"`
}

type RetainedExecutionJournal interface {
	ReserveRequest(context.Context, RetainedRequestDescriptor) error
	ClaimSend(context.Context) (bool, error)
	AppendTerminal(context.Context, int, []byte) error
}
type RetainedJournalAuthority interface {
	BeginRetainedExecution(context.Context, RetainedExecutionInput) (RetainedExecutionJournal, error)
}

type retainedJournalKey struct{}
type retainedItemsKey struct{}
type retainedBulkItems struct{ documents, events []string }
type retainedJournalContext struct {
	journal    RetainedExecutionJournal
	reserved   atomic.Bool
	dispatched atomic.Bool
}

// BeginRetainedJournal preserves the historical non-journal authority contract.
// Production retention constructors must mount a real journal authority.
func BeginRetainedJournal(ctx context.Context, authority RetainedWriteAuthority, input RetainedExecutionInput) (context.Context, error) {
	journaled, ok := authority.(RetainedJournalAuthority)
	if !ok {
		return ctx, nil
	}
	if ctx == nil || ctx.Err() != nil || ctx.Value(retainedJournalKey{}) != nil {
		return nil, ErrUnknownOutcome
	}
	journal, err := journaled.BeginRetainedExecution(ctx, input)
	if err != nil || nilInterface(journal) {
		return nil, ErrUnknownOutcome
	}
	return context.WithValue(ctx, retainedJournalKey{}, &retainedJournalContext{journal: journal}), nil
}
func WithRetainedBulkItems(ctx context.Context, documents, events []string) context.Context {
	return context.WithValue(ctx, retainedItemsKey{}, retainedBulkItems{append([]string(nil), documents...), append([]string(nil), events...)})
}

type RetainedSendPermit struct {
	unused atomic.Bool
	owner  *retainedJournalContext
}

// Only a new, confirmed committed claim can produce this private volatile
// permit. Neither a status lookup nor a replay can reconstruct it.
func PrepareRetainedBulk(ctx context.Context, descriptor RetainedRequestDescriptor) (*RetainedSendPermit, error) {
	state, _ := ctx.Value(retainedJournalKey{}).(*retainedJournalContext)
	if state == nil {
		return nil, nil
	}
	items, ok := ctx.Value(retainedItemsKey{}).(retainedBulkItems)
	if !ok || len(items.documents) == 0 || len(items.documents) != len(items.events) || !state.reserved.CompareAndSwap(false, true) {
		return nil, ErrUnknownOutcome
	}
	descriptor.DocumentIDs, descriptor.EventIDs = append([]string(nil), items.documents...), append([]string(nil), items.events...)
	if state.journal.ReserveRequest(ctx, descriptor) != nil {
		return nil, ErrUnknownOutcome
	}
	permitted, err := state.journal.ClaimSend(ctx)
	if err != nil || !permitted {
		return nil, ErrUnknownOutcome
	}
	permit := &RetainedSendPermit{owner: state}
	permit.unused.Store(true)
	return permit, nil
}
func ConsumeRetainedSendPermit(ctx context.Context, permit *RetainedSendPermit) error {
	state, _ := ctx.Value(retainedJournalKey{}).(*retainedJournalContext)
	if state == nil {
		if permit != nil {
			return ErrUnknownOutcome
		}
		return nil
	}
	if ctx.Err() != nil || permit == nil || permit.owner != state || !permit.unused.CompareAndSwap(true, false) {
		return ErrUnknownOutcome
	}
	state.dispatched.Store(true)
	return nil
}

// AppendRetainedTerminal is called only after the original strict bulk terminal
// validator accepts the complete actual response, before any live readback.
func AppendRetainedTerminal(ctx context.Context, status int, body []byte) error {
	state, _ := ctx.Value(retainedJournalKey{}).(*retainedJournalContext)
	if state == nil {
		return nil
	}
	if !state.dispatched.Load() || len(body) == 0 || len(body) > 8<<20 {
		return ErrUnknownOutcome
	}
	if state.journal.AppendTerminal(ctx, status, append([]byte(nil), body...)) != nil {
		return ErrUnknownOutcome
	}
	return nil
}

// The returned interface has no public execution capability or lease fields.
// Worker authority checks its own concrete private binding before every use.
func RetainedJournalFromContext(ctx context.Context) RetainedExecutionJournal {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(retainedJournalKey{}).(*retainedJournalContext)
	if state == nil {
		return nil
	}
	return state.journal
}
