package audit

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const redactedValue = "[REDACTED]"

type ProductEventInput struct {
	Actor    domain.ProductID
	Action   string
	Target   domain.ProductID
	Outcome  Outcome
	Metadata map[string]string
}

type AuditEvent struct {
	id         domain.ProductID
	scope      domain.Scope
	actor      domain.ProductID
	action     string
	target     domain.ProductID
	outcome    Outcome
	metadata   map[string]string
	occurredAt time.Time
}

func (event AuditEvent) ID() domain.ProductID        { return event.id }
func (event AuditEvent) Scope() domain.Scope         { return event.scope }
func (event AuditEvent) Actor() domain.ProductID     { return event.actor }
func (event AuditEvent) Action() string              { return event.action }
func (event AuditEvent) Target() domain.ProductID    { return event.target }
func (event AuditEvent) Outcome() Outcome            { return event.outcome }
func (event AuditEvent) Metadata() map[string]string { return cloneMetadata(event.metadata) }
func (event AuditEvent) OccurredAt() time.Time       { return event.occurredAt }

type EventStore struct {
	mu     sync.RWMutex
	events []AuditEvent
}

func NewEventStore() *EventStore { return &EventStore{} }

func (store *EventStore) Append(ctx context.Context, event AuditEvent) error {
	if store == nil || ctx == nil || ctx.Err() != nil || !validAuditEvent(event) {
		return ErrMutation
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, existing := range store.events {
		if existing.id == event.id {
			return ErrMutation
		}
	}
	store.events = append(store.events, cloneAuditEvent(event))
	return nil
}

func (store *EventStore) Query(ctx context.Context, organizationID domain.ProductID, limit, offset int) ([]AuditEvent, error) {
	if store == nil || ctx == nil || ctx.Err() != nil || organizationID.IsZero() || limit < 1 || limit > 100 || offset < 0 {
		return nil, ErrMutation
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	values := make([]AuditEvent, 0)
	for _, event := range store.events {
		if event.scope.OrganizationID() == organizationID {
			values = append(values, cloneAuditEvent(event))
		}
	}
	sort.Slice(values, func(first, second int) bool {
		if values[first].occurredAt.Equal(values[second].occurredAt) {
			return values[first].id.String() < values[second].id.String()
		}
		return values[first].occurredAt.After(values[second].occurredAt)
	})
	if offset > len(values) {
		return nil, ErrMutation
	}
	end := min(offset+limit, len(values))
	return append([]AuditEvent(nil), values[offset:end]...), nil
}

type AuditExport struct {
	id             domain.ProductID
	organizationID domain.ProductID
	requestedBy    domain.ProductID
	status         string
	eventCount     int
	createdAt      time.Time
}

func (export AuditExport) ID() domain.ProductID             { return export.id }
func (export AuditExport) OrganizationID() domain.ProductID { return export.organizationID }
func (export AuditExport) RequestedBy() domain.ProductID    { return export.requestedBy }
func (export AuditExport) Status() string                   { return export.status }
func (export AuditExport) EventCount() int                  { return export.eventCount }
func (export AuditExport) CreatedAt() time.Time             { return export.createdAt }

type ProductService struct {
	mu       sync.RWMutex
	store    *EventStore
	generate func() (domain.ProductID, error)
	now      func() time.Time
	exports  map[domain.ProductID]AuditExport
}

func NewProductService(store *EventStore, generate func() (domain.ProductID, error), now func() time.Time) (*ProductService, error) {
	current, ok := readClock(now)
	if store == nil || generate == nil || !ok || !canonicalAuditTime(current) {
		return nil, ErrConfiguration
	}
	return &ProductService{store: store, generate: generate, now: now, exports: map[domain.ProductID]AuditExport{}}, nil
}

func (service *ProductService) Record(ctx context.Context, scope domain.Scope, input ProductEventInput) (AuditEvent, error) {
	current, ok := readClock(serviceClock(service))
	if service == nil || ctx == nil || ctx.Err() != nil || !ok || scope.Validate() != nil || !validProductInput(input) {
		return AuditEvent{}, ErrMutation
	}
	id, err := service.generate()
	if err != nil || id.IsZero() {
		return AuditEvent{}, ErrEmit
	}
	metadata, err := redactMetadata(input.Metadata)
	if err != nil {
		return AuditEvent{}, err
	}
	event := AuditEvent{id: id, scope: scope, actor: input.Actor, action: input.Action, target: input.Target,
		outcome: input.Outcome, metadata: metadata, occurredAt: current}
	if err := service.store.Append(ctx, event); err != nil {
		return AuditEvent{}, ErrEmit
	}
	return cloneAuditEvent(event), nil
}

func (service *ProductService) Query(ctx context.Context, organizationID domain.ProductID, limit, offset int) ([]AuditEvent, error) {
	if service == nil || service.store == nil {
		return nil, ErrConfiguration
	}
	return service.store.Query(ctx, organizationID, limit, offset)
}

func (service *ProductService) CreateExport(ctx context.Context, organizationID, requestedBy domain.ProductID) (AuditExport, error) {
	current, ok := readClock(serviceClock(service))
	if service == nil || ctx == nil || ctx.Err() != nil || organizationID.IsZero() || requestedBy.IsZero() || !ok {
		return AuditExport{}, ErrMutation
	}
	eventCount := 0
	for {
		events, err := service.store.Query(ctx, organizationID, 100, eventCount)
		if err != nil {
			return AuditExport{}, ErrEmit
		}
		eventCount += len(events)
		if len(events) < 100 {
			break
		}
	}
	id, err := service.generate()
	if err != nil || id.IsZero() {
		return AuditExport{}, ErrEmit
	}
	export := AuditExport{id: id, organizationID: organizationID, requestedBy: requestedBy, status: "ready", eventCount: eventCount, createdAt: current}
	service.mu.Lock()
	defer service.mu.Unlock()
	if _, exists := service.exports[id]; exists {
		return AuditExport{}, ErrMutation
	}
	service.exports[id] = export
	return export, nil
}

func (service *ProductService) GetExport(ctx context.Context, organizationID, exportID domain.ProductID) (AuditExport, error) {
	if service == nil || ctx == nil || ctx.Err() != nil || organizationID.IsZero() || exportID.IsZero() {
		return AuditExport{}, ErrMutation
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	value, exists := service.exports[exportID]
	if !exists {
		return AuditExport{}, ErrMutation
	}
	if value.organizationID != organizationID {
		return AuditExport{}, ErrMutation
	}
	return value, nil
}

func redactMetadata(input map[string]string) (map[string]string, error) {
	if len(input) > 32 {
		return nil, ErrMutation
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		if !validMetadataPart(key, 64) || !validMetadataPart(value, 512) {
			return nil, ErrMutation
		}
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "authorization") || strings.Contains(lower, "credential") || strings.Contains(lower, "api_key") {
			result[key] = redactedValue
		} else {
			result[key] = value
		}
	}
	return result, nil
}

func validProductInput(input ProductEventInput) bool {
	return !input.Actor.IsZero() && !input.Target.IsZero() && validAction(input.Action) && validOutcome(input.Outcome)
}

func validAuditEvent(event AuditEvent) bool {
	return !event.id.IsZero() && event.scope.Validate() == nil && !event.actor.IsZero() && !event.target.IsZero() &&
		validAction(event.action) && validOutcome(event.outcome) && canonicalAuditTime(event.occurredAt) && event.metadata != nil
}

func validMetadataPart(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func canonicalAuditTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0)
}

func readClock(clock func() time.Time) (value time.Time, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = time.Time{}, false
		}
	}()
	if clock == nil {
		return time.Time{}, false
	}
	return clock(), true
}

func serviceClock(service *ProductService) func() time.Time {
	if service == nil {
		return nil
	}
	return service.now
}

func cloneAuditEvent(event AuditEvent) AuditEvent {
	event.metadata = cloneMetadata(event.metadata)
	return event
}

func cloneMetadata(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, part := range value {
		result[key] = part
	}
	return result
}
