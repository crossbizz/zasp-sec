package reconciliation

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var (
	ErrInventoryConfiguration = errors.New("inventory configuration rejected")
	ErrInventoryForbidden     = errors.New("inventory authorization rejected")
	ErrInventoryInvalid       = errors.New("inventory request rejected")
	ErrInventoryNotFound      = errors.New("inventory resource not found")
)

type AgentSession struct {
	ID, AgentID domain.ProductID
	Scope       domain.Scope
	StartedAt   time.Time
}

type InventoryService struct {
	store        *MemoryStore
	projector    *MemoryProjector
	capabilities *CapabilityGraph
	sessions     []AgentSession
}

func NewInventoryService(store *MemoryStore, projector *MemoryProjector, capabilities *CapabilityGraph, sessions []AgentSession) (*InventoryService, error) {
	if store == nil || projector == nil || capabilities == nil || len(sessions) > 10_000 {
		return nil, ErrInventoryConfiguration
	}
	retained := append([]AgentSession(nil), sessions...)
	seen := map[domain.ProductID]struct{}{}
	for _, session := range retained {
		if session.ID.IsZero() || session.AgentID.IsZero() || session.Scope.Validate() != nil || !canonicalTime(session.StartedAt) {
			return nil, ErrInventoryConfiguration
		}
		if _, duplicate := seen[session.ID]; duplicate {
			return nil, ErrInventoryConfiguration
		}
		asset, err := store.Get(context.Background(), session.Scope, session.AgentID)
		if err != nil || asset.Kind != KindAgent {
			return nil, ErrInventoryConfiguration
		}
		seen[session.ID] = struct{}{}
	}
	sort.Slice(retained, func(left, right int) bool { return retained[left].ID.String() < retained[right].ID.String() })
	return &InventoryService{store: store, projector: projector, capabilities: capabilities, sessions: retained}, nil
}

func (service *InventoryService) List(ctx context.Context, scope domain.Scope, kind Kind) ([]Asset, error) {
	if !service.usable() {
		return nil, ErrInventoryConfiguration
	}
	values, err := service.store.List(ctx, scope, kind)
	if err != nil {
		return nil, ErrInventoryInvalid
	}
	return values, nil
}

func (service *InventoryService) Get(ctx context.Context, scope domain.Scope, id domain.ProductID, kind Kind) (Asset, error) {
	if !service.usable() {
		return Asset{}, ErrInventoryConfiguration
	}
	value, err := service.store.Get(ctx, scope, id)
	if err != nil || value.Kind != kind {
		return Asset{}, ErrInventoryNotFound
	}
	return value, nil
}

func (service *InventoryService) UpdateAgent(ctx context.Context, scope domain.Scope, id domain.ProductID, owner, team string, tags []string, at time.Time) (Asset, Audit, error) {
	if !service.usable() {
		return Asset{}, Audit{}, ErrInventoryConfiguration
	}
	value, audit, err := service.store.UpdateOwnership(ctx, scope, id, owner, team, tags, at)
	if err != nil {
		return Asset{}, Audit{}, ErrInventoryInvalid
	}
	return value, audit, nil
}

func (service *InventoryService) Capabilities(ctx context.Context, scope domain.Scope, agentID domain.ProductID) ([]Capability, error) {
	if _, err := service.Get(ctx, scope, agentID, KindAgent); err != nil {
		return nil, err
	}
	values, err := service.capabilities.Query(ctx, scope, agentID)
	if err != nil {
		return nil, ErrInventoryNotFound
	}
	return values, nil
}

func (service *InventoryService) Relationships(ctx context.Context, scope domain.Scope, agentID domain.ProductID) ([]Relationship, error) {
	if _, err := service.Get(ctx, scope, agentID, KindAgent); err != nil {
		return nil, err
	}
	values, err := service.projector.ListFrom(ctx, scope, agentID)
	if err != nil {
		return nil, ErrInventoryInvalid
	}
	return values, nil
}

func (service *InventoryService) Sessions(ctx context.Context, scope domain.Scope, agentID domain.ProductID) ([]AgentSession, error) {
	if _, err := service.Get(ctx, scope, agentID, KindAgent); err != nil {
		return nil, err
	}
	if !active(ctx) {
		return nil, ErrInventoryInvalid
	}
	result := []AgentSession{}
	for _, session := range service.sessions {
		if session.Scope == scope && session.AgentID == agentID {
			result = append(result, session)
		}
	}
	return result, nil
}

func (service *InventoryService) usable() bool {
	return service != nil && service.store != nil && service.projector != nil && service.capabilities != nil
}
