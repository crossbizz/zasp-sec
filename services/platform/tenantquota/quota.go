package tenantquota

import (
	"errors"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumLimit uint32 = 1024

var (
	ErrInvalidConfiguration = errors.New("invalid tenant quota configuration")
	ErrInvalidRequest       = errors.New("invalid tenant quota request")
	ErrQuotaExceeded        = errors.New("tenant quota exceeded")
	ErrInvalidPermit        = errors.New("invalid tenant quota permit")
)

type Kind string

const (
	Connector  Kind = "connector"
	GraphQuery Kind = "graph_query"
	Test       Kind = "test"
	AIRequest  Kind = "ai_request"
)

func (kind Kind) String() string {
	if !kind.valid() {
		return ""
	}
	return string(kind)
}

func (kind Kind) valid() bool {
	return kind == Connector || kind == GraphQuery || kind == Test || kind == AIRequest
}

type Key struct {
	organizationID domain.ProductID
	kind           Kind
}

func NewKey(scope domain.Scope, kind Kind) (Key, error) {
	if scope.Validate() != nil || !kind.valid() {
		return Key{}, ErrInvalidRequest
	}
	key := Key{organizationID: scope.OrganizationID(), kind: kind}
	if !key.valid() {
		return Key{}, ErrInvalidRequest
	}
	return key, nil
}

func (key Key) OrganizationID() domain.ProductID {
	if !key.valid() {
		return domain.ProductID{}
	}
	return key.organizationID
}

func (key Key) Kind() Kind {
	if !key.valid() {
		return ""
	}
	return key.kind
}

func (key Key) valid() bool {
	text := key.organizationID.String()
	parsed, err := domain.ParseProductID(text)
	return err == nil && parsed == key.organizationID && key.kind.valid()
}

type Limits struct {
	Connectors   uint32
	GraphQueries uint32
	Tests        uint32
	AIRequests   uint32
}

func (limits Limits) valid() bool {
	return validLimit(limits.Connectors) && validLimit(limits.GraphQueries) &&
		validLimit(limits.Tests) && validLimit(limits.AIRequests)
}

func (limits Limits) limit(kind Kind) uint32 {
	if !limits.valid() || !kind.valid() {
		return 0
	}
	switch kind {
	case Connector:
		return limits.Connectors
	case GraphQuery:
		return limits.GraphQueries
	case Test:
		return limits.Tests
	case AIRequest:
		return limits.AIRequests
	default:
		return 0
	}
}

func validLimit(limit uint32) bool {
	return limit > 0 && limit <= maximumLimit
}

type Usage struct {
	InUse uint32
	Limit uint32
}

type Counter struct {
	state *counterState
}

type counterState struct {
	limits Limits
	mutex  sync.Mutex
	counts map[Key]uint32
}

func New(limits Limits) (*Counter, error) {
	if !limits.valid() {
		return nil, ErrInvalidConfiguration
	}
	return &Counter{state: &counterState{limits: limits, counts: make(map[Key]uint32)}}, nil
}

func (counter *Counter) TryAcquire(scope domain.Scope, kind Kind) (*Permit, error) {
	if !counter.valid() {
		return nil, ErrInvalidRequest
	}
	state := counter.state
	key, err := NewKey(scope, kind)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	limit := state.limits.limit(kind)

	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.counts[key] >= limit {
		return nil, ErrQuotaExceeded
	}
	state.counts[key]++
	return &Permit{state: &permitState{counter: state, key: key}}, nil
}

func (counter *Counter) Usage(scope domain.Scope, kind Kind) (Usage, error) {
	if !counter.valid() {
		return Usage{}, ErrInvalidRequest
	}
	state := counter.state
	key, err := NewKey(scope, kind)
	if err != nil {
		return Usage{}, ErrInvalidRequest
	}
	state.mutex.Lock()
	defer state.mutex.Unlock()
	return Usage{InUse: state.counts[key], Limit: state.limits.limit(kind)}, nil
}

func (counter *Counter) valid() bool {
	return counter != nil && counter.state != nil && counter.state.valid()
}

func (state *counterState) valid() bool {
	return state != nil && state.limits.valid() && state.counts != nil
}

type Permit struct {
	state *permitState
}

type permitState struct {
	mutex    sync.Mutex
	counter  *counterState
	key      Key
	released bool
}

func (permit *Permit) Release() error {
	if permit == nil || permit.state == nil {
		return ErrInvalidPermit
	}
	state := permit.state
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.released || !state.counter.valid() || !state.key.valid() {
		return ErrInvalidPermit
	}

	state.counter.mutex.Lock()
	defer state.counter.mutex.Unlock()
	count, exists := state.counter.counts[state.key]
	if !exists || count == 0 {
		return ErrInvalidPermit
	}
	if count == 1 {
		delete(state.counter.counts, state.key)
	} else {
		state.counter.counts[state.key] = count - 1
	}
	state.released = true
	return nil
}
