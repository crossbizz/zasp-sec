package sensor

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var (
	ErrInvalid     = errors.New("sensor input rejected")
	ErrForbidden   = errors.New("sensor authorization rejected")
	ErrNotFound    = errors.New("sensor not found")
	ErrConflict    = errors.New("sensor conflict")
	ErrUnavailable = errors.New("sensor authority unavailable")
)

type IDGenerator func() (domain.ProductID, error)
type TokenGenerator func() (string, error)
type Input struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}
type Heartbeat struct {
	Capabilities []string `json:"capabilities"`
	Kernel       string   `json:"kernel"`
	BTF          bool     `json:"btf"`
	EventRate    uint64   `json:"event_rate"`
	Drops        uint64   `json:"drops"`
}
type Sensor struct {
	ID                                  domain.ProductID
	Scope                               domain.Scope
	Name, Mode, TokenHash               string
	Capabilities                        []string
	Kernel                              string
	BTF                                 bool
	EventRate, Drops                    uint64
	CreatedAt, UpdatedAt, LastHeartbeat time.Time
}
type Enrollment struct {
	Sensor Sensor
	Token  string
}
type Coverage struct {
	SensorID         domain.ProductID
	Supported        bool
	Status, Kernel   string
	BTF              bool
	Capabilities     []string
	EventRate, Drops uint64
	LastHeartbeat    time.Time
}

type MemoryStore struct {
	mu       sync.RWMutex
	generate IDGenerator
	token    TokenGenerator
	now      func() time.Time
	values   map[domain.ProductID]Sensor
}

func NewMemoryStore(generate IDGenerator, token TokenGenerator, now func() time.Time) *MemoryStore {
	return &MemoryStore{generate: generate, token: token, now: now, values: map[domain.ProductID]Sensor{}}
}

func (store *MemoryStore) Create(ctx context.Context, scope domain.Scope, input Input) (Enrollment, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || !validInput(input) {
		return Enrollment{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, value := range store.values {
		if value.Scope == scope && value.Name == input.Name {
			return Enrollment{}, ErrConflict
		}
	}
	id, err := store.generate()
	if err != nil || id.IsZero() {
		return Enrollment{}, ErrInvalid
	}
	if _, exists := store.values[id]; exists {
		return Enrollment{}, ErrConflict
	}
	token, err := store.token()
	if err != nil || !validToken(token) {
		return Enrollment{}, ErrInvalid
	}
	now := store.now()
	value := Sensor{ID: id, Scope: scope, Name: input.Name, Mode: input.Mode, TokenHash: hashToken(token), CreatedAt: now, UpdatedAt: now}
	store.values[id] = value
	return Enrollment{Sensor: clone(value), Token: token}, nil
}
func (store *MemoryStore) List(ctx context.Context, scope domain.Scope) ([]Sensor, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil {
		return nil, ErrInvalid
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := []Sensor{}
	for _, value := range store.values {
		if value.Scope == scope {
			result = append(result, clone(value))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID.String() < result[j].ID.String() })
	return result, nil
}
func (store *MemoryStore) Get(ctx context.Context, scope domain.Scope, id domain.ProductID) (Sensor, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() {
		return Sensor{}, ErrInvalid
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, exists := store.values[id]
	if !exists {
		return Sensor{}, ErrNotFound
	}
	if value.Scope != scope {
		return Sensor{}, ErrForbidden
	}
	return clone(value), nil
}
func (store *MemoryStore) Update(ctx context.Context, scope domain.Scope, id domain.ProductID, input Input) (Sensor, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() || !validInput(input) {
		return Sensor{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.values[id]
	if !exists {
		return Sensor{}, ErrNotFound
	}
	if value.Scope != scope {
		return Sensor{}, ErrForbidden
	}
	for otherID, other := range store.values {
		if otherID != id && other.Scope == scope && other.Name == input.Name {
			return Sensor{}, ErrConflict
		}
	}
	value.Name = input.Name
	value.Mode = input.Mode
	value.UpdatedAt = store.now()
	store.values[id] = value
	return clone(value), nil
}
func (store *MemoryStore) Delete(ctx context.Context, scope domain.Scope, id domain.ProductID) error {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.values[id]
	if !exists {
		return ErrNotFound
	}
	if value.Scope != scope {
		return ErrForbidden
	}
	delete(store.values, id)
	return nil
}
func (store *MemoryStore) Rotate(ctx context.Context, scope domain.Scope, id domain.ProductID) (Enrollment, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() {
		return Enrollment{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.values[id]
	if !exists {
		return Enrollment{}, ErrNotFound
	}
	if value.Scope != scope {
		return Enrollment{}, ErrForbidden
	}
	token, err := store.token()
	if err != nil || !validToken(token) {
		return Enrollment{}, ErrInvalid
	}
	if subtle.ConstantTimeCompare([]byte(value.TokenHash), []byte(hashToken(token))) == 1 {
		return Enrollment{}, ErrConflict
	}
	value.TokenHash = hashToken(token)
	value.UpdatedAt = store.now()
	store.values[id] = value
	return Enrollment{Sensor: clone(value), Token: token}, nil
}
func (store *MemoryStore) Heartbeat(ctx context.Context, scope domain.Scope, id domain.ProductID, token string, heartbeat Heartbeat) (Sensor, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() || !validToken(token) || !validHeartbeat(heartbeat) {
		return Sensor{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.values[id]
	if !exists {
		return Sensor{}, ErrNotFound
	}
	if value.Scope != scope || subtle.ConstantTimeCompare([]byte(value.TokenHash), []byte(hashToken(token))) != 1 {
		return Sensor{}, ErrForbidden
	}
	now := store.now()
	value.Capabilities = normalizedCapabilities(heartbeat.Capabilities)
	value.Kernel = heartbeat.Kernel
	value.BTF = heartbeat.BTF
	value.EventRate = heartbeat.EventRate
	value.Drops = heartbeat.Drops
	value.LastHeartbeat = now
	value.UpdatedAt = now
	store.values[id] = value
	return clone(value), nil
}
func (store *MemoryStore) Coverage(ctx context.Context, scope domain.Scope, id domain.ProductID) (Coverage, error) {
	value, err := store.Get(ctx, scope, id)
	if err != nil {
		return Coverage{}, err
	}
	status := "awaiting_heartbeat"
	supported := false
	if !value.LastHeartbeat.IsZero() {
		supported = value.BTF && contains(value.Capabilities, "process") && contains(value.Capabilities, "network")
		if supported {
			status = "supported"
		} else {
			status = "degraded"
		}
	}
	return Coverage{SensorID: value.ID, Supported: supported, Status: status, Kernel: value.Kernel, BTF: value.BTF, Capabilities: append([]string(nil), value.Capabilities...), EventRate: value.EventRate, Drops: value.Drops, LastHeartbeat: value.LastHeartbeat}, nil
}

func (store *MemoryStore) usable() bool {
	if store == nil || store.generate == nil || store.token == nil || store.now == nil || store.values == nil {
		return false
	}
	return canonicalTime(store.now())
}
func validInput(value Input) bool {
	return bounded(value.Name, 128) && (value.Mode == "metadata_only" || value.Mode == "full")
}
func validHeartbeat(value Heartbeat) bool {
	return len(value.Capabilities) > 0 && len(value.Capabilities) <= 32 && bounded(value.Kernel, 128) && value.EventRate <= 1_000_000_000 && value.Drops <= 1_000_000_000 && len(normalizedCapabilities(value.Capabilities)) == len(value.Capabilities)
}
func normalizedCapabilities(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if !slug(value) || (index > 0 && result[index-1] == value) {
			return nil
		}
	}
	return result
}
func validToken(value string) bool {
	return strings.HasPrefix(value, "sensor_token_") && len(value) >= 44 && len(value) <= 128 && slug(strings.TrimPrefix(value, "sensor_token_"))
}
func hashToken(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
func clone(value Sensor) Sensor {
	value.Capabilities = append([]string(nil), value.Capabilities...)
	return value
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func validContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	default:
		return true
	}
}
func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func slug(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}
func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Millisecond) == 0
}
