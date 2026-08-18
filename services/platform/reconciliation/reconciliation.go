package reconciliation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrReconciliation = errors.New("asset reconciliation rejected")

type Kind string

const (
	KindAsset    Kind = "asset"
	KindAgent    Kind = "agent"
	KindTool     Kind = "tool"
	KindIdentity Kind = "identity"
	KindRuntime  Kind = "runtime"
)

type SourceAsset struct {
	Scope                                      domain.Scope
	Source, SourceID, Name                     string
	Kind                                       Kind
	Owner, Team                                string
	Tags                                       []string
	CredentialReference, CredentialFingerprint string
	RawCredential                              string
	WorkloadID, SandboxID, Isolation           string
	EvidenceID                                 domain.ProductID
	SeenAt                                     time.Time
}

type Asset struct {
	ID                                         domain.ProductID
	Scope                                      domain.Scope
	Source, SourceID, Name                     string
	Kind                                       Kind
	Owner, Team                                string
	Tags                                       []string
	CredentialReference, CredentialFingerprint string
	WorkloadID, SandboxID, Isolation           string
	EvidenceID                                 domain.ProductID
	FirstSeen, LastSeen                        time.Time
}

type Audit struct {
	ID      domain.ProductID
	Scope   domain.Scope
	AssetID domain.ProductID
	Action  string
	At      time.Time
}

type MemoryStore struct {
	mu     sync.RWMutex
	values map[domain.ProductID]Asset
	keys   map[string]domain.ProductID
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{values: map[domain.ProductID]Asset{}, keys: map[string]domain.ProductID{}}
}

func (store *MemoryStore) Reconcile(ctx context.Context, input SourceAsset) (Asset, error) {
	if store == nil || store.values == nil || store.keys == nil || !active(ctx) || !validSourceAsset(input) {
		return Asset{}, ErrReconciliation
	}
	key := scopeIdentity(input.Scope) + "\x00" + input.Source + "\x00" + string(input.Kind) + "\x00" + input.SourceID
	id, err := deterministicID(key)
	if err != nil {
		return Asset{}, ErrReconciliation
	}
	tags := normalizedTags(input.Tags)
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.keys[key]; ok && retained != id {
		return Asset{}, ErrReconciliation
	}
	value, exists := store.values[id]
	if exists && (value.Scope != input.Scope || value.Source != input.Source || value.SourceID != input.SourceID || value.Kind != input.Kind) {
		return Asset{}, ErrReconciliation
	}
	firstSeen := input.SeenAt
	if exists {
		firstSeen = value.FirstSeen
		if input.SeenAt.Before(value.LastSeen) {
			return Asset{}, ErrReconciliation
		}
	}
	value = Asset{ID: id, Scope: input.Scope, Source: input.Source, SourceID: input.SourceID, Name: input.Name, Kind: input.Kind,
		Owner: input.Owner, Team: input.Team, Tags: tags, CredentialReference: input.CredentialReference,
		CredentialFingerprint: input.CredentialFingerprint, WorkloadID: input.WorkloadID, SandboxID: input.SandboxID,
		Isolation: input.Isolation, EvidenceID: input.EvidenceID, FirstSeen: firstSeen, LastSeen: input.SeenAt}
	store.keys[key], store.values[id] = id, value
	return cloneAsset(value), nil
}

func (store *MemoryStore) UpdateOwnership(ctx context.Context, scope domain.Scope, id domain.ProductID, owner, team string, tags []string, at time.Time) (Asset, Audit, error) {
	if store == nil || !active(ctx) || scope.Validate() != nil || id.IsZero() || !bounded(owner, 128) || !bounded(team, 128) || normalizedTags(tags) == nil || !canonicalTime(at) {
		return Asset{}, Audit{}, ErrReconciliation
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.values[id]
	if !ok || value.Scope != scope || value.Kind != KindAgent || at.Before(value.LastSeen) {
		return Asset{}, Audit{}, ErrReconciliation
	}
	value.Owner, value.Team, value.Tags, value.LastSeen = owner, team, normalizedTags(tags), at
	store.values[id] = value
	auditID, err := deterministicID(scopeIdentity(scope) + "\x00ownership\x00" + id.String() + "\x00" + owner + "\x00" + team + "\x00" + strings.Join(value.Tags, ",") + "\x00" + at.Format(time.RFC3339Nano))
	if err != nil {
		return Asset{}, Audit{}, ErrReconciliation
	}
	return cloneAsset(value), Audit{ID: auditID, Scope: scope, AssetID: id, Action: "ownership.updated", At: at}, nil
}

type Relationship struct {
	From, To   domain.ProductID
	Type       string
	EvidenceID domain.ProductID
}

type Projector interface {
	Upsert(context.Context, domain.Scope, domain.ProductID, Relationship) error
}

func ProjectRelationships(ctx context.Context, projector Projector, scope domain.Scope, values []Relationship) (err error) {
	if !active(ctx) || projector == nil || scope.Validate() != nil || len(values) == 0 || len(values) > 10_000 {
		return ErrReconciliation
	}
	defer func() {
		if recover() != nil {
			err = ErrReconciliation
		}
	}()
	ids := make([]domain.ProductID, len(values))
	seen := make(map[domain.ProductID]struct{}, len(values))
	for index, value := range values {
		if value.From.IsZero() || value.To.IsZero() || value.From == value.To || !bounded(value.Type, 64) || value.EvidenceID.IsZero() {
			return ErrReconciliation
		}
		id, idErr := deterministicID(scopeIdentity(scope) + "\x00relationship\x00" + value.From.String() + "\x00" + value.Type + "\x00" + value.To.String())
		if _, duplicate := seen[id]; idErr != nil || duplicate {
			return ErrReconciliation
		}
		ids[index], seen[id] = id, struct{}{}
	}
	for index, value := range values {
		if projector.Upsert(ctx, scope, ids[index], value) != nil {
			return ErrReconciliation
		}
	}
	return nil
}

type MemoryProjector struct {
	mu     sync.RWMutex
	values map[string]Relationship
}

func NewMemoryProjector() *MemoryProjector {
	return &MemoryProjector{values: map[string]Relationship{}}
}

func (projector *MemoryProjector) Upsert(ctx context.Context, scope domain.Scope, id domain.ProductID, value Relationship) error {
	if projector == nil || projector.values == nil || !active(ctx) || scope.Validate() != nil || id.IsZero() {
		return ErrReconciliation
	}
	key := scopeIdentity(scope) + "\x00" + id.String()
	projector.mu.Lock()
	defer projector.mu.Unlock()
	if existing, ok := projector.values[key]; ok && existing != value {
		return ErrReconciliation
	}
	projector.values[key] = value
	return nil
}

func (projector *MemoryProjector) Count(scope domain.Scope) int {
	if projector == nil || scope.Validate() != nil {
		return 0
	}
	prefix := scopeIdentity(scope) + "\x00"
	projector.mu.RLock()
	defer projector.mu.RUnlock()
	count := 0
	for key := range projector.values {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count
}

func validSourceAsset(value SourceAsset) bool {
	if value.Scope.Validate() != nil || !bounded(value.Source, 64) || !bounded(value.SourceID, 512) || !bounded(value.Name, 256) ||
		value.EvidenceID.IsZero() || !canonicalTime(value.SeenAt) || value.RawCredential != "" || normalizedTags(value.Tags) == nil {
		return false
	}
	switch value.Kind {
	case KindAsset, KindTool:
		return value.CredentialReference == "" && value.CredentialFingerprint == "" && value.WorkloadID == "" && value.SandboxID == "" && value.Isolation == ""
	case KindAgent:
		return optional(value.Owner, 128) && optional(value.Team, 128) && value.CredentialReference == "" && value.CredentialFingerprint == "" && value.WorkloadID == "" && value.SandboxID == "" && value.Isolation == ""
	case KindIdentity:
		return bounded(value.CredentialReference, 256) && validFingerprint(value.CredentialFingerprint) && value.WorkloadID == "" && value.SandboxID == "" && value.Isolation == ""
	case KindRuntime:
		return bounded(value.WorkloadID, 256) && bounded(value.SandboxID, 256) && (value.Isolation == "container" || value.Isolation == "sandbox") && value.CredentialReference == "" && value.CredentialFingerprint == ""
	default:
		return false
	}
}

func normalizedTags(values []string) []string {
	if len(values) > 32 {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	sort.Strings(result)
	for index, value := range result {
		if !bounded(value, 64) || index > 0 && result[index-1] == value {
			return nil
		}
	}
	return result
}

func cloneAsset(value Asset) Asset            { value.Tags = append([]string(nil), value.Tags...); return value }
func active(ctx context.Context) bool         { return ctx != nil && ctx.Err() == nil }
func optional(value string, maximum int) bool { return value == "" || bounded(value, maximum) }
func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == time.UnixMilli(value.UnixMilli()).UTC()
}
func validFingerprint(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha256:")
	if encoded != strings.ToLower(encoded) {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size
}
func scopeIdentity(scope domain.Scope) string {
	return scope.OrganizationID().String() + "\x00" + scope.WorkspaceID().String() + "\x00" + scope.EnvironmentID().String()
}
func deterministicID(value string) (domain.ProductID, error) {
	digest := sha256.Sum256([]byte(value))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	text := hex.EncodeToString(digest[:16])
	return domain.ParseProductID(fmt.Sprintf("pid_%s-%s-%s-%s-%s", text[:8], text[8:12], text[12:16], text[16:20], text[20:32]))
}
