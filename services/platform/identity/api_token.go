package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const apiTokenPrefix = "zasp_pat_"

type APITokenSpec struct {
	OrganizationID domain.ProductID
	PrincipalID    domain.ProductID
	Scope          domain.Scope
	Name           string
	Permissions    []Permission
	ExpiresAt      time.Time
}

type APIToken struct {
	id             domain.ProductID
	organizationID domain.ProductID
	principalID    domain.ProductID
	scope          domain.Scope
	name           string
	permissions    []Permission
	createdAt      time.Time
	expiresAt      time.Time
	lastUsedAt     *time.Time
	revokedAt      *time.Time
}

func (token APIToken) ID() domain.ProductID             { return token.id }
func (token APIToken) OrganizationID() domain.ProductID { return token.organizationID }
func (token APIToken) PrincipalID() domain.ProductID    { return token.principalID }
func (token APIToken) Scope() domain.Scope              { return token.scope }
func (token APIToken) Name() string                     { return token.name }
func (token APIToken) Permissions() []Permission {
	return append([]Permission(nil), token.permissions...)
}
func (token APIToken) CreatedAt() time.Time   { return token.createdAt }
func (token APIToken) ExpiresAt() time.Time   { return token.expiresAt }
func (token APIToken) LastUsedAt() *time.Time { return copyTimePointer(token.lastUsedAt) }
func (token APIToken) RevokedAt() *time.Time  { return copyTimePointer(token.revokedAt) }

type APITokenCredential struct {
	token APIToken
	raw   string
}

func (credential APITokenCredential) Token() APIToken  { return cloneAPIToken(credential.token) }
func (credential APITokenCredential) RawToken() string { return credential.raw }

type storedAPIToken struct {
	token  APIToken
	digest [sha256.Size]byte
}

type APITokenStore struct {
	mu       sync.RWMutex
	generate IDGenerator
	random   io.Reader
	now      func() time.Time
	values   map[domain.ProductID]storedAPIToken
}

func NewAPITokenStore(generate IDGenerator, random io.Reader, now func() time.Time) (*APITokenStore, error) {
	current, ok := readCanonicalClock(now)
	if generate == nil || random == nil || !ok || !canonicalTime(current) {
		return nil, ErrConfiguration
	}
	return &APITokenStore{generate: generate, random: random, now: now, values: map[domain.ProductID]storedAPIToken{}}, nil
}

func (store *APITokenStore) Create(ctx context.Context, spec APITokenSpec) (APITokenCredential, error) {
	now, ok := readCanonicalClock(storeClock(store))
	if store == nil || !validContext(ctx) || !ok || !validAPITokenSpec(spec, now) {
		return APITokenCredential{}, ErrInvalidRecord
	}
	id, err := store.generate()
	if err != nil || !validProductID(id) {
		return APITokenCredential{}, ErrInvalidRecord
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(store.random, secret); err != nil || allZero(secret) {
		return APITokenCredential{}, ErrInvalidRecord
	}
	raw := apiTokenPrefix + base64.RawURLEncoding.EncodeToString(secret)
	token := APIToken{id: id, organizationID: spec.OrganizationID, principalID: spec.PrincipalID, scope: spec.Scope,
		name: spec.Name, permissions: append([]Permission(nil), spec.Permissions...), createdAt: now, expiresAt: spec.ExpiresAt}
	stored := storedAPIToken{token: token, digest: sha256.Sum256([]byte(raw))}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.values[id]; exists {
		return APITokenCredential{}, ErrConflict
	}
	store.values[id] = stored
	return APITokenCredential{token: cloneAPIToken(token), raw: raw}, nil
}

func (store *APITokenStore) List(ctx context.Context, organizationID domain.ProductID) ([]APIToken, error) {
	if store == nil || !validContext(ctx) || !validProductID(organizationID) {
		return nil, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]APIToken, 0)
	for _, value := range store.values {
		if value.token.organizationID == organizationID {
			result = append(result, cloneAPIToken(value.token))
		}
	}
	sort.Slice(result, func(first, second int) bool { return result[first].id.String() < result[second].id.String() })
	return result, nil
}

func (store *APITokenStore) Revoke(ctx context.Context, organizationID, tokenID domain.ProductID) (APIToken, error) {
	now, ok := readCanonicalClock(storeClock(store))
	if store == nil || !validContext(ctx) || !validProductID(organizationID) || !validProductID(tokenID) || !ok {
		return APIToken{}, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.values[tokenID]
	if !exists {
		return APIToken{}, ErrNotFound
	}
	if value.token.organizationID != organizationID {
		return APIToken{}, ErrForbidden
	}
	if value.token.revokedAt != nil {
		return APIToken{}, ErrConflict
	}
	value.token.revokedAt = &now
	store.values[tokenID] = value
	return cloneAPIToken(value.token), nil
}

func (store *APITokenStore) Authenticate(ctx context.Context, raw string, scope domain.Scope, permission Permission) (AuthorizationContext, error) {
	now, ok := readCanonicalClock(storeClock(store))
	if store == nil || !validContext(ctx) || !ok || !validRawAPIToken(raw) || scope.Validate() != nil || !permission.valid() {
		return AuthorizationContext{}, ErrAuthentication
	}
	digest := sha256.Sum256([]byte(raw))
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, value := range store.values {
		if subtle.ConstantTimeCompare(digest[:], value.digest[:]) != 1 {
			continue
		}
		token := value.token
		if token.revokedAt != nil || !now.Before(token.expiresAt) || token.scope != scope {
			return AuthorizationContext{}, ErrAuthentication
		}
		allowed := false
		for _, candidate := range token.permissions {
			allowed = allowed || candidate == permission
		}
		if !allowed {
			return AuthorizationContext{}, ErrForbidden
		}
		token.lastUsedAt = &now
		value.token = token
		store.values[id] = value
		return AuthorizationContext{principalID: token.principalID, scope: scope, permission: permission}, nil
	}
	return AuthorizationContext{}, ErrAuthentication
}

func validAPITokenSpec(spec APITokenSpec, now time.Time) bool {
	if !validProductID(spec.OrganizationID) || !validProductID(spec.PrincipalID) || spec.Scope.Validate() != nil ||
		spec.Scope.OrganizationID() != spec.OrganizationID || !validName(spec.Name) || !canonicalTime(spec.ExpiresAt) ||
		!spec.ExpiresAt.After(now) || len(spec.Permissions) == 0 || len(spec.Permissions) > len(builtInRoles[RoleOrganizationAdmin]) {
		return false
	}
	seen := map[Permission]struct{}{}
	for _, permission := range spec.Permissions {
		if !permission.valid() {
			return false
		}
		if _, duplicate := seen[permission]; duplicate {
			return false
		}
		seen[permission] = struct{}{}
	}
	return true
}

func validRawAPIToken(value string) bool {
	if !strings.HasPrefix(value, apiTokenPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, apiTokenPrefix))
	return err == nil && len(decoded) == 32 && apiTokenPrefix+base64.RawURLEncoding.EncodeToString(decoded) == value
}

func storeClock(store *APITokenStore) func() time.Time {
	if store == nil {
		return nil
	}
	return store.now
}

func readCanonicalClock(clock func() time.Time) (value time.Time, ok bool) {
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

func cloneAPIToken(value APIToken) APIToken {
	value.permissions = append([]Permission(nil), value.permissions...)
	value.lastUsedAt = copyTimePointer(value.lastUsedAt)
	value.revokedAt = copyTimePointer(value.revokedAt)
	return value
}

func copyTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func allZero(value []byte) bool {
	result := byte(0)
	for _, part := range value {
		result |= part
	}
	return result == 0
}
