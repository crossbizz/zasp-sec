package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

var ErrOAuthSecretNotFound = errors.New("OAuth secret not found")

var oauthSecretReferencePattern = regexp.MustCompile(`^ref:oauth/pkce/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$`)
var oauthSecretPrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{2,127}$`)
var kmsKeyPattern = regexp.MustCompile(`^arn:aws:kms:[a-z]{2}(?:-gov)?-[a-z]+-[0-9]:[0-9]{12}:key/[0-9a-f-]{36}$`)

type OAuthSecretDriver interface {
	Create(context.Context, string, string, []byte) error
	Read(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

type durableOAuthSecretStore struct {
	driver  OAuthSecretDriver
	prefix  string
	kmsKey  string
	timeout time.Duration
	now     func() time.Time
}

type storedOAuthSecret struct {
	State     string    `json:"state"`
	Verifier  string    `json:"verifier"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewDurableOAuthSecretStore(driver OAuthSecretDriver, prefix, kmsKey string, timeout time.Duration, now func() time.Time) (ConnectorOAuthSecretStore, error) {
	if nilInterface(driver) || !oauthSecretPrefixPattern.MatchString(prefix) || strings.HasSuffix(prefix, "/") || !kmsKeyPattern.MatchString(kmsKey) || timeout < 100*time.Millisecond || timeout > 10*time.Second || now == nil || now().IsZero() {
		return nil, ErrRepositoryConfiguration
	}
	return &durableOAuthSecretStore{driver: driver, prefix: prefix, kmsKey: kmsKey, timeout: timeout, now: now}, nil
}

func (store *durableOAuthSecretStore) Acquire(ctx context.Context, reference string, candidate OAuthSecretMaterial, expiresAt time.Time) (OAuthSecretMaterial, error) {
	name, ok := store.name(reference)
	if !ok || ctx == nil || ctx.Err() != nil || !validOAuthSecretMaterial(candidate, store.now()) || !expiresAt.Equal(candidate.ExpiresAt) {
		return OAuthSecretMaterial{}, ErrRepositoryOperation
	}
	payload, err := json.Marshal(storedOAuthSecret{State: candidate.State, Verifier: string(candidate.Verifier), ExpiresAt: candidate.ExpiresAt.UTC()})
	if err != nil {
		return OAuthSecretMaterial{}, ErrRepositoryUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, store.timeout)
	defer cancel()
	if err := store.driver.Create(bounded, name, store.kmsKey, payload); err == nil {
		return cloneOAuthSecretMaterial(candidate), nil
	}
	stored, err := store.read(bounded, name)
	if err != nil {
		return OAuthSecretMaterial{}, ErrRepositoryUnavailable
	}
	return stored, nil
}

func (store *durableOAuthSecretStore) Consume(ctx context.Context, reference string) ([]byte, error) {
	name, ok := store.name(reference)
	if !ok || ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, store.timeout)
	defer cancel()
	stored, err := store.read(bounded, name)
	if errors.Is(err, ErrOAuthSecretNotFound) {
		return nil, ErrRepositoryConflict
	}
	if err != nil || !stored.ExpiresAt.After(store.now()) {
		return nil, ErrRepositoryUnavailable
	}
	if err := store.driver.Delete(bounded, name); err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return append([]byte(nil), stored.Verifier...), nil
}

func (store *durableOAuthSecretStore) Delete(ctx context.Context, reference string) error {
	name, ok := store.name(reference)
	if !ok || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, store.timeout)
	defer cancel()
	if err := store.driver.Delete(bounded, name); err != nil && !errors.Is(err, ErrOAuthSecretNotFound) {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (store *durableOAuthSecretStore) read(ctx context.Context, name string) (OAuthSecretMaterial, error) {
	payload, err := store.driver.Read(ctx, name)
	if err != nil {
		return OAuthSecretMaterial{}, err
	}
	if len(payload) < 100 || len(payload) > 2048 {
		return OAuthSecretMaterial{}, ErrRepositoryUnavailable
	}
	var value storedOAuthSecret
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return OAuthSecretMaterial{}, ErrRepositoryUnavailable
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return OAuthSecretMaterial{}, ErrRepositoryUnavailable
	}
	result := OAuthSecretMaterial{State: value.State, Verifier: []byte(value.Verifier), ExpiresAt: value.ExpiresAt.UTC()}
	if !validOAuthSecretMaterial(result, store.now()) {
		return OAuthSecretMaterial{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (store *durableOAuthSecretStore) name(reference string) (string, bool) {
	if store == nil || nilInterface(store.driver) {
		return "", false
	}
	match := oauthSecretReferencePattern.FindStringSubmatch(reference)
	if len(match) != 2 {
		return "", false
	}
	return store.prefix + "/" + match[1], true
}

func validOAuthSecretMaterial(value OAuthSecretMaterial, now time.Time) bool {
	return connectorOAuthValuePattern.MatchString(value.State) && connectorPKCEVerifier(value.Verifier) && value.ExpiresAt.Location() == time.UTC && value.ExpiresAt.After(now) && !value.ExpiresAt.After(now.Add(10*time.Minute+time.Second))
}

func cloneOAuthSecretMaterial(value OAuthSecretMaterial) OAuthSecretMaterial {
	value.Verifier = append([]byte(nil), value.Verifier...)
	value.ExpiresAt = value.ExpiresAt.UTC()
	return value
}
