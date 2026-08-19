package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type oauthSecretDriverStub struct {
	values  map[string][]byte
	created int
	deleted int
}

func (driver *oauthSecretDriverStub) Create(_ context.Context, name, kms string, value []byte) error {
	if kms != "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-4111-8111-111111111111" || name != "zasp/oauth/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		return errors.New("unexpected authority")
	}
	driver.created++
	if _, exists := driver.values[name]; exists {
		return errors.New("already exists")
	}
	driver.values[name] = append([]byte(nil), value...)
	return nil
}
func (driver *oauthSecretDriverStub) Read(_ context.Context, name string) ([]byte, error) {
	value, exists := driver.values[name]
	if !exists {
		return nil, ErrOAuthSecretNotFound
	}
	return append([]byte(nil), value...), nil
}
func (driver *oauthSecretDriverStub) Delete(_ context.Context, name string) error {
	if _, exists := driver.values[name]; !exists {
		return ErrOAuthSecretNotFound
	}
	driver.deleted++
	delete(driver.values, name)
	return nil
}

func TestDurableOAuthSecretStoreReplaysOriginalMaterialAndConsumesOnce(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	driver := &oauthSecretDriverStub{values: map[string][]byte{}}
	store, err := NewDurableOAuthSecretStore(driver, "zasp/oauth", "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-4111-8111-111111111111", time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	reference := "ref:oauth/pkce/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	original := OAuthSecretMaterial{State: strings.Repeat("s", 43), Verifier: []byte(strings.Repeat("v", 43)), ExpiresAt: now.Add(10 * time.Minute)}
	stored, err := store.Acquire(context.Background(), reference, original, original.ExpiresAt)
	if err != nil || stored.State != original.State || string(stored.Verifier) != string(original.Verifier) || !stored.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatalf("initial acquire = %#v, %v", stored, err)
	}
	replayCandidate := OAuthSecretMaterial{State: strings.Repeat("x", 43), Verifier: []byte(strings.Repeat("y", 43)), ExpiresAt: now.Add(9 * time.Minute)}
	replayed, err := store.Acquire(context.Background(), reference, replayCandidate, replayCandidate.ExpiresAt)
	if err != nil || replayed.State != original.State || string(replayed.Verifier) != string(original.Verifier) || !replayed.ExpiresAt.Equal(original.ExpiresAt) || driver.created != 2 {
		t.Fatalf("replayed acquire = %#v, %v creates=%d", replayed, err, driver.created)
	}
	verifier, err := store.Consume(context.Background(), reference)
	if err != nil || string(verifier) != string(original.Verifier) || driver.deleted != 1 {
		t.Fatalf("consume = %q, %v deletes=%d", verifier, err, driver.deleted)
	}
	if _, err := store.Consume(context.Background(), reference); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("replayed consume error = %v", err)
	}
}

func TestDurableOAuthSecretStoreRejectsExpiredMalformedAndLeakyDriverErrors(t *testing.T) {
	now := time.Now().UTC()
	driver := &oauthSecretDriverStub{values: map[string][]byte{}}
	store, err := NewDurableOAuthSecretStore(driver, "zasp/oauth", "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-4111-8111-111111111111", time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{"ref:oauth/pkce/../escape", "ref:github/secret-0001", "ref:oauth/pkce/short"} {
		if _, err := store.Acquire(context.Background(), reference, OAuthSecretMaterial{State: strings.Repeat("s", 43), Verifier: []byte(strings.Repeat("v", 43)), ExpiresAt: now.Add(time.Minute)}, now.Add(time.Minute)); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("hostile reference %q error = %v", reference, err)
		}
	}
	driver.values["zasp/oauth/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"] = []byte(`{"state":"plaintext","verifier":"plaintext","expires_at":"2026-08-19T00:00:00Z","extra":"leak"}`)
	if _, err := store.Consume(context.Background(), "ref:oauth/pkce/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"); !errors.Is(err, ErrRepositoryUnavailable) || strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("hostile secret error = %v", err)
	}
}

var _ OAuthSecretDriver = (*oauthSecretDriverStub)(nil)
