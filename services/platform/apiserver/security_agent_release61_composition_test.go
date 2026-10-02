package apiserver

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentRelease61CompositionRejectsMissingKeysBeforeReadiness(t *testing.T) {
	database := &release61CompositionDatabase{}
	store := &release61CompositionStore{}
	config := SecurityAgentRelease61CompositionConfig{Worker: database, Action: database, Deployment: database, TestWorker: database, Store: store}
	if got, err := NewSecurityAgentRelease61Composition(context.Background(), config); !errors.Is(err, ErrRepositoryConfiguration) || got != nil || database.calls != 0 {
		t.Fatalf("empty signing keys reached readiness: composition=%v err=%v calls=%d", got, err, database.calls)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"release61-component": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	config.Keys = keys
	composition, err := NewSecurityAgentRelease61Composition(context.Background(), config)
	if err != nil || composition == nil || database.calls != 4 {
		t.Fatalf("valid composition unavailable: composition=%v err=%v calls=%d", composition, err, database.calls)
	}
	database.calls = 0
	if err := composition.ValidateSigningKey("release61-component", private.Public().(ed25519.PublicKey)); err != nil || database.calls != 0 {
		t.Fatalf("local signing validation performed I/O or failed: err=%v calls=%d", err, database.calls)
	}
	composition.keys = policy.GatewayPolicyKeys{}
	if err := composition.Ready(context.Background()); !errors.Is(err, ErrRepositoryConfiguration) || database.calls != 0 {
		t.Fatalf("drifted empty keys reached database readiness: err=%v calls=%d", err, database.calls)
	}
}

type release61CompositionDatabase struct{ calls int }

func (d *release61CompositionDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	d.calls++
	return json.RawMessage("true"), nil
}
func (*release61CompositionDatabase) SchemaVersion(context.Context) (string, error) { return "", nil }
func (*release61CompositionDatabase) Exec(context.Context, string, ...any) error    { return nil }

type release61CompositionStore struct{}

func (*release61CompositionStore) Put(context.Context, artifactstore.PutRequest) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, nil
}
func (*release61CompositionStore) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, nil
}
func (*release61CompositionStore) Delete(context.Context, artifactstore.Locator) error { return nil }
func (*release61CompositionStore) ObjectReference(artifactstore.Locator) (string, error) {
	return "", nil
}
