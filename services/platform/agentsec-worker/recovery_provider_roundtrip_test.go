package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type retainedRecoveryArtifacts struct {
	recoveryArtifactStoreFake
	records map[string]artifactstore.Artifact
}

func (s *retainedRecoveryArtifacts) Put(ctx context.Context, req artifactstore.PutRequest) (artifactstore.Artifact, error) {
	obj, err := s.recoveryArtifactStoreFake.Put(ctx, req)
	if err == nil {
		s.records[recoveryLoaderArtifactKey(obj.Locator)] = obj
	}
	return obj, err
}

func (s *retainedRecoveryArtifacts) Get(_ context.Context, loc artifactstore.Locator) (artifactstore.Artifact, error) {
	obj, ok := s.records[recoveryLoaderArtifactKey(loc)]
	if !ok {
		return artifactstore.Artifact{}, artifactstore.ErrGet
	}
	return obj, nil
}

type recordedVersionAuthority string

func (a recordedVersionAuthority) Sign(_ context.Context, data []byte) (string, []byte, error) {
	hash := sha256.Sum256(data)
	return string(a), hash[:], nil
}

func (a recordedVersionAuthority) Verify(_ context.Context, ref string, data, sig []byte) error {
	hash := sha256.Sum256(data)
	if ref != string(a) || !bytes.Equal(hash[:], sig) {
		return errors.New("signature did not match recorded version")
	}
	return nil
}

func TestRecoveryPublishesAndRestoresAVersionedTransitManifest(t *testing.T) {
	const key = "7b43428c-21d3-4b7e-98b4-4cf7af921142"
	auth := recordedVersionAuthority("openbao:transit/v3/" + key)
	ctx := context.Background()
	scope := recoveryWorkerScope(t)
	source, children := recoveryLoaderManifestFixture(t, scope)
	store := &retainedRecoveryArtifacts{records: make(map[string]artifactstore.Artifact)}
	now := func() time.Time { return source.CapturedAt }
	publisher, err := newRecoveryArtifactPublisher(recoveryArtifactPublisherConfig{
		Store: store, Signer: auth, NeonProjectID: source.NeonProjectID, NeonBranchID: source.NeonBranchID, Now: now,
		PostgresLSN: func(context.Context, domain.Scope) (string, error) { return source.PostgresLSN, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string][]json.RawMessage{"counts": {json.RawMessage(`{"assets":3,"findings":2,"policies":1}`)}}
	for i, k := range []string{"configuration", "projection", "evidence"} {
		var items []json.RawMessage
		if err := json.Unmarshal(children[i].Body, &items); err != nil {
			t.Fatal(err)
		}
		sections[k] = items
	}
	loc, err := publisher.Publish(ctx, recoveryBackupPublication{Claim: recoveryOperationClaim{
		Scope: scope, Kind: "backup", OperationID: source.BackupID.String(), Attempt: 1, RetentionDays: 30,
	}, Sections: sections})
	if err != nil || loc.SigningKeyID != key {
		t.Fatal("publisher lost native key ID", err)
	}
	claim := recoveryRestoreClaim(scope)
	claim.Manifest = &loc
	loader, err := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: store, Verifier: recoveryVerifierSet{transit: auth}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	out, err := loader.Load(ctx, claim)
	if err != nil || out.Manifest.BackupID != source.BackupID {
		t.Fatal("restore from published objects", err)
	}
	claim.Manifest.SigningKeyID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := loader.Load(ctx, claim); !errors.Is(err, errRecoveryManifestInvalid) {
		t.Fatal("accepted locator key substitution", err)
	}
}
