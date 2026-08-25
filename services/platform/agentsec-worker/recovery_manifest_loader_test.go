package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
)

type recoveryLoaderStoreFake struct {
	artifact artifactstore.Artifact
	locator  artifactstore.Locator
	calls    int
}

func (*recoveryLoaderStoreFake) Put(context.Context, artifactstore.PutRequest) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, artifactstore.ErrPut
}
func (fake *recoveryLoaderStoreFake) Get(_ context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	fake.calls++
	fake.locator = locator
	return fake.artifact, nil
}
func (*recoveryLoaderStoreFake) Delete(context.Context, artifactstore.Locator) error {
	return artifactstore.ErrDelete
}

type recoveryLoaderSigner struct{}

func (recoveryLoaderSigner) Sign(_ context.Context, payload []byte) (string, []byte, error) {
	digest := sha256.Sum256(payload)
	return "arn:aws:kms:us-west-2:123456789012:key/123e4567-e89b-42d3-a456-426614174000", digest[:], nil
}

type recoveryLoaderVerifier struct{ calls int }

func (verifier *recoveryLoaderVerifier) Verify(_ context.Context, key string, payload, signature []byte) error {
	verifier.calls++
	digest := sha256.Sum256(payload)
	if key != "arn:aws:kms:us-west-2:123456789012:key/123e4567-e89b-42d3-a456-426614174000" || !bytes.Equal(signature, digest[:]) {
		return errors.New("bad signature")
	}
	return nil
}

func TestRecoveryRestoreManifestLoaderPinsObjectAndVerifiesExactPublicAuthority(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	envelope, err := recovery.BuildSignedManifest(context.Background(), recovery.ManifestInput{Scope: manifest.Scope, BackupID: manifest.BackupID, CapturedAt: manifest.CapturedAt, ExpiresAt: manifest.ExpiresAt, NeonProjectID: manifest.NeonProjectID, NeonBranchID: manifest.NeonBranchID, PostgresLSN: manifest.PostgresLSN, Configuration: manifest.Configuration, Projection: manifest.Projection, Evidence: manifest.Evidence, ExpectedCounts: manifest.ExpectedCounts}, recoveryLoaderSigner{})
	if err != nil {
		t.Fatal(err)
	}
	var wire recoverySignedEnvelopeAuthority
	if err := json.Unmarshal(envelope, &wire); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(envelope)
	claim := recoveryRestoreClaim(scope)
	claim.Manifest.VersionID = "version-pinned-1"
	claim.Manifest.SHA256 = hex.EncodeToString(digest[:])
	claim.Manifest.SizeBytes = int64(len(envelope))
	claim.Manifest.Signature = wire.Signature
	store := &recoveryLoaderStoreFake{artifact: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: scope, Reference: manifestReference(t, claim), VersionID: claim.Manifest.VersionID}, MediaType: claim.Manifest.MediaType, Body: envelope, Size: int64(len(envelope)), SHA256: digest}}
	verifier := &recoveryLoaderVerifier{}
	loader, err := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: store, Verifier: verifier, Now: func() time.Time { return manifest.CapturedAt.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.Load(context.Background(), claim)
	if err != nil || loaded.Scope != scope || loaded.BackupID != manifest.BackupID || store.calls != 1 || store.locator.VersionID != "version-pinned-1" || verifier.calls != 1 {
		t.Fatalf("loaded=%#v store=%#v verifier=%d err=%v", loaded, store.locator, verifier.calls, err)
	}

	claim.Manifest.Signature = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	if _, err := loader.Load(context.Background(), claim); !errors.Is(err, errRecoveryManifestInvalid) || verifier.calls != 1 {
		t.Fatalf("public authority drift err=%v verifier=%d", err, verifier.calls)
	}
}

func TestRecoveryRestoreManifestLoaderClassifiesSignatureAndExpiry(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	envelope, err := recovery.BuildSignedManifest(context.Background(), recovery.ManifestInput{Scope: manifest.Scope, BackupID: manifest.BackupID, CapturedAt: manifest.CapturedAt, ExpiresAt: manifest.ExpiresAt, NeonProjectID: manifest.NeonProjectID, NeonBranchID: manifest.NeonBranchID, PostgresLSN: manifest.PostgresLSN, Configuration: manifest.Configuration, Projection: manifest.Projection, Evidence: manifest.Evidence, ExpectedCounts: manifest.ExpectedCounts}, recoveryLoaderSigner{})
	if err != nil {
		t.Fatal(err)
	}
	var wire recoverySignedEnvelopeAuthority
	_ = json.Unmarshal(envelope, &wire)
	digest := sha256.Sum256(envelope)
	claim := recoveryRestoreClaim(scope)
	claim.Manifest.VersionID, claim.Manifest.SHA256, claim.Manifest.SizeBytes, claim.Manifest.Signature = "version-pinned-1", hex.EncodeToString(digest[:]), int64(len(envelope)), wire.Signature
	store := &recoveryLoaderStoreFake{artifact: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: scope, Reference: manifestReference(t, claim), VersionID: claim.Manifest.VersionID}, MediaType: claim.Manifest.MediaType, Body: envelope, Size: int64(len(envelope)), SHA256: digest}}
	badVerifier := &recoveryLoaderVerifier{}
	badStore := *store
	badStore.artifact.Body = bytes.Replace(envelope, []byte(wire.Signature), []byte(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))), 1)
	badDigest := sha256.Sum256(badStore.artifact.Body)
	badStore.artifact.SHA256, badStore.artifact.Size = badDigest, int64(len(badStore.artifact.Body))
	badClaim := claim
	badManifest := *claim.Manifest
	badClaim.Manifest = &badManifest
	badClaim.Manifest.SHA256, badClaim.Manifest.SizeBytes = hex.EncodeToString(badDigest[:]), int64(len(badStore.artifact.Body))
	var badWire recoverySignedEnvelopeAuthority
	_ = json.Unmarshal(badStore.artifact.Body, &badWire)
	badClaim.Manifest.Signature = badWire.Signature
	loader, _ := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: &badStore, Verifier: badVerifier, Now: func() time.Time { return manifest.CapturedAt.Add(time.Hour) }})
	if _, err := loader.Load(context.Background(), badClaim); !errors.Is(err, errRecoverySignatureInvalid) {
		t.Fatalf("signature err=%v", err)
	}

	expiredLoader, _ := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: store, Verifier: &recoveryLoaderVerifier{}, Now: func() time.Time { return manifest.ExpiresAt.Add(time.Second) }})
	if _, err := expiredLoader.Load(context.Background(), claim); !errors.Is(err, errRecoveryManifestExpired) {
		t.Fatalf("expired err=%v", err)
	}
}

func manifestReference(t *testing.T, claim recoveryOperationClaim) domain.EvidenceRef {
	t.Helper()
	identifier := claim.Manifest.Reference[strings.LastIndex(claim.Manifest.Reference, "/")+1:]
	productID, err := domain.ParseProductID(identifier)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := domain.NewEvidenceRef(productID)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}
