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
	artifacts map[string]artifactstore.Artifact
	locators  []artifactstore.Locator
}

func (*recoveryLoaderStoreFake) Put(context.Context, artifactstore.PutRequest) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, artifactstore.ErrPut
}
func (fake *recoveryLoaderStoreFake) Get(_ context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	fake.locators = append(fake.locators, locator)
	artifact, exists := fake.artifacts[recoveryLoaderArtifactKey(locator)]
	if !exists {
		return artifactstore.Artifact{}, artifactstore.ErrGet
	}
	return artifact, nil
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
	manifest, children := recoveryLoaderManifestFixture(t, scope)
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
	manifestArtifact := artifactstore.Artifact{Locator: artifactstore.Locator{Scope: scope, Reference: manifestReference(t, claim), VersionID: claim.Manifest.VersionID}, MediaType: claim.Manifest.MediaType, Body: envelope, Size: int64(len(envelope)), SHA256: digest}
	store := &recoveryLoaderStoreFake{artifacts: recoveryLoaderArtifactMap(append(children, manifestArtifact))}
	verifier := &recoveryLoaderVerifier{}
	loader, err := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: store, Verifier: verifier, Now: func() time.Time { return manifest.CapturedAt.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.Load(context.Background(), claim)
	wantEvidenceDigest, digestErr := recoveryEvidenceDigestFromArtifacts([][]byte{children[2].Body})
	if err != nil || digestErr != nil || loaded.Manifest.Scope != scope || loaded.Manifest.BackupID != manifest.BackupID || loaded.EvidenceSampleDigest != wantEvidenceDigest || len(store.locators) != 4 || store.locators[0].VersionID != "version-pinned-1" || verifier.calls != 1 {
		t.Fatalf("loaded=%#v store=%#v verifier=%d err=%v", loaded, store.locators, verifier.calls, err)
	}

	claim.Manifest.Signature = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	if _, err := loader.Load(context.Background(), claim); !errors.Is(err, errRecoveryManifestInvalid) || verifier.calls != 1 {
		t.Fatalf("public authority drift err=%v verifier=%d", err, verifier.calls)
	}

	delete(store.artifacts, recoveryLoaderArtifactKey(artifactstore.Locator{Scope: manifest.Projection.Scope, Reference: manifest.Projection.Reference, VersionID: manifest.Projection.VersionID}))
	claim.Manifest.Signature = wire.Signature
	if _, err := loader.Load(context.Background(), claim); !errors.Is(err, errRecoveryManifestInvalid) {
		t.Fatalf("missing pinned child err=%v", err)
	}
}

func TestRecoveryRestoreManifestLoaderClassifiesSignatureAndExpiry(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest, children := recoveryLoaderManifestFixture(t, scope)
	envelope, err := recovery.BuildSignedManifest(context.Background(), recovery.ManifestInput{Scope: manifest.Scope, BackupID: manifest.BackupID, CapturedAt: manifest.CapturedAt, ExpiresAt: manifest.ExpiresAt, NeonProjectID: manifest.NeonProjectID, NeonBranchID: manifest.NeonBranchID, PostgresLSN: manifest.PostgresLSN, Configuration: manifest.Configuration, Projection: manifest.Projection, Evidence: manifest.Evidence, ExpectedCounts: manifest.ExpectedCounts}, recoveryLoaderSigner{})
	if err != nil {
		t.Fatal(err)
	}
	var wire recoverySignedEnvelopeAuthority
	_ = json.Unmarshal(envelope, &wire)
	digest := sha256.Sum256(envelope)
	claim := recoveryRestoreClaim(scope)
	claim.Manifest.VersionID, claim.Manifest.SHA256, claim.Manifest.SizeBytes, claim.Manifest.Signature = "version-pinned-1", hex.EncodeToString(digest[:]), int64(len(envelope)), wire.Signature
	manifestArtifact := artifactstore.Artifact{Locator: artifactstore.Locator{Scope: scope, Reference: manifestReference(t, claim), VersionID: claim.Manifest.VersionID}, MediaType: claim.Manifest.MediaType, Body: envelope, Size: int64(len(envelope)), SHA256: digest}
	store := &recoveryLoaderStoreFake{artifacts: recoveryLoaderArtifactMap(append(children, manifestArtifact))}
	badVerifier := &recoveryLoaderVerifier{}
	badStore := &recoveryLoaderStoreFake{artifacts: recoveryLoaderArtifactMap(append(children, manifestArtifact))}
	badArtifact := badStore.artifacts[recoveryLoaderArtifactKey(manifestArtifact.Locator)]
	badArtifact.Body = bytes.Replace(envelope, []byte(wire.Signature), []byte(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))), 1)
	badDigest := sha256.Sum256(badArtifact.Body)
	badArtifact.SHA256, badArtifact.Size = badDigest, int64(len(badArtifact.Body))
	badStore.artifacts[recoveryLoaderArtifactKey(badArtifact.Locator)] = badArtifact
	badClaim := claim
	badManifest := *claim.Manifest
	badClaim.Manifest = &badManifest
	badClaim.Manifest.SHA256, badClaim.Manifest.SizeBytes = hex.EncodeToString(badDigest[:]), int64(len(badArtifact.Body))
	var badWire recoverySignedEnvelopeAuthority
	_ = json.Unmarshal(badArtifact.Body, &badWire)
	badClaim.Manifest.Signature = badWire.Signature
	loader, _ := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: badStore, Verifier: badVerifier, Now: func() time.Time { return manifest.CapturedAt.Add(time.Hour) }})
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

func recoveryLoaderManifestFixture(t *testing.T, scope domain.Scope) (recovery.Manifest, []artifactstore.Artifact) {
	t.Helper()
	manifest := recoveryRestoreManifest(t, scope)
	values := []struct {
		locator *recovery.ArtifactLocator
		body    []byte
	}{
		{locator: &manifest.Configuration, body: []byte(`[{"resource_kind":"integration"}]`)},
		{locator: &manifest.Projection, body: []byte(`[{"integration_id":"pid_71000010-0000-4000-8000-000000000010","projection_cursors":[]}]`)},
		{locator: &manifest.Evidence[0], body: []byte(`[{"artifact_key":"organizations/pid_71000001-0000-4000-8000-000000000001/raw.json","artifact_reference":"pid_71000012-0000-4000-8000-000000000012","artifact_version_id":"version-evidence-1","checksum":"1111111111111111111111111111111111111111111111111111111111111111","collected_at":"2026-08-24T16:00:00Z","id":"pid_71000011-0000-4000-8000-000000000011","media_type":"application/json","object_reference":"s3://zasp-evidence/organizations/pid_71000001-0000-4000-8000-000000000001/raw.json","schema_version":"raw-v1","size_bytes":128}]`)},
	}
	artifacts := make([]artifactstore.Artifact, len(values))
	for index := range values {
		digest := sha256.Sum256(values[index].body)
		values[index].locator.SHA256 = digest
		values[index].locator.SizeBytes = int64(len(values[index].body))
		artifacts[index] = artifactstore.Artifact{Locator: artifactstore.Locator{Scope: scope, Reference: values[index].locator.Reference, VersionID: values[index].locator.VersionID}, MediaType: values[index].locator.MediaType, Body: append([]byte(nil), values[index].body...), Size: int64(len(values[index].body)), SHA256: digest}
	}
	return manifest, artifacts
}

func recoveryLoaderArtifactMap(artifacts []artifactstore.Artifact) map[string]artifactstore.Artifact {
	result := make(map[string]artifactstore.Artifact, len(artifacts))
	for _, artifact := range artifacts {
		result[recoveryLoaderArtifactKey(artifact.Locator)] = artifact
	}
	return result
}

func recoveryLoaderArtifactKey(locator artifactstore.Locator) string {
	return locator.Scope.OrganizationID().String() + "\x1f" + locator.Scope.WorkspaceID().String() + "\x1f" + locator.Scope.EnvironmentID().String() + "\x1f" + locator.Reference.String() + "\x1f" + locator.VersionID
}
