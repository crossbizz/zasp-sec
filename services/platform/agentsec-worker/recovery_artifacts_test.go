package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recoveryArtifactStoreFake struct {
	puts []artifactstore.PutRequest
}

func (fake *recoveryArtifactStoreFake) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	fake.puts = append(fake.puts, request)
	digest := sha256.Sum256(request.Body)
	return artifactstore.Artifact{Locator: artifactstore.Locator{Scope: request.Scope, Reference: request.Reference, VersionID: fmt.Sprintf("version-%d", len(fake.puts))}, MediaType: request.MediaType, Body: append([]byte(nil), request.Body...), Size: int64(len(request.Body)), SHA256: digest}, nil
}

func (fake *recoveryArtifactStoreFake) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, artifactstore.ErrGet
}

func (fake *recoveryArtifactStoreFake) Delete(context.Context, artifactstore.Locator) error {
	return nil
}

func (fake *recoveryArtifactStoreFake) ObjectReference(locator artifactstore.Locator) (string, error) {
	return "s3://zasp-recovery/organizations/" + locator.Scope.OrganizationID().String() + "/workspaces/" + locator.Scope.WorkspaceID().String() + "/environments/" + locator.Scope.EnvironmentID().String() + "/artifacts/" + locator.Reference.String(), nil
}

type recoverySignerFake struct{}

func (recoverySignerFake) Sign(context.Context, []byte) (string, []byte, error) {
	return "arn:aws:kms:us-west-2:123456789012:key/123e4567-e89b-42d3-a456-426614174000", make([]byte, 64), nil
}

func TestRecoveryArtifactPublisherWritesDescriptorsBeforeSignedManifest(t *testing.T) {
	scope := recoveryWorkerScope(t)
	store := &recoveryArtifactStoreFake{}
	publisher, err := newRecoveryArtifactPublisher(recoveryArtifactPublisherConfig{
		Store: store, Signer: recoverySignerFake{}, NeonProjectID: "zasp-production", NeonBranchID: "br-production-main", PostgresLSN: func(context.Context, domain.Scope) (string, error) { return "0/27", nil },
		Now: func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	publication := recoveryBackupPublication{
		Claim: recoveryOperationClaim{Kind: "backup", Scope: scope, OperationID: "pid_71000001-0000-4000-8000-000000000001", Attempt: 1, RetentionDays: 30},
		Sections: map[string][]json.RawMessage{
			"configuration": {json.RawMessage(`{"resource_kind":"integration"}`)},
			"projection":    {json.RawMessage(`{"integration_id":"pid_71000001-0000-4000-8000-000000000001"}`)},
			"evidence":      {json.RawMessage(`{"id":"pid_71000002-0000-4000-8000-000000000002"}`)},
			"counts":        {json.RawMessage(`{"assets":3,"findings":2,"policies":1}`)},
		},
	}
	manifest, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.puts) != 4 || store.puts[0].MediaType != "application/vnd.zasp.recovery-configuration+json" || store.puts[1].MediaType != "application/vnd.zasp.recovery-projection+json" || store.puts[2].MediaType != "application/vnd.zasp.recovery-evidence+json" || store.puts[3].MediaType != "application/vnd.zasp.recovery-manifest+json" {
		t.Fatalf("puts=%#v", store.puts)
	}
	if manifest.SigningKeyID != "123e4567-e89b-42d3-a456-426614174000" || manifest.Signature == "" || manifest.Schema != "recovery_signed_manifest_v1" || manifest.Reference == "" || manifest.VersionID != "version-4" {
		t.Fatalf("manifest=%#v", manifest)
	}
}
