package runtimeevent

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProductionIngestReconcilerFinishesExactPinnedArtifact(t *testing.T) {
	lease := reconciliationLease(t)
	repository := &reconciliationRepositoryStub{leases: []IngestReconciliationLease{lease}}
	artifacts := &reconciliationArtifactStub{artifact: RawArtifact{Scope: lease.Scope, Key: lease.ArtifactKey, Reference: "s3://runtime/" + lease.ArtifactKey, VersionID: "version-17", ContentDigest: lease.ContentDigest, Size: lease.PayloadSize, MediaType: lease.MediaType, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}}
	reconciler, err := NewProductionIngestReconciler(ProductionIngestReconcilerConfig{Repository: repository, Artifacts: artifacts, WorkerID: "ingest-reconciler-1", LeaseSeconds: 60, ClaimLimit: 4, OperationTimeout: time.Second, NewLeaseToken: func() (string, error) { return "runtime-reconciliation-token-0001", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.claims != 1 || repository.finishes != 1 || repository.releases != 0 || repository.quarantines != 0 || artifacts.inspections != 1 || repository.finishedArtifact.VersionID != "version-17" || repository.finishedJobID.IsZero() || repository.finishedOutboxID.IsZero() || repository.finishedJobID == repository.finishedOutboxID {
		t.Fatalf("repository=%#v artifacts=%#v", repository, artifacts)
	}
}

func TestProductionIngestReconcilerClassifiesMissingDriftAndDependency(t *testing.T) {
	for _, test := range []struct {
		name            string
		artifactErr     error
		wantReleaseCode string
		wantQuarantine  bool
	}{
		{name: "missing", artifactErr: ErrProductionIngestArtifactNotFound, wantReleaseCode: "not_found"},
		{name: "dependency", artifactErr: ErrProductionIngestUnavailable, wantReleaseCode: "dependency_unavailable"},
		{name: "drift", artifactErr: ErrProductionIngestArtifactDrift, wantQuarantine: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := reconciliationLease(t)
			repository := &reconciliationRepositoryStub{leases: []IngestReconciliationLease{lease}}
			artifacts := &reconciliationArtifactStub{err: test.artifactErr}
			reconciler, _ := NewProductionIngestReconciler(ProductionIngestReconcilerConfig{Repository: repository, Artifacts: artifacts, WorkerID: "ingest-reconciler-1", LeaseSeconds: 60, ClaimLimit: 1, OperationTimeout: time.Second, NewLeaseToken: func() (string, error) { return "runtime-reconciliation-token-0001", nil }})
			if err := reconciler.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if test.wantQuarantine {
				if repository.quarantines != 1 || repository.releases != 0 || repository.finishes != 0 {
					t.Fatalf("repository=%#v", repository)
				}
				return
			}
			if repository.releases != 1 || repository.releaseCode != test.wantReleaseCode || repository.quarantines != 0 || repository.finishes != 0 {
				t.Fatalf("repository=%#v", repository)
			}
		})
	}
}

func TestProductionIngestReconcilerFailsClosedBeforeClaimsAndOnTokenFailure(t *testing.T) {
	for _, test := range []struct {
		name  string
		ready error
		token func() (string, error)
	}{
		{name: "readiness", ready: ErrProductionIngestUnavailable, token: func() (string, error) { return "runtime-reconciliation-token-0001", nil }},
		{name: "token", token: func() (string, error) { return "", errors.New("provider-secret") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &reconciliationRepositoryStub{readyErr: test.ready}
			reconciler, _ := NewProductionIngestReconciler(ProductionIngestReconcilerConfig{Repository: repository, Artifacts: &reconciliationArtifactStub{}, WorkerID: "ingest-reconciler-1", LeaseSeconds: 60, ClaimLimit: 1, OperationTimeout: time.Second, NewLeaseToken: test.token})
			err := reconciler.RunOnce(context.Background())
			if !errors.Is(err, ErrProductionIngestUnavailable) || repository.claims != 0 || err.Error() != ErrProductionIngestUnavailable.Error() {
				t.Fatalf("err=%v repository=%#v", err, repository)
			}
		})
	}
}

func reconciliationLease(t *testing.T) IngestReconciliationLease {
	t.Helper()
	scope, err := domain.NewScope(reconciliationTestID(t, 1), reconciliationTestID(t, 2), reconciliationTestID(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("reconciliation-artifact"))
	return IngestReconciliationLease{Scope: scope, BatchID: reconciliationTestID(t, 4), Generation: 2, Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute), RequestDigest: sha256.Sum256([]byte("reconciliation-request")), ArtifactKey: "runtime/v15/" + scope.OrganizationID().String() + "/" + scope.WorkspaceID().String() + "/" + scope.EnvironmentID().String() + "/pid_00000005-0000-4000-8000-000000000005/00000000000000000002/" + reconciliationTestID(t, 4).String() + ".json", ContentDigest: digest, PayloadSize: 23, MediaType: "application/json", SchemaVersion: "runtime-event-v1"}
}

func reconciliationTestID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	ids := map[int]string{1: "pid_00000001-0000-4000-8000-000000000001", 2: "pid_00000002-0000-4000-8000-000000000002", 3: "pid_00000003-0000-4000-8000-000000000003", 4: "pid_00000004-0000-4000-8000-000000000004"}
	id, err := domain.ParseProductID(ids[value])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type reconciliationRepositoryStub struct {
	readyErr         error
	leases           []IngestReconciliationLease
	claims           int
	releases         int
	finishes         int
	quarantines      int
	releaseCode      string
	finishedArtifact RawArtifact
	finishedJobID    domain.ProductID
	finishedOutboxID domain.ProductID
}

func (stub *reconciliationRepositoryStub) Ready(context.Context) error { return stub.readyErr }
func (stub *reconciliationRepositoryStub) ClaimReconciliation(context.Context, string, string, int, int) ([]IngestReconciliationLease, error) {
	stub.claims++
	return append([]IngestReconciliationLease(nil), stub.leases...), nil
}
func (stub *reconciliationRepositoryStub) ReleaseReconciliation(_ context.Context, _ IngestReconciliationLease, _, _ string, _ time.Duration, code string) error {
	stub.releases++
	stub.releaseCode = code
	return nil
}
func (stub *reconciliationRepositoryStub) FinishReconciliation(_ context.Context, _ IngestReconciliationLease, _, _ string, jobID, outboxID domain.ProductID, artifact RawArtifact) error {
	stub.finishes++
	stub.finishedJobID, stub.finishedOutboxID, stub.finishedArtifact = jobID, outboxID, artifact
	return nil
}
func (stub *reconciliationRepositoryStub) QuarantineReconciliation(context.Context, IngestReconciliationLease, string, string) error {
	stub.quarantines++
	return nil
}

type reconciliationArtifactStub struct {
	artifact    RawArtifact
	err         error
	inspections int
}

func (stub *reconciliationArtifactStub) Inspect(context.Context, RawArtifactInspect) (RawArtifact, error) {
	stub.inspections++
	return stub.artifact, stub.err
}

var _ ProductionIngestReconciliationRepository = (*reconciliationRepositoryStub)(nil)
var _ RawArtifactInspector = (*reconciliationArtifactStub)(nil)
