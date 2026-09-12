package runtimeevent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type preciseRecoveryDatabase struct {
	payload    json.RawMessage
	statements []string
	readiness  json.RawMessage
	readyError error
}

type preciseRecoveryRepository struct {
	reconciliationRepositoryStub
	unready bool
}

func (repository *preciseRecoveryRepository) ReadyPrecision(context.Context) error {
	if repository.unready {
		return ErrProductionIngestUnavailable
	}
	return nil
}

func TestPreciseReconcilerRecoversMixedVersionsAndRefusesDrift(t *testing.T) {
	for _, unready := range []bool{false, true} {
		first := reconciliationLease(t)
		second := first
		second.SchemaVersion = "runtime-event-v2"
		repository := &preciseRecoveryRepository{reconciliationRepositoryStub: reconciliationRepositoryStub{leases: []IngestReconciliationLease{first, second}}, unready: unready}
		artifacts := &reconciliationArtifactStub{err: ErrProductionIngestArtifactNotFound}
		config := ProductionIngestReconcilerConfig{Repository: repository, Artifacts: artifacts, WorkerID: "ingest-reconciler-1", LeaseSeconds: 60, ClaimLimit: 4, OperationTimeout: time.Second, NewLeaseToken: func() (string, error) { return "runtime-reconciliation-token-0001", nil }}
		reconciler, err := NewPreciseProductionIngestReconciler(config)
		if err != nil {
			t.Fatal(err)
		}
		err = reconciler.RunOnce(context.Background())
		if unready {
			if err == nil || repository.claims != 0 || artifacts.inspections != 0 {
				t.Fatal("precision drift claimed recovery", err)
			}
		} else if err != nil || repository.releases != 2 || artifacts.inspections != 2 {
			t.Fatal("mixed recovery abandoned leases", err, repository.releases, artifacts.inspections)
		}
	}
}

func TestPreciseRecoveryUsesHTTPAcceptanceIdentities(t *testing.T) {
	for _, schema := range []string{"runtime-event-v1", "runtime-event-v2"} {
		lease := reconciliationLease(t)
		lease.SchemaVersion = schema
		repository := &preciseRecoveryRepository{reconciliationRepositoryStub: reconciliationRepositoryStub{leases: []IngestReconciliationLease{lease}}}
		artifacts := &reconciliationArtifactStub{artifact: RawArtifact{Scope: lease.Scope, Key: lease.ArtifactKey, Reference: "s3://runtime/" + lease.ArtifactKey, VersionID: "version-17", ContentDigest: lease.ContentDigest, Size: lease.PayloadSize, MediaType: lease.MediaType, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}}
		reconciler, err := NewPreciseProductionIngestReconciler(ProductionIngestReconcilerConfig{Repository: repository, Artifacts: artifacts, WorkerID: "ingest-reconciler-1", LeaseSeconds: 60, ClaimLimit: 1, OperationTimeout: time.Second, NewLeaseToken: func() (string, error) { return "runtime-reconciliation-token-0001", nil }})
		if err != nil {
			t.Fatal(err)
		}
		job, _ := deterministicID(lease.BatchID.String() + "\x00runtime-job")
		outbox, _ := deterministicID(lease.BatchID.String() + "\x00runtime-outbox")
		if err := reconciler.RunOnce(context.Background()); err != nil || repository.finishes != 1 || repository.finishedJobID != job || repository.finishedOutboxID != outbox {
			t.Fatal("recovered work cannot match HTTP acceptance", schema, err)
		}
	}
}

func (database *preciseRecoveryDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	database.statements = append(database.statements, statement)
	if strings.Contains(statement, "readiness") {
		if database.readiness != nil || database.readyError != nil {
			return database.readiness, database.readyError
		}
		return json.RawMessage(`{"ready":true}`), nil
	}
	return database.payload, nil
}

func TestPreciseRecoveryReadinessFailureNeverIssuesOperation(t *testing.T) {
	lease := reconciliationLease(t)
	lease.SchemaVersion = "runtime-event-v2"
	artifact := RawArtifact{Scope: lease.Scope, Key: lease.ArtifactKey, Reference: "s3://runtime/" + lease.ArtifactKey, VersionID: "version-17", ContentDigest: lease.ContentDigest, Size: lease.PayloadSize, MediaType: lease.MediaType, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}
	for _, scenario := range []struct {
		name, body string
		err        error
	}{
		{"denied", `{"ready":false}`, nil}, {"missing", `{}`, nil}, {"malformed", `{"ready":"true"}`, nil}, {"duplicate", `{"ready":false,"ready":true}`, nil}, {"database error", "", errors.New("database unavailable")},
	} {
		for _, operation := range []string{"claim", "release", "finish", "quarantine"} {
			t.Run(scenario.name+"/"+operation, func(t *testing.T) {
				database := &preciseRecoveryDatabase{readiness: json.RawMessage(scenario.body), readyError: scenario.err}
				repository, _ := NewPostgresPreciseProductionIngestRepository(database)
				var err error
				switch operation {
				case "claim":
					_, err = repository.ClaimReconciliation(context.Background(), "ingest-reconciler-1", "runtime-reconciliation-token-0001", 60, 1)
				case "release":
					err = repository.ReleaseReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001", 30*time.Second, "not_found")
				case "finish":
					err = repository.FinishReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001", reconciliationTestID(t, 1), reconciliationTestID(t, 2), artifact)
				case "quarantine":
					err = repository.QuarantineReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001")
				}
				if !errors.Is(err, ErrProductionIngestUnavailable) || len(database.statements) != 1 || !strings.Contains(database.statements[0], "zasp_production_runtime_precision_readiness") {
					t.Fatal("failed readiness issued operation or wrong result", err, database.statements)
				}
			})
		}
	}
}

func TestPreciseRepositoryClaimsVersionedRecovery(t *testing.T) {
	lease := reconciliationLease(t)
	lease.SchemaVersion = "runtime-event-v2"
	database := &preciseRecoveryDatabase{payload: json.RawMessage(fmt.Sprintf(`[{"organization_id":%q,"workspace_id":%q,"environment_id":%q,"batch_id":%q,"generation":2,"attempt":1,"lease_expires_at":%q,"request_digest":"%x","artifact_key":%q,"content_digest":"%x","payload_size_bytes":23,"media_type":"application/json","schema_version":"runtime-event-v2"}]`, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.BatchID.String(), lease.LeaseExpiresAt.Format(time.RFC3339Nano), lease.RequestDigest, lease.ArtifactKey, lease.ContentDigest))}
	repository, err := NewPostgresPreciseProductionIngestRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := repository.ClaimReconciliation(context.Background(), "ingest-reconciler-1", "runtime-reconciliation-token-0001", 60, 1)
	if err != nil || len(claims) != 1 || claims[0] != lease {
		t.Fatal("precise recovery lease refused", err)
	}
	if len(database.statements) != 2 || !strings.Contains(database.statements[0], "zasp_production_runtime_precision_readiness") || !strings.Contains(database.statements[1], "zasp_runtime_claim_reconciliation_v2") {
		t.Fatal("recovery lost precision readiness or claim isolation", database.statements)
	}
	database.payload = json.RawMessage(strings.Replace(string(database.payload), lease.LeaseExpiresAt.Format(time.RFC3339Nano), lease.LeaseExpiresAt.In(time.FixedZone("database", -7*60*60)).Format(time.RFC3339Nano), 1))
	claims, err = repository.ClaimReconciliation(context.Background(), "ingest-reconciler-1", "runtime-reconciliation-token-0001", 60, 1)
	if err != nil || len(claims) != 1 || claims[0] != lease {
		t.Fatal("database timezone changed lease instant", err)
	}
}

func TestPreciseRepositoryTransitionsVersionedRecovery(t *testing.T) {
	lease := reconciliationLease(t)
	lease.SchemaVersion = "runtime-event-v2"
	for _, outcome := range []string{"release", "finish", "quarantine"} {
		t.Run(outcome, func(t *testing.T) {
			state := "retryable"
			if outcome == "finish" {
				state = "queued"
			}
			if outcome == "quarantine" {
				state = "quarantined"
			}
			database := &preciseRecoveryDatabase{payload: json.RawMessage(fmt.Sprintf(`{"batch_id":%q,"generation":2,"state":%q,"replayed":false}`, lease.BatchID.String(), state))}
			repository, _ := NewPostgresPreciseProductionIngestRepository(database)
			var err error
			switch outcome {
			case "release":
				err = repository.ReleaseReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001", 30*time.Second, "not_found")
			case "quarantine":
				err = repository.QuarantineReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001")
			case "finish":
				err = repository.FinishReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001", reconciliationTestID(t, 1), reconciliationTestID(t, 2), RawArtifact{Scope: lease.Scope, Key: lease.ArtifactKey, Reference: "s3://runtime/" + lease.ArtifactKey, VersionID: "version-17", ContentDigest: lease.ContentDigest, Size: lease.PayloadSize, MediaType: lease.MediaType, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"})
			}
			if err != nil || len(database.statements) != 2 || !strings.Contains(database.statements[0], "zasp_production_runtime_precision_readiness") {
				t.Fatal("versioned recovery transition refused or lacked fresh readiness", err, database.statements)
			}
		})
	}
}
