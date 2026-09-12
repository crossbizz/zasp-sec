package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestPreciseDeliveryMutationsRequireFreshReleaseAuthority(t *testing.T) {
	request := DeliveryClaimRequest{Scope: fixtureScope(t, 120), BatchID: fixtureID(t, 123), Generation: 2, MessageID: "sha256_" + strings.Repeat("a", 64), MessageDigest: sha256.Sum256([]byte("message")), ReceiveCount: 1, WorkerID: "runtime-coordinator-01", LeaseToken: "0123456789abcdef", LeaseSeconds: 30, VisibilitySeconds: 60}
	for _, body := range []string{`{"ready":false}`, `{}`, `{"ready":"true"}`, `{"ready":false,"ready":true}`} {
		for _, operation := range []string{"claim", "heartbeat", "release", "ack"} {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(body)}}
			repository, _ := NewPostgresPrecisePipelineRepository(database, ProductionPipelineAuthorityCoordinator)
			var err error
			switch operation {
			case "claim":
				_, err = repository.ClaimDelivery(context.Background(), request)
			case "heartbeat":
				_, err = repository.HeartbeatDelivery(context.Background(), request)
			case "release":
				_, err = repository.ReleaseDelivery(context.Background(), request, DeliveryOutcomeRetryable, "retryable")
			case "ack":
				_, err = repository.AcknowledgeDelivery(context.Background(), request, sha256.Sum256([]byte("ack")))
			}
			if !errors.Is(err, ErrProductionPipelineUnavailable) || database.calls != 1 || database.statements[0] != productionPrecisionReadySQL {
				t.Fatal("delivery mutated without fresh precision authority", operation, err, database.statements)
			}
		}
	}
}

func TestPrecisePublicReadinessRejectsInvalidContextBeforeDatabase(t *testing.T) {
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`)}}
	repository, _ := NewPostgresPrecisePipelineRepository(database, ProductionPipelineAuthorityCoordinator)
	if err := repository.ReadyPrecision(nil); !errors.Is(err, ErrProductionPipelineUnavailable) || database.calls != 0 {
		t.Fatal("nil context reached precision authority", err, database.calls)
	}
}

func TestPrecisePipelineClaimsClosedStageVersions(t *testing.T) {
	for _, test := range []struct {
		authority          ProductionPipelineAuthority
		stage, prefix, sql string
		max                int
	}{
		{ProductionPipelineAuthorityArchive, "archive", "runtime-archive-v", "SELECT zasp_runtime_claim_archive_v2($1,$2,$3,$4)", 2},
		{ProductionPipelineAuthorityIndex, "index", "runtime-index-v", "SELECT zasp_runtime_claim_index_v2($1,$2,$3,$4)", 2},
		{ProductionPipelineAuthorityCorrelation, "correlate", "runtime-correlation-v", "SELECT zasp_runtime_claim_correlation_v4($1,$2,$3,$4)", 4},
		{ProductionPipelineAuthorityProjection, "project", "runtime-projection-v", "SELECT zasp_runtime_claim_projection_v3($1,$2,$3,$4)", 3},
		{ProductionPipelineAuthorityCoordinator, "complete", "runtime-complete-v", "SELECT zasp_runtime_claim_completion_v3($1,$2,$3,$4)", 3},
	} {
		for version := 0; version <= test.max+1; version++ {
			t.Run(test.stage+strconv.Itoa(version), func(t *testing.T) {
				scope := fixtureScope(t, 130)
				body, _ := json.Marshal([]map[string]any{{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": fixtureID(t, 133).String(), "generation": 4, "stage": test.stage, "attempt": 2, "implementation_version": test.prefix + strconv.Itoa(version), "predecessor_digest": strings.Repeat("b", 64), "input_digest": strings.Repeat("b", 64), "input_reference": "s3://zasp-runtime/results/prior.json", "input_version_id": "version-3", "lease_expires_at": "2030-08-20T12:00:30Z"}})
				database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), body}}
				repository, err := NewPostgresPrecisePipelineRepository(database, test.authority)
				if err != nil {
					t.Fatal(err)
				}
				leases, err := repository.ClaimStages(context.Background(), "precise-worker", "precise-worker-token", 60, 1)
				valid := version >= 1 && version <= test.max
				if (err == nil) != valid || valid && len(leases) != 1 || !valid && leases != nil {
					t.Fatal("stage version boundary", leases, err)
				}
				wantPins := []any{migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint(), string(test.authority)}
				if database.calls != 2 || database.statements[0] != productionPrecisionReadySQL || database.statements[1] != test.sql || !reflect.DeepEqual(database.arguments[0], wantPins) || !reflect.DeepEqual(database.arguments[1], []any{"precise-worker", "precise-worker-token", 60, 1}) {
					t.Fatal("wrong authority or claim", database.statements, database.arguments)
				}
			})
		}
	}
}

func TestPrecisePipelineNeverDowngradesReadiness(t *testing.T) {
	for _, body := range []string{`{"ready":false}`, `{"Ready":true}`, `{"ready":true,"extra":true}`, `{"ready":true,"ready":false}`, `null`, `{"ready":null}`} {
		for _, operation := range []string{"ready", "claim", "heartbeat", "finish"} {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(body), json.RawMessage(`{"ready":true}`)}}
			repository, _ := NewPostgresPrecisePipelineRepository(database, ProductionPipelineAuthorityCoordinator)
			request := sessionProjectionFinishFixture(t)
			var err error
			switch operation {
			case "ready":
				err = repository.Ready(context.Background())
			case "claim":
				_, err = repository.ClaimStages(context.Background(), "precise-worker", "precise-worker-token", 60, 1)
			case "heartbeat":
				_, err = repository.HeartbeatStage(context.Background(), request.Lease, request.WorkerID, request.LeaseToken, 60)
			case "finish":
				_, err = repository.FinishStage(context.Background(), request)
			}
			if !errors.Is(err, ErrProductionPipelineUnavailable) || database.calls != 1 || database.statements[0] != productionPrecisionReadySQL {
				t.Fatal("precision authority downgraded", operation, body, err, database.statements)
			}
		}
	}
}

func TestPrecisePipelineRejectsUnsupportedMutationBeforeDatabase(t *testing.T) {
	for _, version := range []string{"runtime-complete-v4", "runtime-projection-v3", "runtime-complete-v0"} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`)}}
		repository, _ := NewPostgresPrecisePipelineRepository(database, ProductionPipelineAuthorityCoordinator)
		request := sessionProjectionFinishFixture(t)
		request.Lease.ImplementationVersion = version
		if _, err := repository.HeartbeatStage(context.Background(), request.Lease, request.WorkerID, request.LeaseToken, 60); !errors.Is(err, ErrProductionPipeline) || database.calls != 0 {
			t.Fatal("unsupported heartbeat reached database", version, err, database.calls)
		}
		if _, err := repository.FinishStage(context.Background(), request); !errors.Is(err, ErrProductionPipeline) || database.calls != 0 {
			t.Fatal("unsupported finish reached database", version, err, database.calls)
		}
	}
}
