package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestProductionRuntimeIngestHTTPPersistsTransactionalOutboxBeforeAcceptance(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())

	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	scope := fixtureRequestIdentity(t).Scope
	sensorID := "pid_76000101-0000-4000-8000-000000000101"
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'runtime-http-sensor','tetragon')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 migration: %v", err)
	}
	if err := runner.UpProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatalf("v16 migration: %v", err)
	}
	if err := runner.UpProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatalf("v17 migration: %v", err)
	}
	for _, migration := range []struct {
		name  string
		apply func(context.Context) error
	}{
		{"security agent execution", runner.UpProductionSecurityAgentExecution},
		{"identity administration", runner.UpProductionIdentityAdministration},
		{"security agent controls", runner.UpProductionSecurityAgentControls},
		{"security agent autonomous response", runner.UpProductionSecurityAgentAutonomousResponse},
		{"security agent temporary policy", runner.UpProductionSecurityAgentTemporaryPolicy},
		{"security agent connector revocation", runner.UpProductionSecurityAgentConnectorRevocation},
		{"security agent session isolation", runner.UpProductionSecurityAgentSessionIsolation},
		{"red team execution", runner.UpProductionRedTeamExecution},
		{"attack lab execution", runner.UpProductionAttackLabExecution},
		{"production recovery", runner.UpProductionRecovery},
	} {
		if err := migration.apply(ctx); err != nil {
			t.Fatalf("%s: %v", migration.name, err)
		}
	}
	loginNames := []string{"runtime_http_api", "runtime_http_discovery", "runtime_http_ingest", "runtime_http_worker", "runtime_http_outbox", "runtime_http_gateway"}
	if _, err := connection.Exec(ctx, `
		CREATE ROLE runtime_http_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		CREATE ROLE runtime_http_discovery LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		CREATE ROLE runtime_http_ingest LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		CREATE ROLE runtime_http_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		CREATE ROLE runtime_http_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		CREATE ROLE runtime_http_gateway LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_register_principals(session_user,$1,$2,$3,$4,$5,$6)`, loginNames[0], loginNames[1], loginNames[2], loginNames[3], loginNames[4], loginNames[5]).Scan(&registered); err != nil || !registered {
		t.Fatalf("register runtime principals=%t err=%v", registered, err)
	}

	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{0x61}, 16), bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	tokenID := "pid_76000102-0000-4000-8000-000000000102"
	locatorDigest, err := credential.LocatorDigest()
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x81}, 32)
	tokenHash, err := credential.Hash(sensor.SensorTokenAudienceEventIngest, mustProductID(t, tokenID), 1, salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, tokenID, locatorDigest[:], salt, tokenHash[:]); err != nil {
		t.Fatalf("issue runtime token: %v", err)
	}
	wireToken, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}

	ingestConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, loginNames[2])
	defer ingestConnection.Close(context.Background())
	metadata := migrations.ProductionRecovery()
	var releaseReady, principalReady bool
	if err := ingestConnection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2),zasp_discovery_principal_ready('zasp_runtime_ingest')`, metadata.Checksum(), migrations.ProductionRecoverySemanticFingerprint()).Scan(&releaseReady, &principalReady); err != nil || !releaseReady || !principalReady {
		t.Fatalf("runtime ingest authority readiness release=%t principal=%t err=%v", releaseReady, principalReady, err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: ingestConnection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionIngestRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatalf("production ingest readiness: %v", err)
	}
	artifacts := &postgresHTTPIngestArtifactStore{}
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	handler, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{
		Repository:   repository,
		Artifacts:    artifacts,
		MaximumBytes: 1 << 20,
		Clock:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"source":"tetragon","events":[{"event_id":"event-http-1","class":"process","action":"exec","workload_id":"runtime-http","event_time":"2026-08-28T12:00:00.000Z","evidence_id":"pid_76000103-0000-4000-8000-000000000103","content":{"binary":"agent"}}]}`)

	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body))
		value.Header.Set("Authorization", "Bearer "+wireToken)
		value.Header.Set("Content-Type", "application/json")
		value.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
		value.Header.Set("Idempotency-Key", "runtime-http-request-0001")
		return value
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var response struct {
		BatchID string `json:"batch_id"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || response.BatchID == "" {
		t.Fatalf("response=%q err=%v", first.Body.String(), err)
	}
	assertDurable := func() string {
		t.Helper()
		var batchCount, stageCount, outboxCount int
		var organizationID, workspaceID, environmentID, state, artifactReference, artifactVersionID, outboxID string
		if err := connection.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM zasp_runtime_batch_authorities WHERE (organization_id,workspace_id,environment_id,batch_id)=($2,$3,$4,$1)),
		authority.organization_id,authority.workspace_id,authority.environment_id,authority.state,authority.raw_artifact_reference,authority.raw_artifact_version_id,
		(SELECT count(*) FROM zasp_runtime_stage_work WHERE (organization_id,workspace_id,environment_id,batch_id)=($2,$3,$4,$1)),
		(SELECT count(*) FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,deterministic_key)=($2,$3,$4,'runtime:'||$1)),
		(SELECT id FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,deterministic_key)=($2,$3,$4,'runtime:'||$1))
		FROM zasp_runtime_batch_authorities authority
		WHERE (authority.organization_id,authority.workspace_id,authority.environment_id,authority.batch_id)=($2,$3,$4,$1)`, response.BatchID, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&batchCount, &organizationID, &workspaceID, &environmentID, &state, &artifactReference, &artifactVersionID, &stageCount, &outboxCount, &outboxID); err != nil {
			t.Fatal(err)
		}
		if batchCount != 1 || organizationID != scope.OrganizationID().String() || workspaceID != scope.WorkspaceID().String() || environmentID != scope.EnvironmentID().String() || state != "queued" || stageCount != 5 || outboxCount != 1 || outboxID == "" || artifactReference != "s3://zasp-runtime/"+artifacts.request.Key || artifactVersionID != "runtime-http-version-0001" || artifacts.request.Scope != scope {
			t.Fatalf("batch=%d scope=%s/%s/%s state=%q artifact=%q@%q stages=%d outbox=%d id=%q put-scope=%v", batchCount, organizationID, workspaceID, environmentID, state, artifactReference, artifactVersionID, stageCount, outboxCount, outboxID, artifacts.request.Scope)
		}
		return outboxID
	}
	outboxID := assertDurable()
	if artifacts.calls != 1 {
		t.Fatalf("first acceptance artifact puts=%d", artifacts.calls)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusAccepted || second.Body.String() != first.Body.String() {
		t.Fatalf("replay status=%d first=%q second=%q", second.Code, first.Body.String(), second.Body.String())
	}
	if replayedOutboxID := assertDurable(); replayedOutboxID != outboxID {
		t.Fatalf("replay outbox=%q want=%q", replayedOutboxID, outboxID)
	}
	if artifacts.calls != 2 {
		t.Fatalf("replay artifact puts=%d", artifacts.calls)
	}
	t.Run("bound envelope credential lifecycle", func(t *testing.T) {
		for _, up := range []func(context.Context) error{runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook, runner.UpProductionRuntimeQueueReplay, runner.UpProductionRedTeamSafety, runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing, runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority} {
			if err := up(ctx); err != nil {
				t.Fatal("acceptance fixture upgrade", err)
			}
		}
		if err := runner.UpProductionRuntimeAcceptance(ctx); err != nil {
			t.Fatal(err)
		}
		exerciseBoundRuntimeEnvelopeLifecycle(t, ctx, connection, ingestConnection, scope, sensorID, tokenID, wireToken, now)
		t.Run("installed file recovery over HTTPS", func(t *testing.T) {
			exerciseInstalledSensorRecovery(t, ctx, connection, ingestConnection, scope, false)
		})
		t.Run("lineage generation recovery over HTTPS", func(t *testing.T) { exerciseInstalledSensorRecovery(t, ctx, connection, ingestConnection, scope, true) })
		t.Run("admitted chunk consumer recovery over HTTPS", func(t *testing.T) {
			exerciseInstalledSensorRecoveryMode(t, ctx, connection, ingestConnection, scope, "chunks")
		})
		t.Run("incomplete upload across credential rotation", func(t *testing.T) {
			exerciseIncompleteAcceptanceRotation(t, ctx, connection, ingestConnection, scope, now)
		})
	})
}

type postgresHTTPIngestArtifactStore struct {
	calls   int
	request runtimeevent.RawArtifactPut
}

func (store *postgresHTTPIngestArtifactStore) Put(_ context.Context, request runtimeevent.RawArtifactPut) (runtimeevent.RawArtifact, error) {
	store.calls++
	if store.calls == 1 {
		store.request = request
		store.request.Body = bytes.Clone(request.Body)
	} else if store.request.Scope != request.Scope || store.request.Key != request.Key || store.request.MediaType != request.MediaType || store.request.ContentDigest != request.ContentDigest || !bytes.Equal(store.request.Body, request.Body) {
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestArtifactDrift
	}
	return runtimeevent.RawArtifact{
		Scope: request.Scope, Key: request.Key, Reference: "s3://zasp-runtime/" + request.Key,
		VersionID: "runtime-http-version-0001", ContentDigest: request.ContentDigest, Size: int64(len(request.Body)), MediaType: request.MediaType,
		KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
	}, nil
}

var _ runtimeevent.RawArtifactAuthority = (*postgresHTTPIngestArtifactStore)(nil)
