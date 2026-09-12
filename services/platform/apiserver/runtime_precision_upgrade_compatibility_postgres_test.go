package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// Breaks if schema51 stops honoring the schema50 API's compiled readiness
// contract, changes historical event bytes, or rejects its V1 HTTP intake.
// Identity and search candidate selection are local fixtures. Session evidence
// comes from the existing canonical completion fixture and real SQL finisher;
// its target2 checkpoint intentionally remains pending, not provider-verified.
func TestRuntimePrecisionUpgradeKeepsExistingAPIAndV1Intake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	completion, projected := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	var completed json.RawMessage
	if err := coordinator.QueryRow(ctx, sandboxSessionFinishSQL, completion...).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	api := sandboxSessionAPI(t, ctx, admin)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{"unattributed"}, After: "unattributed"}}
	repository, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(database, index, "zasp-runtime-sessions-v2")
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	apiHandler := &identityHTTPHandler{administration: repository, signingKey: []byte(strings.Repeat("s", 32)), now: time.Now}
	search := func() *httptest.ResponseRecorder {
		searchIdentity := identity
		searchIdentity.Permissions = append(append([]string(nil), identity.Permissions...), "investigate_sessions")
		request := workflowRequest(t, searchIdentity, testCorrelationID, "listSessions", nil, http.MethodGet, "/api/v1/sessions?kind=runtime&limit=25", "")
		response := httptest.NewRecorder()
		apiHandler.ServeHTTP(response, request)
		return response
	}

	// Use the historical constructors before51. Never replace these instances
	// after migration, and do not opt into the precise HTTP/schema decoder.
	const sensorID = "pid_76000601-0000-4000-8000-000000000601"
	const tokenID = "pid_76000602-0000-4000-8000-000000000602"
	scope := identity.Scope
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	if _, err := admin.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'upgrade-v1-http','tetragon')`, org, workspace, environment, sensorID); err != nil {
		t.Fatal(err)
	}
	wire, locator, salt, hash := envelopeLifecycleCredential(t, tokenID, 1, 0xe8)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, org, workspace, environment, sensorID, tokenID, locator, salt, hash); err != nil {
		t.Fatal(err)
	}
	ingest := precisionRecoveryIngest(t, ctx, admin)
	ingestDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: ingest})
	if err != nil {
		t.Fatal(err)
	}
	ingestRepository, err := runtimeevent.NewPostgresProductionIngestRepository(ingestDatabase)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)
	artifacts := &upgradeCompatibilityArtifacts{objects: map[string]*postgresHTTPIngestArtifactStore{}}
	ingestHandler, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: ingestRepository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sensor.EnrollmentBinding(scope, mustProductID(t, sensorID))
	if err != nil {
		t.Fatal(err)
	}
	lastStatus := 0
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: binding, Now: func() time.Time { return now }, Token: func() ([]byte, error) { return []byte(wire), nil }, Do: func(request *http.Request) (*http.Response, error) {
		response := httptest.NewRecorder()
		ingestHandler.ServeHTTP(response, request)
		lastStatus = response.Code
		return response.Result(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(suffix string) sensoradapter.RuntimeEnvelope {
		t.Helper()
		event := sensoradapter.RuntimeEvent{EventID: "tetragon:" + strings.Repeat(suffix, 64), Class: "process", Action: "exec", WorkloadID: "k8s:" + strings.Repeat("b", 64), EventTime: "2026-08-20T12:00:00.123Z", EvidenceID: "pid_76000603-0000-4000-8000-000000000603"}
		envelope, err := client.PrepareEnvelope([]sensoradapter.RuntimeEvent{event})
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	first, second := prepare("a"), prepare("c")
	baseline := map[string]string{}
	for _, phase := range []string{"schema50", "schema51"} {
		if phase == "schema51" {
			installRuntimePrecision(t, ctx, admin)
		}
		if version, err := database.SchemaVersion(ctx); err != nil || version != ProductionRecoverySchemaVersion {
			t.Fatal("existing API startup schema probe rejected", phase, version, err)
		}
		if err := repository.Ready(ctx); err != nil {
			t.Fatal("existing target2 API readiness rejected", phase, err)
		}
		if err := ingestRepository.Ready(ctx); err != nil {
			t.Fatal("existing V1 intake readiness rejected", phase, err)
		}
		response := search()
		var page struct {
			Items  []json.RawMessage          `json:"items"`
			Search RuntimeSessionSearchStatus `json:"search"`
		}
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Search.State != "catching_up" || page.Search.Pending != 1 {
			t.Fatal("existing target2 HTTP search rejected or invented currentness", phase, response.Code, response.Body.String())
		}
		for _, item := range projected.Items {
			target := item.SessionID.String()
			if target == "" {
				target = "unattributed"
			}
			for _, operation := range []string{"getSessionEvent", "listSessionEvents"} {
				event, query := item.EventID.String(), ""
				if operation == "listSessionEvents" {
					event, query = "", "limit=25"
				}
				response := sandboxSessionHTTPRequest(t, apiHandler, identity, operation, target, event, query)
				key := operation + ":" + target + ":" + event
				// The full service middleware supplies page cache headers; this
				// standalone handler itself supplies them for evidence detail.
				if response.Code != http.StatusOK || operation == "getSessionEvent" && response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("existing event HTTP read rejected", phase, response.Code, response.Body.String())
				}
				if phase == "schema50" {
					baseline[key] = response.Body.String()
				} else if baseline[key] != response.Body.String() {
					t.Fatal("historical event representation changed across51", key)
				}
			}
		}
		if err := client.IngestEnvelope(ctx, first); err != nil || lastStatus != http.StatusAccepted || artifacts.calls != 1 {
			t.Fatal("existing V1 acceptance/replay rejected", phase, err, lastStatus, artifacts.calls)
		}
	}
	if err := client.IngestEnvelope(ctx, second); err != nil || lastStatus != http.StatusAccepted || artifacts.calls != 2 {
		t.Fatal("fresh V1 acceptance after51 rejected", err, lastStatus, artifacts.calls)
	}
	var batches, stages, wrong int
	if err := admin.QueryRow(ctx, `SELECT count(*),(SELECT count(*) FROM zasp_runtime_stage_work s JOIN zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE b.sensor_id=$1),count(*) FILTER(WHERE payload_schema_version<>'runtime-event-v1') FROM zasp_runtime_batch_authorities WHERE sensor_id=$1`, sensorID).Scan(&batches, &stages, &wrong); err != nil || batches != 2 || stages != 10 || wrong != 0 {
		t.Fatal("V1 acceptance authority changed", batches, stages, wrong, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SchemaVersion(ctx); err == nil {
		t.Fatal("existing API startup accepted51 drift")
	}
	if err := repository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatal("existing API readiness accepted51 drift", err)
	}
	if response := search(); response.Code != http.StatusServiceUnavailable || decodeErrorCode(t, response) != "provider_unavailable" {
		t.Fatal("existing HTTP search accepted51 drift", response.Code, response.Body.String())
	}
	response := sandboxSessionHTTPRequest(t, apiHandler, identity, "listSessionEvents", "unattributed", "", "limit=25")
	if response.Code != http.StatusServiceUnavailable || decodeErrorCode(t, response) != "provider_unavailable" {
		t.Fatal("existing HTTP event read accepted51 drift", response.Code, response.Body.String())
	}
	if err := client.IngestEnvelope(ctx, first); !errors.Is(err, sensoradapter.ErrClientRetryable) || artifacts.calls != 2 {
		t.Fatal("existing V1 replay accepted51 drift or wrote", err, lastStatus, artifacts.calls)
	}
}

// Preserve the existing immutable object fixture's drift checks independently
// for each content-addressed key. This test accepts two distinct HTTP batches.
type upgradeCompatibilityArtifacts struct {
	calls   int
	objects map[string]*postgresHTTPIngestArtifactStore
}

func (store *upgradeCompatibilityArtifacts) Put(ctx context.Context, request runtimeevent.RawArtifactPut) (runtimeevent.RawArtifact, error) {
	store.calls++
	object := store.objects[request.Key]
	if object == nil {
		object = &postgresHTTPIngestArtifactStore{}
		store.objects[request.Key] = object
	}
	return object.Put(ctx, request)
}
