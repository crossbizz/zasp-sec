package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// Real product create/rotate handlers and registered PostgreSQL roles feed a
// real file processor over local certificate-verified HTTPS. Browser identity
// is a scoped fixture; artifact storage is a double, not S3 or deployed proof.
func exerciseInstalledSensorRecovery(t *testing.T, ctx context.Context, admin, ingestConnection *pgx.Conn, scope domain.Scope, withLineage bool) {
	mode := "file"
	if withLineage {
		mode = "lineage"
	}
	exerciseInstalledSensorRecoveryMode(t, ctx, admin, ingestConnection, scope, mode)
}

func exerciseInstalledSensorRecoveryMode(t *testing.T, ctx context.Context, admin, ingestConnection *pgx.Conn, scope domain.Scope, mode string) {
	t.Helper()
	withLineage := mode == "lineage"
	suffix := ""
	if mode != "file" {
		suffix = "-" + mode
	}
	identity := fixtureRequestIdentity(t)
	identity.Scope, identity.CredentialKind = scope, CredentialBearerToken
	org, workspace, environment, principal := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), identity.PrincipalID.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'installed-org','installed-member','security_admin',true) ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='security_admin',active=true`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Installed sensor proof','["view","manage_workflows"]',true) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions='["view","manage_workflows"]'`, org, workspace, environment, principal); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "runtime_http_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	publicRepository, err := NewSensorPublicRepository(apiDatabase)
	if err != nil {
		t.Fatal(err)
	}
	public, err := NewSensorPublicHTTPHandler(publicRepository, bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(id, version string) (sensorEnrollment, string) {
		t.Helper()
		operation, path, body, status := "createSensorEnrollment", "/api/v1/sensors", `{"name":"installed-recovery`+suffix+`","kind":"tetragon","mode":"metadata_only"}`, http.StatusCreated
		if id != "" {
			operation, path, body, status = "rotateSensorToken", path+"/"+id+"/rotate-token", `{}`, http.StatusOK
		}
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "installed-sensor-"+operation+suffix)
		request.Header.Set("X-Zasp-Sensor-Enrollment-Schema", "enrollment-binding-v1")
		if version != "" {
			request.Header.Set("If-Match", version)
		}
		request = request.WithContext(context.WithValue(ctx, identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": id}}))
		response := httptest.NewRecorder()
		public.ServeHTTP(response, request)
		var enrollment sensorEnrollment
		if response.Code != status || json.Unmarshal(response.Body.Bytes(), &enrollment) != nil || enrollment.EnrollmentBinding == "" || enrollment.Token == "" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("real enrollment mutation failed", operation, response.Code)
		}
		return enrollment, response.Header().Get("ETag")
	}
	created, version := mutate("", "")
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: ingestConnection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionIngestRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := &installedSensorArtifacts{}
	ingest, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal("installed ingest handler", err)
	}
	var httpHandler http.Handler = ingest
	chunkTrace := &installedChunkHTTPTrace{handler: ingest}
	if mode == "chunks" {
		httpHandler = chunkTrace
	}
	server := httptest.NewTLSServer(httpHandler)
	defer server.Close()
	if mode == "chunks" {
		exerciseInstalledChunkSensorRecovery(t, ctx, admin, scope, created, version, mutate, server, chunkTrace, artifacts)
		return
	}
	httpClient := server.Client()
	httpClient.Timeout = 5 * time.Second
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	stamp := time.Now().UTC().Add(-time.Second).Format("2006-01-02T15:04:05.000Z")
	line := `{"process_exec":{"process":{"exec_id":"installed-exec","pid":42,"start_time":"` + stamp + `","binary":"/usr/bin/agent","pod":{"namespace":"agentsec","name":"agent-pod","uid":"installed-pod-uid","container":{"id":"containerd://installed-container","name":"agent"}}}},"node_name":"installed-node","time":"` + stamp + `","cluster_name":"installed-cluster","node_labels":{}}`
	// This is an explicit source-generation fixture, not proof of a local
	// Tetragon subscriber, boot resolver or Kubernetes deployment.
	source := sensoradapter.LineageSource{Profile: "tetragon-local-stream-v1", GenerationID: "12345678-1234-1234-1234-123456789005", EnrollmentBinding: created.EnrollmentBinding, NodeName: "installed-node", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003"}
	wantLineage := runtimelineage.Observation{}
	if withLineage {
		line = strings.Replace(line, "installed-pod-uid", "12345678-1234-1234-1234-123456789004", 1)
		line = strings.Replace(line, "containerd://installed-container", "containerd://"+strings.Repeat("a", 64), 1)
		started, err := time.Parse("2006-01-02T15:04:05.000Z", stamp)
		if err != nil {
			t.Fatal(err)
		}
		wantLineage = runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: source.ClusterUID, NodeUID: source.NodeUID, BootID: source.BootID, PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: started.Format(time.RFC3339Nano)}
	}
	if _, err := sensoradapter.NormalizeTetragonLine([]byte(line)); err != nil {
		t.Fatal("invalid installed sensor fixture", err)
	}
	if err := os.WriteFile(logPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, tokenReads := created.Token, 0
	var bodies [][]byte
	var receipts []string
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: server.URL, EnrollmentBinding: created.EnrollmentBinding, Now: time.Now, Token: func() ([]byte, error) { tokenReads++; return []byte(credential), nil }, Do: func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, body)
		request.Body = io.NopCloser(bytes.NewReader(body))
		response, err := httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		responseBody, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusAccepted {
			t.Fatal("installed sensor HTTPS ingest failed", response.StatusCode, err)
		}
		receipts = append(receipts, string(responseBody))
		if len(receipts) == 1 {
			return nil, errors.New("test response lost after durable acceptance")
		}
		response.Body = io.NopCloser(bytes.NewReader(responseBody))
		return response, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	open := func() *sensoradapter.FileProcessor {
		t.Helper()
		normalizer, _ := sensoradapter.NewNormalizer(100)
		if withLineage {
			var err error
			normalizer, err = sensoradapter.NewLineageNormalizer(100, source)
			if err != nil {
				t.Fatal(err)
			}
		}
		processor, err := sensoradapter.NewFileProcessor(sensoradapter.FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: client, MaximumLines: 100})
		if err != nil {
			t.Fatal(err)
		}
		return processor
	}
	first := open()
	if result, err := first.ProcessAvailable(ctx); err != sensoradapter.ErrClientRetryable || result != (sensoradapter.StreamResult{}) {
		t.Fatal("uncertain accepted request was not retained", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	var batchID string
	var originalProvenance string
	if err := admin.QueryRow(ctx, `SELECT batch_id,to_jsonb(b)::text FROM zasp_runtime_batch_authorities b WHERE sensor_id=$1`, created.ID).Scan(&batchID, &originalProvenance); err != nil {
		t.Fatal(err)
	}
	rotated, _ := mutate(created.ID, version)
	if rotated.EnrollmentBinding != created.EnrollmentBinding || rotated.Token == created.Token {
		t.Fatal("real rotation changed enrollment or reused the token")
	}
	credential = rotated.Token
	restarted := open()
	defer restarted.Close()
	if result, err := restarted.ProcessAvailable(ctx); err != nil || result.Read != 1 || result.Submitted != 1 {
		t.Fatal("installed sensor recovery failed", result, err)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || len(receipts) != 2 || receipts[0] != receipts[1] || tokenReads != 2 || artifacts.count() != 1 {
		t.Fatal("recovery changed request, receipt or artifact write count")
	}
	archived, err := runtimeevent.DecodeArchivedBatch(scope, artifacts.body())
	if err != nil || len(archived.Records) != 1 {
		t.Fatal("canonical archive invalid", err)
	}
	record := archived.Records[0]
	if record.ObservedLineage != wantLineage || record.Scope != scope || record.AgentID != (domain.ProductID{}) || record.SessionID != (domain.ProductID{}) || record.ContainerID != "" || record.CgroupID != "" || record.ProcessID != "" {
		t.Fatal("generation observation changed or granted semantic/correlation authority")
	}
	var unchanged bool
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(b)::text=$2 AND (SELECT count(*) FROM zasp_runtime_batch_authorities WHERE sensor_id=$3)=1 AND (SELECT count(*) FROM zasp_runtime_stage_work WHERE batch_id=$1)=5 AND (SELECT count(*) FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1)=1 FROM zasp_runtime_batch_authorities b WHERE batch_id=$1`, batchID, originalProvenance, created.ID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("recovery changed durable provenance or duplicated work", err)
	}
	if result, err := restarted.ProcessAvailable(ctx); err != nil || !result.Idle || len(bodies) != 2 {
		t.Fatal("acknowledged cursor replayed again", result, err)
	}
}

type installedSensorArtifacts struct {
	mu     sync.Mutex
	stores map[installedSensorArtifactKey]*postgresHTTPIngestArtifactStore
	latest installedSensorArtifactKey
}

type installedSensorArtifactKey struct {
	scope domain.Scope
	key   string
}

func (store *installedSensorArtifacts) Put(ctx context.Context, request runtimeevent.RawArtifactPut) (runtimeevent.RawArtifact, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.stores == nil {
		store.stores = make(map[installedSensorArtifactKey]*postgresHTTPIngestArtifactStore)
	}
	key := installedSensorArtifactKey{scope: request.Scope, key: request.Key}
	object := store.stores[key]
	if object == nil {
		object = &postgresHTTPIngestArtifactStore{}
		store.stores[key] = object
	}
	artifact, err := object.Put(ctx, request)
	if err == nil {
		store.latest = key
	}
	return artifact, err
}
func (store *installedSensorArtifacts) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	count := 0
	for _, object := range store.stores {
		count += object.calls
	}
	return count
}

func (store *installedSensorArtifacts) body() []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	if object := store.stores[store.latest]; object != nil {
		return bytes.Clone(object.request.Body)
	}
	return nil
}
