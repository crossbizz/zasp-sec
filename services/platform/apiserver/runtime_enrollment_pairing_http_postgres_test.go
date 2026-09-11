package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

// Uses the real HTTP handlers and registered PostgreSQL roles. The raw artifact
// store is explicitly a test double; S3 and the five worker stages are not proved here.
func exercisePairedProductEnrollmentAndRuntimeIngest(t *testing.T, ctx context.Context, admin *pgx.Conn, database JSONDatabase, identity RequestIdentity, anchor string) {
	t.Helper()
	repository, err := NewSensorPublicRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	product, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Force a sub-microsecond clock on every host. A wall clock that happens to
	// return microseconds hides a committed-token/503 response mismatch.
	clock := time.Now().UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	product.(*sensorPublicHTTPHandler).config.Clock = func() time.Time { return clock }
	body, err := json.Marshal(map[string]string{"name": "HTTP paired source", "kind": "otlp", "mode": "metadata_only", "runtime_sensor_id": anchor})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sensors", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "paired-product-http-0001")
	request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	request = request.WithContext(context.WithValue(ctx, identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "createSensorEnrollment", PathParameters: map[string]string{}}))
	created := httptest.NewRecorder()
	product.ServeHTTP(created, request)
	var enrollment sensorEnrollment
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &enrollment) != nil || enrollment.RuntimeSensorID != anchor || enrollment.Token == "" {
		t.Fatalf("real product pairing create failed status=%d", created.Code)
	}
	assertExpiry := func(generation int64) {
		t.Helper()
		var persisted time.Time
		err := admin.QueryRow(ctx, `SELECT expires_at FROM zasp_sensor_tokens WHERE (organization_id,workspace_id,environment_id,sensor_id,token_generation)=($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), enrollment.ID, generation).Scan(&persisted)
		want := clock.Add(product.(*sensorPublicHTTPHandler).config.TokenTTL).Truncate(time.Microsecond)
		if err != nil || enrollment.TokenExpiresAt == nil || !persisted.Equal(want) || !enrollment.TokenExpiresAt.Equal(want) {
			t.Fatal("persisted and returned credential expiry differ", err)
		}
	}
	assertExpiry(1)
	originalID, originalToken := enrollment.ID, enrollment.Token
	clock = clock.Add(777 * time.Nanosecond)
	rotation := httptest.NewRequest(http.MethodPost, "/api/v1/sensors/"+enrollment.ID+"/rotate-token", strings.NewReader(`{}`))
	rotation.Header.Set("Content-Type", "application/json")
	rotation.Header.Set("Idempotency-Key", "paired-product-rotate-0001")
	rotation.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	rotation.Header.Set("If-Match", created.Header().Get("ETag"))
	rotation = rotation.WithContext(context.WithValue(ctx, identityContextKey{}, identity))
	rotation = rotation.WithContext(context.WithValue(rotation.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "rotateSensorToken", PathParameters: map[string]string{"id": enrollment.ID}}))
	rotated := httptest.NewRecorder()
	product.ServeHTTP(rotated, rotation)
	if rotated.Code != http.StatusOK || json.Unmarshal(rotated.Body.Bytes(), &enrollment) != nil || enrollment.ID != originalID || enrollment.RuntimeSensorID != anchor || enrollment.Token == "" || enrollment.Token == originalToken {
		t.Fatalf("real product pairing rotation failed status=%d", rotated.Code)
	}
	assertExpiry(2)
	config := admin.Config().Copy()
	config.User = "invocation_ingest"
	ingestConnection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer ingestConnection.Close(context.Background())
	ingestDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: ingestConnection})
	if err != nil {
		t.Fatal(err)
	}
	ingestRepository, err := runtimeevent.NewPostgresProductionIngestRepository(ingestDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if err := ingestRepository.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	artifacts := &postgresHTTPIngestArtifactStore{}
	ingest, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: ingestRepository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	batchBody, err := json.Marshal(map[string]any{"source": "otlp", "events": []any{map[string]any{
		"attributes": map[string]string{"event.id": "paired-http-event", "event.class": "tool", "event.action": "invoke", "agent.id": "pid_78400001-0000-4000-8000-000000000001", "session.id": "pid_78400002-0000-4000-8000-000000000002", "task.id": "pairing-task", "tool.id": "pairing-tool", "sandbox.id": "pairing-sandbox", "trace.id": strings.Repeat("a", 32), "span.id": strings.Repeat("b", 16)},
		"event_time": time.Now().UTC().Add(-time.Second).Format("2006-01-02T15:04:05.000Z"), "evidence_id": "pid_78400003-0000-4000-8000-000000000003",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(payload []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(payload)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+enrollment.Token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
		r.Header.Set("Idempotency-Key", "paired-runtime-http-0001")
		response := httptest.NewRecorder()
		ingest.ServeHTTP(response, r)
		return response
	}
	first := call(batchBody)
	var accepted struct {
		BatchID string `json:"batch_id"`
	}
	if first.Code != http.StatusAccepted || json.Unmarshal(first.Body.Bytes(), &accepted) != nil || accepted.BatchID == "" {
		t.Fatalf("paired ingest status=%d", first.Code)
	}
	replacementToken := enrollment.Token
	enrollment.Token = originalToken
	putsBeforeRevoked := artifacts.calls
	if denied := call(batchBody); denied.Code != http.StatusForbidden || artifacts.calls != putsBeforeRevoked {
		t.Fatalf("rotated-away credential status=%d artifact delta=%d", denied.Code, artifacts.calls-putsBeforeRevoked)
	}
	enrollment.Token = replacementToken
	var binding string
	if err := admin.QueryRow(ctx, `SELECT concat_ws('|',generation,source_sensor_id,source_kind,runtime_sensor_id) FROM zasp_runtime_batch_domains WHERE (organization_id,workspace_id,environment_id,batch_id)=($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), accepted.BatchID).Scan(&binding); err != nil || binding != "1|"+enrollment.ID+"|otlp|"+anchor {
		t.Fatal("authenticated ingest lost enrollment domain", err)
	}
	replay := call(batchBody)
	if replay.Code != http.StatusAccepted || replay.Body.String() != first.Body.String() {
		t.Fatalf("paired ingest replay drifted status=%d", replay.Code)
	}
	var hostile map[string]any
	if err := json.Unmarshal(batchBody, &hostile); err != nil {
		t.Fatal(err)
	}
	hostile["runtime_sensor_id"] = "pid_78400004-0000-4000-8000-000000000004"
	hostileBody, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	puts := artifacts.calls
	if response := call(hostileBody); response.Code != http.StatusBadRequest || artifacts.calls != puts {
		t.Fatalf("payload supplied pairing authority status=%d", response.Code)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_batch_domains WHERE source_sensor_id=$1 AND runtime_sensor_id=$2`, enrollment.ID, anchor).Scan(&count); err != nil || count != 1 {
		t.Fatal("replay or hostile payload changed domain count", err)
	}
	enrollment.Token = ""
}
