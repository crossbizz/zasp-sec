package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// Local composition only: real daemon, TLS, public enrollment and PostgreSQL.
// Browser identity, producer source, Kubernetes readiness and artifacts are
// explicit fixtures. No production binary receives a test-only switch.
func TestRuntimeAcceptanceActualDaemonLostSuccessReplay(t *testing.T) {
	if os.Getenv("ZASP_TEST_DAEMON_REPLAY") != "1" {
		t.Skip("requires owned isolated Linux daemon/PostgreSQL composition")
	}
	assertDaemonReplayContainer(t)
	for _, profile := range []string{"tetragon-local-stream-v1", "tetragon-local-stream-v2"} {
		t.Run(profile, func(t *testing.T) { exerciseRuntimeDaemonLostSuccessReplay(t, profile) })
	}
}

func exerciseRuntimeDaemonLostSuccessReplay(t *testing.T, profile string) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	ownership := &daemonReplayOwnership{}
	// Register before every child cleanup, so no owned directory is removed
	// until all later child joins have run and reported their outcomes.
	t.Cleanup(func() { ownership.cleanup(t) })
	dsn := startDaemonReplayPostgres(t, ctx, ownership)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	migrateDaemonReplayDatabase(t, ctx, admin)
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	scope := identity.Scope
	org, workspace, environment, principal := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), identity.PrincipalID.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'daemon-org','daemon-member','security_admin',true);`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Daemon replay proof','["view","manage_workflows"]',true)`, org, workspace, environment, principal); err != nil {
		t.Fatal(err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "runtime_http_api")
	defer api.Close(context.Background())
	apiDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	publicRepo, err := NewSensorPublicRepository(apiDB)
	if err != nil {
		t.Fatal(err)
	}
	public, err := NewSensorPublicHTTPHandler(publicRepo, bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(id, version string) (sensorEnrollment, string) {
		t.Helper()
		op, path, body, status := "createSensorEnrollment", "/api/v1/sensors", `{"name":"actual-daemon-replay","kind":"tetragon","mode":"metadata_only"}`, http.StatusCreated
		if id != "" {
			op, path, body, status = "rotateSensorToken", path+"/"+id+"/rotate-token", `{}`, http.StatusOK
		}
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "daemon-fixture-"+op)
		r.Header.Set("X-Zasp-Sensor-Enrollment-Schema", "enrollment-binding-v1")
		if version != "" {
			r.Header.Set("If-Match", version)
		}
		r = r.WithContext(context.WithValue(ctx, identityContextKey{}, identity))
		r = r.WithContext(context.WithValue(r.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: op, PathParameters: map[string]string{"id": id}}))
		w := httptest.NewRecorder()
		public.ServeHTTP(w, r)
		var result sensorEnrollment
		if w.Code != status || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Token == "" || result.EnrollmentBinding == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("real enrollment mutation failed", op, w.Code)
		}
		return result, w.Header().Get("ETag")
	}
	created, version := mutate("", "")
	ingestConn := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "runtime_http_ingest")
	defer ingestConn.Close(context.Background())
	ingestDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: ingestConn})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionIngestRepository(ingestDB)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := &installedSensorArtifacts{}
	handler, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	trace := &sensorDaemonReplayTrace{handler: handler}
	serverCtx, stopServer := context.WithCancel(ctx)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/v1/runtime/events" {
			trace.ServeHTTP(w, r)
			return
		}
		// Deliberate failed cluster/heartbeat fixtures must not block ingestion.
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	server.Listener.Close()
	server.Listener, err = net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.BaseContext = func(net.Listener) context.Context { return serverCtx }
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.ReadTimeout, server.Config.WriteTimeout = 6*time.Second, 6*time.Second
	server.StartTLS()
	defer func() { stopServer(); server.CloseClientConnections(); server.Close() }()
	endpoint := strings.TrimSuffix(server.URL, ":443")
	credentials := "/var/run/secrets/kubernetes.io/serviceaccount"
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for name, body := range map[string][]byte{"ca.crt": ca, "token": []byte("fixture-cluster-identity"), "namespace": []byte("agentsec")} {
		if err := os.WriteFile(filepath.Join(credentials, name), body, 0444); err != nil {
			t.Fatal(err)
		}
	}
	readyListener, err := net.Listen("tcp", "127.0.0.1:8082")
	if err != nil {
		t.Fatal(err)
	}
	ready := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ready"}`)
	}), ReadHeaderTimeout: time.Second}
	readyDone := make(chan error, 1)
	go func() { readyDone <- ready.Serve(readyListener) }()
	defer func() { ready.Close(); <-readyDone }()
	root := ownership.root(t)
	if err := os.Chmod(root, 0750); err != nil {
		t.Fatal(err)
	}
	config := installedChunkChildConfig{Endpoint: endpoint, CAPath: filepath.Join(credentials, "ca.crt"), TokenPath: filepath.Join(root, "credentials", "token"), SpoolPath: filepath.Join(root, "spool"), CursorPath: filepath.Join(root, "state", "cursor-0.json"), AckPath: filepath.Join(root, "acks"), ResultPath: filepath.Join(root, "result.json"), Stamp: time.Now().UTC().Add(-time.Second).Truncate(time.Millisecond).Format(time.RFC3339Nano), Source: sensoradapter.LineageSource{Profile: "tetragon-local-stream-v1", GenerationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", EnrollmentBinding: created.EnrollmentBinding, NodeName: "node-a", ClusterUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", NodeUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", BootID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}}
	config.Source.Profile = profile
	for _, name := range []string{"spool", "acks", "state", "credentials", "kernel", "btf"} {
		path, mode := filepath.Join(root, name), os.FileMode(0750)
		if name == "state" || name == "credentials" {
			mode = 0700
		}
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if name == "acks" || name == "state" || name == "credentials" {
			if err := os.Chown(path, 65532, 65532); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"kernel", "btf"} {
		if err := os.WriteFile(filepath.Join(root, name, "value"), []byte("6.8.1\n"), 0444); err != nil {
			t.Fatal(err)
		}
	}
	writeToken := func(token string) {
		t.Helper()
		if err := os.WriteFile(config.TokenPath+".new", []byte(token), 0600); err != nil {
			t.Fatal("write owned credential")
		}
		if err := os.Chown(config.TokenPath+".new", 65532, 65532); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(config.TokenPath+".new", config.TokenPath); err != nil {
			t.Fatal(err)
		}
	}
	writeToken(created.Token)
	invoke := func(action string) installedChunkChildResult {
		return invokeDaemonReplayProducerFixture(t, ctx, root, config, action)
	}
	if result := invoke("initialize-single"); result.Outcome != "initialized" || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("single source initialization failed", result.Outcome)
	}
	sourceBefore := daemonReplaySourceSnapshot(t, filepath.Join(config.SpoolPath, "generation-"+config.Source.GenerationID))
	first := startReplayDaemon(t, ctx, root, config, "first")
	waitDaemonReplay(t, ctx, "first database acceptance", func() bool { return len(trace.snapshot()) == 1 })
	first.stop(t)
	entries := trace.snapshot()
	if len(entries) != 1 || entries[0].status != http.StatusAccepted || entries[0].authDigest != sha256.Sum256([]byte("Bearer "+created.Token)) {
		t.Fatal("first daemon didn't lose a real authorized success")
	}
	if result := invoke("verify-daemon-acknowledgment"); result.Outcome != "rejected" {
		t.Fatal("unobserved success published a verified ACK")
	}
	if files, err := os.ReadDir(config.AckPath); err != nil || len(files) != 0 {
		t.Fatal("first daemon published unobserved receipt", err)
	}
	cursor, err := os.ReadFile(config.CursorPath)
	if err != nil || len(cursor) > 2<<20 {
		t.Fatal("missing bounded pending checkpoint", err)
	}
	var pending struct {
		Committed sensoradapter.ChunkProgress `json:"committed"`
		Pending   *struct {
			Envelope *sensoradapter.RuntimeEnvelope `json:"envelope"`
		} `json:"pending"`
	}
	if json.Unmarshal(cursor, &pending) != nil || pending.Pending == nil || pending.Pending.Envelope == nil || pending.Committed.NextSequence != 1 || !bytes.Equal(pending.Pending.Envelope.Body, entries[0].body) || pending.Pending.Envelope.IdempotencyKey != entries[0].key {
		t.Fatal("pending checkpoint doesn't retain exact lost request")
	}
	var batchID, provenance string
	if err := admin.QueryRow(ctx, `SELECT batch_id,to_jsonb(b)::text FROM zasp_runtime_batch_authorities b WHERE sensor_id=$1`, created.ID).Scan(&batchID, &provenance); err != nil {
		t.Fatal("committed first authority missing", err)
	}
	if entries[0].batchID != batchID {
		t.Fatal("lost acceptance receipt named different database authority")
	}
	assertSingleAuthority := func() {
		t.Helper()
		var same bool
		if err := admin.QueryRow(ctx, `SELECT to_jsonb(b)::text=$2 AND (SELECT count(*) FROM zasp_runtime_batch_authorities WHERE sensor_id=$3)=1 AND (SELECT count(*) FROM zasp_runtime_stage_work w JOIN zasp_runtime_batch_authorities a USING(batch_id) WHERE a.sensor_id=$3)=5 AND (SELECT count(*) FROM zasp_discovery_outbox o JOIN zasp_runtime_batch_authorities a ON o.deterministic_key='runtime:'||a.batch_id WHERE a.sensor_id=$3)=1 FROM zasp_runtime_batch_authorities b WHERE batch_id=$1`, batchID, provenance, created.ID).Scan(&same); err != nil || !same || artifacts.count() != 1 {
			t.Fatal("duplicate or changed durable authority", err)
		}
	}
	assertSingleAuthority()
	rotated, _ := mutate(created.ID, version)
	if rotated.EnrollmentBinding != created.EnrollmentBinding || rotated.Token == created.Token {
		t.Fatal("rotation changed enrollment or retained credential")
	}
	writeToken(rotated.Token)
	if after, err := os.ReadFile(config.CursorPath); err != nil || !bytes.Equal(cursor, after) {
		t.Fatal("rotation changed pending state", err)
	}
	if !trace.allowReplay() {
		t.Fatal("joined daemon didn't release replay gate")
	}
	second := startReplayDaemon(t, ctx, root, config, "second")
	waitDaemonReplay(t, ctx, "replayed database acceptance", func() bool { return len(trace.snapshot()) >= 2 })
	waitDaemonReplay(t, ctx, "verified durable source acknowledgment", func() bool {
		result := invoke("verify-daemon-acknowledgment")
		return result.Outcome == "receipt-verified" && result.Progress.NextSequence == 2 && result.Progress.Read == 1 && result.Progress.Submitted == 1 && result.Progress.Dropped == 0
	})
	second.stop(t)
	entries = trace.snapshot()
	if len(entries) != 2 || entries[1].status != http.StatusAccepted || !bytes.Equal(entries[0].body, entries[1].body) || entries[0].key == "" || entries[1].key != entries[0].key || entries[1].authDigest != sha256.Sum256([]byte("Bearer "+rotated.Token)) {
		t.Fatal("actual daemon replay changed request or credential authority")
	}
	assertSingleAuthority()
	if entries[1].batchID != batchID {
		t.Fatal("replayed acceptance receipt named different database authority")
	}
	if after := daemonReplaySourceSnapshot(t, filepath.Join(config.SpoolPath, "generation-"+config.Source.GenerationID)); after != sourceBefore {
		t.Fatal("consumer or credential rotation mutated producer source")
	}
	archive, err := runtimeevent.DecodeArchivedBatch(scope, artifacts.body())
	if err != nil || len(archive.Records) != 1 || archive.Records[0].ObservedLineage.ClusterUID != config.Source.ClusterUID || archive.Records[0].ObservedLineage.NodeUID != config.Source.NodeUID || archive.Records[0].ObservedLineage.BootID != config.Source.BootID {
		t.Fatal("actual upload lost observed lineage", err)
	}
	wantCgroup := ""
	if profile == "tetragon-local-stream-v2" {
		wantCgroup = "18446744073709551615"
	}
	if archive.Records[0].ObservedLineage.CgroupID != wantCgroup {
		t.Fatal("actual daemon archive lost file-event cgroup identity")
	}
	t.Log("actual non-root daemon: committed lost response, unchanged checkpoint, real token rotation, exact replay, single SQL/artifact authority and verified ACK passed")
}
