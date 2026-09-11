package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type installedChunkHTTPEntry struct {
	body       []byte
	key        string
	authDigest [32]byte
	status     int
}

func TestInstalledSensorArtifactsKeepsIndependentObjectIdentities(t *testing.T) {
	store := &installedSensorArtifacts{}
	scope := fixtureRequestIdentity(t).Scope
	first := runtimeevent.RawArtifactPut{Scope: scope, Key: "first", Body: []byte("first body"), MediaType: "application/json"}
	second := first
	second.Key, second.Body = "second", []byte("second body")
	if _, err := store.Put(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), second); err != nil {
		t.Fatalf("independent object rejected: %v", err)
	}
	changed := first
	changed.Body = []byte("different body at same key")
	if _, err := store.Put(context.Background(), changed); err != runtimeevent.ErrProductionIngestArtifactDrift {
		t.Fatal("same-key drift accepted")
	}
	if _, err := store.Put(context.Background(), first); err != nil {
		t.Fatal("original object identity lost", err)
	}
}

type installedChunkHTTPTrace struct {
	mu      sync.Mutex
	handler http.Handler
	entries []installedChunkHTTPEntry
}

func (trace *installedChunkHTTPTrace) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	var body bytes.Buffer
	request.Body = struct {
		io.Reader
		io.Closer
	}{io.TeeReader(request.Body, &body), request.Body}
	response := httptest.NewRecorder()
	trace.handler.ServeHTTP(response, request)
	trace.entries = append(trace.entries, installedChunkHTTPEntry{body: bytes.Clone(body.Bytes()), key: request.Header.Get("Idempotency-Key"), authDigest: sha256.Sum256([]byte(request.Header.Get("Authorization"))), status: response.Code})
	for key, values := range response.Header() {
		writer.Header()[key] = values
	}
	writer.WriteHeader(response.Code)
	_, _ = writer.Write(response.Body.Bytes())
}

func (trace *installedChunkHTTPTrace) snapshot() []installedChunkHTTPEntry {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]installedChunkHTTPEntry(nil), trace.entries...)
}

// This closed test-only wire is consumed by TestInstalledLineageConsumerProcess
// in the separately compiled sensor-agent test binary. No credential is in it.
type installedChunkChildConfig struct {
	Action     string                      `json:"action"`
	Endpoint   string                      `json:"endpoint"`
	CAPath     string                      `json:"ca_path"`
	TokenPath  string                      `json:"token_path"`
	SpoolPath  string                      `json:"spool_path"`
	CursorPath string                      `json:"cursor_path"`
	AckPath    string                      `json:"ack_path"`
	ResultPath string                      `json:"result_path"`
	Stamp      string                      `json:"stamp"`
	Source     sensoradapter.LineageSource `json:"source"`
}

type installedChunkChildResult struct {
	Outcome    string                      `json:"outcome"`
	Result     sensoradapter.StreamResult  `json:"result"`
	Progress   sensoradapter.ChunkProgress `json:"progress"`
	Durable    bool                        `json:"durable"`
	TokenReads int                         `json:"token_reads"`
	Requests   int                         `json:"requests"`
}

func exerciseInstalledChunkSensorRecovery(t *testing.T, ctx context.Context, admin *pgx.Conn, scope domain.Scope, created sensorEnrollment, version string, mutate func(string, string) (sensorEnrollment, string), server *httptest.Server, trace *installedChunkHTTPTrace, artifacts *installedSensorArtifacts) {
	t.Helper()
	directory := t.TempDir()
	binary := filepath.Join(directory, "sensor-agent.test")
	buildCtx, cancelBuild := context.WithTimeout(ctx, 30*time.Second)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "test", "-race", "-c", "-o", binary, ".")
	build.Dir = filepath.Join("..", "..", "sensor-agent")
	build.WaitDelay = time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual sensor-agent test process: %v\n%s", err, output)
	}
	config := installedChunkChildConfig{Endpoint: server.URL, CAPath: filepath.Join(directory, "ca.pem"), TokenPath: filepath.Join(directory, "token"), SpoolPath: filepath.Join(directory, "spool"), CursorPath: filepath.Join(directory, "consumer-state", "cursor-0.json"), ResultPath: filepath.Join(directory, "result.json"), Stamp: time.Now().UTC().Add(-time.Second).Truncate(time.Millisecond).Format(time.RFC3339Nano),
		Source: sensoradapter.LineageSource{Profile: "tetragon-local-stream-v1", GenerationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", EnrollmentBinding: created.EnrollmentBinding, NodeName: "node-a", ClusterUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", NodeUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", BootID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}}
	if err := os.Mkdir(config.SpoolPath, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Dir(config.CursorPath), 0700); err != nil {
		t.Fatal(err)
	}
	config.AckPath = filepath.Join(directory, "acks")
	if err := os.Mkdir(config.AckPath, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.CAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	writeToken := func(token string) {
		t.Helper()
		if err := os.WriteFile(config.TokenPath+".new", []byte(token), 0600); err != nil {
			t.Fatal("write fixture credential")
		}
		if err := os.Rename(config.TokenPath+".new", config.TokenPath); err != nil {
			t.Fatal("rotate fixture credential")
		}
	}
	writeToken(created.Token)
	configPath := filepath.Join(directory, "config.json")
	invoke := func(action string) installedChunkChildResult {
		t.Helper()
		config.Action = action
		raw, err := json.Marshal(config)
		if err != nil || os.WriteFile(configPath, raw, 0600) != nil {
			t.Fatal("write child config")
		}
		if err := os.Remove(config.ResultPath); err != nil && !os.IsNotExist(err) {
			t.Fatal("remove owned prior result")
		}
		callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		command := exec.CommandContext(callCtx, binary, "-test.run=^TestInstalledLineageConsumerProcess$", "-test.count=1")
		command.Env = []string{"ZASP_LINEAGE_CONSUMER_FIXTURE=" + configPath, "PATH=" + os.Getenv("PATH"), "TMPDIR=" + os.TempDir()}
		command.WaitDelay = time.Second
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("sensor child failed (no credential output): %v\n%s", err, output)
		}
		raw, err = os.ReadFile(config.ResultPath)
		var result installedChunkChildResult
		if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &result) != nil {
			t.Fatal("missing child outcome")
		}
		return result
	}
	if err := os.Rename(config.TokenPath, config.TokenPath+".held"); err != nil {
		t.Fatal(err)
	}
	if result := invoke("reserve-incomplete"); result.Outcome != "reservation-left" || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("private reservation fixture failed", result)
	}
	privatePath := filepath.Join(config.SpoolPath, ".creating-"+config.Source.GenerationID)
	if _, err := os.Lstat(filepath.Join(privatePath, "manifest.json")); err != nil {
		t.Fatal("private manifest missing", err)
	}
	if _, err := os.Lstat(filepath.Join(config.SpoolPath, "generation-"+config.Source.GenerationID)); !os.IsNotExist(err) {
		t.Fatal("incomplete reservation was public", err)
	}
	for retry := 0; retry < 2; retry++ {
		if result := invoke("discard-unpublished"); result.Outcome != "reservation-discarded" || result.TokenReads != 0 || result.Requests != 0 {
			t.Fatal("credentialless reservation cleanup failed", result)
		}
	}
	if _, err := os.Lstat(privatePath); !os.IsNotExist(err) {
		t.Fatal("reservation still occupies capacity", err)
	}
	if err := os.Rename(config.TokenPath+".held", config.TokenPath); err != nil {
		t.Fatal(err)
	}
	if result := invoke("initialize-interrupted"); result.Outcome != "initialized" || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("fresh source initialization failed", result)
	}
	generationPath := filepath.Join(config.SpoolPath, "generation-"+config.Source.GenerationID)
	if err := os.Rename(config.TokenPath, config.TokenPath+".held"); err != nil {
		t.Fatal(err)
	}
	for retry := 0; retry < 2; retry++ {
		if result := invoke("recover-interrupted"); result.Outcome != "source-recovered" || result.TokenReads != 0 || result.Requests != 0 {
			t.Fatal("credentialless source recovery failed", result)
		}
	}
	if err := os.Rename(config.TokenPath+".held", config.TokenPath); err != nil {
		t.Fatal(err)
	}
	fragment, err := os.ReadFile(filepath.Join(generationPath, "interrupted.bin"))
	if err != nil || string(fragment) != `{"version":"tetragon-` {
		t.Fatal("recovery lost partial source evidence", err)
	}
	sealRaw, err := os.ReadFile(filepath.Join(generationPath, "closed.json"))
	var recoveredSeal struct {
		CountersUnknown   bool   `json:"counters_unknown"`
		CoverageComplete  bool   `json:"coverage_complete"`
		InterruptedDigest string `json:"interrupted_sha256"`
	}
	if err != nil || json.Unmarshal(sealRaw, &recoveredSeal) != nil || !recoveredSeal.CountersUnknown || recoveredSeal.CoverageComplete || recoveredSeal.InterruptedDigest != fmt.Sprintf("%x", sha256.Sum256(fragment)) {
		t.Fatal("recovery claimed complete coverage", err)
	}
	sourceSnapshot := func() string {
		t.Helper()
		entries, err := os.ReadDir(generationPath)
		if err != nil {
			t.Fatal(err)
		}
		var result strings.Builder
		for _, entry := range entries {
			path := filepath.Join(generationPath, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("invalid fixture source file")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&result, "%s:%o:%x\n", entry.Name(), info.Mode(), sha256.Sum256(raw))
		}
		return result.String()
	}
	originalSource := sourceSnapshot()
	if result := invoke("initialize"); result.Outcome != "rejected" || sourceSnapshot() != originalSource {
		t.Fatal("initialization adopted old source")
	}
	if result := invoke("process-lost-response"); result.Outcome != "retryable" || result.Durable || result.TokenReads != 1 || result.Requests != 1 {
		t.Fatal("actual accepted response loss not retained", result)
	}
	if result := invoke("acknowledge"); result.Outcome != "rejected" || result.Durable || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("pending source acknowledged", result)
	}
	if entries, err := os.ReadDir(config.AckPath); err != nil || len(entries) != 0 {
		t.Fatal("pending proof wrote acknowledgment state", err)
	}
	entries := trace.snapshot()
	if len(entries) != 1 || entries[0].status != http.StatusAccepted || artifacts.count() != 1 {
		t.Fatal("response loss wasn't after durable acceptance")
	}
	var batchID, provenance string
	if err := admin.QueryRow(ctx, `SELECT batch_id,to_jsonb(b)::text FROM zasp_runtime_batch_authorities b WHERE sensor_id=$1`, created.ID).Scan(&batchID, &provenance); err != nil {
		t.Fatal(err)
	}
	firstArchive, err := runtimeevent.DecodeArchivedBatch(scope, artifacts.body())
	if err != nil || len(firstArchive.Records) != 1 {
		t.Fatal("first archive invalid", err)
	}
	stamp, err := time.Parse(time.RFC3339Nano, config.Stamp)
	if err != nil {
		t.Fatal(err)
	}
	want := runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: config.Source.ClusterUID, NodeUID: config.Source.NodeUID, BootID: config.Source.BootID, PodUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: stamp.Format(time.RFC3339Nano)}
	if firstArchive.Records[0].ObservedLineage != want {
		t.Fatal("sanitizer/spool/ingest lost original observation")
	}
	rotated, _ := mutate(created.ID, version)
	if rotated.EnrollmentBinding != created.EnrollmentBinding || rotated.Token == created.Token {
		t.Fatal("actual rotation drifted enrollment or retained token")
	}
	writeToken(rotated.Token)
	beforeCursor, err := os.ReadFile(config.CursorPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(generationPath, "manifest.json")
	backup := filepath.Join(directory, "manifest.backup")
	if err := os.Rename(manifest, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{}"), 0440); err != nil {
		t.Fatal(err)
	}
	if result := invoke("process"); result.Outcome != "rejected" || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("corrupt admission read credential or uploaded", result)
	}
	afterCursor, err := os.ReadFile(config.CursorPath)
	if err != nil || !bytes.Equal(beforeCursor, afterCursor) || len(trace.snapshot()) != 1 {
		t.Fatal("corruption changed checkpoint or reached ingest")
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, manifest); err != nil {
		t.Fatal(err)
	}
	if result := invoke("process"); result.Outcome != "ok" || result.Result.Submitted != 1 || !result.Durable || result.Progress.NextSequence != 2 || result.TokenReads != 1 || result.Requests != 1 {
		t.Fatal("restart replay failed", result)
	}
	entries = trace.snapshot()
	if len(entries) != 2 || entries[1].status != http.StatusAccepted || !bytes.Equal(entries[0].body, entries[1].body) || entries[0].key == "" || entries[0].key != entries[1].key || entries[0].authDigest == entries[1].authDigest || artifacts.count() != 1 {
		t.Fatal("rotation replay changed exact body/key, credential, or write count")
	}
	var unchanged bool
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(b)::text=$2 AND (SELECT count(*) FROM zasp_runtime_batch_authorities WHERE sensor_id=$3)=1 AND (SELECT count(*) FROM zasp_runtime_stage_work WHERE batch_id=$1)=5 AND (SELECT count(*) FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1)=1 FROM zasp_runtime_batch_authorities b WHERE batch_id=$1`, batchID, provenance, created.ID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("replay changed durable scope/provenance or duplicated work", err)
	}
	if result := invoke("reconcile-consumer"); result.Outcome != "ok" || result.Result.Submitted != 1 || result.Progress.NextSequence != 3 {
		t.Fatal("partial identity did not survive second restart", result)
	}
	secondArchive, err := runtimeevent.DecodeArchivedBatch(scope, artifacts.body())
	if err != nil || len(secondArchive.Records) != 1 || secondArchive.Records[0].ObservedLineage != want || secondArchive.Records[0].Action != "write" {
		t.Fatal("partial probe lost exact cached lineage", err)
	}
	for _, record := range append(firstArchive.Records, secondArchive.Records...) {
		if record.Scope != scope || record.AgentID != (domain.ProductID{}) || record.SessionID != (domain.ProductID{}) || record.ContainerID != "" || record.CgroupID != "" || record.ProcessID != "" {
			t.Fatal("observation granted semantic or cross-scope authority")
		}
	}
	if result := invoke("process"); result.Outcome != "ok" || result.Result.Dropped != 1 || result.Result.Submitted != 0 || result.Progress.NextSequence != 4 || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("changed-start partial probe reused PID-only identity", result)
	}
	if result := invoke("process"); result.Outcome != "ok" || !result.Result.Idle || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("drained source replayed again", result)
	}
	for retry := 0; retry < 2; retry++ {
		if result := invoke("acknowledge"); result.Outcome != "acknowledged" || !result.Durable || result.Progress.NextSequence != 4 || result.Progress.Read != 3 || result.Progress.Submitted != 2 || result.Progress.Dropped != 1 || result.TokenReads != 0 || result.Requests != 0 {
			t.Fatal("sealed actual consumption not acknowledged without credentials", result)
		}
	}
	ackPath := filepath.Join(config.AckPath, "ack-"+config.Source.GenerationID+".json")
	ackBytes, err := os.ReadFile(ackPath)
	var ack struct {
		Version     string                            `json:"version"`
		Consumption sensoradapter.VerifiedConsumption `json:"consumption"`
		Manifest    string                            `json:"manifest_sha256"`
		Seal        struct {
			Reason            string `json:"reason"`
			Chunks            int    `json:"chunks"`
			Records           int    `json:"records"`
			Bytes             int64  `json:"bytes"`
			Dropped           uint64 `json:"dropped"`
			Filtered          uint64 `json:"filtered"`
			CoverageComplete  bool   `json:"coverage_complete"`
			CountersUnknown   bool   `json:"counters_unknown"`
			InterruptedBytes  int64  `json:"interrupted_bytes"`
			InterruptedDigest string `json:"interrupted_sha256"`
		} `json:"seal"`
		SealDigest string `json:"seal_sha256"`
	}
	if err != nil || json.Unmarshal(ackBytes, &ack) != nil || ack.Version != "tetragon-consumption-ack-v1" || ack.Consumption.Source != config.Source || ack.Consumption.Destination != server.URL+"/internal/v1/runtime/events" || ack.Consumption.Inode == 0 || ack.Seal.Reason != "producer_restart" || !ack.Seal.CountersUnknown || ack.Seal.InterruptedBytes != int64(len(fragment)) || ack.Seal.InterruptedDigest != recoveredSeal.InterruptedDigest || ack.Seal.Chunks != 3 || ack.Seal.Records != 3 || ack.Seal.Bytes != ack.Consumption.Progress.Bytes || ack.Seal.Dropped != 0 || ack.Seal.Filtered != 0 || ack.Seal.CoverageComplete {
		t.Fatal("acknowledgment lost closure, destination or generation binding", err)
	}
	generationInfo, err := os.Lstat(generationPath)
	if err != nil {
		t.Fatal(err)
	}
	generationStat, ok := generationInfo.Sys().(*syscall.Stat_t)
	if !ok || ack.Consumption.Device != uint64(generationStat.Dev) || ack.Consumption.Inode != generationStat.Ino {
		t.Fatal("acknowledgment physical generation binding drifted")
	}
	// Producer admission must work with the credential physically unavailable.
	// No consumer checkpoint access or service receipt is inferred from this.
	if err := os.Rename(config.TokenPath, config.TokenPath+".held"); err != nil {
		t.Fatal(err)
	}
	if result := invoke("verify-acknowledgment"); result.Outcome != "receipt-verified" || result.Durable || result.Progress != ack.Consumption.Progress || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("producer didn't independently admit exact receipt without credentials", result)
	}
	if err := os.Rename(config.TokenPath+".held", config.TokenPath); err != nil {
		t.Fatal(err)
	}
	unchangedAck, err := os.ReadFile(ackPath)
	if err != nil || !bytes.Equal(ackBytes, unchangedAck) {
		t.Fatal("producer changed consumer receipt", err)
	}
	sealBytes, err := os.ReadFile(filepath.Join(generationPath, "closed.json"))
	manifestBytes, manifestErr := os.ReadFile(filepath.Join(generationPath, "manifest.json"))
	if err != nil || manifestErr != nil || ack.SealDigest != fmt.Sprintf("%x", sha256.Sum256(sealBytes)) || ack.Manifest != fmt.Sprintf("%x", sha256.Sum256(manifestBytes)) {
		t.Fatal("acknowledgment hash didn't bind exact source closure")
	}
	if len(trace.snapshot()) != 3 || artifacts.count() != 2 || sourceSnapshot() != originalSource {
		t.Fatal("consumer changed immutable history or duplicated uploads")
	}
	for _, entry := range trace.snapshot() {
		if bytes.Contains(entry.body, []byte("secret-")) || bytes.Contains(entry.body, []byte("/etc/shadow")) {
			t.Fatal("raw provider data leaked into transport")
		}
	}
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(b)::text=$2 AND (SELECT count(*) FROM zasp_runtime_batch_authorities WHERE sensor_id=$3)=2 AND (SELECT count(*) FROM zasp_runtime_stage_work w JOIN zasp_runtime_batch_authorities a ON (a.organization_id,a.workspace_id,a.environment_id,a.batch_id)=(w.organization_id,w.workspace_id,w.environment_id,w.batch_id) WHERE a.sensor_id=$3)=10 AND (SELECT count(*) FROM zasp_discovery_outbox o JOIN zasp_runtime_batch_authorities a ON (o.organization_id,o.workspace_id,o.environment_id,o.deterministic_key)=(a.organization_id,a.workspace_id,a.environment_id,'runtime:'||a.batch_id) WHERE a.sensor_id=$3)=2 FROM zasp_runtime_batch_authorities b WHERE batch_id=$1`, batchID, provenance, created.ID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("source continuation changed original authority or stage count", err)
	}
	for _, path := range []string{config.TokenPath, config.CursorPath} {
		if err := os.Rename(path, path+".held"); err != nil {
			t.Fatal(err)
		}
	}
	if result := invoke("reconcile-producer"); result.Outcome != "producer-reconciled" || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("accepted source wasn't reclaimed without consumer state", result)
	}
	for _, path := range []string{generationPath, filepath.Join(config.SpoolPath, ".reclaim-"+config.Source.GenerationID)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("reclaimed source directory remains", err)
		}
	}
	completionPath := filepath.Join(config.SpoolPath, "reclaim-"+config.Source.GenerationID+".json")
	completion, err := os.ReadFile(completionPath)
	if err != nil || !bytes.Contains(completion, []byte(`"complete":true`)) {
		t.Fatal("producer completion record missing", err)
	}
	if err := os.Rename(config.AckPath, config.AckPath+".held"); err != nil {
		t.Fatal(err)
	}
	if result := invoke("reclaim-acknowledged"); result.Outcome != "source-reclaimed" || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("completion retry required consumer state", result)
	}
	if err := os.Rename(config.AckPath+".held", config.AckPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config.TokenPath, config.CursorPath} {
		if err := os.Rename(path+".held", path); err != nil {
			t.Fatal(err)
		}
	}
	finalAck, err := os.ReadFile(ackPath)
	if err != nil || !bytes.Equal(ackBytes, finalAck) || len(trace.snapshot()) != 3 || artifacts.count() != 2 {
		t.Fatal("reclamation changed receipt or sent another request", err)
	}
	if err := os.Rename(config.TokenPath, config.TokenPath+".held"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct{ action, outcome string }{{"retire-slot", "slot-retired"}, {"reconcile-producer", "producer-reconciled"}, {"release-slot", "slot-released"}} {
		for retry := 0; retry < 2; retry++ {
			expected := step.outcome
			if step.action == "release-slot" && retry == 1 {
				expected = "slot-idle"
			}
			result := invoke(step.action)
			if result.Outcome != expected || result.TokenReads != 0 || result.Requests != 0 {
				t.Fatal("retirement handshake failed", step.action, result)
			}
			if step.action != "reconcile-producer" && (!result.Result.CoverageUnknown || result.Result.ProducerDroppedTotal != 0) {
				t.Fatal("consumer retirement lost interrupted coverage history", result.Result)
			}
		}
		if step.action == "retire-slot" {
			if _, err := os.Lstat(config.CursorPath); !os.IsNotExist(err) {
				t.Fatal("bound checkpoint retirement left cursor", err)
			}
			raw, err := os.ReadFile(ackPath)
			var receipt struct {
				Version string `json:"version"`
				Digest  string `json:"completion_sha256"`
			}
			sum := sha256.Sum256(completion)
			if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Version != "tetragon-retirement-ack-v1" || receipt.Digest != fmt.Sprintf("%x", sum) {
				t.Fatal("retirement receipt binding", err)
			}
		}
	}
	if err := os.Rename(config.TokenPath+".held", config.TokenPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{completionPath, ackPath, config.CursorPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("handshake state remains", path, err)
		}
	}
	stateEntries, err := os.ReadDir(filepath.Dir(config.CursorPath))
	if err != nil || len(stateEntries) != 3 || stateEntries[0].Name() != ".slots.lock" || stateEntries[1].Name() != "coverage.json" || stateEntries[2].Name() != "cursor-0.json.lock" {
		t.Fatal("authenticated slot release didn't retain fixed locks and coverage", len(stateEntries), err)
	}
	coverage, err := os.ReadFile(filepath.Join(filepath.Dir(config.CursorPath), "coverage.json"))
	var history struct {
		Version           string            `json:"version"`
		EnrollmentBinding string            `json:"enrollment_binding"`
		Destination       string            `json:"destination"`
		Unknown           bool              `json:"counters_unknown"`
		Dropped           uint64            `json:"producer_dropped"`
		Slots             []json.RawMessage `json:"slots"`
	}
	if err != nil || len(coverage) > 64<<10 || json.Unmarshal(coverage, &history) != nil || history.Version != "tetragon-consumer-coverage-v1" || history.EnrollmentBinding != config.Source.EnrollmentBinding || history.Destination != config.Endpoint+"/internal/v1/runtime/events" || !history.Unknown || history.Dropped != 0 || len(history.Slots) != 8 {
		t.Fatal("released slot lost bounded enrollment-bound coverage", err)
	}
	// The fixed deduplication watermark outlives its released assignment. It
	// prevents an idle restart from counting this interrupted generation again.
	var watermark struct {
		Assignment struct {
			Slot        int                         `json:"slot"`
			Source      sensoradapter.LineageSource `json:"source"`
			Destination string                      `json:"destination"`
		} `json:"assignment"`
		Seal json.RawMessage `json:"seal"`
	}
	if json.Unmarshal(history.Slots[0], &watermark) != nil || watermark.Assignment.Slot != 0 || watermark.Assignment.Source != config.Source || watermark.Assignment.Destination != history.Destination || !bytes.Equal(bytes.TrimSpace(watermark.Seal), bytes.TrimSpace(sealRaw)) {
		t.Fatal("released coverage lost the exact generation watermark")
	}
	for _, slot := range history.Slots[1:] {
		if string(slot) != "null" {
			t.Fatal("coverage occupied an unrelated slot")
		}
	}
	if result := invoke("release-slot"); result.Outcome != "slot-idle" || !result.Result.CoverageUnknown || result.TokenReads != 0 || result.Requests != 0 {
		t.Fatal("idle restart lost coverage or required credentials", result)
	}
	if after, err := os.ReadFile(filepath.Join(filepath.Dir(config.CursorPath), "coverage.json")); err != nil || !bytes.Equal(coverage, after) {
		t.Fatal("idle restart changed durable coverage", err)
	}
	for _, path := range []string{config.AckPath, config.SpoolPath} {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 1 {
			t.Fatal("metadata slots not released", path, err)
		}
	}
	if len(trace.snapshot()) != 3 || artifacts.count() != 2 {
		t.Fatal("retirement issued another request")
	}
}
