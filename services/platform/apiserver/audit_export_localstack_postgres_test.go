//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A configured destination must be the first and only policy before admission.
func TestAuditExportLocalStackPolicyBeforeAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	policy := auditExportTestPolicy()
	policy.PolicyID = "pid_52000071-0000-4000-8000-000000000071"
	policy.Bucket = "zasp-owned-localstack-policy"
	policy.ExpectedBucketOwner = "000000000000"
	policy.KMSKeyARN = "arn:aws:kms:us-east-1:000000000000:key/52000072-0000-4000-8000-000000000072"
	f := auditExportPGFixtureWithPolicy(t, ctx, policy)
	f.register(t, ctx)
	args := f.createArgs()
	var body json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	digest, err := migrations.AuditExportPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT policy_id=$3 AND storage_policy->>'policy_digest'=$4 AND (SELECT count(*) FROM zasp_audit_export_policies)=1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7], policy.PolicyID, digest).Scan(&exact); err != nil || !exact {
		t.Fatal("admission did not bind sole configured policy", err)
	}
}

type auditLocalstackHTTPResult struct {
	Method, Key, Query string
	Status             int
}
type auditLocalstackHTTPRecorder struct {
	http.ResponseWriter
	status int
}

func (w *auditLocalstackHTTPRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *auditLocalstackHTTPRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *auditLocalstackHTTPRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(body)
}

type auditLocalstackTraffic struct {
	mu       sync.Mutex
	requests []auditLocalstackHTTPResult
	active   int
	idle     chan struct{}
}

// A hook returning does not prove the outer handler has released its borrowed
// state. Missing this wait can start B or freeze traffic while A still unwinds.
func TestAuditExportLocalStackTrafficDrain(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	traffic := &auditLocalstackTraffic{}
	server := httptest.NewServer(traffic.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(204) })))
	defer server.Close()
	var once sync.Once
	defer once.Do(func() { close(release) })
	go func() {
		defer close(done)
		response, err := server.Client().Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := traffic.drain(ctx)
	cancel()
	if err == nil {
		t.Error("outer forwarding handler admitted an early drain")
	}
	once.Do(func() { close(release) })
	<-done
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := traffic.drain(ctx); err != nil || len(traffic.snapshot()) != 1 {
		t.Fatal("completed forwarding handler failed to drain", err)
	}
}

func (s *auditLocalstackTraffic) drain(ctx context.Context) error {
	s.mu.Lock()
	active, idle := s.active, s.idle
	s.mu.Unlock()
	if active == 0 {
		return nil
	}
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *auditLocalstackTraffic) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if s.active == 0 {
			s.idle = make(chan struct{})
		}
		s.active++
		s.mu.Unlock()
		record := &auditLocalstackHTTPRecorder{ResponseWriter: w}
		defer func() {
			s.mu.Lock()
			s.requests = append(s.requests, auditLocalstackHTTPResult{r.Method, strings.TrimPrefix(r.URL.Path, "/"), r.URL.RawQuery, record.status})
			s.active--
			if s.active == 0 {
				close(s.idle)
			}
			s.mu.Unlock()
		}()
		next.ServeHTTP(record, r)
	})
}
func (s *auditLocalstackTraffic) snapshot() []auditLocalstackHTTPResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]auditLocalstackHTTPResult(nil), s.requests...)
}

// Missing the saved-response barrier, accepting another physical version, or
// ACKing before registered Terminal ready must each fail this real joined lane.
func TestAuditExportWorkerPostgresLocalStackCompletionRestart(t *testing.T) {
	flag := os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_REQUIRED")
	if flag == "" || flag == "false" {
		t.Skip("set ZASP_AUDIT_EXPORT_LOCALSTACK_REQUIRED=true for owned provider acceptance")
	}
	if flag != "true" {
		t.Fatal("invalid required LocalStack flag")
	}
	for _, release := range []struct {
		name    string
		version int64
	}{{"schema52", 52}, {"schema53", 53}} {
		t.Run(release.name, func(t *testing.T) {
			exerciseAuditExportLocalStackRestart(t, release.version)
		})
	}
}

func exerciseAuditExportLocalStackRestart(t *testing.T, version int64) {
	t.Helper()
	ctx, owner := newAuditLocalstackOwner(t)
	policy := owner.setup(t, ctx)
	policyBody, err := auditLocalstackPolicyBytes(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(owner.root, "policy.json")
	if err := os.WriteFile(policyPath, policyBody, 0600); err != nil {
		t.Fatal(err)
	}
	policyHash := sha256.Sum256(policyBody)
	f := auditExportPGFixtureWithPolicy(t, ctx, policy)
	if version == 53 {
		if err := precisionMigrationRunner(t, f.admin).UpProductionSecurityAgentBudgets(ctx); err != nil {
			t.Fatal("upgrade durable restart fixture to current schema53", err)
		}
	}
	var actual int64
	if err := f.admin.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&actual); err != nil || actual != version {
		t.Fatalf("durable restart fixture schema=%d want=%d: %v", actual, version, err)
	}
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	args := f.createArgs()
	var admitted json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&admitted); err != nil {
		t.Fatal("registered Create", err)
	}
	events, _ := auditExportPrepareWorkerSource(t, ctx, f, args)
	observer, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	auditHTTPFixtureOwnConnection(ctx, "LocalStack intent observer", observer)
	binding := audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string)}
	baseIntent := newAuditLocalstackIntent(observer, policy, binding, events)
	intent := func(ctx context.Context, key string) (auditLocalstackExpected, error) {
		object, err := baseIntent(ctx, key)
		if err != nil {
			return object, err
		}
		var wire struct {
			Schema  string              `json:"schema"`
			Binding audit.ExportBinding `json:"binding"`
			Ordinal int64               `json:"ordinal"`
		}
		if json.Unmarshal(object.Body, &wire) != nil {
			return object, errors.New("invalid reconstructed object")
		}
		kind := "chunk"
		if wire.Schema == "audit-export-manifest-v1" {
			kind = "manifest"
		}
		id := auditLocalstackArtifactID(wire.Binding, kind, wire.Ordinal)
		if object.Metadata["artifact_id"] != id || !strings.HasSuffix(object.Key, "/exports/"+id) {
			return object, errors.New("intent path differs from independent identity")
		}
		return object, nil
	}
	type savedProof struct {
		object auditLocalstackExpected
		at     time.Time
	}
	reached := make(chan savedProof, 1)
	released := make(chan struct{})
	hookDone := make(chan struct{})
	var first atomic.Bool
	var forwarder *auditLocalstackForwarder
	forwarder, err = newAuditLocalstackForwarder(ctx, owner.ready.Endpoint, policy, intent, 30*time.Second, func(call context.Context, result auditLocalstackPutResult) error {
		if !first.CompareAndSwap(false, true) {
			return nil
		}
		defer close(hookDone)
		expected, err := intent(call, result.Key)
		if err != nil {
			return err
		}
		expected.Version = result.Version
		if result.Status != 200 {
			return errors.New("first actual Put was not successful")
		}
		if err := forwarder.pinned(call, expected); err != nil {
			return err
		}
		if err := owner.sameContainer(call); err != nil {
			return err
		}
		reached <- savedProof{expected, time.Now()}
		select {
		case <-released:
			return errors.New("withheld result discarded after worker death")
		case <-call.Done():
			return call.Err()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	owner.forwarder = forwarder
	traffic := &auditLocalstackTraffic{}
	provider := newAuditExportProcessProviderWithPolicy(t, ctx, f, worker, args, events, policy, traffic.wrap(forwarder))
	ca, token := filepath.Join(owner.root, "ca.pem"), filepath.Join(owner.root, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(auditExportProcessToken), 0600); err != nil {
		t.Fatal(err)
	}
	owner.binary = filepath.Join(owner.root, "worker.test")
	compile, stop := context.WithTimeout(ctx, 90*time.Second)
	output, err := runSandboxWorkerCommand(compile, exec.Command("go", "test", "-race", "-c", "-o", owner.binary, "../agentsec-worker"))
	stop()
	if err != nil {
		owner.retained = true
		t.Fatalf("owned child compilation: %v\n%s", err, output)
	}
	if err := forwarder.inventory(ctx, map[string]auditLocalstackExpected{}); err != nil {
		t.Fatal("actual bucket not empty", err)
	}
	provider.mu.Lock()
	empty := len(provider.messages) == 0 && provider.sends == 0
	provider.mu.Unlock()
	if !empty {
		t.Fatal("queue not empty")
	}
	publisher := owner.launch(t, ctx, f, provider, "audit-export-outbox", ca, token, "", nil)
	publisherResult := auditLocalstackRequireSuccess(t, ctx, publisher, "audit-export-outbox")
	provider.mu.Lock()
	published := provider.sends == 1 && len(provider.messages) == 1
	messageID := ""
	var messageBody []byte
	if published {
		messageID = provider.messages[0].ID
		messageBody = bytes.Clone(provider.messages[0].Body)
	}
	provider.mu.Unlock()
	if !published {
		t.Fatal("publisher did not Send sole canonical message", provider.problem())
	}
	auditExportAssertProcessPublication(t, ctx, f, args, messageID, 1)
	var queued struct {
		Payload struct {
			PolicyID string `json:"policy_id"`
		} `json:"payload"`
	}
	if json.Unmarshal(messageBody, &queued) != nil || queued.Payload.PolicyID != policy.PolicyID {
		t.Fatal("published policy differs")
	}
	force := make(chan struct{})
	workerA := owner.launch(t, ctx, f, provider, "audit-export", ca, token, policyPath, force)
	var saved savedProof
	select {
	case saved = <-reached:
	case <-workerA.done:
		t.Fatalf("saved-Put barrier not reached; worker exited: %v\n%s", workerA.result.err, workerA.result.output)
	case <-ctx.Done():
		t.Fatal("saved-Put barrier deadline", ctx.Err())
	}
	var barrier bool
	err = f.admin.QueryRow(ctx, `SELECT status='processing' AND attempt=1 AND generation=1 AND captured AND event_count=1006 AND chunk_count=2 AND completion_audit_id IS NULL AND (SELECT count(*) FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2)=1006 AND (SELECT count(*) FROM zasp_audit_export_chunks WHERE organization_id=$1 AND export_id=$2)=2 AND (SELECT count(*) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2)=1 AND (SELECT count(*) FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2)=0 AND (SELECT count(*) FROM zasp_audit_export_retries WHERE organization_id=$1 AND export_id=$2)=0 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&barrier)
	if err != nil || !barrier {
		t.Fatal("saved-Put persisted boundary differs", err)
	}
	auditLocalstackAssertCapturedSource(t, ctx, f, args, events)
	provider.mu.Lock()
	noACK := provider.deletes == 0 && provider.deleteAttempts == 0 && provider.receives == 1
	provider.mu.Unlock()
	if !noACK || ctx.Err() != nil {
		t.Fatal("ACK or timeout before forced death")
	}
	frozen := auditLocalstackCapturedSnapshot(t, ctx, f, args, saved.object.Key, policy.Bucket)
	select {
	case <-hookDone:
		t.Fatal("saved hook ended before force dispatch")
	default:
	}
	close(force)
	a, err := workerA.wait(ctx)
	if err != nil || a.err != testprocess.ErrForceKilled || !a.joined || !a.status.Signaled() || a.status.Signal() != syscall.SIGKILL || bytes.Contains(a.output, []byte("registered LocalStack process completed")) {
		t.Fatal("worker A lacked clean requested SIGKILL join", err, a.err)
	}
	close(released)
	select {
	case <-hookDone:
	case <-ctx.Done():
		t.Fatal("saved response handler not joined")
	}
	if err := traffic.drain(ctx); err != nil {
		t.Fatal("enclosing saved-Put forwarding handler not joined", err)
	}
	t.Logf("saved physical version=%s key=%s pinned_bytes=%d worker_A_pid=%d SIGKILL_status=%d barrier_to_join=%s provider_timeout=30s", saved.object.Version, saved.object.Key, len(saved.object.Body), a.pid, a.status, time.Since(saved.at))
	// This is fixture-only eligibility aging after confirmed death. It is not a
	// measurement of wall-clock lease or SQS visibility expiry.
	tag, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2 AND status='processing' AND generation=1 AND attempt=1`, args[0], args[7])
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("exact dead-worker lease aging", err)
	}
	provider.mu.Lock()
	exactDelivery := len(provider.messages) == 1 && provider.messages[0].ID == messageID && bytes.Equal(provider.messages[0].Body, messageBody) && provider.messages[0].Deliveries == 1 && !provider.messages[0].Deleted
	if exactDelivery {
		provider.messages[0].Visible = time.Now().Add(-time.Second)
	}
	provider.mu.Unlock()
	if !exactDelivery {
		t.Fatal("dead-worker queue identity changed")
	}
	tag, err = f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET target_id='source changed after immutable capture' WHERE organization_id=$1 AND id='pid_53000000-0000-4000-8000-000000000001'`, args[0])
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("source mutation fixture", err)
	}
	if auditLocalstackCapturedSnapshot(t, ctx, f, args, saved.object.Key, policy.Bucket) != frozen {
		t.Fatal("fixture aging changed captured authority")
	}
	workerB := owner.launch(t, ctx, f, provider, "audit-export", ca, token, policyPath, nil)
	b := auditLocalstackRequireSuccess(t, ctx, workerB, "audit-export")
	if err := traffic.drain(ctx); err != nil {
		t.Fatal("worker B forwarding handlers not joined", err)
	}
	if auditLocalstackCapturedSnapshot(t, ctx, f, args, saved.object.Key, policy.Bucket) != frozen {
		t.Fatal("restart replaced immutable capture or first intent")
	}
	inventory := auditLocalstackAssertCompletion(t, ctx, f, args, events, policy, forwarder, provider, 1)
	if inventory[saved.object.Key].Version != saved.object.Version {
		t.Fatal("restart allocated another first-chunk version")
	}
	requests := traffic.snapshot()
	conditional, discovery := 0, 0
	for _, request := range requests {
		if request.Method == "PUT" && request.Key == saved.object.Key && request.Status == 412 {
			conditional++
		}
		if request.Method == "HEAD" && request.Key == saved.object.Key && request.Query == "" && request.Status == 200 {
			discovery++
		}
	}
	if conditional != 1 || discovery != 1 {
		t.Fatal("genuine conditional412/discovery absent", conditional, discovery, requests)
	}
	before := auditExportProcessSQLSnapshot(t, ctx, f, args)
	provider.redeliver(t)
	workerC := owner.launch(t, ctx, f, provider, "audit-export", ca, token, policyPath, nil)
	c := auditLocalstackRequireSuccess(t, ctx, workerC, "audit-export")
	if err := traffic.drain(ctx); err != nil {
		t.Fatal("worker C forwarding handlers not joined", err)
	}
	afterInventory := auditLocalstackAssertCompletion(t, ctx, f, args, events, policy, forwarder, provider, 2)
	if auditExportProcessSQLSnapshot(t, ctx, f, args) != before || !reflect.DeepEqual(inventory, afterInventory) || !reflect.DeepEqual(traffic.snapshot(), requests) {
		t.Fatal("duplicate mutated SQL, physical versions, or S3 requests")
	}
	if err := owner.sameContainer(ctx); err != nil {
		t.Fatal(err)
	}
	identities := map[int]bool{}
	for _, pid := range []int{publisherResult.pid, a.pid, b.pid, c.pid} {
		if pid <= 0 || identities[pid] {
			t.Fatal("process identities reused")
		}
		identities[pid] = true
	}
	body, err := os.ReadFile(policyPath)
	if err != nil || sha256.Sum256(body) != policyHash {
		t.Fatal("private policy changed")
	}
	t.Logf("joined completion/restart source_events=%d publisher=%d A=%d B=%d C=%d container=%s policy_sha256=%x SQL_checksum=%s SQL_fingerprint=%s actual_objects=%d conditional412=1 duplicate_S3_requests=0", len(events), publisherResult.pid, a.pid, b.pid, c.pid, owner.ready.ContainerID, policyHash, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint(), len(inventory))
}

func (o *auditLocalstackOwner) launch(t *testing.T, ctx context.Context, f auditExportPG, p *auditExportProcessProvider, mode, ca, token, policy string, force <-chan struct{}) *auditLocalstackChild {
	t.Helper()
	if o.closing || ctx.Err() != nil {
		t.Fatal("worker launch after owner cutoff")
	}
	if err := o.sameContainer(ctx); err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(f.admin.Config().ConnString())
	if err != nil || target.Scheme != "postgres" {
		t.Fatal("private child DSN")
	}
	login := "audit_export_worker_fixture"
	if mode == "audit-export-outbox" {
		login = "audit_export_outbox_fixture"
		if policy != "" {
			t.Fatal("publisher policy input")
		}
	}
	target.User = url.User(login)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(o.binary, "-test.run=^TestAuditExportLocalStackProcessWorkerPostgres$", "-test.v", "-test.count=1")
	command.ExtraFiles = []*os.File{reader}
	command.Env = []string{"PATH=" + o.path, "ZASP_AUDIT_EXPORT_LOCALSTACK_DSN=" + target.String(), "ZASP_AUDIT_EXPORT_LOCALSTACK_MODE=" + mode, "ZASP_AUDIT_EXPORT_LOCALSTACK_ADDRESS=" + p.server.Listener.Addr().String(), "ZASP_AUDIT_EXPORT_LOCALSTACK_CA=" + ca, "ZASP_AUDIT_EXPORT_LOCALSTACK_TOKEN=" + token}
	if policy != "" {
		command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_LOCALSTACK_POLICY="+policy)
	}
	runCtx, cancel := context.WithTimeout(ctx, 110*time.Second)
	child := auditLocalstackStart(runCtx, command, force, reader, writer)
	innerCancel := child.cancel
	child.cancel = func() { cancel(); innerCancel() }
	o.children = append(o.children, child)
	return child
}
func auditLocalstackRequireSuccess(t *testing.T, ctx context.Context, child *auditLocalstackChild, mode string) auditLocalstackRun {
	t.Helper()
	result, err := child.wait(ctx)
	marker := "registered LocalStack process completed: mode=" + mode + " pid="
	index := strings.Index(string(result.output), marker)
	var pid int
	if err != nil || result.err != nil || !result.joined || index < 0 || bytes.Contains(result.output, []byte("--- SKIP:")) || !bytes.Contains(result.output, []byte("--- PASS: TestAuditExportLocalStackProcessWorkerPostgres")) {
		t.Fatalf("non-skipped child acceptance absent: %v %v\n%s", err, result.err, result.output)
	}
	if _, err := fmt.Sscanf(string(result.output)[index+len(marker):], "%d", &pid); err != nil || pid != result.pid || !result.status.Exited() || result.status.ExitStatus() != 0 {
		t.Fatal("child terminal identity differs")
	}
	t.Logf("joined child mode=%s pid=%d exit=0 output_sha256=%x\n%s", mode, pid, sha256.Sum256(result.output), result.output)
	return result
}

func auditLocalstackCapturedSnapshot(t *testing.T, ctx context.Context, f auditExportPG, args []any, key, bucket string) string {
	t.Helper()
	var snapshot string
	err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('capture',(SELECT jsonb_build_object('capture_id',capture_id,'captured_at',captured_at,'captured',captured,'event_count',event_count,'chunk_count',chunk_count,'chunk_bytes',chunk_bytes,'chain_root',encode(chain_root,'hex'),'manifest',encode(manifest_bytes,'hex'),'storage_policy',storage_policy,'policy_id',policy_id) FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY ordinal) FROM zasp_audit_export_events e WHERE organization_id=$1 AND export_id=$2),'chunks',(SELECT jsonb_agg(to_jsonb(c) ORDER BY ordinal) FROM zasp_audit_export_chunks c WHERE organization_id=$1 AND export_id=$2),'first_intent',(SELECT to_jsonb(i) FROM zasp_audit_export_intents i WHERE organization_id=$1 AND export_id=$2 AND object_reference=$3))::text`, args[0], args[7], "s3://"+bucket+"/"+key).Scan(&snapshot)
	if err != nil {
		t.Fatal("immutable capture snapshot", err)
	}
	return snapshot
}

func auditLocalstackAssertCompletion(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, policy migrations.AuditExportConfiguration, forwarder *auditLocalstackForwarder, p *auditExportProcessProvider, acks int) map[string]auditLocalstackExpected {
	t.Helper()
	binding := audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string)}
	if err := f.admin.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&binding.CaptureID); err != nil {
		t.Fatal(err)
	}
	expected, err := auditExportProcessExpected(binding, events)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := audit.DecodeExportManifest(expected["manifest:0"])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(expected["manifest:0"])
	var exact bool
	err = f.admin.QueryRow(ctx, `SELECT status='ready' AND captured AND attempt=2 AND generation=2 AND event_count=$3 AND chunk_count=$4 AND chunk_bytes=$5 AND manifest_bytes=$6 AND reserved_bytes=$5+octet_length($6::bytea) AND lease_worker IS NULL AND lease_token_digest IS NULL AND lease_expires_at IS NULL AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.id=j.completion_audit_id AND a.organization_id=j.organization_id AND a.workspace_id=j.workspace_id AND a.environment_id=j.environment_id AND a.actor_id=j.principal_id AND a.target_id=j.id AND a.action='audit_export.complete' AND a.outcome='succeeded' AND a.occurred_at=j.completed_at AND a.metadata=jsonb_build_object('event_count',$3::bigint,'chunk_count',$4::bigint,'chunk_bytes',$5::bigint,'manifest_sha256',$7::text)) AND (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='audit_export.complete')=1 AND (SELECT count(*) FROM zasp_audit_export_retries WHERE organization_id=$1)=0 FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7], len(events), manifest.ChunkCount, manifest.ChunkBytes, expected["manifest:0"], hex.EncodeToString(sum[:])).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("resumed ready authority/quota/completion differs", err)
	}
	policyDigest, err := migrations.AuditExportPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	err = f.admin.QueryRow(ctx, `SELECT encode(chain_root,'hex')=$3 AND policy_id=$4 AND storage_policy->>'policy_digest'=$5 AND (SELECT count(*) FROM zasp_audit_export_intents WHERE organization_id=$1 AND export_id=$2)=$6 AND (SELECT count(*) FROM zasp_audit_export_receipts WHERE organization_id=$1 AND export_id=$2)=$6 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7], manifest.ChainRoot, policy.PolicyID, policyDigest, len(expected)).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("ready chain/policy or complete receipt cardinality differs", err)
	}
	rows, err := f.admin.Query(ctx, `SELECT i.kind,i.ordinal,i.artifact_id,i.object_reference,i.sha256,i.size_bytes,r.version_id,r.sha256,r.size_bytes FROM zasp_audit_export_intents i JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=$1 AND i.export_id=$2 ORDER BY i.kind,i.ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	inventory := map[string]auditLocalstackExpected{}
	for rows.Next() {
		var kind, id, reference, version string
		var ordinal, size, receiptSize int64
		var digest, receiptDigest []byte
		if err := rows.Scan(&kind, &ordinal, &id, &reference, &digest, &size, &version, &receiptDigest, &receiptSize); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		body, ok := expected[fmt.Sprintf("%s:%d", kind, ordinal)]
		digestSum := sha256.Sum256(body)
		key := fmt.Sprintf("organizations/%s/workspaces/%s/environments/%s/exports/%s", binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, id)
		if !ok || id != auditLocalstackArtifactID(binding, kind, ordinal) || reference != "s3://"+policy.Bucket+"/"+key || size != int64(len(body)) || receiptSize != size || !bytes.Equal(digest, digestSum[:]) || !bytes.Equal(receiptDigest, digestSum[:]) || !auditLocalstackVersion(version) {
			rows.Close()
			t.Fatal("receipt/intent differs from original projected source")
		}
		inventory[key] = auditLocalstackExpected{Key: key, Version: version, Body: body, Metadata: map[string]string{"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID, "environment_id": binding.EnvironmentID, "artifact_id": id, "media_type": "application/json", "sha256": hex.EncodeToString(digestSum[:])}}
		t.Logf("physical receipt kind=%s ordinal=%d version=%s bytes=%d sha256=%x", kind, ordinal, version, size, digestSum)
	}
	rows.Close()
	if rows.Err() != nil || len(inventory) != len(expected) {
		t.Fatal("incomplete physical receipt set", rows.Err())
	}
	if err := forwarder.inventory(ctx, inventory); err != nil {
		t.Fatal("actual paginated version inventory/pinned reads differ", err)
	}
	p.mu.Lock()
	terminal := p.sends == 1 && p.receives == acks+1 && p.deletes == acks && p.deleteAttempts == acks && len(p.messages) == 1 && p.messages[0].Deleted && p.failure == "" && len(p.objects) == 0
	p.mu.Unlock()
	if !terminal {
		t.Fatal("Terminal/ACK or controlled queue state differs", p.problem())
	}
	var get json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, args[0], args[1], args[2], args[3], args[4], args[5], args[7], int64(1), nil, args[11], args[12]).Scan(&get); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Export json.RawMessage `json:"export"`
	}
	if json.Unmarshal(get, &envelope) != nil {
		t.Fatal("ready envelope")
	}
	descriptor, err := audit.DecodeExportDescriptor(envelope.Export)
	if err != nil || descriptor.Status != "ready" || descriptor.EventCount == nil || *descriptor.EventCount != int64(len(events)) || descriptor.ChunkCount == nil || *descriptor.ChunkCount != manifest.ChunkCount || descriptor.ManifestSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("registered ready descriptor differs", err)
	}
	return inventory
}

func auditLocalstackArtifactID(binding audit.ExportBinding, kind string, ordinal int64) string {
	sum := sha256.Sum256([]byte(binding.ExportID + "\x00" + binding.CaptureID + "\x00" + fmt.Sprintf("audit-export-%s:%d", kind, ordinal)))
	value := hex.EncodeToString(sum[:])
	return "pid_" + value[:8] + "-" + value[8:12] + "-4" + value[13:16] + "-8" + value[17:20] + "-" + value[20:32]
}

func auditLocalstackAssertCapturedSource(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage) {
	t.Helper()
	rows, err := f.admin.Query(ctx, `SELECT ordinal,canonical_event FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2 ORDER BY ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var ordinal int
		var body []byte
		if err := rows.Scan(&ordinal, &body); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if count >= len(events) || ordinal != count+1 || !bytes.Equal(body, events[count]) {
			rows.Close()
			t.Fatal("captured event differs from pre-capture projection")
		}
		count++
	}
	rows.Close()
	if rows.Err() != nil || count != len(events) {
		t.Fatal("captured source coverage", rows.Err())
	}
	var binding audit.ExportBinding
	binding.OrganizationID = args[0].(string)
	binding.WorkspaceID = args[1].(string)
	binding.EnvironmentID = args[2].(string)
	binding.ExportID = args[7].(string)
	if err := f.admin.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&binding.CaptureID); err != nil {
		t.Fatal(err)
	}
	expected, err := auditExportProcessExpected(binding, events)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = f.admin.Query(ctx, `SELECT ordinal,first_event,event_count,previous_digest,sha256,size_bytes FROM zasp_audit_export_chunks WHERE organization_id=$1 AND export_id=$2 ORDER BY ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	count = 0
	for rows.Next() {
		var ordinal, first, n, size int64
		var previous, digest []byte
		if err := rows.Scan(&ordinal, &first, &n, &previous, &digest, &size); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		body, ok := expected[fmt.Sprintf("chunk:%d", ordinal)]
		sum := sha256.Sum256(body)
		chunk, err := audit.DecodeExportChunk(body)
		if !ok || err != nil || ordinal != int64(count+1) || first != chunk.FirstEvent || n != chunk.EventCount || hex.EncodeToString(previous) != chunk.PreviousDigest || !bytes.Equal(digest, sum[:]) || size != int64(len(body)) {
			rows.Close()
			t.Fatal("captured chunk plan differs from projected source", err)
		}
		count++
	}
	rows.Close()
	if rows.Err() != nil || count != len(expected)-1 {
		t.Fatal("chunk plan coverage", rows.Err())
	}
}
