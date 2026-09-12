package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/sandboxcutover"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

const composedCutoverKMS = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
const composedCutoverTemplate = `{"metadata":{"labels":{"app":"agentsec-api"}},"spec":{"containers":[{"env":[{"name":"ZASP_RUNTIME_SESSION_INDEX","value":"zasp-runtime-sessions-v1"}],"image":"fixture/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"api"}]}}`

// Close runs before fixture resources close, including on a fatal assertion.
type composedTasks struct {
	ctx     context.Context
	cancel  context.CancelFunc
	release func()
	done    []<-chan struct{}
}

func newComposedTasks(ctx context.Context, release func()) *composedTasks {
	ctx, cancel := context.WithCancel(ctx)
	return &composedTasks{ctx: ctx, cancel: cancel, release: release}
}
func (g *composedTasks) start(fn func(context.Context)) {
	done := make(chan struct{})
	g.done = append(g.done, done)
	go func() { defer close(done); fn(g.ctx) }()
}
func (g *composedTasks) close() error {
	g.cancel()
	g.release()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for _, done := range g.done {
		select {
		case <-done:
		case <-deadline.C:
			return fmt.Errorf("owned composed task did not join before resource cleanup")
		}
	}
	return nil
}
func (f *composedCutoverFixture) tasks(release func()) *composedTasks {
	g := newComposedTasks(f.ctx, release)
	f.t.Cleanup(func() {
		if err := g.close(); err != nil {
			f.t.Error(err)
		}
	})
	return g
}

func TestSandboxCutoverComposedTaskCleanup(t *testing.T) {
	gate := make(chan struct{})
	g := newComposedTasks(context.Background(), func() { close(gate) })
	defer g.cancel()
	finished := make(chan struct{})
	g.start(func(ctx context.Context) { <-gate; <-ctx.Done(); close(finished) })
	if err := g.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("cleanup returned before cancelling and joining the owned task")
	}
}

type composedCutoverObject struct {
	body     []byte
	version  string
	metadata map[string]string
}
type composedCutoverFixture struct {
	t                           *testing.T
	ctx                         context.Context
	admin                       *pgx.Conn
	database                    *sandboxcutover.PostgresDatabase
	binding                     sandboxcutover.ReleaseBinding
	dependencies                sandboxcutover.Dependencies
	kubernetes                  *sandboxcutover.KubernetesClient
	mu                          sync.Mutex
	objects                     map[string]composedCutoverObject
	documents                   []sessionsearch.Document
	deployment                  map[string]any
	patches, accepted, searches int
	reads                       []string
	fault                       string
	pendingNew                  bool
	beforePatch                 func()
	onRevalidate                func()
	nextID                      int
	caPEM                       string
	observationList             func(http.ResponseWriter, *http.Request) bool
}

// Approval and consumer observations are declared fixtures. PostgreSQL capture,
// locking, SDK object reads, signed exact HTTP search and TLS CAS are real.
func newComposedCutover(t *testing.T, fault string) *composedCutoverFixture {
	return newComposedCutoverTemplates(t, fault, composedCutoverTemplate, strings.Replace(composedCutoverTemplate, "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2", 1))
}
func newComposedCutoverTemplates(t *testing.T, fault, from, to string) *composedCutoverFixture {
	t.Helper()
	ctx, admin, database, b := cutoverPostgresFixture(t)
	f := &composedCutoverFixture{t: t, ctx: ctx, admin: admin, database: database, binding: b, objects: map[string]composedCutoverObject{}, fault: fault}
	f.binding.ArtifactDigest = strings.Repeat("a", 64)
	f.binding.From = sandboxcutover.Manifest{SchemaVersion: 50, Phase: "backfill", APIIndex: "zasp-runtime-sessions-v1", APITemplateDigest: composedHash([]byte(from)), OtherResourcesDigest: strings.Repeat("b", 64)}
	f.binding.To = sandboxcutover.Manifest{SchemaVersion: 50, Phase: "query", APIIndex: "zasp-runtime-sessions-v2", APITemplateDigest: composedHash([]byte(to)), OtherResourcesDigest: strings.Repeat("b", 64)}
	f.binding.Namespace, f.binding.NamespaceUID, f.binding.ProviderIdentity = "agentsec", "namespace-owned", "owned-provider-fixture"
	var template map[string]any
	if err := json.Unmarshal([]byte(from), &template); err != nil {
		t.Fatal(err)
	}
	f.deployment = map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "agentsec-api", "namespace": "agentsec", "uid": "api-owned", "resourceVersion": "opaque-old/~", "annotations": map[string]any{"example/retained": "yes"}}, "spec": map[string]any{"replicas": float64(1), "template": template}}
	kube := httptest.NewTLSServer(http.HandlerFunc(f.serveKubernetes))
	t.Cleanup(kube.Close)
	f.binding.KubernetesServer = kube.URL
	f.binding.KubernetesCADigest = composedHash(kube.Certificate().Raw)
	f.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kube.Certificate().Raw}))
	kubernetes, err := sandboxcutover.NewKubernetes(sandboxcutover.KubernetesConfig{Binding: f.binding, FromTemplateJSON: from, ToTemplateJSON: to, CAPEM: f.caPEM, BearerToken: "owned-token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kubernetes.Close)
	f.kubernetes = kubernetes
	f.seedReceipt(false)
	provider := httptest.NewServer(http.HandlerFunc(f.serveProvider))
	t.Cleanup(provider.Close)
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "owned-key", SecretAccessKey: "owned-secret"}, nil
	})
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(provider.URL), UsePathStyle: true, Credentials: credentials, HTTPClient: provider.Client()})
	artifacts, err := sandboxcutover.NewS3ArtifactReader(client, sandboxcutover.ArtifactConfig{Binding: f.binding, Bucket: "zasp-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: composedCutoverKMS})
	if err != nil {
		t.Fatal(err)
	}
	search, err := opensearchdriver.NewSandboxSessionIndex(opensearchdriver.Config{Endpoint: provider.URL, Region: "us-east-1", RequestTimeout: time.Second, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20, AllowTestLoopback: true}, credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(search.Close)
	f.dependencies = sandboxcutover.Dependencies{Releases: f, Database: database, Artifacts: artifacts, Search: search, Observer: f, Kubernetes: kubernetes, Now: time.Now, NewTransitionID: func() string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.nextID++
		return fmt.Sprintf("owned-transition-%d", f.nextID)
	}}
	return f
}
func composedHash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func (f *composedCutoverFixture) Verify(_ context.Context, reference string) (sandboxcutover.ReleaseBinding, error) {
	if reference != "owned-approved-fixture" {
		return sandboxcutover.ReleaseBinding{}, fmt.Errorf("unverified fixture")
	}
	return f.binding, nil
}
func (f *composedCutoverFixture) ObserveBackfill(context.Context, sandboxcutover.ReleaseBinding) (sandboxcutover.Observation, error) {
	return sandboxcutover.Observation{ObservedAt: time.Now().UTC(), IdentityDigest: strings.Repeat("c", 64), API: sandboxcutover.APIIdentity{UID: "api-owned", ResourceVersion: "opaque-old/~", TemplateDigest: f.binding.From.APITemplateDigest}}, nil
}
func (f *composedCutoverFixture) RevalidateBackfill(_ context.Context, _ sandboxcutover.ReleaseBinding, previous sandboxcutover.Observation) (sandboxcutover.Observation, error) {
	if f.onRevalidate != nil {
		f.onRevalidate()
	}
	previous.ObservedAt = time.Now().UTC()
	return previous, nil
}
func (f *composedCutoverFixture) snapshot() string {
	f.t.Helper()
	var value string
	err := f.admin.QueryRow(f.ctx, `SELECT jsonb_build_object('receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY organization_id,batch_id) FROM zasp_runtime_session_projection_receipts r),'v1',(SELECT jsonb_agg(to_jsonb(q) ORDER BY organization_id,batch_id) FROM zasp_runtime_session_search_outbox q),'v2',(SELECT jsonb_agg(to_jsonb(q) ORDER BY organization_id,batch_id) FROM zasp_runtime_sandbox_search_outbox q),'stages',(SELECT jsonb_agg(to_jsonb(s) ORDER BY organization_id,batch_id,stage_order) FROM zasp_runtime_stage_work s))::text`).Scan(&value)
	if err != nil {
		f.t.Fatal(err)
	}
	return value
}

func (f *composedCutoverFixture) seedReceipt(other bool) {
	f.t.Helper()
	if err := f.seedReceiptContext(f.ctx, other); err != nil {
		f.t.Fatal(err)
	}
}
func (f *composedCutoverFixture) seedReceiptContext(ctx context.Context, other bool) error {
	root := "7951"
	if other {
		root = "7952"
	}
	pid := func(n int) domain.ProductID {
		value, err := domain.ParseProductID(fmt.Sprintf("pid_%s%04d-0000-4000-8000-%012d", root, n, n))
		if err != nil {
			panic(err) // All IDs below are fixed fixture constants.
		}
		return value
	}
	org, ws, env, sensor, batch := pid(1), pid(2), pid(3), pid(4), pid(5)
	scope, err := domain.NewScope(org, ws, env)
	if err != nil {
		return err
	}
	archive := []byte(fmt.Sprintf(`{"source":"tetragon","events":[{"event_id":"cutover-composed-%s","class":"file","action":"read","workload_id":"owned-runtime","event_time":"2026-09-09T10:00:00.000Z","evidence_id":"%s"}]}`, root, pid(6)))
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, archive)
	if err != nil {
		return err
	}
	archiveKey := fmt.Sprintf("runtime/v15/%s/%s/%s/%s/%020d/%s.json", org, ws, env, sensor, 1, batch)
	archiveRef := "s3://zasp-evidence/" + archiveKey
	projected, err := runtimeprojection.ProjectSandbox(runtimeprojection.Batch{Scope: scope, BatchID: batch, Generation: 1, ArchiveReference: archiveRef, ArchiveVersionID: "archive-owned-v1", ArchiveDigest: sha256.Sum256(archive), Body: archive, Correlations: []runtimecorrelation.Result{{EventID: decoded.Records[0].ID, Confidence: domain.EvidenceConfidenceUnattributed}}})
	if err != nil {
		return err
	}
	receipt := runtimeprojection.Receipt{ImplementationVersion: "runtime-projection-v2", Scope: scope, BatchID: batch, Generation: 1, InputReference: "s3://zasp-evidence/correlation-owned.json", InputVersionID: "correlation-v1", InputDigest: sha256.Sum256([]byte("owned-correlation-fixture")), ArchiveReference: archiveRef, ArchiveVersionID: "archive-owned-v1", ArchiveDigest: sha256.Sum256(archive), EffectDigest: projected.ContentDigest, Items: projected.Items}
	body, digest, reference, err := runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		return err
	}
	receiptKey := fmt.Sprintf("organizations/%s/workspaces/%s/environments/%s/artifacts/%s", org, ws, env, reference)
	binding := sessionsearch.ReceiptBinding{Scope: scope, BatchID: batch, Generation: 1, ReceiptDigest: digest}
	documents, err := sessionsearch.BuildDocuments(binding, body, archive)
	if err != nil {
		return err
	}
	metadata := func(data []byte) map[string]string {
		return map[string]string{"organization_id": org.String(), "workspace_id": ws.String(), "environment_id": env.String(), "media_type": "application/json", "sha256": composedHash(data)}
	}
	archiveMeta, receiptMeta := metadata(archive), metadata(body)
	receiptMeta["artifact_id"] = reference.String()
	f.mu.Lock()
	f.objects[archiveKey] = composedCutoverObject{archive, "archive-owned-v1", archiveMeta}
	f.objects[receiptKey] = composedCutoverObject{body, "receipt-owned-v1", receiptMeta}
	f.documents = append(f.documents, documents...)
	f.mu.Unlock()
	// Fixture-owned inserts establish canonical completed authority directly.
	// They are not claims about authenticated intake or real worker completion.
	for _, query := range []string{
		`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Composed cutover fixture',$2)`,
	} {
		if _, err := f.admin.Exec(ctx, query, org.String(), root+".cutover.invalid"); err != nil {
			return err
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Fixture');`, org.String(), ws.String()); err != nil {
		return err
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Fixture','production')`, org.String(), ws.String(), env.String()); err != nil {
		return err
	}
	args := []any{org.String(), ws.String(), env.String(), sensor.String(), batch.String(), archiveRef, archiveKey, sha256Bytes(archive), len(archive), "s3://zasp-evidence/" + receiptKey, digest[:], projected.ContentDigest[:], []string{projected.Items[0].EventID.String()}}
	for _, query := range []string{
		`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,$4,'Fixture','tetragon')`,
		`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,decode(repeat('ab',16),'hex'),digest($1::text,'sha256'),now()+interval '1 day')`,
		`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version,state) VALUES($1,$2,$3,$5,$4,'cutover-composed-0001',$8,1,$6,$9,'application/json','runtime-v1','processing')`,
		`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,$5,$4,$4,1,1,'cutover-composed-0001',$8,$8,'tetragon','application/json','runtime-v1',$9,1,$7,$6,'archive-owned-v1',$8,$9,'fixture-kms',now(),'processing')`,
		`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) SELECT $1,$2,$3,$5,1,stage,ord,version,$8,'succeeded',1,$12,$10,'receipt-owned-v1',$11,now() FROM (VALUES('project',4,'runtime-projection-v2'),('complete',5,'runtime-complete-v2')) v(stage,ord,version)`,
		`INSERT INTO zasp_runtime_session_projection_receipts(organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,event_ids) VALUES($1,$2,$3,$5,1,$11,$13)`,
		`UPDATE zasp_runtime_sandbox_search_outbox SET state='indexed',attempt=1,worker_id='fixture-worker',lease_digest=decode(repeat('ab',32),'hex'),indexed_at=now() WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`,
	} { // Bind only used parameters, preserving each independently written value.
		if other && f.pendingNew && strings.HasPrefix(query, "UPDATE zasp_runtime_sandbox_search_outbox") {
			continue
		}
		indexes := map[string]int{}
		values := []any{}
		query = regexp.MustCompile(`\$[0-9]+`).ReplaceAllStringFunc(query, func(parameter string) string {
			if index, ok := indexes[parameter]; ok {
				return fmt.Sprintf("$%d", index)
			}
			original, _ := strconv.Atoi(parameter[1:])
			values = append(values, args[original-1])
			indexes[parameter] = len(values)
			return fmt.Sprintf("$%d", len(values))
		})
		if _, err := f.admin.Exec(ctx, query, values...); err != nil {
			return fmt.Errorf("seed composed authority: %w", err)
		}
	}
	return nil
}
func sha256Bytes(data []byte) []byte { digest := sha256.Sum256(data); return digest[:] }

func (f *composedCutoverFixture) serveProvider(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, r.Method+" "+r.URL.Path)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		f.t.Error("unsigned read")
	}
	if strings.HasPrefix(r.URL.Path, "/zasp-evidence/") {
		object, ok := f.objects[strings.TrimPrefix(r.URL.Path, "/zasp-evidence/")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if (r.Method != "HEAD" && r.Method != "GET") || r.URL.Query().Get("versionId") != object.version || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
			f.t.Error("unbounded artifact request")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(object.body)))
		w.Header().Set("X-Amz-Version-Id", object.version)
		w.Header().Set("X-Amz-Server-Side-Encryption", "aws:kms")
		w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", composedCutoverKMS)
		w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sha256Bytes(object.body)))
		for key, value := range object.metadata {
			w.Header().Set("X-Amz-Meta-"+key, value)
		}
		if r.Method == "GET" {
			data := object.body
			if f.fault == "artifact-bytes" {
				data = bytes.Clone(data)
				data[0] ^= 1
			}
			_, _ = w.Write(data)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method + " " + r.URL.Path {
	case "GET /zasp-runtime-sessions-v2/_mapping":
		_, _ = io.WriteString(w, `{"zasp-runtime-sessions-v2":`+composedSearchSchema+`}`)
	case "GET /zasp-runtime-sessions-v2/_doc/_zasp_session_schema_v2":
		_ = json.NewEncoder(w).Encode(map[string]any{"_index": "zasp-runtime-sessions-v2", "_id": "_zasp_session_schema_v2", "_version": 1, "_seq_no": 0, "_primary_term": 1, "found": true, "_source": map[string]any{"record_type": "schema_marker", "schema_version": 2, "mapping_digest": "sha256:" + composedHash([]byte(composedSearchSchema))}})
	case "POST /zasp-runtime-sessions-v2/_search":
		f.searches++
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		hits := []any{}
		for _, document := range f.documents {
			if bytes.Contains(body, []byte(document.DocumentID)) {
				hits = append(hits, map[string]any{"_index": "zasp-runtime-sessions-v2", "_id": document.DocumentID, "_version": 1, "_seq_no": 0, "_primary_term": 1, "_score": nil, "_source": document})
			}
		}
		if f.fault == "missing-hit" {
			hits = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"took": 1, "timed_out": false, "_shards": map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": len(hits), "relation": "eq"}, "max_score": nil, "hits": hits}})
	default:
		f.t.Error("provider mutation/unowned read", r.Method, r.URL)
		w.WriteHeader(400)
	}
}

func (f *composedCutoverFixture) serveKubernetes(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer owned-token" {
		f.t.Error("wrong Kubernetes token")
		w.WriteHeader(401)
		return
	}
	if r.Method == "PATCH" {
		body, err := io.ReadAll(io.LimitReader(r.Body, (4<<20)+1))
		if err != nil || len(body) > 4<<20 {
			w.WriteHeader(400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if f.beforePatch != nil {
			f.beforePatch()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if f.observationList != nil && f.observationList(w, r) {
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/agentsec" {
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "agentsec", "uid": "namespace-owned"}})
		return
	}
	if r.URL.Path != "/apis/apps/v1/namespaces/agentsec/deployments/agentsec-api" {
		f.t.Error("unowned Kubernetes path")
		w.WriteHeader(404)
		return
	}
	if r.Method == "GET" {
		_ = json.NewEncoder(w).Encode(f.deployment)
		return
	}
	if r.Method != "PATCH" || r.Header.Get("Content-Type") != "application/json-patch+json" {
		f.t.Error("unowned Kubernetes mutation")
		w.WriteHeader(400)
		return
	}
	f.patches++
	var operations []struct {
		Op, Path string
		Value    any
	}
	if json.NewDecoder(r.Body).Decode(&operations) != nil {
		w.WriteHeader(400)
		return
	}
	metadata := f.deployment["metadata"].(map[string]any)
	spec := f.deployment["spec"].(map[string]any)
	for _, operation := range operations {
		if operation.Op == "test" {
			value := map[string]any{"/metadata/uid": metadata["uid"], "/metadata/resourceVersion": metadata["resourceVersion"], "/spec/template": spec["template"]}[operation.Path]
			if !reflect.DeepEqual(value, operation.Value) {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "code": 409, "reason": "Conflict"})
				return
			}
		}
	}
	for _, operation := range operations {
		if operation.Op == "replace" && operation.Path == "/spec/template" {
			spec["template"] = operation.Value
		} else if operation.Op == "add" && strings.HasPrefix(operation.Path, "/metadata/annotations/zasp.io~1cutover-") {
			metadata["annotations"].(map[string]any)[strings.ReplaceAll(strings.TrimPrefix(operation.Path, "/metadata/annotations/"), "~1", "/")] = operation.Value
		} else if operation.Op != "test" {
			f.t.Error("unapproved patch field")
			w.WriteHeader(400)
			return
		}
	}
	metadata["resourceVersion"] = "opaque-new/~"
	f.accepted++
	_ = json.NewEncoder(w).Encode(f.deployment)
}

func TestSandboxCutoverComposedPostgres(t *testing.T) {
	f := newComposedCutover(t, "none")
	before := f.snapshot()
	capture, err := f.database.Capture(f.ctx, f.binding)
	if err != nil || len(capture.Records) != 1 {
		t.Fatalf("initial real canonical capture rejected: %+v %v", capture, err)
	}
	result := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	if result.Outcome != sandboxcutover.Applied || !result.CleanupConfirmed || result.Audit.ReceiptCount != 1 || f.patches != 1 || f.accepted != 1 || f.searches != 1 {
		t.Fatalf("real PG/provider/TLS composition rejected: %+v patches=%d applied=%d search=%d reads=%v", result, f.patches, f.accepted, f.searches, f.reads)
	}
	if f.snapshot() != before {
		t.Fatal("cutover mutated canonical stage/receipt/v1/v2 evidence")
	}
	if _, err := f.kubernetes.Reconcile(f.ctx, f.binding, result.Audit); err != nil || f.patches != 1 {
		t.Fatal("reconciliation was not exact and read-only", err)
	}
	f.mu.Lock()
	deploymentBefore, _ := json.Marshal(f.deployment)
	f.mu.Unlock()
	again := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	f.mu.Lock()
	deploymentAfter, _ := json.Marshal(f.deployment)
	patches, accepted := f.patches, f.accepted
	f.mu.Unlock()
	if again.Outcome != sandboxcutover.Refused || patches != 1 || accepted != 1 || !bytes.Equal(deploymentBefore, deploymentAfter) || f.snapshot() != before {
		t.Fatal("already-query invocation changed audit, template or evidence", again, patches, accepted)
	}
}

func TestSandboxCutoverComposedProviderFailureCannotDispatch(t *testing.T) {
	for _, fault := range []string{"artifact-bytes", "missing-hit"} {
		t.Run(fault, func(t *testing.T) {
			f := newComposedCutover(t, fault)
			before := f.snapshot()
			r := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
			if r.Outcome != sandboxcutover.Refused || f.patches != 0 || len(f.reads) == 0 {
				t.Fatal("provider failure authorized dispatch", r, f.patches, f.reads)
			}
			if fault == "missing-hit" && f.searches != 1 {
				t.Fatal("missing occurrence did not reach exact search")
			}
			if f.snapshot() != before {
				t.Fatal("provider refusal mutated canonical evidence")
			}
		})
	}
}

type composedBeforeFence struct {
	sandboxcutover.Database
	before func()
}

func (d composedBeforeFence) WithFence(ctx context.Context, b sandboxcutover.ReleaseBinding, fn func(sandboxcutover.Fence) error) (sandboxcutover.FenceResult, error) {
	d.before()
	return d.Database.WithFence(ctx, b, fn)
}

func TestSandboxCutoverComposedFreshReceiptChangesCutoff(t *testing.T) {
	f := newComposedCutover(t, "none")
	f.dependencies.Database = composedBeforeFence{f.database, func() { f.seedReceipt(true) }}
	r := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	if r.Outcome != sandboxcutover.Refused || !r.CleanupConfirmed || f.patches != 0 || f.searches != 1 {
		t.Fatal("new unverified receipt crossed fenced recapture", r, f.patches, f.searches)
	}
	capture, err := f.database.Capture(f.ctx, f.binding)
	if err != nil || len(capture.Records) != 2 {
		t.Fatal("new committed receipt disappeared", capture, err)
	}
}

func TestSandboxCutoverComposedConcurrentFenceRefuses(t *testing.T) {
	f := newComposedCutover(t, "none")
	before := f.snapshot()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	tasks := f.tasks(unblock)
	f.onRevalidate = func() { close(entered); <-release }
	done := make(chan sandboxcutover.Result, 1)
	tasks.start(func(ctx context.Context) {
		done <- sandboxcutover.ExecuteSandboxQueryCutover(ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	})
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first invocation never reached actual held fence")
	}
	b := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	if b.Outcome != sandboxcutover.Refused || !b.CleanupConfirmed || f.patches != 0 {
		t.Fatal("contender crossed real database fence", b, f.patches)
	}
	unblock()
	select {
	case a := <-done:
		if a.Outcome != sandboxcutover.Applied || !a.CleanupConfirmed || f.patches != 1 {
			t.Fatal("fenced winner failed", a, f.patches)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("winner did not finish")
	}
	if f.snapshot() != before {
		t.Fatal("contenders changed canonical evidence")
	}
}

func TestSandboxCutoverComposedPostDispatchReceiptRemainsPending(t *testing.T) {
	f := newComposedCutover(t, "none")
	f.pendingNew = true
	peer := cutoverPeer(t, f.ctx, f.admin)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	tasks := f.tasks(unblock)
	f.beforePatch = func() { close(entered); <-release }
	done := make(chan sandboxcutover.Result, 1)
	tasks.start(func(ctx context.Context) {
		done <- sandboxcutover.ExecuteSandboxQueryCutover(ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	})
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("authorized dispatch did not reach server")
	}
	writer := make(chan error, 1)
	tasks.start(func(ctx context.Context) { writer <- f.seedReceiptContext(ctx, true) })
	if err := awaitCutoverLock(f.ctx, peer, f.admin.PgConn().PID(), "zasp_runtime_session_projection_receipts"); err != nil {
		t.Fatal("new receipt was not blocked during dispatch", err)
	}
	select {
	case <-writer:
		t.Fatal("receipt crossed held fence")
	default:
	}
	unblock()
	select {
	case result := <-done:
		if result.Outcome != sandboxcutover.Applied || !result.CleanupConfirmed || result.Audit.ReceiptCount != 1 {
			t.Fatal("dispatch cutoff changed", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dispatch did not release fence")
	}
	select {
	case err := <-writer:
		if err != nil {
			t.Fatal("receipt writer failed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("receipt stayed blocked after confirmed cleanup")
	}
	var pending, indexed int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE state='pending'),count(*) FILTER (WHERE state='indexed') FROM zasp_runtime_sandbox_search_outbox`).Scan(&pending, &indexed); err != nil || pending != 1 || indexed != 1 {
		t.Fatal("late receipt did not remain ordinary pending work", pending, indexed, err)
	}
	if f.patches != 1 || f.accepted != 1 {
		t.Fatal("late receipt caused redispatch", f.patches, f.accepted)
	}
}

func TestSandboxCutoverComposedDelayedPersistenceOverlap(t *testing.T) {
	for _, winner := range []int{0, 1} {
		t.Run(fmt.Sprint(winner), func(t *testing.T) {
			f := newComposedCutover(t, "none")
			before := f.snapshot()
			entered := make(chan int, 2)
			release := []chan struct{}{make(chan struct{}), make(chan struct{})}
			var gateMu sync.Mutex
			calls := 0
			once := []sync.Once{{}, {}}
			unblock := func(i int) { once[i].Do(func() { close(release[i]) }) }
			tasks := f.tasks(func() { unblock(0); unblock(1) })
			f.beforePatch = func() {
				gateMu.Lock()
				index := calls
				calls++
				gateMu.Unlock()
				if index >= 2 {
					t.Error("PATCH retry")
					return
				}
				entered <- index
				<-release[index]
			}
			results := make([]sandboxcutover.Result, 2)
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(tasks.ctx, 10*time.Second)
				defer cancel()
				done := make(chan sandboxcutover.Result, 1)
				tasks.start(func(context.Context) {
					done <- sandboxcutover.ExecuteSandboxQueryCutover(ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
				})
				select {
				case index := <-entered:
					if index != i {
						t.Fatal("unexpected invocation", index)
					}
				case <-time.After(10 * time.Second):
					cancel()
					t.Fatal("actual PATCH did not reach delayed gate")
				}
				cancel() // The body reached the server; local cancellation cannot undo it.
				select {
				case results[i] = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("cancelled invocation did not clean up")
				}
				if results[i].Outcome != sandboxcutover.Indeterminate || !results[i].CleanupConfirmed {
					t.Fatal("late write was classified as refused or lost cleanup", results[i])
				}
				cleanup, err := f.database.WithFence(f.ctx, f.binding, func(fence sandboxcutover.Fence) error { return fence.Ready(f.ctx) })
				if err != nil || !cleanup.CleanupConfirmed {
					t.Fatal("real fence survived cancelled invocation", cleanup, err)
				}
			}
			if results[0].Audit.TransitionID == results[1].Audit.TransitionID || results[0].Audit.ReceiptSetDigest != results[1].Audit.ReceiptSetDigest || results[0].Audit.ReceiptCount != 1 || results[1].Audit.ReceiptCount != 1 || !results[1].Audit.AuthorizedAt.After(results[0].Audit.AuthorizedAt) {
				t.Fatal("overlap reused or lost independent authority", results)
			}
			// Observe persistence via bounded reads; no client retries or write probes.
			for _, index := range []int{winner, 1 - winner} {
				unblock(index)
				deadline := time.Now().Add(5 * time.Second)
				for {
					f.mu.Lock()
					n := f.patches
					f.mu.Unlock()
					if n >= map[bool]int{true: 1, false: 2}[index == winner] {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("server persistence wait timed out")
					}
					time.Sleep(time.Millisecond)
				}
			}
			for index, result := range results {
				state, err := f.kubernetes.Reconcile(f.ctx, f.binding, result.Audit)
				if index == winner {
					if err != nil || state.Audit != result.Audit {
						t.Fatal("winner not reconciled", state, err)
					}
				} else if err == nil {
					t.Fatal("loser borrowed winning transition", state)
				}
			}
			f.mu.Lock()
			patches, accepted := f.patches, f.accepted
			f.mu.Unlock()
			if patches != 2 || accepted != 1 {
				t.Fatal("expected two invocations but one accepted CAS", patches, accepted)
			}
			if f.snapshot() != before {
				t.Fatal("delayed persistence changed canonical evidence")
			}
		})
	}
}

const composedSearchSchema = `{"mappings":{"dynamic":"strict","properties":{"action":{"type":"keyword"},"agent_id":{"type":"keyword"},"archive_digest":{"type":"keyword"},"batch_id":{"type":"keyword"},"confidence":{"type":"keyword"},"credential_id":{"type":"keyword"},"decision":{"type":"keyword"},"document_id":{"type":"keyword"},"domain_digest":{"type":"keyword"},"environment_id":{"type":"keyword"},"event_class":{"type":"keyword"},"event_id":{"type":"keyword"},"event_time":{"type":"date","format":"strict_date_time"},"file_digest":{"type":"keyword"},"generation":{"type":"long"},"investigation_id":{"type":"keyword"},"mapping_digest":{"type":"keyword"},"metadata_version":{"type":"integer"},"observed_principal_id":{"type":"keyword"},"organization_id":{"type":"keyword"},"process_digest":{"type":"keyword"},"receipt_digest":{"type":"keyword"},"record_type":{"type":"keyword"},"resource_digest":{"type":"keyword"},"sandbox_id":{"type":"keyword"},"sandbox_source_sensor_id":{"type":"keyword"},"schema_version":{"type":"integer"},"source":{"type":"keyword"},"tool_id":{"type":"keyword"},"workspace_id":{"type":"keyword"}}}}`
