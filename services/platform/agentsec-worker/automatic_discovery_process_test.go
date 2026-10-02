package main

// Connected-browser helpers. They run in separate, explicitly selected test
// processes. Only provider transport, credentials and object storage are local;
// scheduling, repository authority, parsing and snapshot application are real.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const automaticParser = "inventory-parser-2026.08.20"
const automaticTool = "collector-tool-2026.08.20"

type automaticCollectionTrace struct {
	collection.ProviderClient
	collection.ReadinessProbe
	t       *testing.T
	outcome collection.Outcome
	err     error
}

func (trace *automaticCollectionTrace) CollectWithCredential(ctx context.Context, request collection.Request, credential []byte) (collection.Outcome, error) {
	trace.outcome, trace.err = trace.ProviderClient.CollectWithCredential(ctx, request, credential)
	trace.t.Logf("parser boundary: outcome=%T error=%v", trace.outcome, trace.err)
	if complete, ok := trace.outcome.(collection.CompleteResult); ok {
		snapshot := complete.Snapshot()
		trace.t.Logf("snapshot boundary: typed=%t entities=%d relationships=%d evidence=%d digest=%x", snapshot.TypedObservations(), snapshot.EntityCount(), snapshot.RelationshipCount(), snapshot.EvidenceCount(), snapshot.Digest())
	}
	return trace.outcome, trace.err
}

type automaticPageTrace struct {
	*kubernetesdiscovery.KubernetesCollectionAPI
	t *testing.T
}

func (trace *automaticPageTrace) FetchCollectionPage(ctx context.Context, credential []byte, request kubernetesdiscovery.CollectionPageRequest) (kubernetesdiscovery.CollectionPage, error) {
	page, err := trace.KubernetesCollectionAPI.FetchCollectionPage(ctx, credential, request)
	trace.t.Logf("provider boundary: page=%d complete=%t entities=%d relationships=%d bytes=%d sha256=%x error=%v", request.Page, page.Complete, len(page.Entities), len(page.Relationships), len(page.Raw), sha256.Sum256(page.Raw), err)
	return page, err
}

type automaticAdmissionCheckpoint struct {
	apiserver.JSONDatabase
	paused atomic.Bool
}

func (database *automaticAdmissionCheckpoint) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	value, err := database.JSONDatabase.QueryJSON(ctx, statement, args...)
	if err == nil && strings.Contains(statement, "zasp_execution_request_scheduled_sync(") {
		// QueryJSON has returned only after its transaction committed. No reply
		// or advance is synthesized, and cancellation leaves the real lease.
		database.paused.Store(true)
		fmt.Println("AUTOMATIC_ADMISSION_COMMITTED")
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return value, err
}

func automaticProcessDatabase(t *testing.T, ctx context.Context, dsn string) *apiserver.PostgresJSONDatabase {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns, config.MinConns = 3, 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	database, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestAutomaticDiscoverySchedulerProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_AUTOMATIC_SCHEDULER_DSN")
	if dsn == "" {
		t.Skip("selected browser process only")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 12*time.Minute)
	defer deadline()
	database := automaticProcessDatabase(t, ctx, dsn)
	checkpoint := &automaticAdmissionCheckpoint{JSONDatabase: database}
	config := workerRuntimeConfig{Mode: workerModeScheduler, PostgresDSN: dsn, DatabaseAuthority: "zasp_discovery_scheduler", WorkerID: "automatic-discovery-scheduler-first", PollInterval: 100 * time.Millisecond, LeaseDuration: 5 * time.Second, BatchSize: 1, ShutdownTimeout: time.Second, ParserVersion: automaticParser, ToolVersion: automaticTool}
	deps, err := composeWorkerRuntime(ctx, config, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer deps.Close()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	fmt.Println("AUTOMATIC_SCHEDULER_READY")
	if err := runAutomaticSchedulerPolling(ctx, deps.Processor); err != nil {
		t.Fatal(err)
	}
	if !checkpoint.paused.Load() {
		t.Fatal("stopped before committed admission checkpoint")
	}
}

func runAutomaticSchedulerPolling(ctx context.Context, processor workerProcessor) error {
	var ready atomic.Bool
	runWorkerPollingLoop(ctx, processor, 100*time.Millisecond, &ready)
	return nil
}

func TestAutomaticDiscoverySchedulerRecoversTransientRelayDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	processor := workerProcessorFunc(func(context.Context) error {
		calls++
		if calls == 1 {
			return errWorkerExecution
		}
		cancel()
		return nil
	})
	if err := runAutomaticSchedulerPolling(ctx, processor); err != nil || calls != 2 {
		t.Fatalf("scheduler stopped instead of reconnecting on next poll: calls=%d err=%v", calls, err)
	}
}

// Returns only 127.0.0.1 for the exact owned provider hostname. The real pinned
// production transport still checks every DNS answer, port and TLS hostname.
func automaticDNSReply(query []byte) []byte {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	i, labels := 12, []string{}
	for i < len(query) && query[i] != 0 {
		n := int(query[i])
		i++
		if n > 63 || i+n > len(query) {
			return nil
		}
		labels = append(labels, string(query[i:i+n]))
		i += n
	}
	if i+5 > len(query) || strings.Join(labels, ".") != "prod.example" {
		return nil
	}
	// Go's resolver includes one empty EDNS OPT record. Accept exactly that
	// bounded form and omit it from the response; never echo arbitrary data.
	additional := binary.BigEndian.Uint16(query[10:12])
	if additional == 0 {
		if i+5 != len(query) {
			return nil
		}
	} else if additional == 1 {
		opt := query[i+5:]
		if len(opt) != 11 || opt[0] != 0 || binary.BigEndian.Uint16(opt[1:3]) != 41 || binary.BigEndian.Uint16(opt[3:5]) < 512 || string(opt[5:]) != "\x00\x00\x00\x00\x00\x00" {
			return nil
		}
	} else {
		return nil
	}
	typeValue := binary.BigEndian.Uint16(query[i+1 : i+3])
	if binary.BigEndian.Uint16(query[i+3:i+5]) != 1 || typeValue != 1 && typeValue != 28 {
		return nil
	}
	reply := append([]byte(nil), query[:i+5]...)
	reply[2], reply[3] = 0x81, 0x80
	for j := 6; j < 12; j++ {
		reply[j] = 0
	}
	if typeValue == 1 {
		reply[7] = 1
		reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
	}
	return reply
}

func TestAutomaticDiscoveryDNSRefusesForeignNamesAndMalformedQuestions(t *testing.T) {
	query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 'p', 'r', 'o', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	reply := automaticDNSReply(query)
	if len(reply) != len(query)+16 || string(reply[len(reply)-4:]) != "\x7f\x00\x00\x01" {
		t.Fatalf("missing exact loopback answer: %x", reply)
	}
	for _, invalid := range [][]byte{nil, query[:len(query)-1], append(append([]byte(nil), query...), 0), append([]byte(nil), query...)} {
		if len(invalid) == len(query) {
			invalid[13] = 'x'
		}
		if automaticDNSReply(invalid) != nil {
			t.Fatal("foreign or malformed DNS accepted")
		}
	}
}

func TestAutomaticDiscoveryDNSAnswersActualGoResolver(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	questions := make(chan []byte, 8)
	go func() {
		defer close(joined)
		buf := make([]byte, 1024)
		for {
			n, peer, err := packet.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case questions <- append([]byte(nil), buf[:n]...):
			default:
			}
			if reply := automaticDNSReply(buf[:n]); reply != nil {
				_, _ = packet.WriteTo(reply, peer)
			}
		}
	}()
	defer func() { _ = packet.Close(); <-joined }()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addresses, err := resolver.LookupIPAddr(ctx, "prod.example")
	if err != nil {
		select {
		case query := <-questions:
			t.Fatalf("Go resolver did not receive owned answer: %v; question=%x", err, query)
		default:
			t.Fatal(err)
		}
	}
	if len(addresses) != 1 || !addresses[0].IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("unexpected resolver answers: %v", addresses)
	}
}

func automaticKubernetesAPI(t *testing.T, scenario string) (*kubernetesdiscovery.KubernetesCollectionAPI, *atomic.Int64) {
	t.Helper()
	if scenario != "complete" && scenario != "changed" && scenario != "partial" && scenario != "failed" {
		t.Fatal("invalid provider scenario")
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsJoined := make(chan struct{})
	go func() {
		defer close(dnsJoined)
		buffer := make([]byte, 1024)
		for {
			n, addr, err := packet.ReadFrom(buffer)
			if err != nil {
				return
			}
			if reply := automaticDNSReply(buffer[:n]); reply != nil {
				_, _ = packet.WriteTo(reply, addr)
			}
		}
	}()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = original; _ = packet.Close(); <-dnsJoined })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"prod.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:443")
	if err != nil {
		t.Fatal("owned Kubernetes port443 unavailable:", err)
	}
	calls := &atomic.Int64{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Host != "prod.example" {
			http.Error(w, "invalid request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"gitVersion":"v1.31.0"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer local-e2e-credential-material" {
			http.Error(w, "invalid credential", 403)
			return
		}
		calls.Add(1)
		if scenario == "failed" {
			fmt.Fprint(w, `{"malformed":true}`)
			return
		}
		phases := map[string][2]string{"/api/v1/namespaces": {"v1", "Namespace"}, "/api/v1/serviceaccounts": {"v1", "ServiceAccount"}, "/apis/rbac.authorization.k8s.io/v1/roles": {"rbac.authorization.k8s.io/v1", "Role"}, "/apis/rbac.authorization.k8s.io/v1/clusterroles": {"rbac.authorization.k8s.io/v1", "ClusterRole"}, "/apis/rbac.authorization.k8s.io/v1/rolebindings": {"rbac.authorization.k8s.io/v1", "RoleBinding"}, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"}, "/apis/apps/v1/deployments": {"apps/v1", "Deployment"}, "/apis/apps/v1/statefulsets": {"apps/v1", "StatefulSet"}, "/apis/apps/v1/daemonsets": {"apps/v1", "DaemonSet"}, "/apis/batch/v1/jobs": {"batch/v1", "Job"}, "/apis/batch/v1/cronjobs": {"batch/v1", "CronJob"}}
		phase, ok := phases[r.URL.Path]
		if !ok {
			http.Error(w, "unknown phase", 404)
			return
		}
		items, continuation := "[]", ""
		if scenario == "partial" {
			continuation = fmt.Sprintf("remaining-%d", calls.Load())
		} else {
			switch phase[1] {
			case "Namespace":
				items = `[{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"ns-zasp","name":"zasp"}}]`
			case "ServiceAccount":
				items = `[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"uid":"sa-support","name":"support","namespace":"zasp"}}]`
			case "Deployment":
				name := "scheduled-agent"
				if scenario == "changed" {
					name = "scheduled-agent-updated"
				}
				items = fmt.Sprintf(`[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"deployment-scheduled-agent","name":%q,"namespace":"zasp","labels":{"zasp.ai/entity-kind":"agent"}},"spec":{"template":{"spec":{"serviceAccountName":"support","containers":[{"name":"agent","image":"example/agent:v1"}]}}}}]`, name)
			}
		}
		fmt.Fprintf(w, `{"apiVersion":%q,"kind":%q,"metadata":{"continue":%q},"items":%s}`, phase[0], phase[1]+"List", continuation, items)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	api, err := kubernetesdiscovery.NewPinnedKubernetesCollectionAPI(kubernetesdiscovery.PinnedCollectionAPIConfig{Endpoint: "https://prod.example", CABundlePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), AllowedCIDRs: []string{"127.0.0.1/32"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return api, calls
}

func TestAutomaticDiscoveryCollectionProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_AUTOMATIC_DISCOVERY_DSN")
	if dsn == "" {
		t.Skip("selected browser process only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database := automaticProcessDatabase(t, ctx, dsn)
	scenario := os.Getenv("ZASP_AUTOMATIC_DISCOVERY_SCENARIO")
	api, calls := automaticKubernetesAPI(t, scenario)
	driver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetesdiscovery.NewCollectionClient(&automaticPageTrace{KubernetesCollectionAPI: api, t: t}, artifacts, kubernetesdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: automaticParser, ToolVersion: automaticTool, Clock: combinedE2EClock})
	if err != nil {
		t.Fatal(err)
	}
	collectionTrace := &automaticCollectionTrace{ProviderClient: client, ReadinessProbe: client.(collection.ReadinessProbe), t: t}
	client = collectionTrace
	base, err := newCombinedE2ECollectorFactory("complete", automaticParser, automaticTool)
	if err != nil {
		t.Fatal(err)
	}
	factory := base.(*productionDiscoveryCollectorFactory)
	registrations := factory.providers.(*firstPartyCollectionFactory).registrations
	for i := range registrations {
		if registrations[i].Provider == collection.ProviderKubernetes {
			registrations[i].Client = client
			registrations[i].Readiness = client.(collection.ReadinessProbe)
		}
	}
	factory.providers, err = newFirstPartyCollectionFactory(registrations)
	if err != nil {
		t.Fatal(err)
	}
	trace := &combinedE2ETracingDatabase{delegate: database}
	repository, err := apiserver.NewDiscoveryExecutionRepository(trace, apiserver.DiscoveryExecutionAuthorityWorker)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	queue := &combinedE2EDiscoveryQueue{delivery: jobqueue.Delivery{Job: jobqueue.Job{Scope: combinedE2EScope(t), JobID: combinedE2EProductID(t, os.Getenv("ZASP_AUTOMATIC_DISCOVERY_JOB")), Kind: "discovery", Payload: []byte(`{}`)}}}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{Authority: repository, Queue: queue, CollectorFactory: factory, WorkerID: "automatic-discovery-collector", LeaseSeconds: 10, BatchSize: 1, HeartbeatInterval: 3 * time.Second, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("registered discovery trace: %s", trace.Trace())
	driver.mu.Lock()
	for _, object := range driver.objects {
		t.Logf("artifact boundary: bytes=%d sha256=%x version=%s", object.Size, object.SHA256, object.VersionID)
	}
	driver.mu.Unlock()
	if scenario == "complete" || scenario == "changed" {
		if _, ok := collectionTrace.outcome.(collection.CompleteResult); !ok || collectionTrace.err != nil {
			t.Fatal("complete provider did not produce a complete snapshot")
		}
		if !strings.Contains(trace.Trace(), "zasp_execution_apply_complete_snapshot") {
			t.Fatal("complete snapshot did not reach registered persistence")
		}
	}
	if queue.acknowledged != (scenario != "partial") {
		t.Fatalf("wrong delivery acknowledgement; provider_calls=%d database=%s", calls.Load(), trace.Trace())
	}
	if calls.Load() == 0 {
		t.Fatal("production Kubernetes HTTP client was not reached")
	}
	if (scenario == "complete" || scenario == "changed") && calls.Load() != 11 {
		t.Fatal("full snapshot skipped a Kubernetes phase")
	}
	fmt.Printf("AUTOMATIC_COLLECTION_COMPLETED scenario=%s provider_calls=%d\n", scenario, calls.Load())
}
