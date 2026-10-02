package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/types/known/durationpb"
)

type continuationNetwork struct{ target string }

func (n continuationNetwork) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if host != "example.com" {
		return nil, fmt.Errorf("foreign DNS name")
	}
	return []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}}, nil
}
func (n continuationNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != "203.0.113.8:443" {
		return nil, fmt.Errorf("foreign pinned destination")
	}
	return (&net.Dialer{}).DialContext(ctx, network, n.target)
}

type continuationSecrets struct {
	root string
	ca   []byte
}

func (s continuationSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if aws.ToString(in.VersionStage) != "AWSCURRENT" {
		return nil, fmt.Errorf("unversioned secret")
	}
	var body []byte
	switch aws.ToString(in.SecretId) {
	case s.root + "/kubernetes/connection/customer-0001":
		body = []byte(`{"endpoint":"https://example.com","context":"customer","ca_reference":"ref:kubernetes/ca/customer-0001","credential_reference":"ref:kubernetes/credential/customer-0001"}`)
	case s.root + "/kubernetes/ca/customer-0001":
		body = append([]byte(nil), s.ca...)
	case s.root + "/kubernetes/credential/customer-0001":
		body = []byte("owned-kubernetes-credential-0001")
	case s.root + "/github/app-private-key-0001", s.root + "/okta/client-secret-0001":
		body = []byte("owned-readiness-material-0001")
	default:
		return nil, fmt.Errorf("foreign secret reference")
	}
	return &secretsmanager.GetSecretValueOutput{SecretBinary: body}, nil
}

// Real pinned HTTPS, real cursor grammar, real SQL, S3 driver and Temporal
// history segments. The network seam only redirects approved TCP IO to our TLS
// provider, whose certificate must still authenticate the original hostname.
func TestProductDiscoveryShippedContinuation(t *testing.T) {
	if os.Getenv("ZASP_P4B_CONTINUATION") != "true" {
		t.Skip("requires owned72 parent")
	}
	began := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var start orchestration.DiscoveryStart
	if json.Unmarshal([]byte(os.Getenv("ZASP_P4B_START")), &start) != nil || start.Continuation == nil {
		t.Fatal("start")
	}
	namespace := fmt.Sprintf("p4b-owned-%d", time.Now().UnixNano())
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.WorkflowService().RegisterNamespace(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, Description: "P4B owned local integration", WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	defer deleteOwnedDiscoveryNamespace(t, c, namespace)

	var pages atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.Host != "example.com" {
			http.Error(w, "foreign provider request", 400)
			return
		}
		if r.URL.Path == "/version" {
			_, _ = w.Write([]byte(`{"gitVersion":"v1.31.0"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer owned-kubernetes-credential-0001" {
			http.Error(w, "credential refused", 403)
			return
		}
		n := pages.Add(1)
		if n%64 == 0 {
			t.Log("real persisted provider page", n, "elapsed", time.Since(began))
		}
		version, kind, next, items := "", "", "", "[]"
		switch r.URL.Path {
		case "/api/v1/namespaces":
			page := 1
			if token := r.URL.Query().Get("continue"); token != "" {
				var err error
				page, err = strconv.Atoi(strings.TrimPrefix(token, "page-"))
				if err != nil || token != "page-"+strconv.Itoa(page) {
					http.Error(w, "bad cursor", 400)
					return
				}
			}
			if page < 1 || page > 257 || int(n) != page {
				http.Error(w, "repeated or skipped cursor", 400)
				return
			}
			version, kind = "v1", "Namespace"
			if page < 257 {
				next = "page-" + strconv.Itoa(page+1)
			}
			items = fmt.Sprintf(`[{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"ns-%03d","name":"ns-%03d"}}]`, page, page)
		case "/api/v1/serviceaccounts":
			version, kind = "v1", "ServiceAccount"
		case "/apis/rbac.authorization.k8s.io/v1/roles":
			version, kind = "rbac.authorization.k8s.io/v1", "Role"
		case "/apis/rbac.authorization.k8s.io/v1/clusterroles":
			version, kind = "rbac.authorization.k8s.io/v1", "ClusterRole"
		case "/apis/rbac.authorization.k8s.io/v1/rolebindings":
			version, kind = "rbac.authorization.k8s.io/v1", "RoleBinding"
		case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			version, kind = "rbac.authorization.k8s.io/v1", "ClusterRoleBinding"
		case "/apis/apps/v1/deployments":
			version, kind = "apps/v1", "Deployment"
		case "/apis/apps/v1/statefulsets":
			version, kind = "apps/v1", "StatefulSet"
		case "/apis/apps/v1/daemonsets":
			version, kind = "apps/v1", "DaemonSet"
		case "/apis/batch/v1/jobs":
			version, kind = "batch/v1", "Job"
		case "/apis/batch/v1/cronjobs":
			version, kind = "batch/v1", "CronJob"
		default:
			http.Error(w, "unexpected phase", 400)
			return
		}
		_, _ = fmt.Fprintf(w, `{"apiVersion":%q,"kind":%q,"metadata":{"continue":%q},"items":%s}`, version, kind+"List", next, items)
	}))
	defer provider.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})
	fga := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controlled-fga-token" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer fga.Close()
	token := filepath.Join(t.TempDir(), "fga-token")
	if err := os.WriteFile(token, []byte("controlled-fga-token"), 0400); err != nil {
		t.Fatal(err)
	}
	cfg := validDiscoveryRuntimeConfig()
	cfg.PostgresDSN = os.Getenv("ZASP_P4B_WORKER_DSN")
	cfg.ParserVersion, cfg.ToolVersion = "parser_v1", "tool_v1"
	cfg.AWSCollectorVersion, cfg.KubernetesCollectorVersion, cfg.GitHubCollectorVersion, cfg.OktaCollectorVersion = "collector_v1", "collector_v1", "collector_v1", "collector_v1"
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: namespace, TaskQueue: namespace + "-agents", DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: token, Timeout: 10 * time.Second}
	q := &productRuntimeQueue{}
	var closed atomic.Int32
	var storage *productVersionedS3
	restartBoundary := make(chan struct{})
	var boundaryReached atomic.Bool
	external := productionWorkerIO()
	external.discovery = func(config productionDiscoveryDependencyConfig) (discoveryDependencyIO, error) {
		io := productRuntimeIO(t, config, q, &closed)
		io.Secrets = continuationSecrets{config.Cloud.SecretRoot, ca}
		network := continuationNetwork{provider.Listener.Addr().String()}
		io.KubernetesNetwork = &kubernetesdiscovery.CollectionNetwork{Resolver: network, Dialer: network}
		if storage == nil {
			storage = io.S3.(*productRuntimeS3).productVersionedS3
		} else {
			io.S3.(*productRuntimeS3).productVersionedS3 = storage
		}
		storage.observe = func(stage string, ctx context.Context, err error) {
			remaining := time.Duration(0)
			if deadline, ok := ctx.Deadline(); ok {
				remaining = time.Until(deadline)
			}
			t.Log("artifact boundary refused", stage, "provider pages", pages.Load(), "context", ctx.Err(), "remaining", remaining, "error", err)
		}
		storage.beforePut = func(ctx context.Context) error {
			if pages.Load() == 256 && boundaryReached.CompareAndSwap(false, true) {
				close(restartBoundary)
				select {
				case <-activity.GetWorkerStopChannel(ctx):
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}
		return io, nil
	}
	deps, err := buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("continuation shipped startup", err)
	}
	defer deps.Close()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	outboxConfig := validSchedulerRuntimeConfig()
	outboxConfig.Mode, outboxConfig.DatabaseAuthority, outboxConfig.WorkerID = workerModeOutbox, "zasp_outbox_worker", "owned-p4b-outbox"
	outboxConfig.DiscoveryQueueURL, outboxConfig.AWSRegion = cfg.DiscoveryQueueURL, cfg.AWSRegion
	outboxConfig.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-outbox"
	outboxConfig.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	outboxConfig.PostgresDSN = os.Getenv("ZASP_P4B_OUTBOX_DSN")
	outboxConfig.RuntimeServices = cfg.RuntimeServices
	external.outbox = func(workerRuntimeConfig) (outboxDependencyIO, error) {
		return outboxDependencyIO{Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "ASIAEXAMPLE000001", SecretAccessKey: strings.Repeat("s", 40), SessionToken: strings.Repeat("t", 32), CanExpire: true, Expires: time.Now().Add(time.Hour)}, nil
		}), Queue: q, Close: func() error { return nil }}, nil
	}
	outbox, err := buildWorkerRuntimeWithIO(ctx, outboxConfig, external)
	if err != nil {
		t.Fatal("continuation outbox", err)
	}
	defer outbox.Close()
	if err := outbox.Processor.RunOnce(ctx); err != nil {
		t.Fatal("production queue publish", err)
	}
	if err := deps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("sole stable starter", err)
	}
	id, _ := orchestration.DiscoveryWorkflowID(start)
	description, err := c.DescribeWorkflowExecution(ctx, id, "")
	if err != nil {
		t.Fatal(err)
	}
	firstRun := description.WorkflowExecutionInfo.Execution.RunId
	type completed struct {
		result orchestration.DiscoveryResult
		err    error
	}
	completion, joined := make(chan completed, 1), make(chan struct{})
	waitCtx, waitCancel := context.WithCancel(ctx)
	go func() {
		defer close(joined)
		var result orchestration.DiscoveryResult
		err := c.GetWorkflow(waitCtx, id, firstRun).Get(waitCtx, &result)
		completion <- completed{result, err}
	}()
	defer func() { waitCancel(); <-joined }()
	select {
	case result := <-completion:
		t.Fatal("ended before cold restart", result, pages.Load())
	case <-ctx.Done():
		t.Fatal("restart boundary", ctx.Err())
	case <-restartBoundary:
	}
	// The external write boundary sees the SDK stop signal, then the Activity
	// finishes its durable receipt before Close joins and releases its cache.
	if err := deps.Close(); err != nil || closed.Load() != 1 || pages.Load() != 256 {
		t.Fatal("joined boundary stop", closed.Load(), pages.Load(), err)
	}
	deps, err = buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("cold worker construction", err)
	}
	defer deps.Close()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("cold worker readiness", err)
	}
	t.Log("cold worker restarted from verified storage at page", pages.Load())
	result := <-completion
	if result.err != nil || result.result.Outcome != "succeeded" {
		t.Fatal("continued sync", result.result, pages.Load(), result.err)
	}
	if pages.Load() != 267 || storage.writes != 534 {
		t.Fatal("fresh page or artifact replay", pages.Load(), storage.writes)
	}
	history := c.GetWorkflowHistory(ctx, id, firstRun, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	continued := false
	for history.HasNext() {
		event, err := history.Next()
		if err != nil {
			t.Fatal(err)
		}
		if a := event.GetWorkflowExecutionContinuedAsNewEventAttributes(); a != nil {
			var next orchestration.DiscoveryStart
			if converter.GetDefaultDataConverter().FromPayloads(a.Input, &next) != nil || next.Continuation == nil || next.Continuation.CheckpointVersion != 256 || !next.Continuation.Deadline.Equal(start.Continuation.Deadline) || next.Ref != start.Ref || next.IntegrationID != start.IntegrationID || a.NewExecutionRunId == firstRun {
				t.Fatal("continuation lost scoped receipt or original budget")
			}
			continued = true
			t.Log("actual Continue-As-New receipt", next.Continuation.CheckpointVersion, "original deadline", next.Continuation.Deadline)
		}
	}
	if !continued {
		t.Fatal("inventory stopped short of real history boundary")
	}
	if err := deps.Close(); err != nil || closed.Load() != 2 {
		t.Fatal("joined continuation shutdown", closed.Load(), err)
	}
}
