package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// Launched by the owned PostgreSQL parent. Only external AWS inventory/security,
// secrets/STS and S3 are controlled; product SQL and all collection adapters run.
func TestProductDiscoveryInstalledCollector(t *testing.T) {
	dsn := os.Getenv("ZASP_P4B_WORKER_DSN")
	if dsn == "" {
		t.Skip("requires owned discovery72 PostgreSQL parent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	var start orchestration.DiscoveryStart
	if err := json.Unmarshal([]byte(os.Getenv("ZASP_P4B_START")), &start); err != nil || start.Continuation == nil {
		t.Fatal("start", err)
	}
	now := func() time.Time { return time.Now().UTC() }
	credentials, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: productSecretReader(func(context.Context, string) ([]byte, error) { return []byte("external-id-customer-0001"), nil }), AssumeRole: &discoveryAssumeRoleStub{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE000001"), SecretAccessKey: aws.String(strings.Repeat("s", 40)), SessionToken: aws.String(strings.Repeat("t", 32)), Expiration: aws.Time(now().Add(time.Hour))}}}, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	storage := &productVersionedS3{items: map[string]*discoveryS3APIStub{}}
	artifacts, err := newProductionDiscoveryArtifactAuthority(storage, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: 5 * time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := newProductionLiveDiscoveryCollectorFactory(productionDiscoveryClientConfig{Artifacts: artifacts, Credentials: credentials, AWSInventory: &discoveryInventoryCallerStub{}, AWSSecurity: &discoverySecurityAnalyzerStub{}, AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "collector_v1", GitHubCollectorVersion: "collector_v1", OktaCollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", KubernetesAllowedCIDRs: []string{"203.0.113.0/24"}, ProviderTimeout: time.Second, ReadinessTimeout: time.Second, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	product, err := newTemporalDiscoveryProduct(&discoveryProductObservedDB{JSONDatabase: db, t: t}, factory)
	if err != nil {
		t.Fatal("installed product", err)
	}
	deadline := start.Continuation.Deadline
	start.Continuation = nil
	command := orchestration.DiscoveryPageCommand{Start: start, Deadline: deadline}
	var page orchestration.DiscoveryPage
	for n := 1; n <= 4; n++ {
		page, err = product.CollectDiscoveryPage(ctx, command)
		want := "partial"
		if n == 4 {
			want = "complete"
		}
		if err != nil || page.Outcome != want {
			t.Fatal("actual bounded fresh page", n, page, err)
		}
		writes := storage.writes
		replay, err := product.CollectDiscoveryPage(ctx, command)
		if err != nil || replay != page || storage.writes != writes || writes != n*2 {
			t.Fatal("page replay/resume storage", n, replay, err, writes, storage.writes)
		}
		command.ExpectedCheckpointVersion, command.ExpectedCheckpointDigest = page.CheckpointVersion, page.ReceiptDigest
	}
	receipt, err := product.ApplyDiscoverySnapshot(ctx, orchestration.DiscoveryApplyCommand{Start: start, Deadline: deadline, CompleteReceiptDigest: page.ReceiptDigest})
	if err != nil || len(receipt) != 64 {
		t.Fatal("typed application", receipt, err)
	}
	if err := product.FinishDiscovery(ctx, orchestration.DiscoveryFinish{Start: start, Outcome: "succeeded", ReceiptDigest: receipt}); err != nil {
		t.Fatal("finish", err)
	}
	settled, err := product.ReconcileDiscoveryOutcome(ctx, orchestration.DiscoveryReconcile{Start: start, Deadline: deadline, Reason: "cancelled"})
	if err != nil || settled.Outcome != "succeeded" || settled.ReceiptDigest != receipt {
		t.Fatal("settlement", settled, err)
	}
	if err := product.Ready(ctx); err != nil {
		t.Fatal("ordinary inventory content changed readiness", err)
	}
}

// Controlled external S3 IO with actual version-pinned bytes. The real S3
// driver still performs conditional Put, Head/Get readback and integrity checks.
type productVersionedS3 struct {
	mu        sync.Mutex
	items     map[string]*discoveryS3APIStub
	writes    int
	reads     int
	observe   func(string, context.Context, error)
	beforePut func(context.Context) error
}

func (s *productVersionedS3) PutObject(ctx context.Context, in *s3.PutObjectInput, options ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if s.beforePut != nil {
		if err := s.beforePut(ctx); err != nil {
			return nil, err
		}
	}
	if err := collection.CheckEffectBoundary(ctx); err != nil {
		if s.observe != nil {
			s.observe("put current authority", ctx, err)
		}
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := aws.ToString(in.Bucket) + "/" + aws.ToString(in.Key)
	if s.items[key] != nil {
		return nil, errors.New("controlled conditional conflict")
	}
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	stub := &discoveryS3APIStub{body: body}
	out, err := stub.PutObject(ctx, in, options...)
	if err == nil {
		s.items[key] = stub
		s.writes++
	}
	return out, err
}
func (s *productVersionedS3) HeadObject(ctx context.Context, in *s3.HeadObjectInput, options ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if err := collection.CheckEffectBoundary(ctx); err != nil {
		if s.observe != nil {
			s.observe("head current authority", ctx, err)
		}
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	stub := s.items[aws.ToString(in.Bucket)+"/"+aws.ToString(in.Key)]
	if stub == nil || in.VersionId != nil && aws.ToString(in.VersionId) != "version-0001" {
		return nil, errors.New("controlled version missing")
	}
	return stub.HeadObject(ctx, in, options...)
}
func (s *productVersionedS3) GetObject(ctx context.Context, in *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if err := collection.CheckEffectBoundary(ctx); err != nil {
		if s.observe != nil {
			s.observe("get current authority", ctx, err)
		}
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	stub := s.items[aws.ToString(in.Bucket)+"/"+aws.ToString(in.Key)]
	if stub == nil || aws.ToString(in.VersionId) != "version-0001" {
		return nil, errors.New("controlled version missing")
	}
	return stub.GetObject(ctx, in, options...)
}

type discoveryProductObservedDB struct {
	apiserver.JSONDatabase
	t *testing.T
}

func (d *discoveryProductObservedDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	raw, err := d.JSONDatabase.QueryJSON(ctx, q, args...)
	d.t.Log("product SQL", q, "error", err)
	if strings.Contains(q, "prepare_page") && err == nil {
		var value struct {
			Input *apiserver.DiscoveryCollectionInput `json:"input"`
			Page  *orchestration.DiscoveryPage        `json:"page"`
		}
		decode := json.Unmarshal(raw, &value)
		if value.Input != nil {
			d.t.Log("prepared input", value.Input.Provider, "observation zone", value.Input.ObservationTime.Location(), "deadline zone", value.Input.Deadline.Location(), "configuration bytes", len(value.Input.Configuration), "decode", decode)
		}
	}
	return raw, err
}
