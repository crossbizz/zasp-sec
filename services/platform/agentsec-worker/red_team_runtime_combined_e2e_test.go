package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue/sqsdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// Runs inside the pinned Promptfoo image against the harness-owned PostgreSQL
// and LocalStack. Only the final customer invocation is a deterministic fixture;
// worker, engine, TLS adapter, lease resolver, outbox, queue and storage are real.
func TestProductionCombinedE2ERedTeamRuntime(t *testing.T) {
	if os.Getenv("ZASP_RED_TEAM_RUNTIME_PROOF") != "true" {
		t.Skip("requires the owned combined runtime container")
	}
	if os.Getuid() != 1000 || os.Getgid() != 1000 {
		t.Fatal("runtime proof must use the production image user")
	}
	dsn, err := url.Parse(os.Getenv("ZASP_RED_TEAM_RUNTIME_DSN"))
	if err != nil || dsn.Scheme != "postgres" || dsn.Hostname() != "host.docker.internal" || dsn.Port() == "" || dsn.User.Username() != "zasp_e2e" || dsn.Path != "/postgres" || dsn.RawQuery != "sslmode=disable" {
		t.Fatal("disposable database identity rejected")
	}
	endpoint, err := url.Parse(os.Getenv("ZASP_RED_TEAM_RUNTIME_AWS"))
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "host.docker.internal" || endpoint.Port() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		t.Fatal("disposable AWS endpoint rejected")
	}
	runID := os.Getenv("ZASP_RED_TEAM_RUNTIME_RUN_ID")
	workerID(t, runID)
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	var initial string
	if err := admin.QueryRow(ctx, `SELECT state||'|'||attempt FROM zasp_red_team_runs WHERE run_id=$1`, runID).Scan(&initial); err != nil || initial != "queued|0" {
		t.Fatalf("browser did not queue an untouched run: %s %v", initial, err)
	}
	database := func(principal string) apiserver.JSONDatabase {
		copy := *dsn
		copy.User = url.User(principal)
		return combinedE2ERecoveryDatabase(t, ctx, copy.String())
	}
	awsEndpoint := endpoint.String()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	base := aws.Config{Region: "us-east-1", HTTPClient: client, Retryer: func() aws.Retryer { return aws.NopRetryer{} }, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
	})}
	s3API := s3.NewFromConfig(base, func(o *s3.Options) { o.BaseEndpoint = &awsEndpoint; o.UsePathStyle = true })
	sqsAPI := sqs.NewFromConfig(base, func(o *sqs.Options) { o.BaseEndpoint = &awsEndpoint })
	kmsAPI := kms.NewFromConfig(base, func(o *kms.Options) { o.BaseEndpoint = &awsEndpoint })
	key, err := kmsAPI.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String("Disposable composed Red Team proof")})
	if err != nil {
		t.Fatal(err)
	}
	keyARN := aws.ToString(key.KeyMetadata.Arn)
	const bucket = "zasp-red-team-runtime-proof"
	if _, err := s3API.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s3API.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	dlq, err := sqsAPI.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("red-team-proof-dlq")})
	if err != nil {
		t.Fatal(err)
	}
	dlqAttrs, err := sqsAPI.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: dlq.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
	if err != nil {
		t.Fatal(err)
	}
	redrive, _ := json.Marshal(map[string]string{"deadLetterTargetArn": dlqAttrs.Attributes["QueueArn"], "maxReceiveCount": "5"})
	queueInfo, err := sqsAPI.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("red-team-proof"), Attributes: map[string]string{"VisibilityTimeout": "30", "RedrivePolicy": string(redrive)}})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := sqsdriver.New(sqsAPI, sqsdriver.Config{QueueURL: "https://sqs.us-east-1.amazonaws.com/000000000000/red-team-proof", VisibilityTimeoutSeconds: 30, MaximumReceiveCount: 5})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: 5 * time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := newProductionDiscoveryArtifactAuthority(s3API, productionDiscoveryArtifactConfig{Bucket: bucket, ExpectedBucketOwner: "000000000000", KMSKeyARN: keyARN, MaximumBytes: 1 << 20, OperationTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := redteamadapter.NewPostgresResolver(database("zasp_e2e_red_team_adapter"), migrations.ProductionRedTeamInvocation().Checksum(), migrations.ProductionRedTeamInvocationSemanticFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Ready(ctx); err != nil {
		t.Fatal("registered schema-38 adapter is not ready", err)
	}
	fixture := &redTeamRuntimeCustomerFixture{runID: runID}
	token := bytes.Repeat([]byte("r"), 64)
	handler, err := redteamadapter.NewHandler(redteamadapter.Config{WorkerToken: token, MaximumRequestBytes: 64 << 10}, resolver, fixture)
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	// This exact secret mount is an owned in-memory filesystem in the proof image.
	caFile := redTeamRuntimeTLS(t, "/var/run/secrets/zasp-red-team", handler)
	tokenFile := "/var/run/secrets/zasp-red-team/adapter-token"
	if err := os.WriteFile(tokenFile, token, 0o400); err != nil {
		t.Fatal(err)
	}
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{Artifacts: artifacts, Command: productionRedTeamCommand{}, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate", TargetTokenFile: tokenFile, TargetCAFile: caFile, TempRoot: temp, Timeout: 90 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	publisher := &redTeamRuntimeDuplicatePublisher{queue: queue}
	queueReady := func(ctx context.Context) error {
		_, err := sqsAPI.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queueInfo.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
		return err
	}
	outboxConfig := validRedTeamOutboxRuntimeConfig()
	outboxConfig.PostgresDSN = strings.Replace(dsn.String(), "zasp_e2e@", "zasp_e2e_red_team_outbox@", 1)
	outbox, err := composeRedTeamOutboxWorkerRuntime(outboxConfig, database("zasp_e2e_red_team_outbox"), publisher, queueReady)
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	workerConfig := validRedTeamRuntimeConfig()
	workerConfig.PostgresDSN = strings.Replace(dsn.String(), "zasp_e2e@", "zasp_e2e_red_team_worker@", 1)
	workerConfig.BatchSize = 1
	workerConfig.RedTeamTargetTokenFile, workerConfig.RedTeamTargetCAFile = tokenFile, caFile
	workerConfig.RedTeamRunnerTimeout = 90 * time.Second
	if !validWorkerRuntimeConfig(workerConfig) {
		t.Fatal("proof must preserve the production worker configuration boundary")
	}
	// Local SDK services are real, but test credentials do not attest a cloud role.
	localReady := func(ctx context.Context) error {
		if err := queueReady(ctx); err != nil {
			return err
		}
		if _, err := s3API.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String("000000000000")}); err != nil {
			return err
		}
		return resolver.Ready(ctx)
	}
	worker, err := composeRedTeamWorkerRuntime(workerConfig, database("zasp_e2e_red_team_worker"), &productionRedTeamDependencies{Queue: queue, Runner: runner, ready: localReady, close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	if err := outbox.Ready(ctx); err != nil {
		t.Fatal("composed outbox readiness", err)
	}
	if err := worker.Ready(ctx); err != nil {
		t.Fatal("composed worker readiness", err)
	}
	// The fair outbox claim intentionally returns only one event per tenant per
	// pass. The earlier browser cancellation also has a pending terminal delivery.
	for pass := 0; pass < 10; pass++ {
		if err := outbox.Processor.RunOnce(ctx); err != nil {
			t.Fatal("outbox publication", err)
		}
		var published bool
		if err := admin.QueryRow(ctx, `SELECT state='published' FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1`, runID).Scan(&published); err != nil {
			t.Fatal(err)
		}
		if published {
			break
		}
		if pass == 9 {
			t.Fatal("target run outbox was not published within the bounded drain")
		}
	}
	if publisher.published < 1 || publisher.published > 10 {
		t.Fatal("no bounded real publication")
	}
	// Both deliveries are physically published through SQS. The second must ACK
	// the terminal run without a second engine invocation or stored attempt.
	for i := 0; i < publisher.published*2; i++ {
		if err := worker.Processor.RunOnce(ctx); err != nil {
			t.Fatalf("delivery %d failed: %v", i, err)
		}
	}
	var summary string
	if err := admin.QueryRow(ctx, `SELECT concat_ws('|',state,attempt,COALESCE(verdict,'none'),COALESCE(error_code,'none')) FROM zasp_red_team_runs WHERE run_id=$1`, runID).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	if summary != "complete|1|fail|none" {
		t.Fatalf("runtime result=%s customer calls=%d", summary, fixture.calls.Load())
	}
	var state, verdict, objectKey, version string
	var attempt, attempts, published int
	var checksum []byte
	var size int64
	var leaseCleared bool
	if err := admin.QueryRow(ctx, `SELECT state,verdict,attempt,evidence_key,evidence_version_id,evidence_checksum,evidence_size,lease_token IS NULL AND worker_id IS NULL AND lease_expires_at IS NULL,(SELECT count(*) FROM zasp_red_team_attempts WHERE run_id=$1),(SELECT count(*) FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1 AND state='published') FROM zasp_red_team_runs WHERE run_id=$1`, runID).Scan(&state, &verdict, &attempt, &objectKey, &version, &checksum, &size, &leaseCleared, &attempts, &published); err != nil {
		t.Fatal(err)
	}
	if state != "complete" || verdict != "fail" || attempt != 1 || attempts != 1 || published != 1 || !leaseCleared || fixture.calls.Load() != 1 {
		t.Fatalf("runtime result state=%s verdict=%s attempt=%d stored=%d publication=%d cleared=%v calls=%d", state, verdict, attempt, attempts, published, leaseCleared, fixture.calls.Load())
	}
	object, err := s3API.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(objectKey), VersionId: aws.String(version), ExpectedBucketOwner: aws.String("000000000000")})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(object.Body, 1<<20))
	object.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if size != int64(len(body)) || !bytes.Equal(checksum, digest[:]) || aws.ToString(object.VersionId) != version || object.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || aws.ToString(object.SSEKMSKeyId) != keyARN {
		t.Fatal("durable S3 version/checksum/KMS binding differs from PostgreSQL")
	}
	var evidence redTeamRunnerOutput
	if json.Unmarshal(body, &evidence) != nil || evidence.RunID != runID || evidence.Verdict != "fail" || evidence.EngineVersion != "0.121.19" || len(evidence.Evidence) != 1 || evidence.Evidence[0] != "prompt_injection: unsafe behavior observed" {
		t.Fatalf("unexpected normalized evidence: %s", body)
	}
	for _, secret := range []string{string(token), "proof-secret-fixture", "ZASP_RED_TEAM_PROMPT_INJECTION", "lease_token", "ref:red-team/"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("private adapter output leaked into evidence")
		}
	}
	for _, queueURL := range []*string{queueInfo.QueueUrl, dlq.QueueUrl} {
		attrs, err := sqsAPI.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queueURL, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameApproximateNumberOfMessages, sqstypes.QueueAttributeNameApproximateNumberOfMessagesNotVisible, sqstypes.QueueAttributeNameApproximateNumberOfMessagesDelayed}})
		if err != nil || attrs.Attributes["ApproximateNumberOfMessages"] != "0" || attrs.Attributes["ApproximateNumberOfMessagesNotVisible"] != "0" || attrs.Attributes["ApproximateNumberOfMessagesDelayed"] != "0" {
			t.Fatalf("queue/DLQ not empty: %v %v", attrs, err)
		}
		empty, err := sqsAPI.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 1, WaitTimeSeconds: 1})
		if err != nil || len(empty.Messages) != 0 {
			t.Fatalf("queue/DLQ empty receive failed: %v %v", empty, err)
		}
	}
	t.Log("red team runtime proof passed: browser queue, real outbox/SQS duplicate ACK, pinned Promptfoo, TLS Go adapter with live PostgreSQL lease, one fail attempt, versioned KMS evidence; customer invocation fixture only")
}

type redTeamRuntimeDuplicatePublisher struct {
	queue     *jobqueue.Queue
	published int
}

func (p *redTeamRuntimeDuplicatePublisher) PublishBatch(ctx context.Context, jobs []jobqueue.Job) (jobqueue.PublishResult, error) {
	first, err := p.queue.PublishBatch(ctx, jobs)
	if err != nil {
		return first, err
	}
	second, err := p.queue.PublishBatch(ctx, jobs)
	if err != nil {
		return second, err
	}
	if !exactOutboxPublishResult(first, jobs) || !exactOutboxPublishResult(second, jobs) {
		return jobqueue.PublishResult{}, errWorkerExecution
	}
	p.published += len(jobs)
	return first, nil
}

type redTeamRuntimeCustomerFixture struct {
	runID string
	calls atomic.Int32
}

func (f *redTeamRuntimeCustomerFixture) Invoke(_ context.Context, request redteamadapter.Invocation) (string, error) {
	if request.RunID != f.runID || request.Scope.OrganizationID().String() != "pid_10000001-0000-4000-8000-000000000001" || request.Scope.WorkspaceID().String() != "pid_10000022-0000-4000-8000-000000000022" || request.Scope.EnvironmentID().String() != "pid_10000023-0000-4000-8000-000000000023" || request.Binding.TargetID != "pid_7f300003-0000-4000-8000-000000000003" || request.Binding.CredentialReference != "ref:red-team/target_e2e_0001" || request.Binding.Endpoint != "https://adapter.customer.example/v1/evaluate" || request.Binding.TargetKind != "agent_endpoint" || request.Binding.Version != 1 || request.Category != "prompt_injection" || !strings.Contains(request.Input, "ZASP_RED_TEAM_PROMPT_INJECTION") {
		return "", redteamadapter.ErrAdapter
	}
	f.calls.Add(1)
	return "ZASP_RED_TEAM_PROMPT_INJECTION proof-secret-fixture", nil
}

func redTeamRuntimeTLS(t *testing.T, directory string, handler http.Handler) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-red-team-adapter"}, DNSNames: []string{"agentsec-red-team-adapter.zasp.svc.cluster.local"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(directory, "adapter-ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o400); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; err != http.ErrServerClosed {
			t.Error(err)
		}
	})
	return caFile
}
