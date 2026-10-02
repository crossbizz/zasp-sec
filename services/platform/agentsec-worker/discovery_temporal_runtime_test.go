package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"go.temporal.io/api/operatorservice/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

type productRuntimeS3 struct {
	*productVersionedS3
	*discoveryArtifactReadinessStub
}
type productRuntimeSTS struct {
	*discoveryAssumeRoleStub
	*discoveryArtifactReadinessStub
}
type productRuntimeQueue struct {
	discoveryQueueAPIStub
	mu   sync.Mutex
	body string
	ack  bool
}

func (q *productRuntimeQueue) SendMessageBatch(_ context.Context, in *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(in.Entries) != 1 {
		return nil, fmt.Errorf("unexpected fixture batch")
	}
	entry := in.Entries[0]
	q.body = aws.ToString(entry.MessageBody)
	q.ack = false
	sum := md5.Sum([]byte(q.body))
	return &sqs.SendMessageBatchOutput{Successful: []sqstypes.SendMessageBatchResultEntry{{Id: entry.Id, MessageId: aws.String("owned-p4b-message-1"), MD5OfMessageBody: aws.String(fmt.Sprintf("%x", sum))}}}, nil
}

func (q *productRuntimeQueue) ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ack || q.body == "" {
		return &sqs.ReceiveMessageOutput{}, nil
	}
	d := md5.Sum([]byte(q.body))
	return &sqs.ReceiveMessageOutput{Messages: []sqstypes.Message{{Body: aws.String(q.body), MD5OfBody: aws.String(fmt.Sprintf("%x", d)), MessageId: aws.String("owned-p4b-message-1"), ReceiptHandle: aws.String("owned-p4b-receipt-1"), Attributes: map[string]string{"ApproximateReceiveCount": "1"}}}}, nil
}
func (q *productRuntimeQueue) DeleteMessageBatch(_ context.Context, in *sqs.DeleteMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := &sqs.DeleteMessageBatchOutput{}
	for _, entry := range in.Entries {
		if aws.ToString(entry.ReceiptHandle) != "owned-p4b-receipt-1" {
			return nil, fmt.Errorf("foreign receipt")
		}
		out.Successful = append(out.Successful, sqstypes.DeleteMessageBatchResultEntry{Id: entry.Id})
	}
	q.ack = true
	return out, nil
}

// Only provider/cloud IO is controlled. Dependency composition still builds
// the real Secrets Manager reader, credential resolver, S3/SQS drivers, AWS
// inventory adapter and four-provider factory in shipped production code.
func productRuntimeIO(t *testing.T, cfg productionDiscoveryDependencyConfig, q *productRuntimeQueue, closed *atomic.Int32) discoveryDependencyIO {
	t.Helper()
	keyID := "11111111-1111-4111-8111-111111111111"
	ready := &discoveryArtifactReadinessStub{
		head: &s3.HeadBucketOutput{BucketRegion: aws.String(cfg.Cloud.Region)}, versioning: &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled},
		encryption: &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String(cfg.Artifacts.KMSKeyARN)}, BucketKeyEnabled: aws.Bool(true)}}}},
		key:        &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{AWSAccountId: aws.String(cfg.Artifacts.ExpectedBucketOwner), Arn: aws.String(cfg.Artifacts.KMSKeyARN), KeyId: aws.String(keyID), Enabled: true, KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeySpec: kmstypes.KeySpecSymmetricDefault, Origin: kmstypes.OriginTypeAwsKms}},
		identity:   &sts.GetCallerIdentityOutput{Account: aws.String(cfg.Artifacts.ExpectedBucketOwner), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/" + cfg.Cloud.RoleARN[strings.LastIndex(cfg.Cloud.RoleARN, "/")+1:] + "/owned-p4b")},
	}
	queueARN := "arn:aws:sqs:" + cfg.Cloud.Region + ":123456789012:agentsec-discovery-jobs"
	q.output = &sqs.GetQueueAttributesOutput{Attributes: map[string]string{"QueueArn": queueARN, "RedrivePolicy": `{"deadLetterTargetArn":"` + queueARN + `-dlq","maxReceiveCount":"5"}`}}
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	return discoveryDependencyIO{
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "ASIAEXAMPLE000001", SecretAccessKey: strings.Repeat("s", 40), SessionToken: strings.Repeat("t", 32), CanExpire: true, Expires: expiry}, nil
		}),
		Secrets:    &discoverySecretsManagerStub{output: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte("external-id-customer-0001")}},
		AssumeRole: &productRuntimeSTS{&discoveryAssumeRoleStub{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE000001"), SecretAccessKey: aws.String(strings.Repeat("s", 40)), SessionToken: aws.String(strings.Repeat("t", 32)), Expiration: aws.Time(expiry)}}}, ready},
		S3:         &productRuntimeS3{&productVersionedS3{items: map[string]*discoveryS3APIStub{}}, ready}, KMS: ready, Queue: q,
		Inventory: discoveryAWSInventoryFactory{Identity: func(string, aws.Credentials) (discoveryCallerIdentityAPI, error) {
			return &discoveryCallerIdentityStub{output: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp/owned-p4b")}}, nil
		}, IAM: func(string, aws.Credentials) (discoveryAWSIAMAPI, error) { return &discoveryInventoryIAMStub{}, nil }, EC2: func(region string, _ aws.Credentials) (discoveryAWSEC2API, error) {
			return &discoveryInventoryEC2Stub{region: region}, nil
		}},
		Security: &discoverySecurityAnalyzerStub{}, Close: func() error { closed.Add(1); return nil },
	}
}

func TestProductDiscoveryShippedTemporalRuntime(t *testing.T) {
	dsn := os.Getenv("ZASP_P4B_WORKER_DSN")
	if dsn == "" {
		t.Skip("requires owned72 PostgreSQL parent and local Temporal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	_, err = c.WorkflowService().RegisterNamespace(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, Description: "P4B owned local integration", WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteOwnedDiscoveryNamespace(t, c, namespace)
	info, err := c.WorkflowService().GetSystemInfo(ctx, &workflowservice.GetSystemInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("local Temporal", info.ServerVersion, "namespace", namespace)
	fga := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controlled-fga-token" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer fga.Close()
	token := filepath.Join(t.TempDir(), "fga-token")
	if err := os.WriteFile(token, []byte("controlled-fga-token"), 0400); err != nil {
		t.Fatal(err)
	}
	cfg := validDiscoveryRuntimeConfig()
	cfg.PostgresDSN = dsn
	cfg.ParserVersion = "parser_v1"
	cfg.ToolVersion = "tool_v1"
	cfg.AWSCollectorVersion = "collector_v1"
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: namespace, TaskQueue: namespace + "-agents", DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: token, Timeout: 10 * time.Second}
	q := &productRuntimeQueue{}
	var closed atomic.Int32
	var storage *productVersionedS3
	firstIO, releaseIO := make(chan struct{}), make(chan struct{})
	var firstBlocked atomic.Bool
	var releaseOnce sync.Once
	releaseFirst := func() { releaseOnce.Do(func() { close(releaseIO) }) }
	defer releaseFirst()
	external := productionWorkerIO()
	external.discovery = func(config productionDiscoveryDependencyConfig) (discoveryDependencyIO, error) {
		io := productRuntimeIO(t, config, q, &closed)
		storage = io.S3.(*productRuntimeS3).productVersionedS3
		io.S3.(*productRuntimeS3).productVersionedS3.beforePut = func(ctx context.Context) error {
			if firstBlocked.CompareAndSwap(false, true) {
				close(firstIO)
				select {
				case <-releaseIO:
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
		t.Fatal("shipped72 startup", err)
	}
	defer func() {
		releaseFirst()
		if err := deps.Close(); err != nil {
			t.Error("joined shutdown", err)
		}
	}()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("shipped72 readiness", err)
	}
	schedulerConfig := validSchedulerRuntimeConfig()
	schedulerConfig.PostgresDSN = os.Getenv("ZASP_P4B_SCHEDULER_DSN")
	schedulerConfig.RuntimeServices = cfg.RuntimeServices
	scheduler, err := buildWorkerRuntimeWithIO(ctx, schedulerConfig, external)
	if err != nil {
		t.Fatal("shipped scheduler startup", err)
	}
	defer scheduler.Close()
	if err := scheduler.Processor.RunOnce(ctx); err != nil {
		t.Fatal("schedule delivery", err)
	}
	scheduleRef := orchestration.DiscoveryScheduleRef{OrganizationID: start.Ref.OrganizationID, WorkspaceID: start.Ref.WorkspaceID, EnvironmentID: start.Ref.EnvironmentID, IntegrationID: start.IntegrationID, ScheduleID: os.Getenv("ZASP_P4B_SCHEDULE_ID")}
	scheduleID, _ := orchestration.DiscoveryScheduleID(scheduleRef)
	if _, err := c.ScheduleClient().GetHandle(ctx, scheduleID).Describe(ctx); err != nil {
		t.Fatal("schedule missing", err)
	}
	if err := c.ScheduleClient().GetHandle(ctx, scheduleID).Delete(ctx); err != nil {
		t.Fatal("owned schedule deletion", err)
	}
	if err := scheduler.Close(); err != nil {
		t.Fatal(err)
	}
	scheduler, err = buildWorkerRuntimeWithIO(ctx, schedulerConfig, external)
	if err != nil {
		t.Fatal("repair scheduler startup", err)
	}
	defer scheduler.Close()
	if err := scheduler.Processor.RunOnce(ctx); err != nil {
		t.Fatal("missing schedule repair", err)
	}
	if description, err := c.ScheduleClient().GetHandle(ctx, scheduleID).Describe(ctx); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("repaired Schedule: now=%s spec=%+v state=%+v info=%+v", time.Now().UTC(), description.Schedule.Spec, description.Schedule.State, description.Info)
	}
	outboxConfig := validSchedulerRuntimeConfig()
	outboxConfig.Mode, outboxConfig.DatabaseAuthority, outboxConfig.WorkerID = workerModeOutbox, "zasp_outbox_worker", "owned-p4b-outbox"
	outboxConfig.PostgresDSN = os.Getenv("ZASP_P4B_OUTBOX_DSN")
	outboxConfig.DiscoveryQueueURL, outboxConfig.AWSRegion = cfg.DiscoveryQueueURL, cfg.AWSRegion
	outboxConfig.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-outbox"
	outboxConfig.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	var outboxClosed atomic.Int32
	external.outbox = func(workerRuntimeConfig) (outboxDependencyIO, error) {
		return outboxDependencyIO{Queue: q, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "ASIAEXAMPLE000001", SecretAccessKey: strings.Repeat("s", 40), SessionToken: strings.Repeat("t", 32)}, nil
		}), Close: func() error { outboxClosed.Add(1); return nil }}, nil
	}
	outbox, err := buildWorkerRuntimeWithIO(ctx, outboxConfig, external)
	if err != nil {
		t.Fatal("shipped outbox startup", err)
	}
	defer outbox.Close()
	if err := outbox.Ready(ctx); err != nil {
		t.Fatal("shipped outbox ready", err)
	}
	if err := outbox.Processor.RunOnce(ctx); err != nil {
		t.Fatal("shipped SQL to SQS delivery", err)
	}
	if err := deps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("sole shipped start", err)
	}
	id, _ := orchestration.DiscoveryWorkflowID(start)
	select {
	case <-firstIO:
	case <-ctx.Done():
		t.Fatal("first active effect", ctx.Err())
	}
	httpHandler, scope := productDiscoveryHTTP(t, ctx)
	manualID := productManualHTTP(t, httpHandler, scope, start.IntegrationID)
	deliver := func() string {
		t.Helper()
		if err := outbox.Processor.RunOnce(ctx); err != nil {
			t.Fatal("new SQL outbox delivery", err)
		}
		q.mu.Lock()
		body := q.body
		q.mu.Unlock()
		var envelope struct {
			JobID          string `json:"job_id"`
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
		}
		if json.Unmarshal([]byte(body), &envelope) != nil || envelope.JobID == "" {
			t.Fatal("new canonical envelope")
		}
		if err := deps.Processor.RunOnce(ctx); err != nil {
			t.Fatal("new sole start", err)
		}
		workflowID := strings.Join([]string{"discovery/v1", envelope.OrganizationID, envelope.WorkspaceID, envelope.EnvironmentID, start.IntegrationID, envelope.JobID}, "/")
		return workflowID
	}
	waitSuccess := func(workflowID string) {
		t.Helper()
		var result orchestration.DiscoveryResult
		if err := c.GetWorkflow(ctx, workflowID, "").Get(ctx, &result); err != nil || result.Outcome != "succeeded" {
			t.Fatal("new complete sync", result, err)
		}
	}
	manualWorkflow := deliver()
	waitTicker := time.NewTicker(50 * time.Millisecond)
	defer waitTicker.Stop()
	for {
		value := productSyncHTTP(t, httpHandler, scope, start.IntegrationID, manualID)
		if value.LastErrorCode != nil && *value.LastErrorCode == "retryable" {
			if value.Attempt != 0 || value.Status != "queued" || value.StartedAt != nil || value.RetryAt == nil {
				t.Fatal("overlap wait forged dispatch", value)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("durable overlap wait", ctx.Err())
		case <-waitTicker.C:
		}
	}
	releaseFirst()
	waitSuccess(id)
	waitSuccess(manualWorkflow)
	if value := productSyncHTTP(t, httpHandler, scope, start.IntegrationID, manualID); value.Status != "succeeded" || value.Attempt != 1 || value.SnapshotID == nil || value.RetryAt != nil {
		t.Fatal("completed HTTP readback", value)
	}
	// Wait for our Schedule to produce its nominal occurrence. The Activity,
	// current SQL authority and sole outbox route all remain real.
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		description, err := c.ScheduleClient().GetHandle(ctx, scheduleID).Describe(ctx)
		if err != nil {
			t.Fatal("schedule describe", err)
		}
		if len(description.Info.RecentActions) > 0 {
			action := description.Info.RecentActions[len(description.Info.RecentActions)-1]
			if action.StartWorkflowResult == nil {
				t.Fatal("scheduled workflow missing")
			}
			var admitted orchestration.DiscoveryResult
			if err := c.GetWorkflow(ctx, action.StartWorkflowResult.WorkflowID, action.StartWorkflowResult.FirstExecutionRunID).Get(ctx, &admitted); err != nil || admitted.Outcome != "admitted" {
				t.Fatal("real nominal occurrence", admitted, err)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("scheduled occurrence timeout")
		case <-ticker.C:
		}
	}
	waitSuccess(deliver())
	if raw := os.Getenv("ZASP_P4B_FOREIGN_IDS"); raw != "" {
		var ids []string
		if json.Unmarshal([]byte(raw), &ids) != nil || len(ids) != 5 {
			t.Fatal("second tenant identity")
		}
		foreignHandler, foreignScope := productDiscoveryHTTP(t, ctx, ids)
		foreignRef := scheduleRef
		foreignRef.OrganizationID = ids[0]
		foreignScheduleID, err := orchestration.DiscoveryScheduleID(foreignRef)
		if err != nil || foreignScheduleID == scheduleID {
			t.Fatal("tenant Schedule identity collision", err)
		}
		// The shipped scheduler deliberately scans one desired row per turn in
		// this fixture. Its first post-restart turn repaired the first tenant;
		// this next turn must visit the second tenant using the scoped cursor.
		if err := scheduler.Processor.RunOnce(ctx); err != nil {
			t.Fatal("second tenant desired schedule delivery", err)
		}
		foreignSchedule, err := c.ScheduleClient().GetHandle(ctx, foreignScheduleID).Describe(ctx)
		if err != nil || !foreignSchedule.Schedule.State.Paused {
			t.Fatal("second same-name Schedule missing/active", err)
		}
		foreignID := productManualHTTP(t, foreignHandler, foreignScope, ids[4])
		foreignWorkflow := deliver()
		if foreignWorkflow == id || !strings.HasPrefix(foreignWorkflow, "discovery/v1/"+ids[0]+"/") {
			t.Fatal("tenant run identity collision")
		}
		waitSuccess(foreignWorkflow)
		foreignResult := productSyncHTTP(t, foreignHandler, foreignScope, ids[4], foreignID)
		if foreignResult.Status != "succeeded" || foreignResult.DiscoveredCount != 3 || foreignResult.Attempt != 1 {
			t.Fatal("foreign tenant missed independent inventory", foreignResult)
		}
		for _, response := range []*httptest.ResponseRecorder{productSyncHTTPResponse(httpHandler, scope, start.IntegrationID, foreignID), productSyncHTTPResponse(foreignHandler, foreignScope, ids[4], manualID)} {
			if response.Code != http.StatusNotFound && response.Code != http.StatusForbidden {
				t.Fatal("cross-tenant sync visible", response.Code, response.Body.String())
			}
		}
		storage.mu.Lock()
		ownObjects, foreignObjects := 0, 0
		for key := range storage.items {
			if strings.Contains(key, "/organizations/"+start.Ref.OrganizationID+"/") {
				ownObjects++
			}
			if strings.Contains(key, "/organizations/"+ids[0]+"/") {
				foreignObjects++
			}
		}
		storage.mu.Unlock()
		if ownObjects != 24 || foreignObjects != 8 {
			t.Fatal("cross-tenant artifact storage", ownObjects, foreignObjects)
		}
		t.Log("identical-name connector scopes retained distinct schedules, runs, HTTP receipts and artifact keys")
	}
	if err := outbox.Close(); err != nil || outboxClosed.Load() != 1 {
		t.Fatal("outbox clients not joined", outboxClosed.Load(), err)
	}
	if err := deps.Close(); err != nil || closed.Load() != 1 {
		t.Fatal("owned clients not joined", closed.Load(), err)
	}
	if deps.Ready(context.Background()) == nil {
		t.Fatal("closed worker ready")
	}
	q.mu.Lock()
	acked := q.ack
	q.mu.Unlock()
	if !acked {
		t.Fatal("confirmed start not acknowledged")
	}
}

func deleteOwnedDiscoveryNamespace(t *testing.T, c client.Client, namespace string) {
	t.Helper()
	if !strings.HasPrefix(namespace, "p4b-owned-") {
		t.Fatal("refusing unowned namespace")
	}
	if _, err := strconv.ParseInt(strings.TrimPrefix(namespace, "p4b-owned-"), 10, 64); err != nil {
		t.Fatal("refusing malformed namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	desc, err := c.WorkflowService().DescribeNamespace(ctx, &workflowservice.DescribeNamespaceRequest{Namespace: namespace})
	if err != nil || desc.NamespaceInfo == nil || desc.NamespaceInfo.Description != "P4B owned local integration" {
		t.Error("namespace ownership verification", err)
		return
	}
	if _, err := c.OperatorService().DeleteNamespace(ctx, &operatorservice.DeleteNamespaceRequest{Namespace: namespace}); err != nil {
		t.Error("owned namespace retirement", err)
	} else {
		t.Log("retired owned namespace", namespace)
	}
}

func TestProductDiscoveryRetireOwnedNamespace(t *testing.T) {
	namespace := os.Getenv("ZASP_P4B_RETIRE_NAMESPACE")
	if namespace == "" {
		t.Skip("explicit owned failed-run cleanup only")
	}
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deleteOwnedDiscoveryNamespace(t, c, namespace)
}

func TestDiscoveryRuntimeBorrowersJoinBeforeClose(t *testing.T) {
	b := &discoveryRuntimeBorrowers{}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- b.run(context.Background(), func() error { close(entered); <-release; return nil }) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b.close(ctx) == nil {
		t.Fatal("close passed outstanding borrower")
	}
	called := false
	if b.run(context.Background(), func() error { called = true; return nil }) == nil || called {
		t.Fatal("new borrow accepted after close")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := b.close(context.Background()); err != nil {
		t.Fatal("retry did not join", err)
	}
}
