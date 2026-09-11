package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue/sqsdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent/s3rawstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// The harness owns PostgreSQL, SQS/S3, OpenSearch and authenticated TLS Neo4j.
// Cloud IAM and Neo4j publisher-role attestation remain external deployment gates.
func TestProductionCombinedE2ERuntimeQueueIndex(t *testing.T) {
	dsn := os.Getenv("ZASP_COMBINED_E2E_RUNTIME_PIPELINE_DSN")
	if dsn == "" {
		t.Skip("requires disposable combined E2E harness")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme != "postgres" || parsed.Hostname() != "127.0.0.1" || parsed.User.Username() != "zasp_e2e" {
		t.Fatal("disposable database identity rejected")
	}
	awsEndpoint := runtimePipelineLoopback(t, os.Getenv("ZASP_COMBINED_E2E_RUNTIME_AWS_ENDPOINT"))
	searchEndpoint := runtimePipelineLoopback(t, os.Getenv("ZASP_COMBINED_E2E_RUNTIME_SEARCH_ENDPOINT"))
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	realGraph := newRuntimePipelineGraphFixture(t, ctx)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	runtimePipelineAwaitHTTP(t, ctx, awsEndpoint+"/_localstack/health")
	runtimePipelineAwaitHTTP(t, ctx, searchEndpoint+"/_cluster/health?wait_for_status=yellow&timeout=1s")
	creds := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
	})
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	base := aws.Config{Region: "us-east-1", Credentials: creds, HTTPClient: client, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	s3API := s3.NewFromConfig(base, func(o *s3.Options) { o.BaseEndpoint = &awsEndpoint; o.UsePathStyle = true })
	sqsAPI := sqs.NewFromConfig(base, func(o *sqs.Options) { o.BaseEndpoint = &awsEndpoint })
	kmsAPI := kms.NewFromConfig(base, func(o *kms.Options) { o.BaseEndpoint = &awsEndpoint })
	key, err := kmsAPI.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String("Disposable runtime pipeline proof")})
	if err != nil {
		t.Fatal(err)
	}
	keyARN := aws.ToString(key.KeyMetadata.Arn)
	const bucket = "zasp-runtime-pipeline-proof"
	if _, err := s3API.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s3API.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	dlq, err := sqsAPI.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("runtime-events-dlq")})
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := sqsAPI.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: dlq.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
	if err != nil {
		t.Fatal(err)
	}
	redrive, _ := json.Marshal(map[string]string{"deadLetterTargetArn": attributes.Attributes["QueueArn"], "maxReceiveCount": "5"})
	queueInfo, err := sqsAPI.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("runtime-events"), Attributes: map[string]string{"VisibilityTimeout": "30", "RedrivePolicy": string(redrive)}})
	if err != nil {
		t.Fatal(err)
	}
	// Keep the production queue URL validator unchanged. The SDK's explicit local
	// endpoint sends real requests to the owned emulator, using this queue identity.
	driver, err := sqsdriver.New(sqsAPI, sqsdriver.Config{QueueURL: "https://sqs.us-east-1.amazonaws.com/000000000000/runtime-events", VisibilityTimeoutSeconds: 30, MaximumReceiveCount: 5})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: 5 * time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	searchDriver, err := opensearchdriver.New(opensearchdriver.Config{Endpoint: searchEndpoint, Region: "us-east-1", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20, AllowTestLoopback: true}, creds, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	defer searchDriver.Close()
	if err := searchDriver.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	sessionIndex, err := opensearchdriver.NewSessionIndex(opensearchdriver.Config{Endpoint: searchEndpoint, Region: "us-east-1", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20, AllowTestLoopback: true}, creds, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	defer sessionIndex.Close()
	if err := sessionIndex.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	configureOwnedSingleNodeSessionIndex(t, ctx, searchEndpoint)
	index, err := runtimeindex.New(searchDriver, runtimeindex.Config{MaximumBatchBytes: 8 << 20, MaximumDocuments: 1000})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s3rawstore.New(s3API, s3rawstore.Config{Bucket: bucket, ExpectedBucketOwner: "000000000000", KMSKeyARN: keyARN, MaximumBytes: 1 << 20, OperationTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := newProductionDiscoveryArtifactAuthority(s3API, productionDiscoveryArtifactConfig{Bucket: bucket, ExpectedBucketOwner: "000000000000", KMSKeyARN: keyARN, MaximumBytes: 8 << 20, OperationTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	database := func(principal string) apiserver.JSONDatabase {
		copy := *parsed
		copy.User = url.User(principal)
		return combinedE2ERecoveryDatabase(t, ctx, copy.String())
	}
	scope, err := domain.NewScope(workerID(t, "pid_10000001-0000-4000-8000-000000000001"), workerID(t, "pid_10000022-0000-4000-8000-000000000022"), workerID(t, "pid_10000023-0000-4000-8000-000000000023"))
	if err != nil {
		t.Fatal(err)
	}
	const sensorID = "pid_78000101-0000-4000-8000-000000000101"
	tokenID := workerID(t, "pid_78000102-0000-4000-8000-000000000102")
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Runtime pipeline proof','tetragon','active')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID); err != nil {
		t.Fatal(err)
	}
	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{0x68}, 16), bytes.Repeat([]byte{0x78}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	locator, err := credential.LocatorDigest()
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x82}, 32)
	tokenHash, err := credential.Hash(sensor.SensorTokenAudienceEventIngest, tokenID, 1, salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, tokenID.String(), locator[:], salt, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	wireToken, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	ingestRepository, err := runtimeevent.NewPostgresProductionIngestRepository(database("zasp_e2e_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ingestRepository.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	processDigest, err := runtimemetadata.DigestSelector("process", "/usr/bin/agent")
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately reverse event time at ingress. Twenty-six records cross the
	// production timeline's 25-row page boundary without seeding session tables.
	observedLineage := runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: "78100001-0000-4000-8000-000000000001", NodeUID: "78100002-0000-4000-8000-000000000002", BootID: "78100003-0000-4000-8000-000000000003", PodUID: "78100004-0000-4000-8000-000000000004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: now.Add(-time.Minute).Format(time.RFC3339Nano), CgroupID: "12345"}
	events := make([]map[string]any, 26)
	for i := range events {
		events[i] = map[string]any{"event_id": fmt.Sprintf("runtime-pipeline-%d", i+1), "class": "process", "action": "exec", "workload_id": "runtime-pipeline", "event_time": now.Add(-time.Duration(i) * time.Second).Format("2006-01-02T15:04:05.000Z"), "evidence_id": fmt.Sprintf("pid_78000103-0000-4000-8000-%012d", i+103), "content": map[string]string{"binary": "agent"}, "search_metadata": map[string]string{"process_digest": processDigest}}
		events[i]["observed_lineage"] = observedLineage
	}
	// Keep the same 26 canonical timestamps and process selector while proving
	// the three kernel observation classes through the actual workers.
	events[1]["class"], events[1]["action"] = "file", "read"
	events[2]["class"], events[2]["action"] = "network", "connect"
	body, err := json.Marshal(map[string]any{"source": "tetragon", "events": events})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: ingestRepository, Artifacts: raw, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ingest := func(foreign bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body)).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer "+wireToken)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
		request.Header.Set("Idempotency-Key", "runtime-pipeline-proof-0001")
		if foreign {
			request.Header.Set("X-Zasp-Organization", "pid_90000001-0000-4000-8000-000000000001")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if denied := ingest(true); denied.Code != http.StatusBadRequest {
		t.Fatalf("caller tenant override status=%d", denied.Code)
	}
	accepted := ingest(false)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("ingest status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	var acceptedBatch struct {
		BatchID string `json:"batch_id"`
	}
	if err := json.Unmarshal(accepted.Body.Bytes(), &acceptedBatch); err != nil || acceptedBatch.BatchID == "" {
		t.Fatal("missing durable batch")
	}
	if replay := ingest(false); replay.Code != http.StatusAccepted || replay.Body.String() != accepted.Body.String() {
		t.Fatalf("ingest replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	outboxRepository, err := apiserver.NewRuntimeOutboxRepository(database("zasp_e2e_outbox"))
	if err != nil {
		t.Fatal(err)
	}
	if err := outboxRepository.Ready(ctx); err != nil {
		t.Fatalf("runtime outbox readiness: %v", err)
	}
	publisher := &runtimePipelinePublisher{queue: queue, t: t}
	outbox, err := newOutboxProcessor(outboxProcessorConfig{Authority: outboxRepository, Publisher: publisher, Topic: runtimeOutboxTopic, WorkerID: "runtime-proof-outbox", LeaseSeconds: 30, BatchSize: 10, RetrySeconds: 5, NewLeaseToken: newWorkerLeaseToken, Ready: outboxRepository.Ready})
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	coordinatorConfig := validRuntimeCoordinatorConfig()
	observedQueue := &runtimePipelineDeliveryQueue{Queue: queue}
	coordinator, err := composeRuntimeCoordinatorWorkerRuntime(coordinatorConfig, database("zasp_e2e_coordinator"), &productionRuntimeQueueDependencies{Queue: observedQueue, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise duplicate liveness before running stages. Only fixture lease clocks
	// are advanced; production functions perform every claim and transition.
	deliveryRepository, err := runtimeevent.NewPostgresProductionPipelineRepository(database("zasp_e2e_coordinator"), runtimeevent.ProductionPipelineAuthorityCoordinator)
	if err != nil {
		t.Fatal(err)
	}
	claimPhysical := func(worker string) (jobqueue.Receipt, runtimeevent.DeliveryClaimRequest) {
		deliveries, err := queue.ConsumeBatch(ctx, 1)
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("physical delivery missing: %v", err)
		}
		delivery := deliveries[0]
		payload, batchID, ok := decodeRuntimeDeliveryJob(delivery.Job)
		if !ok {
			t.Fatal("invalid physical envelope")
		}
		token, err := newWorkerLeaseToken()
		if err != nil {
			t.Fatal(err)
		}
		request := runtimeevent.DeliveryClaimRequest{Scope: delivery.Job.Scope, BatchID: batchID, Generation: payload.Generation, MessageID: delivery.Receipt.MessageKey(), MessageDigest: delivery.Job.AuthorityDigest, ReceiveCount: delivery.ReceiveCount, WorkerID: worker, LeaseToken: token, LeaseSeconds: 30, VisibilitySeconds: 30}
		claim, err := deliveryRepository.ClaimDelivery(ctx, request)
		if err != nil || claim.Disposition != runtimeevent.DeliveryDispositionClaimed {
			t.Fatalf("physical claim=%#v err=%v", claim, err)
		}
		return delivery.Receipt, request
	}
	originalReceipt, originalRequest := claimPhysical("runtime-proof-original")
	foreignScope, err := domain.NewScope(workerID(t, "pid_90000001-0000-4000-8000-000000000001"), workerID(t, "pid_90000002-0000-4000-8000-000000000002"), workerID(t, "pid_90000003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	foreignRequest := originalRequest
	foreignRequest.Scope = foreignScope
	if _, err := deliveryRepository.ClaimDelivery(ctx, foreignRequest); err == nil {
		t.Fatal("cross-tenant physical delivery claimed another tenant's batch")
	}
	wrongGeneration := originalRequest
	wrongGeneration.Generation++
	if _, err := deliveryRepository.ClaimDelivery(ctx, wrongGeneration); err == nil {
		t.Fatal("physical delivery claimed a different generation")
	}
	if _, err := queue.PublishBatch(ctx, publisher.jobs); err != nil {
		t.Fatal(err)
	}
	awaitAcknowledgements := func(want int64) {
		t.Helper()
		// A visibility deadline or successful publish does not guarantee the next
		// short poll returns every message. Run the normal worker polling loop
		// until the exact expected provider deletes have actually succeeded.
		for attempt := 0; attempt < 200 && observedQueue.ackCount.Load() < want; attempt++ {
			if err := coordinator.Processor.RunOnce(ctx); err != nil {
				t.Fatalf("coordinator replay: %v", err)
			}
			if observedQueue.ackCount.Load() >= want {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		if observedQueue.ackCount.Load() != want {
			t.Fatalf("coordinator acknowledged=%d received=%d want=%d", observedQueue.ackCount.Load(), observedQueue.receiveCount.Load(), want)
		}
	}
	awaitAcknowledgements(1)
	var activeMessage string
	if err := admin.QueryRow(ctx, `SELECT message_id FROM zasp_runtime_deliveries WHERE batch_id=$1`, acceptedBatch.BatchID).Scan(&activeMessage); err != nil || activeMessage != originalRequest.MessageID {
		t.Fatal("active duplicate replaced original authority")
	}
	fenceStale := func(request runtimeevent.DeliveryClaimRequest) {
		if _, err := deliveryRepository.HeartbeatDelivery(ctx, request); err == nil {
			t.Fatal("stale physical owner renewed replacement")
		}
		if _, err := deliveryRepository.ReleaseDelivery(ctx, request, runtimeevent.DeliveryOutcomeRetryable, "retryable"); err == nil {
			t.Fatal("stale physical owner released replacement")
		}
		if _, err := deliveryRepository.AcknowledgeDelivery(ctx, request, runtimeQueueAcknowledgementDigest(request.MessageID)); err == nil {
			t.Fatal("stale physical owner acknowledged replacement")
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_deliveries SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE batch_id=$1`, acceptedBatch.BatchID); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.PublishBatch(ctx, publisher.jobs); err != nil {
		t.Fatal(err)
	}
	leaseTakeoverReceipt, leaseTakeoverRequest := claimPhysical("runtime-proof-lease-takeover")
	fenceStale(originalRequest)
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_deliveries SET visibility_deadline=transaction_timestamp()-interval '1 second' WHERE batch_id=$1`, acceptedBatch.BatchID); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.PublishBatch(ctx, publisher.jobs); err != nil {
		t.Fatal(err)
	}
	visibilityReceipt, _ := claimPhysical("runtime-proof-visibility-takeover")
	fenceStale(leaseTakeoverRequest)
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_deliveries SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE batch_id=$1`, acceptedBatch.BatchID); err != nil {
		t.Fatal(err)
	}
	if err := queue.ExtendVisibility(ctx, []jobqueue.Receipt{visibilityReceipt}, time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(1100 * time.Millisecond):
	}
	coordinatorResult := make(chan error, 1)
	observedQueue.received.Store(false)
	go func() {
		for attempt := 0; attempt < 100; attempt++ {
			err := coordinator.Processor.RunOnce(ctx)
			if err != nil || observedQueue.received.Load() {
				coordinatorResult <- err
				return
			}
			select {
			case <-ctx.Done():
				coordinatorResult <- ctx.Err()
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
		coordinatorResult <- fmt.Errorf("runtime coordinator received no visible message")
	}()
	// No privileged UPDATE completes stages or authorizes queue deletion. Each
	// stage uses its registered production principal and durable lease transition.
	archive, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: s3API, Bucket: bucket, ExpectedOwner: "000000000000", KMSKeyARN: keyARN, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	indexExecutor, err := newRuntimeIndexExecutor(runtimeIndexExecutorConfig{Reader: archive, Index: index, Receipts: receipts, ImplementationVersion: "runtime-index-v1"})
	if err != nil {
		t.Fatal(err)
	}
	sessionExecutor, err := newRuntimeSessionSearchExecutor(archive, receipts, sessionIndex)
	if err != nil {
		t.Fatal(err)
	}
	var sessionWorker workerProcessor
	correlationGraph, projectionGraph := &runtimePipelineGraphObserver{delegate: realGraph}, &runtimePipelineGraphObserver{delegate: realGraph}
	// Schema 48 still creates v1 jobs. Exercise the pre-staged production v2
	// reader against those untouched jobs and the real candidate authority.
	correlationConfig := validRuntimeCorrelationConfig()
	correlationConfig.RuntimeStageVersion = "runtime-correlation-v2"
	correlation, err := newRuntimeCorrelationExecutorWithDatabase(runtimeCorrelationExecutorConfig{Reader: archive, Receipts: receipts, Graph: correlationGraph, ImplementationVersion: correlationConfig.RuntimeStageVersion}, database("zasp_e2e_correlation"))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: archive, Receipts: receipts, Graph: projectionGraph, ImplementationVersion: "runtime-projection-v1"})
	if err != nil {
		t.Fatal(err)
	}
	complete, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: receipts, ImplementationVersion: "runtime-complete-v1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []struct {
		config    workerRuntimeConfig
		principal string
		executor  runtimeStageExecutor
	}{
		{validRuntimeArchiveConfig(), "zasp_e2e_archive", archive}, {validRuntimeIndexConfig(), "zasp_e2e_index", indexExecutor}, {correlationConfig, "zasp_e2e_correlation", correlation}, {validRuntimeProjectionConfig(), "zasp_e2e_runtime_projection", projection}, {validRuntimeCompleteConfig(), "zasp_e2e_coordinator", complete},
	} {
		stageName, _, ok := runtimeStageBinding(stage.config.Mode)
		if !ok {
			t.Fatal("invalid stage")
		}
		// Pass the actual executor so composition retains its version negotiation
		// and authorized-execution interfaces, as it does in production.
		stageDependencies := &productionRuntimeStageDependencies{Stage: stageName, Executor: stage.executor, ready: func(context.Context) error { return nil }, close: func() error { return nil }}
		if stageName == runtimeevent.RuntimeStageIndex {
			stageDependencies.Sessions = sessionExecutor
			stageDependencies.SessionReady = sessionIndex.Ready
		}
		runtime, err := composeRuntimeStageWorkerRuntime(stage.config, &sessionSearchProofDatabase{JSONDatabase: database(stage.principal), test: t}, stageDependencies)
		if err != nil {
			t.Fatalf("compose %s: %v", stageName, err)
		}
		if stageName == runtimeevent.RuntimeStageIndex {
			sessionWorker = runtime.Processor
		}
		var state string
		for attempt := 0; attempt < 100; attempt++ {
			if err := runtime.Processor.RunOnce(ctx); err != nil {
				t.Fatalf("execute %s: %v", stageName, err)
			}
			if err := admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`, acceptedBatch.BatchID, string(stageName)).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state == "succeeded" {
				break
			}
			if state != "pending" && state != "leased" {
				t.Fatalf("stage %s state=%s", stageName, state)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		if state != "succeeded" {
			select {
			case coordinatorErr := <-coordinatorResult:
				t.Fatalf("stage %s did not finish; coordinator=%v received=%t", stageName, coordinatorErr, observedQueue.received.Load())
			default:
				t.Fatalf("stage %s did not finish; received=%t", stageName, observedQueue.received.Load())
			}
		}
	}
	select {
	case err := <-coordinatorResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for _, receipt := range []jobqueue.Receipt{originalReceipt, leaseTakeoverReceipt} {
		if err := queue.ExtendVisibility(ctx, []jobqueue.Receipt{receipt}, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(1100 * time.Millisecond):
	}
	awaitAcknowledgements(4)
	var reference, version, digest, state string
	var stages, outboxCount int
	if err := admin.QueryRow(ctx, `SELECT raw_artifact_reference,raw_artifact_version_id,encode(raw_artifact_checksum,'hex'),state,(SELECT count(*) FROM zasp_runtime_stage_work WHERE batch_id=$1 AND state='succeeded'),(SELECT count(*) FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1) FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, acceptedBatch.BatchID).Scan(&reference, &version, &digest, &state, &stages, &outboxCount); err != nil {
		t.Fatal(err)
	}
	object, err := s3API.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(strings.TrimPrefix(reference, "s3://"+bucket+"/")), VersionId: &version, ExpectedBucketOwner: aws.String("000000000000"), ChecksumMode: s3types.ChecksumModeEnabled})
	if err != nil {
		t.Fatal(err)
	}
	archived, err := io.ReadAll(io.LimitReader(object.Body, 1<<20))
	object.Body.Close()
	if err != nil || aws.ToString(object.VersionId) != version {
		t.Fatal("archive readback mismatch")
	}
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, archived)
	if err != nil || len(decoded.Records) != 26 || decoded.Records[0].SourceEventID != "runtime-pipeline-1" || decoded.Records[0].Scope != scope || len(decoded.Records[0].Content) != 0 {
		t.Fatal("canonical metadata-only archive lost event identity, scope, or content filtering")
	}
	for i, record := range decoded.Records {
		if record.ObservedLineage != observedLineage || record.ContainerID != "" || record.CgroupID != "" || record.ProcessID != "" {
			t.Fatal("observed lineage lost or promoted into legacy matching fields")
		}
		if record.SourceEventID != fmt.Sprintf("runtime-pipeline-%d", i+1) || record.Scope != scope || len(record.Content) != 0 {
			t.Fatal("multi-event archive lost ordered identity, scope or content filtering")
		}
	}
	inputDigest := sha256.Sum256(archived)
	if digest != hex.EncodeToString(inputDigest[:]) || stages != 5 || outboxCount != 1 || state != "succeeded" {
		t.Fatalf("batch state=%s stages=%d outbox=%d digest=%s", state, stages, outboxCount, digest)
	}
	replayIndex, err := index.Apply(ctx, runtimeindex.Batch{Scope: scope, BatchID: workerID(t, acceptedBatch.BatchID), Generation: 1, InputDigest: inputDigest, ArchiveReference: reference, ArchiveVersionID: version, Body: archived})
	if err != nil || len(replayIndex.DocumentIDs) != 26 || !replayIndex.Replayed {
		t.Fatalf("index replay=%#v err=%v", replayIndex, err)
	}
	readIndex := func() json.RawMessage {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, searchEndpoint+"/zasp-runtime-events-v1/_doc/"+replayIndex.DocumentIDs[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var document struct {
			Found   bool            `json:"found"`
			Version int             `json:"_version"`
			Source  json.RawMessage `json:"_source"`
		}
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&document) != nil || !document.Found || document.Version != 1 {
			t.Fatal("index readback missing or duplicate version")
		}
		var fields map[string]any
		if json.Unmarshal(document.Source, &fields) != nil {
			t.Fatal("index source invalid")
		}
		for name, want := range map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": acceptedBatch.BatchID, "archive_reference": reference, "archive_version_id": version, "input_digest": digest} {
			if fields[name] != want {
				t.Fatalf("index/archive %s mismatch: got=%v want=%s", name, fields[name], want)
			}
		}
		return document.Source
	}
	beforeIndex := readIndex()
	versions := func() int {
		result, err := s3API.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		if err != nil || aws.ToBool(result.IsTruncated) || len(result.DeleteMarkers) != 0 {
			t.Fatal("archive versions unavailable")
		}
		return len(result.Versions)
	}
	beforeVersions := versions()
	if beforeVersions != 5 {
		t.Fatalf("expected raw archive and four stage receipts, versions=%d", beforeVersions)
	}
	stageSnapshot := func() string {
		var snapshot string
		if err := admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(work_row) ORDER BY stage_order)::text FROM zasp_runtime_stage_work work_row WHERE batch_id=$1`, acceptedBatch.BatchID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	beforeStages := stageSnapshot()
	// Read only. Every row was written by the production completion worker from
	// its verified S3 projection receipt, never by a session seed fixture.
	sessionSnapshot := func() string {
		var snapshot string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('events',(SELECT jsonb_agg(to_jsonb(event) ORDER BY event.event_time,event.event_id) FROM zasp_runtime_session_events event WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3),'receipts',(SELECT jsonb_agg(to_jsonb(receipt) ORDER BY receipt.batch_generation) FROM zasp_runtime_session_projection_receipts receipt WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4))::text`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), acceptedBatch.BatchID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	var eventCount, receiptCount int
	var summaryCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_summaries WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id='unattributed' AND event_count=26 AND unattributed_count=26 AND exact_count=0 AND strong_count=0 AND probable_count=0 AND minimum_agent_id IS NULL AND maximum_agent_id IS NULL`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&summaryCount); err != nil || summaryCount != 1 {
		t.Fatalf("worker-written runtime summary count=%d error=%v", summaryCount, err)
	}
	summarySnapshot := func() string {
		var snapshot string
		if err := admin.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(summary) ORDER BY id),'[]'::jsonb)::text FROM zasp_runtime_session_summaries summary WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	beforeSummaries := summarySnapshot()
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_events WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&eventCount); err != nil || eventCount != 26 {
		t.Fatalf("durable runtime event count=%d error=%v", eventCount, err)
	}
	var unknownCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_events WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND confidence='unattributed' AND session_id IS NULL AND agent_id IS NULL`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&unknownCount); err != nil || unknownCount != 26 {
		t.Fatalf("unknown runtime attribution changed: count=%d error=%v", unknownCount, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_projection_receipts receipt JOIN zasp_runtime_stage_work stage USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE receipt.batch_id=$1 AND stage.stage='project' AND receipt.receipt_digest=stage.result_digest AND cardinality(receipt.event_ids)=26`, acceptedBatch.BatchID).Scan(&receiptCount); err != nil || receiptCount != 1 {
		t.Fatalf("projection receipt not bound to predecessor: count=%d error=%v", receiptCount, err)
	}
	proveRuntimeSessionSearchIndex(t, ctx, admin, scope, workerID(t, acceptedBatch.BatchID), archived, sessionIndex, sessionWorker, receipts)
	beforeSessions := sessionSnapshot()
	if len(publisher.jobs) != 1 {
		t.Fatal("outbox published duplicate jobs")
	}
	for replay := 0; replay < 2; replay++ {
		if _, err := queue.PublishBatch(ctx, publisher.jobs); err != nil {
			t.Fatalf("SQS redelivery publish: %v", err)
		}
		awaitAcknowledgements(int64(5 + replay))
	}
	if replay := ingest(false); replay.Code != http.StatusAccepted || replay.Body.String() != accepted.Body.String() {
		t.Fatalf("terminal ingest replay changed batch: status=%d body=%s", replay.Code, replay.Body.String())
	}
	if err := outbox.RunOnce(ctx); err != nil || len(publisher.jobs) != 1 {
		t.Fatal("terminal ingest replay republished outbox")
	}
	if stageSnapshot() != beforeStages || versions() != beforeVersions || !bytes.Equal(beforeIndex, readIndex()) {
		t.Fatal("SQS redelivery duplicated pipeline effects")
	}
	if sessionSnapshot() != beforeSessions {
		t.Fatal("SQS redelivery changed runtime session projection or confidence")
	}
	if summarySnapshot() != beforeSummaries {
		t.Fatal("SQS redelivery changed runtime session summaries")
	}
	t.Log("runtime session summaries proven: completion-triggered unknown collection, byte-stable replay")
	t.Log("runtime session persistence proven: worker-written event, unknown attribution retained, predecessor receipt digest, byte-stable replay")
	t.Logf("runtime pipeline durable batch=%s archive=%s@%s document=%s", acceptedBatch.BatchID, reference, version, replayIndex.DocumentIDs[0])
	assertQueuesEmpty := func() {
		for _, queueURL := range []*string{queueInfo.QueueUrl, dlq.QueueUrl} {
			attributes, err := sqsAPI.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queueURL, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameApproximateNumberOfMessages, sqstypes.QueueAttributeNameApproximateNumberOfMessagesNotVisible, sqstypes.QueueAttributeNameApproximateNumberOfMessagesDelayed}})
			if err != nil || len(attributes.Attributes) != 3 {
				t.Fatal("queue depth unavailable")
			}
			for _, count := range attributes.Attributes {
				if count != "0" {
					t.Fatalf("queue has visible/inflight/delayed messages: %v; coordinator received=%d acknowledged=%d", attributes.Attributes, observedQueue.receiveCount.Load(), observedQueue.ackCount.Load())
				}
			}
			messages, err := sqsAPI.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10, WaitTimeSeconds: 1})
			if err != nil || len(messages.Messages) != 0 {
				t.Fatalf("queue not empty: messages=%v err=%v", messages, err)
			}
		}
	}
	assertQueuesEmpty()
	if correlationGraph.calls != 1 || projectionGraph.calls != 1 {
		t.Fatal("unexpected downstream graph fixture calls")
	}
	// A separately enrolled OTLP source supplies semantic observations. Kernel
	// events never acquire these classes, semantic IDs, or Exact confidence.
	const semanticSensor = "pid_78000201-0000-4000-8000-000000000201"
	const semanticSession = "pid_78000202-0000-4000-8000-000000000202"
	const semanticAgent = "pid_78000203-0000-4000-8000-000000000203"
	semanticTokenID := workerID(t, "pid_78000204-0000-4000-8000-000000000204")
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Semantic pipeline proof','otlp','active')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), semanticSensor); err != nil {
		t.Fatal(err)
	}
	semanticCredential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{0x69}, 16), bytes.Repeat([]byte{0x79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer semanticCredential.Destroy()
	semanticLocator, err := semanticCredential.LocatorDigest()
	if err != nil {
		t.Fatal(err)
	}
	semanticHash, err := semanticCredential.Hash(sensor.SensorTokenAudienceEventIngest, semanticTokenID, 1, salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), semanticSensor, semanticTokenID.String(), semanticLocator[:], salt, semanticHash[:]); err != nil {
		t.Fatal(err)
	}
	semanticWire, err := semanticCredential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	semanticEvents := make([]map[string]any, 0, 3)
	for i, pair := range [][2]string{{"tool", "invoke"}, {"credential", "use"}, {"policy", "block"}} {
		metadata := map[string]string{}
		if pair[0] == "credential" {
			metadata["credential_id"] = "pid_78000205-0000-4000-8000-000000000205"
		}
		if pair[0] == "policy" {
			metadata["decision"] = pair[1]
		}
		semanticEvents = append(semanticEvents, map[string]any{
			"observed_lineage": observedLineage,
			"attributes":       map[string]string{"event.id": fmt.Sprintf("semantic-pipeline-%d", i), "event.class": pair[0], "event.action": pair[1], "agent.id": semanticAgent, "session.id": semanticSession, "task.id": "semantic-task", "tool.id": "semantic-tool", "sandbox.id": "semantic-sandbox", "trace.id": strings.Repeat("a", 32), "span.id": strings.Repeat("b", 16)},
			"event_time":       now.Add(-time.Duration(30+i) * time.Second).Format("2006-01-02T15:04:05.000Z"),
			"evidence_id":      fmt.Sprintf("pid_78000206-0000-4000-8000-%012d", 206+i), "search_metadata": metadata,
		})
	}
	semanticBody, err := json.Marshal(map[string]any{"source": "otlp", "events": semanticEvents})
	if err != nil {
		t.Fatal(err)
	}
	semanticIngest := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(semanticBody)).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer "+semanticWire)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
		request.Header.Set("Idempotency-Key", "semantic-pipeline-proof-0001")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	semanticAccepted := semanticIngest()
	var semanticBatch struct {
		BatchID string `json:"batch_id"`
	}
	if semanticAccepted.Code != http.StatusAccepted || json.Unmarshal(semanticAccepted.Body.Bytes(), &semanticBatch) != nil || semanticBatch.BatchID == "" {
		t.Fatalf("semantic ingest status=%d body=%s", semanticAccepted.Code, semanticAccepted.Body.String())
	}
	if err := outbox.RunOnce(ctx); err != nil || len(publisher.jobs) != 2 {
		t.Fatalf("semantic outbox: %v", err)
	}
	semanticCoordinatorResult := make(chan error, 1)
	go func() { semanticCoordinatorResult <- coordinator.Processor.RunOnce(ctx) }()
	semanticCorrelation, err := newRuntimeCorrelationExecutorWithDatabase(runtimeCorrelationExecutorConfig{Reader: archive, Receipts: receipts, Graph: realGraph, ImplementationVersion: correlationConfig.RuntimeStageVersion}, database("zasp_e2e_correlation"))
	if err != nil {
		t.Fatal(err)
	}
	semanticProjection, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: archive, Receipts: receipts, Graph: realGraph, ImplementationVersion: "runtime-projection-v1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []struct {
		config    workerRuntimeConfig
		principal string
		executor  runtimeStageExecutor
	}{
		{validRuntimeArchiveConfig(), "zasp_e2e_archive", archive},
		{validRuntimeIndexConfig(), "zasp_e2e_index", indexExecutor},
		{correlationConfig, "zasp_e2e_correlation", semanticCorrelation},
		{validRuntimeProjectionConfig(), "zasp_e2e_runtime_projection", semanticProjection},
		{validRuntimeCompleteConfig(), "zasp_e2e_coordinator", complete},
	} {
		stageName, _, ok := runtimeStageBinding(stage.config.Mode)
		if !ok {
			t.Fatal("invalid semantic stage")
		}
		dependencies := &productionRuntimeStageDependencies{Stage: stageName, Executor: stage.executor, ready: func(context.Context) error { return nil }, close: func() error { return nil }}
		if stageName == runtimeevent.RuntimeStageIndex {
			dependencies.Sessions, dependencies.SessionReady = sessionExecutor, sessionIndex.Ready
		}
		runtime, err := composeRuntimeStageWorkerRuntime(stage.config, database(stage.principal), dependencies)
		if err != nil {
			t.Fatal(err)
		}
		var state string
		for attempt := 0; attempt < 100; attempt++ {
			if err := runtime.Processor.RunOnce(ctx); err != nil {
				t.Fatalf("semantic stage %s: %v", stageName, err)
			}
			err := admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`, semanticBatch.BatchID, string(stageName)).Scan(&state)
			if err != nil && err != pgx.ErrNoRows {
				t.Fatal(err)
			}
			if state == "succeeded" {
				break
			}
			if state != "" && state != "pending" && state != "leased" {
				t.Fatalf("semantic stage %s state=%s", stageName, state)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		if state != "succeeded" {
			t.Fatalf("semantic stage %s did not complete", stageName)
		}
	}
	select {
	case err := <-semanticCoordinatorResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := sessionWorker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var semanticCount, classCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_events event JOIN zasp_runtime_session_projection_receipts receipt USING(organization_id,workspace_id,environment_id) WHERE receipt.batch_id=$1 AND event.event_id=ANY(receipt.event_ids) AND event.confidence='exact' AND event.session_id=$2 AND event.agent_id=$3 AND event.source='otlp'`, semanticBatch.BatchID, semanticSession, semanticAgent).Scan(&semanticCount); err != nil || semanticCount != 3 {
		t.Fatalf("semantic projection count=%d err=%v", semanticCount, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(DISTINCT event_class) FROM zasp_runtime_session_events WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&classCount); err != nil || classCount != 6 {
		t.Fatalf("six-class projection count=%d err=%v", classCount, err)
	}
	var semanticIndexed int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE batch_id=$1 AND state='indexed' AND attempt=1`, semanticBatch.BatchID).Scan(&semanticIndexed); err != nil || semanticIndexed != 1 {
		t.Fatalf("semantic search checkpoint count=%d err=%v", semanticIndexed, err)
	}
	// These emitters have no configured pairing. Identical observed qualifiers
	// must not create authority or rewrite already committed unknown evidence.
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_events WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND source='tetragon' AND confidence='unattributed' AND session_id IS NULL AND agent_id IS NULL`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&unknownCount); err != nil || unknownCount != 26 {
		t.Fatal("same observed lineage granted unpaired sensors correlation authority")
	}
	var semanticReference, semanticVersion, semanticDigest string
	if err := admin.QueryRow(ctx, `SELECT raw_artifact_reference,raw_artifact_version_id,encode(raw_artifact_checksum,'hex') FROM zasp_runtime_batch_authorities WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), semanticBatch.BatchID).Scan(&semanticReference, &semanticVersion, &semanticDigest); err != nil {
		t.Fatal(err)
	}
	semanticObject, err := s3API.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(strings.TrimPrefix(semanticReference, "s3://"+bucket+"/")), VersionId: &semanticVersion, ExpectedBucketOwner: aws.String("000000000000"), ChecksumMode: s3types.ChecksumModeEnabled})
	if err != nil {
		t.Fatal(err)
	}
	semanticArchived, err := io.ReadAll(io.LimitReader(semanticObject.Body, 1<<20))
	semanticObject.Body.Close()
	if err != nil || aws.ToString(semanticObject.VersionId) != semanticVersion {
		t.Fatal("semantic archive readback mismatch")
	}
	semanticArchiveDigest := sha256.Sum256(semanticArchived)
	if hex.EncodeToString(semanticArchiveDigest[:]) != semanticDigest {
		t.Fatal("semantic lineage not bound to archive digest")
	}
	semanticDecoded, err := runtimeevent.DecodeArchivedBatch(scope, semanticArchived)
	if err != nil || len(semanticDecoded.Records) != 3 {
		t.Fatal("semantic archive decode failed")
	}
	for _, record := range semanticDecoded.Records {
		if record.ObservedLineage != observedLineage || record.AgentID.String() != semanticAgent || record.SessionID.String() != semanticSession || len(record.Content) != 0 {
			t.Fatal("semantic archive lost observed lineage")
		}
	}
	beforeSemanticReplay := sessionSnapshot()
	beforeSemanticVersions := versions()
	if replay := semanticIngest(); replay.Code != http.StatusAccepted || replay.Body.String() != semanticAccepted.Body.String() {
		t.Fatal("semantic ingest replay drift")
	}
	if _, err := queue.PublishBatch(ctx, publisher.jobs[1:]); err != nil {
		t.Fatal(err)
	}
	awaitAcknowledgements(8)
	if sessionSnapshot() != beforeSemanticReplay || versions() != beforeSemanticVersions {
		t.Fatal("semantic replay changed canonical evidence")
	}
	proveRuntimeV1BacklogReceipt(t, ctx, admin, receipts, scope, acceptedBatch.BatchID, 26, domain.EvidenceConfidenceUnattributed)
	proveRuntimeV1BacklogReceipt(t, ctx, admin, receipts, scope, semanticBatch.BatchID, 3, domain.EvidenceConfidenceExact)
	t.Log("runtime v2 reader v1 backlog proven: production-created raw and semantic jobs, unchanged v1 versions and exact S3 receipts, no candidate observations or snapshots, stable replay; schema48 local proof only")
	t.Log("semantic observation pipeline proven: separately enrolled OTLP source, actual five-stage receipts, six canonical classes, scoped Exact instrumentation and stable replay; no raw content or enforcement assertion")
	runner, err := migrations.NewRunner(&runtimePipelineMigrationDatabase{connection: admin})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal("routing upgrade after v1 backlog", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 49 {
		t.Fatal("routing release not installed", version, err)
	}
	// Replaying previously accepted payloads after upgrade must not re-route them.
	if replay := semanticIngest(); replay.Code != http.StatusAccepted || replay.Body.String() != semanticAccepted.Body.String() {
		t.Fatal("routing upgrade changed original acceptance replay")
	}
	proveRuntimeV1BacklogReceipt(t, ctx, admin, receipts, scope, acceptedBatch.BatchID, 26, domain.EvidenceConfidenceUnattributed)
	proveRuntimeV1BacklogReceipt(t, ctx, admin, receipts, scope, semanticBatch.BatchID, 3, domain.EvidenceConfidenceExact)
	proveRuntimeCandidateRecovery(t, ctx, runtimeCandidateRecoveryFixture{admin: admin, database: database, handler: handler, outbox: outbox, coordinator: coordinator.Processor, sessions: sessionWorker, queue: observedQueue, archive: archive, index: indexExecutor, receipts: receipts, graph: realGraph})
	t.Log("runtime correlation routing proven: migrated48-to49 after v1 backlog, original acceptance replay preserved, fresh production ingestion creates v2 and actual registered workers complete frozen Strong/Probable receipts; local owned composition, not cloud deployment")
	assertQueuesEmpty()
	t.Log("runtime observed lineage preservation proven: exact S3 versions and committed digests, same qualified observations from separate enrollments, original v1 unknown kernel attribution and explicit semantic IDs retained, immutable replay; fresh v2 Strong/Probable proven separately on local schema49, live producer attestation NOT RUN")
	t.Log("runtime pipeline proof passed: production roles, durable ingest/outbox, actual local SQS/S3/OpenSearch/authenticated TLS Neo4j, five stage receipts, replay and empty DLQ; cloud IAM and graph publisher-role attestation NOT RUN")
}

// Use the production runner against the owned database, including its exact
// checksum, catalog-fingerprint and lock checks. No hand-applied migration SQL.
type runtimePipelineMigrationDatabase struct{ connection *pgx.Conn }

func (database *runtimePipelineMigrationDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return database.connection.QueryRow(ctx, statement, arguments...)
}
func (database *runtimePipelineMigrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	transaction, err := database.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &runtimePipelineMigrationTransaction{transaction: transaction}, nil
}

type runtimePipelineMigrationTransaction struct{ transaction pgx.Tx }

func (transaction *runtimePipelineMigrationTransaction) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return transaction.transaction.QueryRow(ctx, statement, arguments...)
}
func (transaction *runtimePipelineMigrationTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := transaction.transaction.Exec(ctx, statement, arguments...)
	return err
}
func (transaction *runtimePipelineMigrationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}
func (transaction *runtimePipelineMigrationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

func proveRuntimeV1BacklogReceipt(t *testing.T, ctx context.Context, admin *pgx.Conn, receipts artifactstore.ArtifactStore, scope domain.Scope, batch string, count int, confidence domain.EvidenceConfidence) {
	t.Helper()
	var implementation, reference, version string
	var generation int64
	var digest []byte
	if err := admin.QueryRow(ctx, `SELECT implementation_version,batch_generation,result_reference,result_version_id,result_digest FROM zasp_runtime_stage_work WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4 AND stage='correlate' AND state='succeeded'`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch).Scan(&implementation, &generation, &reference, &version, &digest); err != nil || implementation != "runtime-correlation-v1" {
		t.Fatalf("v2 reader changed v1 job version: %q err=%v", implementation, err)
	}
	locator, ok := runtimeReceiptLocator(scope, reference, version)
	if !ok {
		t.Fatal("v1 backlog receipt locator rejected")
	}
	artifact, err := receipts.Get(ctx, locator)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtimecorrelation.DecodeReceipt(artifact.Body)
	if err != nil || artifact.Locator != locator || !bytes.Equal(digest, artifact.SHA256[:]) || sha256.Sum256(artifact.Body) != artifact.SHA256 || receipt.Scope != scope || receipt.BatchID.String() != batch || receipt.Generation != generation || receipt.ImplementationVersion != implementation || receipt.CandidateSnapshotDigest != ([sha256.Size]byte{}) || len(receipt.Results) != count {
		t.Fatal("v1 backlog receipt binding changed", err)
	}
	for _, result := range receipt.Results {
		if result.Confidence != confidence {
			t.Fatal("v2 reader changed v1 evidence confidence")
		}
	}
	var observations, snapshots int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_candidate_observations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4),(SELECT count(*) FROM zasp_runtime_candidate_snapshots WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch).Scan(&observations, &snapshots); err != nil || observations != 0 || snapshots != 0 {
		t.Fatalf("v1 backlog acquired candidate state: observations=%d snapshots=%d err=%v", observations, snapshots, err)
	}
}

type runtimePipelinePublisher struct {
	queue *jobqueue.Queue
	t     *testing.T
	jobs  []jobqueue.Job
}

type runtimePipelineDeliveryQueue struct {
	*jobqueue.Queue
	deliveryMu   sync.Mutex
	deliveries   map[string]jobqueue.Receipt
	received     atomic.Bool
	receiveCount atomic.Int64
	ackCount     atomic.Int64
}

func (queue *runtimePipelineDeliveryQueue) ConsumeBatch(ctx context.Context, limit int) ([]jobqueue.Delivery, error) {
	deliveries, err := queue.Queue.ConsumeBatch(ctx, limit)
	if len(deliveries) > 0 {
		queue.deliveryMu.Lock()
		if queue.deliveries == nil {
			queue.deliveries = make(map[string]jobqueue.Receipt)
		}
		for _, delivery := range deliveries {
			if _, batch, ok := decodeRuntimeDeliveryJob(delivery.Job); ok {
				queue.deliveries[batch.String()] = delivery.Receipt
			}
		}
		queue.deliveryMu.Unlock()
		queue.received.Store(true)
		queue.receiveCount.Add(int64(len(deliveries)))
	}
	return deliveries, err
}

func (queue *runtimePipelineDeliveryQueue) AcknowledgeBatch(ctx context.Context, receipts []jobqueue.Receipt) error {
	if err := queue.Queue.AcknowledgeBatch(ctx, receipts); err != nil {
		return err
	}
	queue.ackCount.Add(int64(len(receipts)))
	return nil
}

func (p *runtimePipelinePublisher) PublishBatch(ctx context.Context, jobs []jobqueue.Job) (jobqueue.PublishResult, error) {
	p.jobs = append(p.jobs, jobs...)
	result, err := p.queue.PublishBatch(ctx, jobs)
	if err != nil {
		p.t.Logf("real SQS publish failed: %v", err)
	}
	return result, err
}

func runtimePipelineLoopback(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatal("disposable endpoint rejected")
	}
	return raw
}

func runtimePipelineAwaitHTTP(t *testing.T, ctx context.Context, endpoint string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for attempt := 0; attempt < 90; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	t.Fatal(fmt.Errorf("dependency did not become ready: %s", strings.Split(endpoint, "?")[0]))
}
