package main

import (
	"context"
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type auditExportCompositionDatabase struct{ *auditExportWorkerDatabase }

func (*auditExportCompositionDatabase) SchemaVersion(context.Context) (string, error) {
	return "", errors.New("unexpected generic readiness")
}
func (*auditExportCompositionDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected generic exec")
}

type auditExportProductionQueueFixture struct {
	*runtimeQueueReadinessStub
	consumes    int
	receive     func(context.Context, *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error)
	messages    []types.Message
	sends, acks int
	renew       func(context.Context, *sqs.ChangeMessageVisibilityBatchInput) (*sqs.ChangeMessageVisibilityBatchOutput, error)
	renewals    int
}

func (q *auditExportProductionQueueFixture) ChangeMessageVisibilityBatch(ctx context.Context, input *sqs.ChangeMessageVisibilityBatchInput, _ ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
	q.renewals++
	if q.renew != nil {
		return q.renew(ctx, input)
	}
	if aws.ToString(input.QueueUrl) != "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports" || len(input.Entries) != 1 || input.Entries[0].VisibilityTimeout != 180 || aws.ToString(input.Entries[0].ReceiptHandle) != "owned-sdk-receipt" {
		return nil, errors.New("incorrect export renewal")
	}
	return &sqs.ChangeMessageVisibilityBatchOutput{Successful: []types.ChangeMessageVisibilityBatchResultEntry{{Id: input.Entries[0].Id}}}, nil
}

func auditReceiptProductionFixture(t *testing.T) (workerRuntimeDependencies, *auditExportProductionQueueFixture, *auditExportExecutionFixture) {
	t.Helper()
	config, clients, q, _ := auditExportProductionClientsFixture(t, "audit-export")
	f := newAuditExportExecutionFixture(t, true)
	f.finished = true
	job := auditExportDispatchJobFixture(t, f)
	wire := []byte(fmt.Sprintf(`{"version":1,"job_id":%q,"organization_id":%q,"workspace_id":%q,"environment_id":%q,"kind":"audit-export","payload":%s,"authority_digest":"%x"}`, job.JobID.String(), job.Scope.OrganizationID().String(), job.Scope.WorkspaceID().String(), job.Scope.EnvironmentID().String(), job.Payload, job.AuthorityDigest))
	sum := md5.Sum(wire)
	q.messages = []types.Message{{Body: aws.String(string(wire)), MessageId: aws.String("owned-sdk-message"), ReceiptHandle: aws.String("owned-sdk-receipt"), MD5OfBody: aws.String(hex.EncodeToString(sum[:])), Attributes: map[string]string{"ApproximateReceiveCount": "1"}}}
	deps, err := composeAuditExportWorkerRuntime(context.Background(), config, f.db, clients)
	if err != nil {
		t.Fatal(err)
	}
	return deps, q, f
}

func TestAuditExportProductionRenewalSDKContract(t *testing.T) {
	for _, mode := range []string{"configured visibility", "nil", "partial", "unknown", "duplicate", "failed"} {
		t.Run(mode, func(t *testing.T) {
			deps, q, f := auditReceiptProductionFixture(t)
			defer deps.Close()
			q.renew = func(ctx context.Context, input *sqs.ChangeMessageVisibilityBatchInput) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
				if len(input.Entries) != 1 || input.Entries[0].VisibilityTimeout != 180 || aws.ToString(input.Entries[0].Id) != f.lease.Binding.ExportID || aws.ToString(input.Entries[0].ReceiptHandle) != "owned-sdk-receipt" {
					return nil, errors.New("wrong SDK visibility authority")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					return nil, errors.New("queue operation unbounded")
				}
				out := &sqs.ChangeMessageVisibilityBatchOutput{Successful: []types.ChangeMessageVisibilityBatchResultEntry{{Id: input.Entries[0].Id}}}
				switch mode {
				case "nil":
					return nil, nil
				case "partial":
					out.Successful = nil
				case "unknown":
					out.Successful[0].Id = aws.String("foreign")
				case "duplicate":
					out.Successful = append(out.Successful, out.Successful[0])
				case "failed":
					out.Failed = []types.BatchResultErrorEntry{{Id: input.Entries[0].Id, Code: aws.String("private failure")}}
				}
				return out, nil
			}
			err := deps.Processor.RunOnce(context.Background())
			valid := mode == "configured visibility"
			if (err == nil) != valid || !valid && q.acks != 0 || valid && (q.renewals != 2 || q.acks != 1) {
				t.Fatal("SDK renewal contract", err, q.renewals, q.acks)
			}
		})
	}
}

func TestAuditExportProductionCloseRetainsBlockedReceiptOwnerAndRetriesCleanup(t *testing.T) {
	deps, q, _ := auditReceiptProductionFixture(t)
	r := deps.Processor.(*auditExportProductionRuntime)
	r.shutdown = 10 * time.Millisecond
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	q.renew = func(ctx context.Context, _ *sqs.ChangeMessageVisibilityBatchInput) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, errors.New("owned refusal")
	}
	done := make(chan error, 1)
	go func() { done <- deps.Processor.RunOnce(context.Background()) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("renewal not reached: %v", err)
	case <-time.After(time.Second):
		t.Fatal("renewal not reached")
	}
	if deps.Close() == nil {
		close(release)
		<-done
		t.Fatal("unjoined owner credited clean")
	}
	<-canceled
	select {
	case <-done:
		t.Fatal("active call released before owner joined")
	default:
	}
	// Probe driver lifecycle without re-entering the blocked renewal boundary.
	_, probeErr := r.driver.ConsumeBatch(context.Background(), 2)
	close(release)
	if err := <-done; err == nil {
		t.Fatal("canceled owner succeeded")
	}
	if probeErr != nil {
		t.Fatal("driver drained beneath active receipt owner", probeErr)
	}
	if deps.Close() != nil {
		t.Fatal("joined retry did not finish cleanup")
	}
	if _, err := r.driver.ConsumeBatch(context.Background(), 1); err == nil {
		t.Fatal("cleanup retry left driver open")
	}
}

func (q *auditExportProductionQueueFixture) SendMessageBatch(_ context.Context, input *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	q.sends++
	if aws.ToString(input.QueueUrl) != "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports" || len(input.Entries) != 1 {
		return nil, errors.New("wrong dedicated publish")
	}
	entry := input.Entries[0]
	body := aws.ToString(entry.MessageBody)
	digest := md5.Sum([]byte(body))
	checksum := hex.EncodeToString(digest[:])
	q.messages = []types.Message{{Body: aws.String(body), MessageId: aws.String("owned-sdk-message"), ReceiptHandle: aws.String("owned-sdk-receipt"), MD5OfBody: aws.String(checksum), Attributes: map[string]string{string(types.MessageSystemAttributeNameApproximateReceiveCount): "1"}}}
	return &sqs.SendMessageBatchOutput{Successful: []types.SendMessageBatchResultEntry{{Id: entry.Id, MessageId: aws.String("owned-sdk-message"), MD5OfMessageBody: aws.String(checksum)}}}, nil
}
func (q *auditExportProductionQueueFixture) DeleteMessageBatch(_ context.Context, input *sqs.DeleteMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
	q.acks++
	if aws.ToString(input.QueueUrl) != "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports" || len(input.Entries) != 1 || aws.ToString(input.Entries[0].ReceiptHandle) != "owned-sdk-receipt" {
		return nil, errors.New("wrong export ACK")
	}
	q.messages = nil
	return &sqs.DeleteMessageBatchOutput{Successful: []types.DeleteMessageBatchResultEntry{{Id: input.Entries[0].Id}}}, nil
}

func (q *auditExportProductionQueueFixture) ReceiveMessage(ctx context.Context, input *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	q.consumes++
	if q.receive != nil {
		return q.receive(ctx, input)
	}
	if aws.ToString(input.QueueUrl) != "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports" || input.VisibilityTimeout != 180 || input.MaxNumberOfMessages != 2 {
		return nil, errors.New("incorrect export receive configuration")
	}
	return &sqs.ReceiveMessageOutput{Messages: q.messages}, nil
}

type auditExportProductionS3Fixture struct{ calls int }

func (s *auditExportProductionS3Fixture) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.calls++
	return nil, errors.New("unexpected S3 write")
}
func (s *auditExportProductionS3Fixture) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	s.calls++
	return nil, errors.New("unexpected S3 probe")
}
func (s *auditExportProductionS3Fixture) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	s.calls++
	return nil, errors.New("unexpected S3 read")
}

func auditExportProductionClientsFixture(t *testing.T, mode string) (workerRuntimeConfig, *auditExportProductionClients, *auditExportProductionQueueFixture, *auditExportProductionS3Fixture) {
	t.Helper()
	config, err := loadWorkerRuntimeConfig(mapLookup(auditExportProductionEnvironment(mode)))
	if err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports"
	queue := &auditExportProductionQueueFixture{runtimeQueueReadinessStub: &runtimeQueueReadinessStub{attributes: map[string]string{string(types.QueueAttributeNameQueueArn): arn, string(types.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"` + arn + `-dlq","maxReceiveCount":"20"}`}}}
	role, session := "zasp-production-audit-export-worker", "zasp-audit-export-worker"
	if mode == "audit-export-outbox" {
		role, session = "zasp-production-audit-export-outbox", "zasp-audit-export-outbox"
	}
	storage := &auditExportProductionS3Fixture{}
	clients := &auditExportProductionClients{queue: queue, identity: &runtimeIdentityStub{account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/" + role + "/" + session}, credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret", SessionToken: "fixture-session", CanExpire: true, Expires: time.Now().Add(10 * time.Minute)}, nil
	}), transport: &http.Transport{}, artifacts: map[string]s3driver.API{}}
	if mode == "audit-export" {
		clients.artifacts["pid_52000041-0000-4000-8000-000000000041"] = storage
	}
	return config, clients, queue, storage
}

func TestAuditExportProductionCompositionUsesFreshDedicatedAuthority(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		t.Run(mode, func(t *testing.T) {
			config, clients, queue, storage := auditExportProductionClientsFixture(t, mode)
			ready := true
			db := &auditExportWorkerDatabase{respond: func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					if !reflect.DeepEqual(args, []any{migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint(), config.DatabaseAuthority}) {
						t.Fatal("wrong compiled mode authority")
					}
					if ready {
						return json.RawMessage(`true`), nil
					}
					return json.RawMessage(`false`), nil
				}
				if mode == "audit-export-outbox" && sql == auditExportOutboxClaimSQL {
					if len(args) != 6 || !validAuditExportLeaseToken(args[1].(string)) || args[2] != 180 || args[3] != 2 {
						t.Fatal("outbox composed wrong token or lease/batch")
					}
					return json.RawMessage(`[]`), nil
				}
				t.Fatal("unexpected mode operation", sql)
				return nil, errors.New("unexpected SQL")
			}}
			deps, err := composeAuditExportWorkerRuntime(context.Background(), config, db, clients)
			if err != nil || deps.Processor == nil || deps.Ready == nil || deps.Close == nil {
				t.Fatal("production export mode unavailable", err)
			}
			defer deps.Close()
			if len(db.queries) == 0 || queue.attributeCalls != 1 || storage.calls != 0 {
				t.Fatal("startup authority missing or synthetic storage probe")
			}
			if err := deps.Processor.RunOnce(context.Background()); err != nil {
				t.Fatal("selected processor unavailable", err)
			}
			if mode == "audit-export" && queue.consumes != 1 || mode == "audit-export-outbox" && queue.consumes != 0 {
				t.Fatal("mode selected opposite processor")
			}
			before := len(db.queries)
			consumes := queue.consumes
			ready = false
			if deps.Processor.RunOnce(context.Background()) == nil || len(db.queries) != before+1 || queue.consumes != consumes {
				t.Fatal("healthy startup cache bypassed current SQL authority")
			}
			if err := deps.Close(); err != nil {
				t.Fatal(err)
			}
			before = len(db.queries)
			if deps.Ready(context.Background()) == nil || deps.Processor.RunOnce(context.Background()) == nil || len(db.queries) != before {
				t.Fatal("closed runtime admitted work")
			}
		})
	}
}

func TestAuditExportActualFactoryChecks52BeforeProviderAccess(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		config, err := loadWorkerRuntimeConfig(mapLookup(auditExportProductionEnvironment(mode)))
		if err != nil {
			t.Fatal(err)
		}
		db := &auditExportCompositionDatabase{&auditExportWorkerDatabase{respond: func(context.Context, string, ...any) (json.RawMessage, error) { return json.RawMessage(`false`), nil }}}
		if _, err := composeWorkerRuntime(context.Background(), config, db); err == nil || len(db.queries) != 1 || db.queries[0].SQL != auditExportWorkerReadySQL {
			t.Fatal("actual factory omitted dedicated52 readiness", mode, err)
		}
	}
}

// Real composed processors, SQL codecs, jobqueue and SQS driver; external SQL
// terminal state and SDK responses are declared fixture boundaries, not durable
// PostgreSQL/SQS acceptance. No synthetic S3 success is provided.
func TestAuditExportProductionModesPublishThenSelectHistoricalTerminal(t *testing.T) {
	for _, fault := range []string{"ready historical", "unknown revision", "busy"} {
		t.Run(fault, func(t *testing.T) {
			outConfig, outClients, queue, _ := auditExportProductionClientsFixture(t, "audit-export-outbox")
			published := false
			outDB := &auditExportWorkerDatabase{respond: func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				switch sql {
				case auditExportWorkerReadySQL:
					return json.RawMessage(`true`), nil
				case auditExportOutboxClaimSQL:
					if !validAuditExportLeaseToken(args[1].(string)) {
						t.Fatal("publisher generated incompatible token")
					}
					return json.Marshal([]any{auditExportOutboxWire()})
				case auditExportOutboxFinishSQL:
					if queue.sends != 1 || len(queue.messages) != 1 || !providerAckPattern.MatchString(args[8].(string)) {
						t.Fatal("outbox finished before exact publish")
					}
					published = true
					return json.RawMessage(`{"finished":true}`), nil
				}
				t.Fatal("unexpected publisher SQL", sql)
				return nil, errors.New("unexpected SQL")
			}}
			publisher, err := composeAuditExportWorkerRuntime(context.Background(), outConfig, outDB, outClients)
			if err != nil {
				t.Fatal(err)
			}
			defer publisher.Close()
			if err := publisher.Processor.RunOnce(context.Background()); err != nil || !published || queue.acks != 0 {
				t.Fatal("composed publish failed", err)
			}
			config, clients, _, storage := auditExportProductionClientsFixture(t, "audit-export")
			clients.queue = queue
			old := config.AuditExports.Policies[0]
			newer := old
			newer.PolicyID = "pid_52000049-0000-4000-8000-000000000049"
			config.AuditExports.Policies = []migrations.AuditExportConfiguration{newer, old}
			clients.artifacts[newer.PolicyID] = storage
			if fault == "unknown revision" {
				config.AuditExports.Policies = config.AuditExports.Policies[:1]
				delete(clients.artifacts, old.PolicyID)
			}
			f := newAuditExportExecutionFixture(t, true)
			f.finished = fault != "busy"
			f.change = "busy"
			base := f.db.respond
			claims := 0
			f.db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerClaimSQL {
					claims++
					if args[7] != old.PolicyID || !validAuditExportLeaseToken(args[5].(string)) {
						t.Fatal("historical policy or64hex token substituted")
					}
				}
				return base(ctx, sql, args...)
			}
			worker, err := composeAuditExportWorkerRuntime(context.Background(), config, f.db, clients)
			if err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			// Mutating the input after construction must not substitute the policy.
			config.AuditExports.Policies[0].Bucket = "caller-mutation"
			err = worker.Processor.RunOnce(context.Background())
			if fault == "ready historical" {
				if err != nil || claims != 1 || queue.acks != 1 {
					t.Fatal("terminal historical delivery failed", err)
				}
			} else if err == nil || queue.acks != 0 || fault == "unknown revision" && claims != 0 {
				t.Fatal("untrusted/nonterminal delivery acknowledged")
			}
			if storage.calls != 0 {
				t.Fatal("terminal or unknown delivery touched S3")
			}
		})
	}
}

func TestAuditExportProductionCloseCancelsAndJoinsOwnedWork(t *testing.T) {
	for _, boundary := range []string{"queue receive", "readiness SQL"} {
		t.Run(boundary, func(t *testing.T) {
			config, clients, queue, _ := auditExportProductionClientsFixture(t, "audit-export")
			config.ShutdownTimeout = time.Second
			wait := false
			entered := make(chan struct{})
			db := &auditExportWorkerDatabase{respond: func(ctx context.Context, _ string, _ ...any) (json.RawMessage, error) {
				if wait && boundary == "readiness SQL" {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return json.RawMessage(`true`), nil
			}}
			queue.receive = func(ctx context.Context, _ *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			deps, err := composeAuditExportWorkerRuntime(context.Background(), config, db, clients)
			if err != nil {
				t.Fatal(err)
			}
			wait = true
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if boundary == "readiness SQL" {
					done <- deps.Ready(ctx)
				} else {
					done <- deps.Processor.RunOnce(ctx)
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				cancel()
				t.Fatal("owned boundary not reached")
			}
			start := time.Now()
			closeErr := deps.Close()
			if closeErr != nil || time.Since(start) > 500*time.Millisecond {
				t.Error("Close failed to cancel promptly", closeErr)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Error("canceled owned work succeeded")
				}
			case <-time.After(250 * time.Millisecond):
				t.Error("Close returned before owned work joined")
				cancel()
				<-done
			}
			if deps.Close() != closeErr {
				t.Fatal("repeated Close changed result")
			}
		})
	}
}

func TestAuditExportProductionCloseClosesActualIdleTransport(t *testing.T) {
	config, clients, _, _ := auditExportProductionClientsFixture(t, "audit-export-outbox")
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("owned")) }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()
	response, err := (&http.Client{Transport: clients.transport}).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("owned keepalive fixture")
	}
	deps, err := composeAuditExportWorkerRuntime(context.Background(), config, &auditExportWorkerDatabase{}, clients)
	if err != nil {
		t.Fatal(err)
	}
	if deps.Close() != nil {
		t.Fatal("close failed")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("idle provider socket remained open")
	}
}

func TestAuditExportProductionCredentialsNeverDetachRefresh(t *testing.T) {
	entered, finished, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cache := newAuditExportCredentialCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		close(entered)
		defer close(finished)
		select {
		case <-ctx.Done():
		case <-release:
		}
		return aws.Credentials{}, errors.New("owned refresh stopped")
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := cache.Retrieve(ctx); done <- err }()
	<-entered
	cancel()
	select {
	case <-finished:
	case <-time.After(250 * time.Millisecond):
		t.Error("credential refresh escaped caller cancellation")
	}
	close(release)
	<-finished
	if err := <-done; err == nil {
		t.Fatal("canceled refresh succeeded")
	}
}

func TestAuditExportProductionCredentialCacheSerializesAndBoundsWaiters(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cache := newAuditExportCredentialCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return aws.Credentials{}, ctx.Err()
			}
		}
		return aws.Credentials{AccessKeyID: "owned-access", SecretAccessKey: "owned-secret", SessionToken: "owned-session", CanExpire: true, Expires: time.Now().Add(10 * time.Minute)}, nil
	}))
	first := make(chan error, 1)
	go func() { _, err := cache.Retrieve(context.Background()); first <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := cache.Retrieve(ctx); err == nil || calls.Load() != 1 {
		t.Error("waiting caller launched parallel refresh")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Retrieve(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("healthy credentials were not reused", err)
	}
	cache.(*auditExportCredentialCache).credentials.Expires = time.Now().Add(30 * time.Second)
	if _, err := cache.Retrieve(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatal("near-expiry credentials failed to refresh", err)
	}
}

func TestAuditExportProductionCloseReportsUnjoinedBoundary(t *testing.T) {
	config, clients, queue, _ := auditExportProductionClientsFixture(t, "audit-export")
	config.ShutdownTimeout = time.Second
	entered, release := make(chan struct{}), make(chan struct{})
	queue.receive = func(context.Context, *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
		close(entered)
		<-release
		return nil, errors.New("noncooperating boundary released")
	}
	deps, err := composeAuditExportWorkerRuntime(context.Background(), config, &auditExportWorkerDatabase{}, clients)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- deps.Processor.RunOnce(context.Background()) }()
	<-entered
	start := time.Now()
	err = deps.Close()
	elapsed := time.Since(start)
	close(release)
	runErr := <-done
	if err == nil || runErr == nil || elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
		t.Fatal("unjoined provider credited as clean shutdown", err, elapsed)
	}
	if deps.Ready(context.Background()) == nil || deps.Close() != nil {
		t.Fatal("failed shutdown reopened runtime or joined cleanup retry failed")
	}
}

func TestAuditExportProductionStartupRefusesUnreadyBeforeAnyProvider(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		for _, wire := range []string{`false`, `null`, `"true"`, `true true`} {
			t.Run(mode+wire, func(t *testing.T) {
				config, clients, queue, storage := auditExportProductionClientsFixture(t, mode)
				calls := 0
				clients.credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					calls++
					return aws.Credentials{}, errors.New("must not retrieve")
				})
				db := &auditExportWorkerDatabase{respond: func(context.Context, string, ...any) (json.RawMessage, error) { return json.RawMessage(wire), nil }}
				_, err := composeAuditExportWorkerRuntime(context.Background(), config, db, clients)
				clients.transport.CloseIdleConnections()
				if err == nil || len(db.queries) != 1 || calls != 0 || queue.attributeCalls != 0 || storage.calls != 0 {
					t.Fatal("unready startup reached provider")
				}
			})
		}
	}
}

func TestAuditExportProductionActualSDKStartupUsesOwnedWebIdentityAndReadOnlyQueue(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		t.Run(mode, func(t *testing.T) {
			config, err := loadWorkerRuntimeConfig(mapLookup(auditExportProductionEnvironment(mode)))
			if err != nil {
				t.Fatal(err)
			}
			clients, err := newAuditExportProductionClients(config)
			if err != nil {
				t.Fatal(err)
			}
			defer clients.transport.CloseIdleConnections()
			role, session := "arn:aws:iam::123456789012:role/zasp-production-audit-export-worker", "zasp-audit-export-worker"
			if mode == "audit-export-outbox" {
				role, session = "arn:aws:iam::123456789012:role/zasp-production-audit-export-outbox", "zasp-audit-export-outbox"
			}
			const token = "header.payload.signature-with-private-SDK-test-token-1234567890123456789"
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			// Only the private fixture path and owned TLS dial are substituted. Actual
			// SDK clients, signing, role/session arguments and regional URLs are used.
			clients.credentials.(*auditExportCredentialCache).provider.(*outboxWebIdentityProvider).tokenFile = path
			var assume, identity, attributes, unexpected atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "sts.us-east-1.amazonaws.com" {
					if r.ParseForm() != nil {
						unexpected.Add(1)
						http.Error(w, "invalid form", 400)
						return
					}
					w.Header().Set("Content-Type", "text/xml")
					switch r.Form.Get("Action") {
					case "AssumeRoleWithWebIdentity":
						assume.Add(1)
						if r.Form.Get("RoleArn") != role || r.Form.Get("RoleSessionName") != session || r.Form.Get("WebIdentityToken") != token || r.Form.Get("DurationSeconds") != "900" || r.Header.Get("Authorization") != "" {
							unexpected.Add(1)
							http.Error(w, "wrong explicit role exchange", 400)
							return
						}
						fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAOWNEDFIXTURE000</AccessKeyId><SecretAccessKey>owned-fixture-secret-not-real</SecretAccessKey><SessionToken>owned-fixture-session-not-real</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339))
					case "GetCallerIdentity":
						identity.Add(1)
						if !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAOWNEDFIXTURE000/") || r.Header.Get("X-Amz-Security-Token") != "owned-fixture-session-not-real" {
							unexpected.Add(1)
							http.Error(w, "wrong signed identity", 400)
							return
						}
						roleName := role[strings.LastIndex(role, "/")+1:]
						fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:sts::123456789012:assumed-role/%s/%s</Arn><UserId>owned-user</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`, roleName, session)
					default:
						unexpected.Add(1)
						http.Error(w, "unexpected STS operation", 400)
					}
					return
				}
				if r.Host == "sqs.us-east-1.amazonaws.com" && r.Header.Get("X-Amz-Target") == "AmazonSQS.GetQueueAttributes" {
					attributes.Add(1)
					body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
					var request struct {
						QueueURL   string   `json:"QueueUrl"`
						Attributes []string `json:"AttributeNames"`
					}
					if err != nil || len(body) > 4096 || json.Unmarshal(body, &request) != nil || request.QueueURL != "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports" || !reflect.DeepEqual(request.Attributes, []string{"QueueArn", "RedrivePolicy"}) || !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAOWNEDFIXTURE000/") {
						unexpected.Add(1)
						http.Error(w, "wrong queue authority", 400)
						return
					}
					w.Header().Set("Content-Type", "application/x-amz-json-1.0")
					io.WriteString(w, `{"Attributes":{"QueueArn":"arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports","RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports-dlq\",\"maxReceiveCount\":\"20\"}"}}`)
					return
				}
				unexpected.Add(1)
				http.Error(w, "startup must not access S3 or other services", 400)
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			clients.transport.TLSClientConfig.RootCAs = roots
			clients.transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
			clients.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			deps, err := composeAuditExportWorkerRuntime(context.Background(), config, &auditExportWorkerDatabase{}, clients)
			if err != nil {
				t.Fatal("actual SDK startup failed", err, assume.Load(), identity.Load(), attributes.Load(), unexpected.Load())
			}
			defer deps.Close()
			if err := deps.Ready(context.Background()); err != nil {
				t.Fatal("fresh actual SDK readiness failed", err)
			}
			if assume.Load() != 1 || identity.Load() != 2 || attributes.Load() != 2 || unexpected.Load() != 0 {
				t.Fatal("startup/readiness bypassed explicit SDK authority or touched storage")
			}
		})
	}
}

func TestAuditExportProductionSDKClientsUseOnlyTrustedPolicyRegions(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-not-authority")
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		t.Run(mode, func(t *testing.T) {
			config, err := loadWorkerRuntimeConfig(mapLookup(auditExportProductionEnvironment(mode)))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "audit-export" {
				second := config.AuditExports.Policies[0]
				second.PolicyID = "pid_52000049-0000-4000-8000-000000000049"
				second.KMSKeyARN = "arn:aws:kms:eu-west-1:210987654321:key/52000042-0000-4000-8000-000000000042"
				second.ExpectedBucketOwner = "210987654321"
				config.AuditExports.Policies = append(config.AuditExports.Policies, second)
			}
			clients, err := newAuditExportProductionClients(config)
			if err != nil || clients == nil {
				t.Fatal("explicit SDK configuration unavailable", err)
			}
			defer clients.transport.CloseIdleConnections()
			queueOptions := clients.queue.(*sqs.Client).Options()
			identityOptions := clients.identity.(*sts.Client).Options()
			httpClient, ok := queueOptions.HTTPClient.(*http.Client)
			if !ok || httpClient.Transport != clients.transport || httpClient.Timeout != 5*time.Second || clients.transport.Proxy != nil || httpClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse || queueOptions.Region != "us-east-1" || queueOptions.BaseEndpoint != nil || queueOptions.Credentials != clients.credentials || identityOptions.Credentials != clients.credentials || identityOptions.HTTPClient != httpClient || identityOptions.Region != "us-east-1" {
				t.Fatal("SDK client escaped explicit transport/credentials/region")
			}
			if mode == "audit-export-outbox" {
				if len(clients.artifacts) != 0 {
					t.Fatal("publisher acquired S3 authority")
				}
				return
			}
			if len(clients.artifacts) != 2 {
				t.Fatal("historical revision omitted")
			}
			for id, region := range map[string]string{"pid_52000041-0000-4000-8000-000000000041": "us-east-1", "pid_52000049-0000-4000-8000-000000000049": "eu-west-1"} {
				options := clients.artifacts[id].(*s3.Client).Options()
				if options.Region != region || options.BaseEndpoint != nil || options.UsePathStyle || options.HTTPClient != httpClient || options.Credentials != clients.credentials {
					t.Fatal("historical S3 authority silently substituted")
				}
			}
		})
	}
}

func TestAuditExportProductionQueueBindsExactDedicatedAuthority(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		for _, fault := range []string{"valid", "valid numeric", "decimal count", "exponent count", "null count", "queue", "dlq", "receive budget", "unknown redrive", "alias redrive", "duplicate redrive", "trailing redrive", "account", "role", "session"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				config, err := loadWorkerRuntimeConfig(mapLookup(auditExportProductionEnvironment(mode)))
				if err != nil {
					t.Fatal(err)
				}
				arn := "arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports"
				queue := &runtimeQueueReadinessStub{attributes: map[string]string{string(types.QueueAttributeNameQueueArn): arn, string(types.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"` + arn + `-dlq","maxReceiveCount":"20"}`}}
				session, role := "zasp-audit-export-worker", "zasp-production-audit-export-worker"
				if mode == "audit-export-outbox" {
					session, role = "zasp-audit-export-outbox", "zasp-production-audit-export-outbox"
				}
				identity := &runtimeIdentityStub{account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/" + role + "/" + session}
				redrive := queue.attributes[string(types.QueueAttributeNameRedrivePolicy)]
				switch fault {
				case "valid numeric":
					redrive = strings.Replace(redrive, `"20"`, `20`, 1)
				case "decimal count":
					redrive = strings.Replace(redrive, `"20"`, `20.0`, 1)
				case "exponent count":
					redrive = strings.Replace(redrive, `"20"`, `2e1`, 1)
				case "null count":
					redrive = strings.Replace(redrive, `"20"`, `null`, 1)
				case "queue":
					queue.attributes[string(types.QueueAttributeNameQueueArn)] = "arn:aws:sqs:us-east-1:123456789012:agentsec-background"
				case "dlq":
					redrive = strings.Replace(redrive, "-dlq", "-other", 1)
				case "receive budget":
					redrive = strings.Replace(redrive, `"20"`, `"5"`, 1)
				case "unknown redrive":
					redrive = strings.Replace(redrive, `"20"`, `"20","extra":true`, 1)
				case "alias redrive":
					redrive = strings.Replace(redrive, `"maxReceiveCount"`, `"MaxReceiveCount"`, 1)
				case "duplicate redrive":
					redrive = strings.Replace(redrive, `"20"`, `"5","maxReceiveCount":"20"`, 1)
				case "trailing redrive":
					redrive += `{}`
				case "account":
					identity.account = "210987654321"
				case "role":
					identity.arn = strings.Replace(identity.arn, role, "foreign", 1)
				case "session":
					identity.arn = strings.Replace(identity.arn, "/"+session, "/foreign", 1)
				}
				queue.attributes[string(types.QueueAttributeNameRedrivePolicy)] = redrive
				err = readyAuditExportProductionQueue(context.Background(), config, queue, identity)
				if fault == "valid" || fault == "valid numeric" {
					if err != nil || queue.attributeCalls != 1 || identity.calls != 1 {
						t.Fatal("exact export authority refused", err)
					}
				} else if err == nil {
					t.Fatal("foreign or malformed provider authority accepted")
				}
			})
		}
	}
}

func TestAuditExportProductionConstructorsHonorStartupContext(t *testing.T) {
	for _, kind := range []string{"worker", "outbox", "executor"} {
		for _, boundary := range []string{"nil", "canceled", "earlier deadline", "cancel on return"} {
			t.Run(kind+"/"+boundary, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				deadline, _ := ctx.Deadline()
				if boundary == "nil" {
					ctx = nil
				}
				if boundary == "canceled" {
					cancel()
				}
				inherited := true
				db := &auditExportWorkerDatabase{respond: func(actual context.Context, _ string, _ ...any) (json.RawMessage, error) {
					d, ok := actual.Deadline()
					inherited = ok && !d.After(deadline)
					if boundary == "cancel on return" {
						cancel()
					}
					return json.RawMessage(`true`), nil
				}}
				var err error
				switch kind {
				case "worker":
					_, err = newPostgresAuditExportAuthorityContext(ctx, db, auditExportWorkerPolicyFixture())
				case "outbox":
					_, err = newPostgresAuditExportOutboxAuthorityContext(ctx, db)
				case "executor":
					fixture := newAuditExportExecutionFixture(t, true)
					config := fixture.config
					config.Database = db
					_, err = newAuditExportExecutorContext(ctx, config)
				}
				if boundary == "earlier deadline" {
					if err != nil || !inherited || len(db.queries) != 1 {
						t.Fatal("startup lost caller deadline", err)
					}
				} else if err == nil || (boundary == "nil" || boundary == "canceled") && len(db.queries) != 0 {
					t.Fatal("startup cancellation authorized SQL or success")
				}
			})
		}
	}
}

const workerAuditExportPoliciesJSON = `[{"schema":"audit-export-policy-v1","policy_id":"pid_52000041-0000-4000-8000-000000000041","bucket":"zasp-audit-export-fixture","expected_bucket_owner":"123456789012","kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042","maximum_export_bytes":1073741824,"maximum_retained_bytes":10737418240,"maximum_inflight":2,"capture_timeout_seconds":120}]`

func auditExportProductionEnvironment(mode string) map[string]string {
	values := map[string]string{
		"ZASP_WORKER_MODE": mode, "ZASP_POSTGRES_DSN": "postgres://audit_export_worker_login@postgres.internal/zasp?sslmode=verify-full", "ZASP_DATABASE_AUTHORITY": "zasp_audit_export_worker", "ZASP_WORKER_ID": "audit-export-worker-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "180s", "ZASP_BATCH_SIZE": "2", "ZASP_SHUTDOWN_TIMEOUT": "20s", "ZASP_PROVIDER_TIMEOUT": "5s", "ZASP_AWS_REGION": "us-east-1",
		"ZASP_AUDIT_EXPORT_QUEUE_URL":               "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports",
		"ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	}
	if mode == "audit-export-outbox" {
		values["ZASP_DATABASE_AUTHORITY"] = "zasp_audit_export_outbox"
		values["ZASP_POSTGRES_DSN"] = "postgres://audit_export_outbox_login@postgres.internal/zasp?sslmode=verify-full"
		values["ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN"] = "arn:aws:iam::123456789012:role/zasp-production-audit-export-outbox"
	} else {
		values["ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN"] = "arn:aws:iam::123456789012:role/zasp-production-audit-export-worker"
		values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = workerAuditExportPoliciesJSON
	}
	return values
}

func TestAuditExportProductionConfigSelectsOnlyExplicitModeAuthority(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		t.Run(mode, func(t *testing.T) {
			values := auditExportProductionEnvironment(mode)
			config, err := loadWorkerRuntimeConfig(mapLookup(values))
			if err != nil || string(config.Mode) != mode || config.DatabaseAuthority != values["ZASP_DATABASE_AUTHORITY"] {
				t.Fatal("explicit registered export mode unavailable", err)
			}
			if config.AuditExports == nil || config.AuditExports.QueueURL != values["ZASP_AUDIT_EXPORT_QUEUE_URL"] || config.AuditExports.WriterRoleARN != values["ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN"] || config.AuditExports.PublisherRoleARN != values["ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN"] {
				t.Fatal("mode lost explicit queue/role")
			}
			if mode == "audit-export" && (len(config.AuditExports.Policies) != 1 || config.AuditExports.Policies[0].PolicyID != "pid_52000041-0000-4000-8000-000000000041") {
				t.Fatal("configured immutable revision missing")
			}
			if mode == "audit-export-outbox" && len(config.AuditExports.Policies) != 0 {
				t.Fatal("publisher acquired storage policy")
			}
		})
	}
}

func TestAuditExportProductionConfigKeepsHistoricalRevisionsClosed(t *testing.T) {
	for _, failure := range []string{"valid history", "empty", "duplicate revision", "unknown key", "alias", "null", "trailing", "too many"} {
		t.Run(failure, func(t *testing.T) {
			values := auditExportProductionEnvironment("audit-export")
			first := strings.TrimSuffix(strings.TrimPrefix(workerAuditExportPoliciesJSON, "["), "]")
			second := strings.Replace(first, "pid_52000041-0000-4000-8000-000000000041", "pid_52000049-0000-4000-8000-000000000049", 1)
			// Trusted history may deliberately pin a different region and bucket owner.
			second = strings.ReplaceAll(strings.Replace(second, "us-east-1", "eu-west-1", 1), "123456789012", "210987654321")
			switch failure {
			case "valid history":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = "[" + first + "," + second + "]"
			case "empty":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = "[]"
			case "duplicate revision":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = "[" + first + "," + first + "]"
			case "unknown key":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = strings.Replace(workerAuditExportPoliciesJSON, `"schema":`, `"role_arn":"foreign","schema":`, 1)
			case "alias":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = strings.Replace(workerAuditExportPoliciesJSON, `"policy_id":`, `"Policy_ID":`, 1)
			case "null":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = "null"
			case "trailing":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] += " []"
			case "too many":
				values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = "[" + strings.Repeat(first+",", 64) + first + "]"
			}
			config, err := loadWorkerRuntimeConfig(mapLookup(values))
			if failure != "valid history" {
				if err == nil {
					t.Fatal("untrusted policy revisions accepted")
				}
				return
			}
			if err != nil || len(config.AuditExports.Policies) != 2 || config.AuditExports.Policies[1].KMSKeyARN != "arn:aws:kms:eu-west-1:210987654321:key/52000042-0000-4000-8000-000000000042" {
				t.Fatal("explicit historical policy rewritten", err)
			}
			values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = "[]"
			if len(config.AuditExports.Policies) != 2 {
				t.Fatal("configuration retained caller-owned state")
			}
		})
	}
}

func TestAuditExportProductionConfigRejectsSelectorsOnLegacyWorker(t *testing.T) {
	base := map[string]string{"ZASP_WORKER_MODE": "scheduler", "ZASP_POSTGRES_DSN": "postgres://scheduler@postgres.internal/zasp?sslmode=verify-full", "ZASP_DATABASE_AUTHORITY": "zasp_discovery_scheduler", "ZASP_WORKER_ID": "scheduler-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s", "ZASP_DISCOVERY_PARSER_VERSION": "inventory-parser-2026.08.20", "ZASP_DISCOVERY_TOOL_VERSION": "collector-tool-2026.08.20"}
	config, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || config.AuditExports != nil {
		t.Fatal("legacy defaults changed", err)
	}
	for _, key := range []string{"ZASP_AUDIT_EXPORT_QUEUE_URL", "ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN", "ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN", "ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE", "ZASP_AUDIT_EXPORT_POLICIES_JSON", "ZASP_AUDIT_EXPORT_READER_ROLE_ARN", "ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY"} {
		values := cloneStringMap(base)
		values[key] = "injected"
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); err == nil {
			t.Fatal("legacy worker ignored explicit export authority", key)
		}
	}
}

func TestAuditExportProductionConfigRejectsMissingOrMixedAuthority(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		for _, failure := range []string{"queue", "role", "token", "timeout", "wrong queue", "wrong region", "wrong account", "legacy role", "legacy queue", "reader", "cursor", "opposite role", "wrong database authority", "NOLOGIN database user", "unsafe database login", "short lease", "large batch", "policies"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				values := auditExportProductionEnvironment(mode)
				role := "ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN"
				opposite := "ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN"
				if mode == "audit-export-outbox" {
					role, opposite = opposite, role
				}
				switch failure {
				case "queue":
					delete(values, "ZASP_AUDIT_EXPORT_QUEUE_URL")
				case "role":
					delete(values, role)
				case "token":
					values["ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE"] = "/tmp/token"
				case "timeout":
					delete(values, "ZASP_PROVIDER_TIMEOUT")
				case "wrong queue":
					values["ZASP_AUDIT_EXPORT_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-background"
				case "wrong region":
					values["ZASP_AWS_REGION"] = "us-west-2"
				case "wrong account":
					values[role] = "arn:aws:iam::210987654321:role/other"
				case "legacy role":
					values["ZASP_OUTBOX_ROLE_ARN"] = "arn:aws:iam::123456789012:role/legacy"
				case "legacy queue":
					values["ZASP_RUNTIME_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-runtime-events"
				case "reader":
					values["ZASP_AUDIT_EXPORT_READER_ROLE_ARN"] = "arn:aws:iam::123456789012:role/reader"
				case "cursor":
					values["ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY"] = strings.Repeat("x", 32)
				case "opposite role":
					values[opposite] = values[role]
				case "wrong database authority":
					values["ZASP_DATABASE_AUTHORITY"] = "zasp_outbox_worker"
				case "NOLOGIN database user":
					values["ZASP_POSTGRES_DSN"] = "postgres://" + values["ZASP_DATABASE_AUTHORITY"] + "@postgres.internal/zasp?sslmode=verify-full"
				case "unsafe database login":
					values["ZASP_POSTGRES_DSN"] = "postgres://untrusted-user@postgres.internal/zasp?sslmode=verify-full"
				case "short lease":
					values["ZASP_LEASE_DURATION"] = "59s"
				case "large batch":
					values["ZASP_BATCH_SIZE"] = "11"
				case "policies":
					if mode == "audit-export" {
						delete(values, "ZASP_AUDIT_EXPORT_POLICIES_JSON")
					} else {
						values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = workerAuditExportPoliciesJSON
					}
				}
				if _, err := loadWorkerRuntimeConfig(mapLookup(values)); err == nil {
					t.Fatal("missing/mixed export authority accepted")
				}
			})
		}
	}
}
