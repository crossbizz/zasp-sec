package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type capacityInventory struct {
	discoveryInventoryCallerStub
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type capacityObservedDriver struct {
	workerPostgresDriver
	t               *testing.T
	mu              sync.Mutex
	historicalApply bool
	recordQuery     string
	recordArgs      []any
}
type capacityObservedRow struct {
	apiserver.PostgresRow
	operation string
	t         *testing.T
}

func (d *capacityObservedDriver) QueryRow(ctx context.Context, q string, args ...any) apiserver.PostgresRow {
	d.mu.Lock()
	if strings.Contains(q, "zasp_temporal72.record_page(") {
		d.recordQuery, d.recordArgs = q, append([]any{}, args...)
	}
	if d.historicalApply && strings.Contains(q, "zasp_temporal72.apply_retained_snapshot(") {
		// Only this fixture seeds an edge with the unchanged pre72 writer.
		// The next call uses the shipped wrapper to adopt its existing identity.
		d.historicalApply = false
		q = strings.Replace(q, "zasp_temporal72.apply_retained_snapshot", "zasp_execution_apply_complete_snapshot", 1)
	}
	d.mu.Unlock()
	return capacityObservedRow{PostgresRow: d.workerPostgresDriver.QueryRow(ctx, q, args...), operation: strings.SplitN(q, "(", 2)[0], t: d.t}
}
func (r capacityObservedRow) Scan(values ...any) error {
	err := r.PostgresRow.Scan(values...)
	if e, ok := err.(*pgconn.PgError); ok {
		r.t.Log("installed SQL boundary", r.operation, e.Code, e.Message)
	}
	return err
}

type capacityObservedAuthority struct {
	*apiserver.DiscoveryExecutionRepository
	appliedNonempty bool
	succeeded       bool
	afterApply      func(context.Context, domain.Scope, apiserver.ExecutionCompleteSnapshot, apiserver.ExecutionSnapshotApplyResult) error
}

func (a *capacityObservedAuthority) ApplyCompleteSnapshot(ctx context.Context, scope domain.Scope, input apiserver.ExecutionCompleteSnapshot) (apiserver.ExecutionSnapshotApplyResult, error) {
	result, err := a.DiscoveryExecutionRepository.ApplyCompleteSnapshot(ctx, scope, input)
	var entities []json.RawMessage
	a.appliedNonempty = err == nil && json.Unmarshal(input.Entities, &entities) == nil && len(entities) > 0 && len(result.CandidateDigest) == 32 && result.SnapshotID == input.SnapshotID
	if err == nil && a.afterApply != nil {
		err = a.afterApply(ctx, scope, input, result)
	}
	return result, err
}
func (a *capacityObservedAuthority) FinishDiscoveryJob(ctx context.Context, scope domain.Scope, input apiserver.DiscoveryJobCompletion) (apiserver.WorkCompletionResult, error) {
	result, err := a.DiscoveryExecutionRepository.FinishDiscoveryJob(ctx, scope, input)
	a.succeeded = err == nil && result.State == "succeeded" && input.Outcome == "succeeded"
	return result, err
}

func (c *capacityInventory) GetCollectionInventory(ctx context.Context, credential []byte) (awsdiscovery.CollectionInventory, error) {
	c.calls.Add(1)
	if c.entered != nil {
		c.once.Do(func() {
			close(c.entered)
			select {
			case <-c.release:
			case <-ctx.Done():
			}
		})
	}
	return c.discoveryInventoryCallerStub.GetCollectionInventory(ctx, credential)
}

// The parent owns PostgreSQL. Both collector routes use actual repositories,
// credential binding, collector adapters and typed inventory SQL. Only cloud
// IO and the queue transport are controlled.
func TestDiscoveryCapacityInstalledIO(t *testing.T) {
	dsn := os.Getenv("ZASP_P4B_FIX1_WORKER_DSN")
	if dsn == "" {
		t.Skip("requires owned fix1 PostgreSQL parent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	driver := &capacityObservedDriver{workerPostgresDriver: workerPostgresDriver{pool: pool}, t: t, historicalApply: os.Getenv("ZASP_P4B_FIX1_HISTORICAL_EDGE") == "1"}
	db, err := apiserver.NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	var start orchestration.DiscoveryStart
	if json.Unmarshal([]byte(os.Getenv("ZASP_P4B_START")), &start) != nil || start.Continuation == nil {
		t.Fatal("start")
	}
	deadline := start.Continuation.Deadline
	start.Continuation = nil
	_, scope, err := discoveryProductArgs(start)
	if err != nil {
		t.Fatal(err)
	}
	job, err := domain.ParseProductID(os.Getenv("ZASP_P4B_FIX1_LEGACY_JOB"))
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Now().UTC() }
	var secretReads atomic.Int64
	credentials, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: productSecretReader(func(context.Context, string) ([]byte, error) {
		secretReads.Add(1)
		return []byte("external-id-customer-0001"), nil
	}), AssumeRole: &discoveryAssumeRoleStub{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE000001"), SecretAccessKey: aws.String(strings.Repeat("s", 40)), SessionToken: aws.String(strings.Repeat("t", 32)), Expiration: aws.Time(now().Add(time.Hour))}}}, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	storage := &productVersionedS3{items: map[string]*discoveryS3APIStub{}}
	artifacts, err := newProductionDiscoveryArtifactAuthority(storage, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: 5 * time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	inventory := &capacityInventory{}
	legacyFirst := os.Getenv("ZASP_P4B_FIX1_ORDER") == "legacy"
	if legacyFirst {
		inventory.entered = make(chan struct{})
		inventory.release = make(chan struct{})
	}
	factory, err := newProductionLiveDiscoveryCollectorFactory(productionDiscoveryClientConfig{Artifacts: artifacts, Credentials: credentials, AWSInventory: inventory, AWSSecurity: &discoverySecurityAnalyzerStub{}, AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "collector_v1", GitHubCollectorVersion: "collector_v1", OktaCollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", KubernetesAllowedCIDRs: []string{"203.0.113.0/24"}, ProviderTimeout: 15 * time.Second, ReadinessTimeout: time.Second, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	product, err := newTemporalDiscoveryProduct(db, factory)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := apiserver.NewDiscoveryExecutionRepository(db, apiserver.DiscoveryExecutionAuthorityWorker)
	if err != nil {
		t.Fatal(err)
	}
	steps := []string{}
	queue := &recordingDiscoveryQueue{steps: &steps}
	observed := &capacityObservedAuthority{DiscoveryExecutionRepository: repository}
	if ownerDSN := os.Getenv("ZASP_P4B_FIX1_OWNER_DSN"); ownerDSN != "" {
		owner, err := pgxpool.New(ctx, ownerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close()
		observed.afterApply = func(ctx context.Context, scope domain.Scope, input apiserver.ExecutionCompleteSnapshot, first apiserver.ExecutionSnapshotApplyResult) error {
			replay, err := repository.ApplyCompleteSnapshot(ctx, scope, input)
			if err != nil || !bytes.Equal(first.CandidateDigest, replay.CandidateDigest) {
				return fmt.Errorf("retained exact apply replay: %v", err)
			}
			var original string
			changed := "pid_72920001-0000-4000-8000-000000000001"
			args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.IntegrationID}
			if err := owner.QueryRow(ctx, `SELECT id FROM zasp_inventory_relationships WHERE(organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)`, args...).Scan(&original); err != nil {
				return err
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_inventory_relationships SET id=$5 WHERE(organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)`, append(args, changed)...); err != nil {
				return err
			}
			defer func() {
				if _, err := owner.Exec(context.Background(), `UPDATE zasp_inventory_relationships SET id=$5 WHERE(organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)`, append(args, original)...); err != nil {
					t.Error("fixture edge restoration", err)
				}
			}()
			// A changed mutable inventory mapping must not alter a committed
			// retry's digest or projection payload. The fixture restores it.
			replay, err = repository.ApplyCompleteSnapshot(ctx, scope, input)
			if err != nil || !bytes.Equal(first.CandidateDigest, replay.CandidateDigest) {
				return fmt.Errorf("retained replay consulted later inventory: %v", err)
			}
			return nil
		}
	}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{Authority: observed, Queue: queue, CollectorFactory: factory, WorkerID: "capacity-live", LeaseSeconds: 60, BatchSize: 1, Now: now, NewLeaseToken: func() (string, error) { return "capacity-live-token-0001", nil }})
	if err != nil {
		t.Fatal(err)
	}
	delivery := jobqueue.Delivery{Job: jobqueue.Job{Scope: scope, JobID: job, Kind: "discovery"}}
	command := orchestration.DiscoveryPageCommand{Start: start, Deadline: deadline}
	if legacyFirst {
		done := make(chan error, 1)
		go func() { done <- processor.process(ctx, delivery) }()
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(inventory.release) }) }
		joined := false
		defer func() {
			release()
			if !joined {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("retained worker did not join")
				}
			}
		}()
		select {
		case <-inventory.entered:
		case err := <-done:
			joined = true
			t.Fatal("retained did not reach provider", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		reads, calls := secretReads.Load(), inventory.calls.Load()
		page, err := product.CollectDiscoveryPage(ctx, command)
		if err != nil || page.Outcome != "retryable" || secretReads.Load() != reads || inventory.calls.Load() != calls || storage.writes != 0 {
			t.Fatal("second72 owner performed IO", page, err, secretReads.Load(), inventory.calls.Load(), storage.writes)
		}
		command.ExpectedCheckpointVersion, command.ExpectedCheckpointDigest = page.CheckpointVersion, page.ReceiptDigest
		release()
		if err := <-done; err != nil {
			joined = true
			t.Fatal("retained application", err)
		}
		joined = true
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	} else {
		page, err := product.CollectDiscoveryPage(ctx, command)
		if err != nil || page.Outcome != "partial" {
			t.Fatal("first72 owner", page, err)
		}
		command.ExpectedCheckpointVersion, command.ExpectedCheckpointDigest = page.CheckpointVersion, page.ReceiptDigest
		reads, calls, writes := secretReads.Load(), inventory.calls.Load(), storage.writes
		if err := processor.process(ctx, delivery); err != nil || secretReads.Load() != reads || inventory.calls.Load() != calls || storage.writes != writes || len(steps) != 0 {
			t.Fatal("second retained owner performed IO/ACK", err, steps)
		}
	}
	var page orchestration.DiscoveryPage
	for n := 0; n < 5; n++ {
		page, err = product.CollectDiscoveryPage(ctx, command)
		if err != nil || (page.Outcome != "partial" && page.Outcome != "complete") {
			t.Fatal("72 post-release progress", page, err)
		}
		if page.Outcome == "complete" {
			break
		}
		command.ExpectedCheckpointVersion, command.ExpectedCheckpointDigest = page.CheckpointVersion, page.ReceiptDigest
	}
	if page.Outcome != "complete" {
		t.Fatal("72 did not complete")
	}
	receipt, err := product.ApplyDiscoverySnapshot(ctx, orchestration.DiscoveryApplyCommand{Start: start, Deadline: deadline, CompleteReceiptDigest: page.ReceiptDigest})
	if err != nil {
		t.Fatal("72 apply", err)
	}
	if err := product.FinishDiscovery(ctx, orchestration.DiscoveryFinish{Start: start, Outcome: "succeeded", ReceiptDigest: receipt}); err != nil {
		t.Fatal(err)
	}
	if !legacyFirst {
		if err := processor.process(ctx, delivery); err != nil {
			t.Fatal("retained post-release progress", err)
		}
	}
	if len(steps) != 1 || steps[0] != "ack" || !observed.appliedNonempty || !observed.succeeded {
		t.Fatal("typed nonempty application and succeeded completion required before ACK", steps, observed.appliedNonempty, observed.succeeded)
	}
	// The second owner's later observation must not change the first complete
	// page receipt. This replays the original raw candidate, not its mapped IDs.
	var replay orchestration.DiscoveryPage
	driver.mu.Lock()
	recordQuery, recordArgs := driver.recordQuery, append([]any{}, driver.recordArgs...)
	driver.mu.Unlock()
	if err := product.query(ctx, recordQuery, &replay, recordArgs...); err != nil || replay != page {
		t.Fatal("complete page replay changed after later inventory", replay, page, err)
	}
	t.Log("both actual collector routes completed; blocked second owner made zero credential/provider/storage calls; original72 deadline retained")
}
