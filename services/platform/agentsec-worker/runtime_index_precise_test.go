package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"strings"
	"testing"
	"time"
)

func TestPreciseIndexWorkerReadsVersionedEvidenceThroughProductionReader(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(fmt.Sprintf("drift=%v", drift), func(t *testing.T) {
			config, execution, driver, receipts := preciseIndexWorker(t)
			body := bytes.Clone(config.Reader.(*runtimeArchivedReaderStub).body)
			lease := &execution.lease
			lease.InputReference = fmt.Sprintf("s3://runtime-evidence/runtime/v15/%s/%s/%s/pid_70000002-0000-4000-8000-000000000003/%020d/%s.json", lease.Scope.OrganizationID(), lease.Scope.WorkspaceID(), lease.Scope.EnvironmentID(), lease.Generation, lease.BatchID)
			api := &runtimeArchiveAPIStub{body: body, lease: *lease}
			if drift {
				api.body = append(bytes.Clone(body), '\n')
			}
			reader, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: api, Bucket: "runtime-evidence", ExpectedOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 64 << 20})
			if err != nil {
				t.Fatal(err)
			}
			config.Reader = reader
			executor, err := newRuntimeIndexExecutor(config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(context.Background(), execution)
			if drift {
				if err != errRuntimeStageMalformed || effect != (runtimeStageEffect{}) || driver.calls != 0 || receipts.putCalls != 0 || api.getCalls != 0 {
					t.Fatal("altered evidence crossed reader boundary", err)
				}
				return
			}
			if err != nil || driver.calls != 1 || receipts.putCalls != 1 || api.headCalls != 1 || api.getCalls != 1 {
				t.Fatal("composed read failed", err)
			}
			if aws.ToString(api.headInput.VersionId) != lease.InputVersionID || aws.ToString(api.getInput.VersionId) != lease.InputVersionID || aws.ToString(api.getInput.ExpectedBucketOwner) != "123456789012" {
				t.Fatal("unbound S3 read")
			}
			receipt, err := runtimeevent.DecodeStageReceipt(receipts.put.Body)
			if err != nil || receipt.ArchiveReference != lease.InputReference || receipt.ArchiveVersionID != lease.InputVersionID || receipt.ArchiveDigest != lease.InputDigest || receipt.EffectDigest != driver.input.ContentDigest {
				t.Fatal("composed receipt lost evidence", err)
			}
		})
	}
}

func TestPreciseIndexWorkerDrainsHistoricalBytesAndUsesRenewedLease(t *testing.T) {
	config, execution, _, receipts := preciseIndexWorker(t)
	execution.renewal = &runtimeStageLeaseRenewal{expiresAt: time.Now().Add(time.Minute)}
	execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
	executor, err := newRuntimeIndexExecutor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteAuthorized(context.Background(), execution); err != nil || receipts.putCalls != 1 {
		t.Fatal("renewed indexing failed", err)
	}
	config, execution, _, receipts = preciseIndexWorker(t)
	execution.lease.ImplementationVersion = "runtime-index-v1"
	body := runtimeIndexBody(execution.lease)
	execution.lease.InputDigest = sha256.Sum256(body)
	execution.lease.PredecessorDigest = &execution.lease.InputDigest
	config.Reader = &runtimeArchivedReaderStub{body: body}
	config.ImplementationVersion = "runtime-index-v1"
	old, err := newRuntimeIndexExecutor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Execute(context.Background(), execution.lease); err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(receipts.put.Body)
	config.ImplementationVersion = "runtime-index-v2"
	newer, err := newRuntimeIndexExecutor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newer.ExecuteAuthorized(context.Background(), execution); err != nil || !bytes.Equal(before, receipts.put.Body) {
		t.Fatal("V1 drain changed receipt bytes", err)
	}
}

type preciseIndexDriver struct {
	calls int
	input runtimeindex.DriverBatch
	after func()
}

func (d *preciseIndexDriver) Apply(_ context.Context, b runtimeindex.DriverBatch) (runtimeindex.DriverResult, error) {
	d.calls++
	d.input = b
	ids := make([]string, len(b.Documents))
	for i, v := range b.Documents {
		ids[i] = v.DocumentID
	}
	if d.after != nil {
		d.after()
	}
	return runtimeindex.DriverResult{BatchID: b.BatchID, Generation: b.Generation, InputDigest: b.InputDigest, ContentDigest: b.ContentDigest, DocumentIDs: ids}, nil
}

func preciseIndexWorker(t *testing.T) (runtimeIndexExecutorConfig, runtimeStageExecution, *preciseIndexDriver, *runtimeReceiptStoreStub) {
	t.Helper()
	f := preciseExecutorFixture(t)
	lease := f.execution.lease
	lease.Stage = runtimeevent.RuntimeStageIndex
	lease.ImplementationVersion = "runtime-index-v2"
	lease.InputDigest = sha256.Sum256(f.archive)
	lease.PredecessorDigest = &lease.InputDigest
	lease.InputReference = "s3://zasp-evidence/raw.json"
	lease.InputVersionID = "raw-v2"
	driver := &preciseIndexDriver{}
	store, err := runtimeindex.New(driver, runtimeindex.Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000})
	if err != nil {
		t.Fatal(err)
	}
	receipts := &runtimeReceiptStoreStub{}
	return runtimeIndexExecutorConfig{Reader: &runtimeArchivedReaderStub{body: f.archive}, Index: store, Receipts: receipts, ImplementationVersion: "runtime-index-v2"}, runtimeStageExecution{lease: lease, workerID: "precise-index-worker", leaseToken: strings.Repeat("a", 32)}, driver, receipts
}

func TestPreciseIndexWorkerWritesV2Receipt(t *testing.T) {
	config, execution, driver, receipts := preciseIndexWorker(t)
	executor, err := newRuntimeIndexExecutor(config)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.ExecuteAuthorized(context.Background(), execution)
	if err != nil || !validRuntimeStageEffect(effect) || driver.calls != 1 || receipts.putCalls != 1 {
		t.Fatal("precise indexing failed", err)
	}
	receipt, err := runtimeevent.DecodeStageReceipt(receipts.put.Body)
	if err != nil || receipt.ImplementationVersion != "runtime-index-v2" || receipt.EffectDigest != driver.input.ContentDigest || receipt.ArchiveDigest != execution.lease.InputDigest || len(receipt.ItemIDs) != 1 {
		t.Fatal("index receipt binding lost", err)
	}
	if driver.input.Documents[0].AgentID != "" || driver.input.Documents[0].SessionID != "" {
		t.Fatal("observed identity promoted")
	}
}

func TestPreciseIndexWorkerRejectsMissingCapability(t *testing.T) {
	config, _, _, _ := preciseIndexWorker(t)
	config.Index = &runtimeIndexStoreStub{}
	if _, err := newRuntimeIndexExecutor(config); err == nil {
		t.Fatal("V2 accepted legacy-only store")
	}
}

func TestPreciseIndexWorkerRejectsUnprivilegedAndInvalidLease(t *testing.T) {
	for _, scenario := range []string{"unprivileged", "worker", "token", "predecessor", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			config, execution, driver, receipts := preciseIndexWorker(t)
			executor, err := newRuntimeIndexExecutor(config)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "worker":
				execution.workerID = ""
			case "token":
				execution.leaseToken = ""
			case "predecessor":
				execution.lease.PredecessorDigest = nil
			case "expired":
				execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			}
			if scenario == "unprivileged" {
				_, err = executor.Execute(context.Background(), execution.lease)
			} else {
				_, err = executor.ExecuteAuthorized(context.Background(), execution)
			}
			if err != errRuntimeStageMalformed || driver.calls != 0 || receipts.putCalls != 0 {
				t.Fatal("invalid execution crossed boundary", err)
			}
		})
	}
}

func TestPreciseIndexWorkerCancellationBeforeReceipt(t *testing.T) {
	config, execution, driver, receipts := preciseIndexWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	driver.after = cancel
	executor, err := newRuntimeIndexExecutor(config)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.ExecuteAuthorized(ctx, execution)
	if err != errRuntimeStageRetryable || effect != (runtimeStageEffect{}) || driver.calls != 1 || receipts.putCalls != 0 {
		t.Fatal("canceled index wrote receipt", err)
	}
}
