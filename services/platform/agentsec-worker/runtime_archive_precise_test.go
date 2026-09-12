package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type preciseArchiveExpiryAPI struct {
	*runtimeArchiveAPIStub
	after func()
}

func (api *preciseArchiveExpiryAPI) GetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	result, err := api.runtimeArchiveAPIStub.GetObject(ctx, input, options...)
	api.after()
	return result, err
}

func TestPreciseArchiveExecutionRequiresCapabilityAndValidBody(t *testing.T) {
	for _, scenario := range []string{"valid", "direct", "worker", "token", "expired", "renewed", "lost during read", "legacy body", "historical"} {
		t.Run(scenario, func(t *testing.T) {
			f := preciseExecutorFixture(t)
			lease := f.execution.lease
			lease.Stage = runtimeevent.RuntimeStageArchive
			lease.ImplementationVersion = "runtime-archive-v2"
			if scenario == "historical" {
				lease.ImplementationVersion = "runtime-archive-v1"
			}
			body := f.archive
			if scenario == "legacy body" || scenario == "historical" {
				body = []byte(`{"events":[]}`)
			}
			lease.InputDigest = sha256.Sum256(body)
			lease.InputReference = fmt.Sprintf("s3://runtime-evidence/runtime/v15/%s/%s/%s/pid_70000002-0000-4000-8000-000000000003/%020d/%s.json", lease.Scope.OrganizationID(), lease.Scope.WorkspaceID(), lease.Scope.EnvironmentID(), lease.Generation, lease.BatchID)
			lease.InputVersionID = "archive-v2"
			execution := runtimeStageExecution{lease: lease, workerID: "archive-worker", leaseToken: strings.Repeat("a", 32)}
			switch scenario {
			case "worker":
				execution.workerID = ""
			case "token":
				execution.leaseToken = ""
			case "expired", "renewed":
				execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			}
			if scenario == "renewed" {
				execution.renewal = &runtimeStageLeaseRenewal{expiresAt: time.Now().Add(time.Minute)}
			}
			api := &runtimeArchiveAPIStub{body: body, lease: lease}
			executor, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: api, Bucket: "runtime-evidence", ExpectedOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 64 << 20})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "lost during read" {
				execution.renewal = &runtimeStageLeaseRenewal{expiresAt: time.Now().Add(time.Minute)}
				executor.config.API = &preciseArchiveExpiryAPI{runtimeArchiveAPIStub: api, after: func() {
					execution.renewal.mu.Lock()
					execution.renewal.expiresAt = time.Now().Add(-time.Second)
					execution.renewal.mu.Unlock()
				}}
			}
			var effect runtimeStageEffect
			if scenario == "direct" {
				effect, err = executor.Execute(context.Background(), execution.lease)
			} else {
				authorized, ok := any(executor).(authorizedRuntimeStageExecutor)
				if !ok {
					t.Fatal("archive lacks authorized execution")
				}
				effect, err = authorized.ExecuteAuthorized(context.Background(), execution)
			}
			if scenario == "lost during read" {
				if err != errRuntimeStageRetryable || effect != (runtimeStageEffect{}) {
					t.Fatal("lost lease reported success", err)
				}
			} else if scenario == "valid" || scenario == "renewed" || scenario == "historical" {
				if err != nil || effect.ResultDigest != lease.InputDigest || effect.EffectDigest != lease.InputDigest || effect.ResultVersionID != lease.InputVersionID || effect.ResultReference != lease.InputReference {
					t.Fatal("precise archive failed", err)
				}
				if scenario == "historical" {
					old, oldErr := executor.Execute(context.Background(), lease)
					if oldErr != nil || old != effect {
						t.Fatal("historical effect changed", oldErr)
					}
				}
			} else {
				if err != errRuntimeStageMalformed || effect != (runtimeStageEffect{}) {
					t.Fatal("invalid archive accepted", err)
				}
				if scenario != "legacy body" && api.headCalls != 0 {
					t.Fatal("invalid capability reached S3")
				}
			}
		})
	}
}
