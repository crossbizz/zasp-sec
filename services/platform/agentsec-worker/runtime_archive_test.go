package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeArchiveExecutorVerifiesExactVersionedRawEvidence(t *testing.T) {
	body := []byte(`{"events":[{"kind":"process"}]}`)
	lease := runtimeArchiveLease(t, body)
	api := &runtimeArchiveAPIStub{body: body, lease: lease}
	executor, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: api, Bucket: "runtime-evidence", ExpectedOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if effect.EffectDigest != lease.InputDigest || effect.ResultDigest != lease.InputDigest || effect.ResultReference != lease.InputReference || effect.ResultVersionID != lease.InputVersionID || api.headCalls != 1 || api.getCalls != 1 {
		t.Fatalf("effect=%#v head=%d get=%d", effect, api.headCalls, api.getCalls)
	}
	if api.headInput == nil || aws.ToString(api.headInput.VersionId) != lease.InputVersionID || api.getInput == nil || aws.ToString(api.getInput.VersionId) != lease.InputVersionID {
		t.Fatalf("head/get=%#v / %#v", api.headInput, api.getInput)
	}
}

func TestRuntimeArchiveExecutorFailsClosedOnEvidenceDrift(t *testing.T) {
	body := []byte(`{"events":[{"kind":"process"}]}`)
	for name, mutate := range map[string]func(*runtimeArchiveAPIStub, *runtimeevent.StageLease){
		"content": func(api *runtimeArchiveAPIStub, _ *runtimeevent.StageLease) { api.body = []byte(`{"events":[]}`) },
		"version": func(_ *runtimeArchiveAPIStub, lease *runtimeevent.StageLease) {
			lease.InputVersionID = "foreign-version"
		},
		"bucket": func(_ *runtimeArchiveAPIStub, lease *runtimeevent.StageLease) {
			lease.InputReference = "s3://foreign-bucket/runtime/v15/input.json"
		},
		"key scope": func(_ *runtimeArchiveAPIStub, lease *runtimeevent.StageLease) {
			lease.InputReference = "s3://runtime-evidence/runtime/v15/pid_70000099-0000-4000-8000-000000000099/" + lease.Scope.WorkspaceID().String() + "/" + lease.Scope.EnvironmentID().String() + "/pid_70000002-0000-4000-8000-000000000003/00000000000000000001/" + lease.BatchID.String() + ".json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			lease := runtimeArchiveLease(t, body)
			api := &runtimeArchiveAPIStub{body: body, lease: lease}
			mutate(api, &lease)
			executor, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: api, Bucket: "runtime-evidence", ExpectedOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 64 << 20})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.Execute(context.Background(), lease); err != errRuntimeStageMalformed {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRuntimeArchiveExecutorClassifiesProviderFailuresWithoutLeakingThem(t *testing.T) {
	body := []byte(`{"events":[{"kind":"process"}]}`)
	for code, want := range map[string]error{"AccessDenied": errRuntimeStageDenied, "NoSuchVersion": errRuntimeStageMalformed, "SlowDown": errRuntimeStageRetryable} {
		t.Run(code, func(t *testing.T) {
			lease := runtimeArchiveLease(t, body)
			api := &runtimeArchiveAPIStub{body: body, lease: lease, headErr: &smithy.GenericAPIError{Code: code, Message: "provider-secret-must-not-escape"}}
			executor, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: api, Bucket: "runtime-evidence", ExpectedOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 64 << 20})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.Execute(context.Background(), lease); err != want || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error=%v want=%v", err, want)
			}
		})
	}
}

type runtimeArchiveAPIStub struct {
	body      []byte
	lease     runtimeevent.StageLease
	headInput *s3.HeadObjectInput
	getInput  *s3.GetObjectInput
	headCalls int
	getCalls  int
	headErr   error
}

func (stub *runtimeArchiveAPIStub) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	stub.headCalls++
	stub.headInput = input
	if stub.headErr != nil {
		return nil, stub.headErr
	}
	digest := sha256.Sum256(stub.body)
	return &s3.HeadObjectOutput{ContentLength: aws.Int64(int64(len(stub.body))), ContentType: aws.String("application/json"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:])), VersionId: aws.String(stub.lease.InputVersionID), ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"), Metadata: runtimeArchiveMetadata(stub.lease.Scope, digest)}, nil
}

func (stub *runtimeArchiveAPIStub) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	stub.getCalls++
	stub.getInput = input
	digest := sha256.Sum256(stub.body)
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(stub.body)), ContentLength: aws.Int64(int64(len(stub.body))), ContentType: aws.String("application/json"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:])), VersionId: aws.String(stub.lease.InputVersionID), ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"), Metadata: runtimeArchiveMetadata(stub.lease.Scope, digest)}, nil
}

func runtimeArchiveLease(t *testing.T, body []byte) runtimeevent.StageLease {
	t.Helper()
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageArchive)
	lease.InputDigest = sha256.Sum256(body)
	lease.InputVersionID = "runtime-version-0001"
	sensorID := workerID(t, "pid_70000002-0000-4000-8000-000000000003")
	key := fmt.Sprintf("runtime/v15/%s/%s/%s/%s/%020d/%s.json", lease.Scope.OrganizationID(), lease.Scope.WorkspaceID(), lease.Scope.EnvironmentID(), sensorID, lease.Generation, lease.BatchID)
	lease.InputReference = "s3://runtime-evidence/" + key
	lease.LeaseExpiresAt = time.Now().Add(time.Minute)
	return lease
}
