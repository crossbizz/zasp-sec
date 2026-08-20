package s3rawstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestStorePutsExactCreateOnlyVersionedRuntimeArtifact(t *testing.T) {
	request := rawPut(t)
	api := &rawS3Stub{}
	api.put = func(_ context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
		if aws.ToString(input.Bucket) != "zasp-runtime-prod" || aws.ToString(input.Key) != request.Key || aws.ToString(input.IfNoneMatch) != "*" || input.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || aws.ToString(input.SSEKMSKeyId) != rawKMSKey || aws.ToString(input.ExpectedBucketOwner) != "123456789012" || aws.ToInt64(input.ContentLength) != int64(len(request.Body)) || aws.ToString(input.ContentType) != "application/json" {
			t.Fatalf("put=%#v", input)
		}
		body := make([]byte, len(request.Body))
		if _, err := input.Body.Read(body); err != nil || !bytes.Equal(body, request.Body) {
			t.Fatalf("body=%x err=%v", body, err)
		}
		return &s3.PutObjectOutput{VersionId: aws.String("version-v15-1"), ChecksumSHA256: aws.String(checksumText(request.ContentDigest)), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(rawKMSKey)}, nil
	}
	api.head = exactHead(request, "version-v15-1")
	store, err := New(api, Config{Bucket: "zasp-runtime-prod", ExpectedBucketOwner: "123456789012", KMSKeyARN: rawKMSKey, MaximumBytes: 1 << 20, OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Put(context.Background(), request)
	if err != nil || artifact.Key != request.Key || artifact.Reference != "s3://zasp-runtime-prod/"+request.Key || artifact.VersionID != "version-v15-1" || artifact.ContentDigest != request.ContentDigest || artifact.Size != int64(len(request.Body)) || artifact.KMSKeyARN != rawKMSKey {
		t.Fatalf("artifact=%#v err=%v", artifact, err)
	}
}

func TestStoreReconcilesLostPutAcknowledgementAndRejectsDrift(t *testing.T) {
	request := rawPut(t)
	for _, test := range []struct {
		name    string
		head    *s3.HeadObjectOutput
		wantErr bool
	}{
		{name: "exact", head: exactHead(request, "version-v15-lost")},
		{name: "drift", head: exactHead(request, "version-v15-lost"), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.wantErr {
				test.head.ChecksumSHA256 = aws.String(checksumText(sha256.Sum256([]byte("different"))))
			}
			api := &rawS3Stub{put: func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
				return nil, errors.New("provider-secret")
			}, head: test.head}
			store, _ := New(api, Config{Bucket: "zasp-runtime-prod", ExpectedBucketOwner: "123456789012", KMSKeyARN: rawKMSKey, MaximumBytes: 1 << 20, OperationTimeout: time.Second})
			artifact, err := store.Put(context.Background(), request)
			if test.wantErr {
				if !errors.Is(err, runtimeevent.ErrProductionIngestUnknown) || artifact != (runtimeevent.RawArtifact{}) || bytes.Contains([]byte(err.Error()), []byte("provider-secret")) {
					t.Fatalf("artifact=%#v err=%v", artifact, err)
				}
				return
			}
			if err != nil || artifact.VersionID != "version-v15-lost" || api.putCalls != 1 || api.headCalls != 1 {
				t.Fatalf("artifact=%#v err=%v calls=%d/%d", artifact, err, api.putCalls, api.headCalls)
			}
		})
	}
}

const rawKMSKey = "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"

func rawPut(t *testing.T) runtimeevent.RawArtifactPut {
	t.Helper()
	scope, err := domain.NewScope(rawID(t, 1), rawID(t, 2), rawID(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"source":"tetragon","events":[{"id":"one"}]}`)
	return runtimeevent.RawArtifactPut{Scope: scope, Key: "runtime/v15/" + scope.OrganizationID().String() + "/" + scope.WorkspaceID().String() + "/" + scope.EnvironmentID().String() + "/pid_00000004-0000-4000-8000-000000000004/00000000000000000001/pid_00000005-0000-4000-8000-000000000005.json", MediaType: "application/json", Body: body, ContentDigest: sha256.Sum256(body)}
}

func rawID(t *testing.T, seed int) domain.ProductID {
	t.Helper()
	value, err := domain.ParseProductID(map[int]string{1: "pid_00000001-0000-4000-8000-000000000001", 2: "pid_00000002-0000-4000-8000-000000000002", 3: "pid_00000003-0000-4000-8000-000000000003"}[seed])
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func exactHead(request runtimeevent.RawArtifactPut, version string) *s3.HeadObjectOutput {
	return &s3.HeadObjectOutput{VersionId: aws.String(version), ContentLength: aws.Int64(int64(len(request.Body))), ContentType: aws.String(request.MediaType), ChecksumSHA256: aws.String(checksumText(request.ContentDigest)), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(rawKMSKey), Metadata: rawMetadata(request)}
}

type rawS3Stub struct {
	put       func(context.Context, *s3.PutObjectInput) (*s3.PutObjectOutput, error)
	head      *s3.HeadObjectOutput
	putCalls  int
	headCalls int
}

func (stub *rawS3Stub) PutObject(ctx context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	stub.putCalls++
	return stub.put(ctx, input)
}
func (stub *rawS3Stub) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	stub.headCalls++
	return stub.head, nil
}
