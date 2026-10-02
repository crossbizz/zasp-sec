package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

// Keep the real artifact store and S3 driver; only provider responses are
// controlled. This does not prove a live bucket, IAM policy or KMS deployment.
type redTeamReadbackAPI struct {
	discoveryS3APIStub
	t    *testing.T
	gets int
}

func (api *redTeamReadbackAPI) PutObject(ctx context.Context, input *s3.PutObjectInput, options ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	api.body = bytes.Clone(body)
	return api.discoveryS3APIStub.PutObject(ctx, input, options...)
}

func (api *redTeamReadbackAPI) GetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	api.t.Helper()
	if aws.ToString(input.VersionId) != "version-0001" || aws.ToString(input.Key) != aws.ToString(api.put.Key) || aws.ToString(input.Bucket) != "zasp-production-evidence" || aws.ToString(input.ExpectedBucketOwner) != "123456789012" {
		api.t.Fatal("readback lost exact version/scoped key/bucket owner")
	}
	api.gets++
	return api.discoveryS3APIStub.GetObject(ctx, input, options...)
}

type redTeamReadbackStore struct {
	artifactstore.ObjectReferencingArtifactStore
	puts []artifactstore.PutRequest
	api  *redTeamReadbackAPI
}

func newRedTeamReadbackStore(t *testing.T) *redTeamReadbackStore {
	t.Helper()
	api := &redTeamReadbackAPI{t: t}
	store, err := newProductionDiscoveryArtifactAuthority(api, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return &redTeamReadbackStore{ObjectReferencingArtifactStore: store, api: api}
}

func (store *redTeamReadbackStore) Put(ctx context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	result, err := store.ObjectReferencingArtifactStore.Put(ctx, request)
	if err == nil {
		request.Body = bytes.Clone(request.Body)
		store.puts = append(store.puts, request)
	}
	return result, err
}
