package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type discoveryS3APIStub struct {
	put      *s3.PutObjectInput
	head     *s3.HeadObjectInput
	get      *s3.GetObjectInput
	body     []byte
	metadata map[string]string
}

func (stub *discoveryS3APIStub) PutObject(_ context.Context, input *s3.PutObjectInput, options ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	stub.put = input
	stub.metadata = input.Metadata
	for _, option := range options {
		option(&s3.Options{})
	}
	return &s3.PutObjectOutput{VersionId: aws.String("version-0001"), ChecksumSHA256: input.ChecksumSHA256, ServerSideEncryption: "aws:kms", SSEKMSKeyId: input.SSEKMSKeyId}, nil
}

func (stub *discoveryS3APIStub) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	stub.head = input
	digest := sha256.Sum256(stub.body)
	return &s3.HeadObjectOutput{VersionId: aws.String("version-0001"), ContentLength: aws.Int64(int64(len(stub.body))), ContentType: aws.String("application/json"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:])), ServerSideEncryption: "aws:kms", SSEKMSKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"), Metadata: stub.metadata}, nil
}

func (stub *discoveryS3APIStub) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	stub.get = input
	digest := sha256.Sum256(stub.body)
	return &s3.GetObjectOutput{VersionId: aws.String("version-0001"), Body: io.NopCloser(bytes.NewReader(stub.body)), ContentLength: aws.Int64(int64(len(stub.body))), ContentType: aws.String("application/json"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:])), ServerSideEncryption: "aws:kms", SSEKMSKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"), Metadata: stub.metadata}, nil
}

func TestProductionDiscoveryArtifactAuthorityUsesExactS3Boundary(t *testing.T) {
	stub := &discoveryS3APIStub{body: []byte(`{"version":"redacted_page_v1"}`)}
	authority, err := newProductionDiscoveryArtifactAuthority(stub, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	scope := discoveryCredentialScope(t)
	reference, _ := domain.ParseEvidenceRef(discoveryCredentialID(8).String())
	artifact, err := authority.Put(context.Background(), artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(stub.body)})
	if err != nil {
		t.Fatal(err)
	}
	wantKey := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + reference.String()
	if aws.ToString(stub.put.Bucket) != "zasp-production-evidence" || aws.ToString(stub.put.Key) != wantKey || aws.ToString(stub.put.ExpectedBucketOwner) != "123456789012" || aws.ToString(stub.put.SSEKMSKeyId) != "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111" || aws.ToString(stub.put.IfNoneMatch) != "*" || artifact.VersionID != "version-0001" {
		t.Fatalf("S3 boundary drift: put=%#v artifact=%#v", stub.put, artifact)
	}
	objectReference, err := authority.ObjectReference(artifact.Locator)
	if err != nil || objectReference != "s3://zasp-production-evidence/"+wantKey {
		t.Fatalf("reference=%q err=%v", objectReference, err)
	}
}

func TestProductionDiscoveryArtifactAuthorityRejectsAmbientOrBroadConfiguration(t *testing.T) {
	valid := productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20}
	tests := []func(*productionDiscoveryArtifactConfig){
		func(config *productionDiscoveryArtifactConfig) { config.Bucket = "" },
		func(config *productionDiscoveryArtifactConfig) { config.ExpectedBucketOwner = "" },
		func(config *productionDiscoveryArtifactConfig) { config.KMSKeyARN = "alias/broad" },
		func(config *productionDiscoveryArtifactConfig) { config.OperationTimeout = 31 * time.Second },
		func(config *productionDiscoveryArtifactConfig) { config.MaximumBytes = (64 << 20) + 1 },
	}
	for index, mutate := range tests {
		config := valid
		mutate(&config)
		if _, err := newProductionDiscoveryArtifactAuthority(&discoveryS3APIStub{}, config); err == nil {
			t.Fatalf("hostile config %d accepted", index)
		}
	}
	if _, err := newProductionDiscoveryArtifactAuthority(nil, valid); err == nil {
		t.Fatal("nil/ambient S3 authority accepted")
	}
}

var _ interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
} = (*discoveryS3APIStub)(nil)
