package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestS3ArtifactDriverMapsAndReprovesExactEncryptedState(t *testing.T) {
	t.Parallel()

	marker := "0123456789abcdef"
	cloud, key, bucket := artifactDriverFixture(marker)
	var retained PutObjectRequest
	driver, err := newS3ArtifactDriver(cloud, bucket, key, marker, 1024, func(request PutObjectRequest) {
		retained = clonePutObjectRequest(request)
	})
	if err != nil {
		t.Fatalf("newS3ArtifactDriver() error = %v", err)
	}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1024})
	if err != nil {
		t.Fatalf("artifactstore.New() error = %v", err)
	}
	request := artifactPutRequest(t)
	wantDigest := sha256.Sum256(request.Body)

	put, err := store.Put(context.Background(), request)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if retained.Bucket != bucket || retained.Key != artifactCanonicalKey(request.Locator) || retained.KMSKeyID != key.ARN ||
		!bytes.Equal(retained.Body, request.Body) || retained.Metadata["sha256"] != artifactChecksum(wantDigest) ||
		!equalStringMaps(retained.Tags, artifactProofTags(marker)) {
		t.Fatalf("retained request = %#v", retained)
	}
	if !equalStringMaps(retained.Metadata, artifactMetadata(request.Locator, request.MediaType, wantDigest)) {
		t.Fatalf("metadata = %#v", retained.Metadata)
	}
	if put.SHA256 != wantDigest || !bytes.Equal(put.Body, request.Body) {
		t.Fatalf("Put() = %#v", put)
	}

	got, err := store.Get(context.Background(), request.Locator)
	if err != nil || got.SHA256 != wantDigest || !bytes.Equal(got.Body, request.Body) {
		t.Fatalf("Get() = %#v, %v", got, err)
	}
	if err := store.Delete(context.Background(), request.Locator); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	objects, err := cloud.ListObjects(context.Background(), bucket, "")
	if err != nil || len(objects) != 0 {
		t.Fatalf("objects after Delete = %#v, %v", objects, err)
	}
}

func TestS3ArtifactDriverReconcilesOnlyExactAppliedPut(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		configure func(*fakeCloud)
		wantOK    bool
	}{
		{name: "ambiguous exact", configure: func(cloud *fakeCloud) { cloud.ambiguous["put-object"] = true }, wantOK: true},
		{name: "definitive unapplied", configure: func(cloud *fakeCloud) { cloud.fail["put-object"] = errProvider }},
		{name: "wrong encryption", configure: func(cloud *fakeCloud) { cloud.wrongObjectKey = true }},
		{name: "foreign extra object", configure: func(cloud *fakeCloud) { cloud.foreignObject = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := "0123456789abcdef"
			cloud, key, bucket := artifactDriverFixture(marker)
			test.configure(cloud)
			driver, err := newS3ArtifactDriver(cloud, bucket, key, marker, 1024, func(PutObjectRequest) {})
			if err != nil {
				t.Fatalf("newS3ArtifactDriver() error = %v", err)
			}
			store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1024})
			if err != nil {
				t.Fatalf("artifactstore.New() error = %v", err)
			}
			_, putErr := store.Put(context.Background(), artifactPutRequest(t))
			if (putErr == nil) != test.wantOK {
				t.Fatalf("Put() error = %v, want success %v", putErr, test.wantOK)
			}
		})
	}
}

func TestS3ArtifactDriverRejectsInvalidConfigurationAndMalformedState(t *testing.T) {
	t.Parallel()

	marker := "0123456789abcdef"
	cloud, key, bucket := artifactDriverFixture(marker)
	invalid := []struct {
		client s3API
		bucket string
		key    *KMSKey
		marker string
		limit  int64
	}{
		{bucket: bucket, key: key, marker: marker, limit: 1},
		{client: cloud, key: key, marker: marker, limit: 1},
		{client: cloud, bucket: bucket, marker: marker, limit: 1},
		{client: cloud, bucket: bucket, key: key, marker: "invalid", limit: 1},
		{client: cloud, bucket: bucket, key: key, marker: marker},
	}
	for index, config := range invalid {
		if _, err := newS3ArtifactDriver(config.client, config.bucket, config.key, config.marker, config.limit, func(PutObjectRequest) {}); !errors.Is(err, errConfiguration) {
			t.Fatalf("invalid config %d error = %v", index, err)
		}
	}

	driver, err := newS3ArtifactDriver(cloud, bucket, key, marker, 1024, func(PutObjectRequest) {})
	if err != nil {
		t.Fatal(err)
	}
	locator := artifactPutRequest(t).Locator
	cloud.bucket.object = &ObjectValue{ObjectInfo: ObjectInfo{
		Key: artifactCanonicalKey(locator), ETag: "etag", Algorithm: sseAlgorithmKMS, KMSKeyID: key.ARN,
		Metadata: map[string]string{"organization_id": locator.OrganizationID().String()}, Tags: artifactProofTags(marker),
	}, Body: []byte("malformed")}
	if _, err := driver.Get(context.Background(), artifactstore.DriverLocator{
		Key: artifactCanonicalKey(locator), Scope: locator.Scope, Reference: locator.Reference,
	}); err == nil {
		t.Fatal("Get accepted malformed provider state")
	}
}

func TestRunArtifactStoreProofExactLifecycleAndAudit(t *testing.T) {
	t.Parallel()

	marker := "0123456789abcdef"
	cloud := newFakeCloud(marker)
	result, err := RunArtifactStoreProof(context.Background(), ArtifactProofOptions{
		Endpoint: "http://127.0.0.1:4566", Marker: marker, KMS: cloud, S3: cloud,
		CleanupTimeout: time.Second, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RunArtifactStoreProof() error = %v", err)
	}
	if !result.Put || !result.Get || !result.Delete || !result.Scoped || !result.Encrypted || !result.Cleanup || result.KMSKeyID == "" {
		t.Fatalf("result = %#v", result)
	}
	if cloud.bucket != nil || len(cloud.aliases) != 0 || cloud.key.State != keyStatePendingDeletion || cloud.key.Enabled {
		t.Fatalf("cleanup state = bucket %#v aliases %#v key %#v", cloud.bucket, cloud.aliases, cloud.key)
	}
	if err := AuditArtifactStore(context.Background(), cloud, cloud, marker, result.KMSKeyID); err != nil {
		t.Fatalf("AuditArtifactStore() error = %v", err)
	}
}

func TestRunArtifactStoreProofRejectsCollisionWithoutMutation(t *testing.T) {
	t.Parallel()

	marker := "0123456789abcdef"
	cloud := newFakeCloud(marker)
	cloud.bucket = &fakeBucket{name: artifactBucketName(marker)}
	_, err := RunArtifactStoreProof(context.Background(), ArtifactProofOptions{
		Endpoint: "http://127.0.0.1:4566", Marker: marker, KMS: cloud, S3: cloud,
		CleanupTimeout: time.Second, PollInterval: time.Millisecond,
	})
	if !errors.Is(err, errOwnership) {
		t.Fatalf("RunArtifactStoreProof() error = %v", err)
	}
	if slicesContains(cloud.operations, "create-key") || slicesContains(cloud.operations, "create-bucket") {
		t.Fatalf("mutations after collision = %#v", cloud.operations)
	}
}

func TestRunArtifactStoreProofReconcilesAnExactAmbiguousBucket(t *testing.T) {
	t.Parallel()

	marker := "0123456789abcdef"
	cloud := newFakeCloud(marker)
	cloud.artifactAmbiguousBucket = true
	result, err := RunArtifactStoreProof(context.Background(), ArtifactProofOptions{
		Endpoint: "http://127.0.0.1:4566", Marker: marker, KMS: cloud, S3: cloud,
		CleanupTimeout: time.Second, PollInterval: time.Millisecond,
	})
	if err != nil || !result.Cleanup || cloud.bucket != nil {
		t.Fatalf("RunArtifactStoreProof() = %#v, %v; bucket %#v", result, err, cloud.bucket)
	}
}

func TestRunArtifactStoreProofCleanupFailureWinsAndContinues(t *testing.T) {
	t.Parallel()

	marker := "0123456789abcdef"
	cloud := newFakeCloud(marker)
	cloud.fail["delete-object"] = errProvider
	_, err := RunArtifactStoreProof(context.Background(), ArtifactProofOptions{
		Endpoint: "http://127.0.0.1:4566", Marker: marker, KMS: cloud, S3: cloud,
		CleanupTimeout: time.Second, PollInterval: time.Millisecond,
	})
	if !errors.Is(err, errCleanup) {
		t.Fatalf("RunArtifactStoreProof() error = %v", err)
	}
	if len(cloud.aliases) != 0 || cloud.key.State != keyStatePendingDeletion || !slicesContains(cloud.operations, "list-buckets") {
		t.Fatalf("cleanup did not continue = operations %#v aliases %#v key %#v", cloud.operations, cloud.aliases, cloud.key)
	}
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func artifactDriverFixture(marker string) (*fakeCloud, *KMSKey, string) {
	cloud := newFakeCloud(marker)
	key := cloud.expectedKey()
	cloud.key = key
	bucket := "zasp-m1-12-" + marker + "-artifacts"
	cloud.bucket = &fakeBucket{name: bucket, tags: artifactLifecycleTags(marker, "artifact-bucket"), algorithm: sseAlgorithmKMS, keyID: key.ARN}
	return cloud, &key, bucket
}

func artifactPutRequest(t *testing.T) artifactstore.PutRequest {
	t.Helper()
	ids := make([]domain.ProductID, 4)
	for index := range ids {
		text := []string{
			"pid_00000000-0000-4000-8000-000000000001",
			"pid_00000000-0000-4000-8000-000000000002",
			"pid_00000000-0000-4000-8000-000000000003",
			"pid_00000000-0000-4000-8000-000000000004",
		}[index]
		parsed, err := domain.ParseProductID(text)
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = parsed
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	reference, err := domain.NewEvidenceRef(ids[3])
	if err != nil {
		t.Fatal(err)
	}
	return artifactstore.PutRequest{
		Locator:   artifactstore.Locator{Scope: scope, Reference: reference},
		MediaType: "application/json", Body: []byte(`{"kind":"evidence-archive","version":1}`),
	}
}
