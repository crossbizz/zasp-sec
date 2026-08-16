package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type ArtifactProofOptions struct {
	Endpoint       string
	Marker         string
	KMS            kmsAPI
	S3             s3API
	CleanupTimeout time.Duration
	PollInterval   time.Duration
}

type ArtifactProofResult struct {
	KMSKeyID                   string
	Put, Get, Delete           bool
	Scoped, Encrypted, Cleanup bool
}

type artifactCleanupTargets struct {
	key    *KMSKey
	alias  *KMSAlias
	bucket *BucketState
	object *PutObjectRequest
}

func RunArtifactStoreProof(ctx context.Context, options ArtifactProofOptions) (result ArtifactProofResult, resultErr error) {
	if ctx == nil || options.KMS == nil || options.S3 == nil || !markerPattern.MatchString(options.Marker) {
		return result, errConfiguration
	}
	if _, err := validateEndpoint(ctx, options.Endpoint, nil); err != nil {
		return result, errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 20 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 100 * time.Millisecond
	}

	targets := &artifactCleanupTargets{}
	defer func() {
		panicked := recover() != nil
		cleanupErr := cleanupArtifactStorage(options, targets)
		result.Cleanup = cleanupErr == nil
		if targets.key != nil {
			result.KMSKeyID = targets.key.ID
		}
		if cleanupErr != nil {
			resultErr = errCleanup
		} else if panicked {
			resultErr = errProvider
		}
	}()

	if err := preflightArtifactStorage(ctx, options); err != nil {
		return result, err
	}
	key, err := createArtifactKey(ctx, options.KMS, options.Marker, targets)
	if err != nil {
		return result, err
	}
	if _, err := createArtifactAlias(ctx, options.KMS, options.Marker, key, targets); err != nil {
		return result, err
	}
	bucket, err := createArtifactBucket(ctx, options.S3, options.Marker, key, targets)
	if err != nil {
		return result, err
	}

	driver, err := newS3ArtifactDriver(options.S3, bucket.Name, key, options.Marker, 1024, func(request PutObjectRequest) {
		candidate := clonePutObjectRequest(request)
		targets.object = &candidate
	})
	if err != nil {
		return result, errConfiguration
	}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: 20 * time.Second, MaximumBytes: 1024})
	if err != nil {
		return result, errConfiguration
	}
	request, err := artifactPutRequestFixture()
	if err != nil {
		return result, errConfiguration
	}
	put, err := store.Put(ctx, request)
	if err != nil {
		return result, errProvider
	}
	result.Put = true
	result.Scoped = artifactCanonicalKey(request.Locator) == artifactCanonicalKey(put.Locator)
	result.Encrypted = true
	got, err := store.Get(ctx, request.Locator)
	if err != nil || got.Locator != put.Locator || got.MediaType != put.MediaType || got.Size != put.Size || got.SHA256 != put.SHA256 || !bytes.Equal(got.Body, put.Body) {
		return result, errContent
	}
	result.Get = true
	if err := store.Delete(ctx, request.Locator); err != nil {
		return result, errProvider
	}
	result.Delete = true
	objects, err := options.S3.ListObjects(ctx, bucket.Name, "")
	if err != nil || len(objects) != 0 || !result.Scoped || !result.Encrypted {
		return result, errContent
	}
	return result, nil
}

func artifactPutRequestFixture() (artifactstore.PutRequest, error) {
	texts := []string{
		"pid_00000000-0000-4000-8000-000000000001",
		"pid_00000000-0000-4000-8000-000000000002",
		"pid_00000000-0000-4000-8000-000000000003",
		"pid_00000000-0000-4000-8000-000000000004",
	}
	ids := make([]domain.ProductID, len(texts))
	for index, text := range texts {
		parsed, err := domain.ParseProductID(text)
		if err != nil {
			return artifactstore.PutRequest{}, errConfiguration
		}
		ids[index] = parsed
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		return artifactstore.PutRequest{}, errConfiguration
	}
	reference, err := domain.NewEvidenceRef(ids[3])
	if err != nil {
		return artifactstore.PutRequest{}, errConfiguration
	}
	return artifactstore.PutRequest{
		Locator:   artifactstore.Locator{Scope: scope, Reference: reference},
		MediaType: "application/json",
		Body:      []byte(`{"kind":"evidence-archive","version":1}`),
	}, nil
}

func preflightArtifactStorage(ctx context.Context, options ArtifactProofOptions) error {
	keys, err := options.KMS.ListKeys(ctx)
	if err != nil {
		return errProvider
	}
	for _, key := range keys {
		if strings.HasPrefix(key.Description, artifactResourcePrefix+options.Marker) || key.Tags["zasp-marker"] == options.Marker {
			return errOwnership
		}
	}
	aliases, err := options.KMS.ListAliases(ctx, artifactAliasName(options.Marker))
	if err != nil {
		return errProvider
	}
	if len(aliases) != 0 {
		return errOwnership
	}
	buckets, err := options.S3.ListBuckets(ctx, artifactBucketName(options.Marker))
	if err != nil {
		return errProvider
	}
	if len(buckets) != 0 {
		return errOwnership
	}
	return nil
}

func createArtifactKey(ctx context.Context, client kmsAPI, marker string, targets *artifactCleanupTargets) (*KMSKey, error) {
	request := CreateKeyRequest{Description: artifactDescription(marker), Tags: artifactLifecycleTags(marker, "artifact-key")}
	created, createErr := client.CreateKey(ctx, request)
	if createErr != nil && !errors.Is(createErr, errMutationAmbiguous) {
		return nil, errProvider
	}
	if createErr == nil && validKeyIdentity(created) && created.Description == request.Description {
		created.Tags = cloneStringMap(request.Tags)
		targets.key = &created
		owned, err := proveArtifactKey(ctx, client, created.ID, marker, keyStateEnabled)
		if err == nil && owned.ID == created.ID && owned.ARN == created.ARN {
			targets.key = owned
			return owned, nil
		}
	}
	keys, listErr := client.ListKeys(ctx)
	if listErr != nil {
		return nil, errProvider
	}
	var exact []KMSKey
	for _, candidate := range keys {
		if candidate.Description != request.Description {
			continue
		}
		owned, err := proveArtifactKey(ctx, client, candidate.ID, marker, keyStateEnabled)
		if err == nil {
			exact = append(exact, *owned)
		}
	}
	if len(exact) != 1 {
		if createErr != nil {
			return nil, errProvider
		}
		return nil, errOwnership
	}
	targets.key = &exact[0]
	return &exact[0], nil
}

func proveArtifactKey(ctx context.Context, client kmsAPI, keyID, marker, state string) (*KMSKey, error) {
	key, err := client.DescribeKey(ctx, keyID)
	if err != nil || !validKeyIdentity(key) || key.Description != artifactDescription(marker) || key.State != state ||
		key.Spec != keySpecSymmetric || key.Usage != keyUsageEncryptDecrypt || key.Origin != keyOriginAWSKMS ||
		key.Manager != keyManagerCustomer || key.Enabled != (state == keyStateEnabled) {
		return nil, errOwnership
	}
	tags, err := client.ListKeyTags(ctx, key.ID)
	if err != nil || !equalStringMaps(tags, artifactLifecycleTags(marker, "artifact-key")) {
		return nil, errOwnership
	}
	key.Tags = cloneStringMap(tags)
	return &key, nil
}

func createArtifactAlias(ctx context.Context, client kmsAPI, marker string, key *KMSKey, targets *artifactCleanupTargets) (*KMSAlias, error) {
	name := artifactAliasName(marker)
	createErr := client.CreateAlias(ctx, name, key.ID)
	if createErr != nil && !errors.Is(createErr, errMutationAmbiguous) {
		return nil, errProvider
	}
	if createErr == nil {
		targets.alias = &KMSAlias{Name: name, KeyID: key.ID}
	}
	aliases, err := client.ListAliases(ctx, name)
	if err != nil {
		return nil, errProvider
	}
	exact := exactAliases(aliases, name)
	if len(exact) != 1 || !sameKeyIdentity(exact[0].KeyID, key) {
		if createErr != nil {
			return nil, errProvider
		}
		return nil, errOwnership
	}
	targets.alias = &exact[0]
	return &exact[0], nil
}

func createArtifactBucket(ctx context.Context, client s3API, marker string, key *KMSKey, targets *artifactCleanupTargets) (*BucketState, error) {
	name := artifactBucketName(marker)
	createErr := client.CreateBucket(ctx, name)
	if createErr != nil {
		if !errors.Is(createErr, errMutationAmbiguous) {
			return nil, errProvider
		}
		buckets, err := client.ListBuckets(ctx, name)
		if err != nil || countExactStrings(buckets, name) != 1 {
			return nil, errProvider
		}
	}
	targets.bucket = &BucketState{Name: name, Provisional: true}
	if err := client.PutBucketTags(ctx, name, artifactLifecycleTags(marker, "artifact-bucket")); err != nil {
		return nil, errProvider
	}
	if err := client.PutBucketEncryption(ctx, name, key.ARN); err != nil {
		return nil, errProvider
	}
	state, err := client.GetBucketState(ctx, name)
	if err != nil || !validArtifactBucket(state, marker, key) {
		return nil, errOwnership
	}
	state.Provisional = false
	*targets.bucket = state
	return &state, nil
}

func cleanupArtifactStorage(options ArtifactProofOptions, targets *artifactCleanupTargets) error {
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	failed := false
	if targets.object != nil && artifactCleanupStep(func() error {
		return cleanupArtifactObject(ctx, options.S3, options.Marker, targets.key, targets.bucket, targets.object, options.PollInterval)
	}) != nil {
		failed = true
	}
	if targets.bucket != nil && artifactCleanupStep(func() error {
		return cleanupArtifactBucket(ctx, options.S3, options.Marker, targets.key, targets.bucket, options.PollInterval)
	}) != nil {
		failed = true
	}
	if targets.alias != nil && artifactCleanupStep(func() error {
		return cleanupArtifactAlias(ctx, options.KMS, options.Marker, targets.key, targets.alias, options.PollInterval)
	}) != nil {
		failed = true
	}
	if targets.key != nil && artifactCleanupStep(func() error {
		return cleanupArtifactKey(ctx, options.KMS, options.Marker, targets.key, options.PollInterval)
	}) != nil {
		failed = true
	}
	if failed {
		return errCleanup
	}
	return nil
}

func artifactCleanupStep(run func() error) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCleanup
		}
	}()
	return run()
}

func cleanupArtifactObject(ctx context.Context, client s3API, marker string, key *KMSKey, bucket *BucketState, target *PutObjectRequest, interval time.Duration) error {
	if bucket == nil || key == nil {
		return errCleanup
	}
	state, err := client.GetBucketState(ctx, bucket.Name)
	if err != nil || !validArtifactBucket(state, marker, key) {
		return errCleanup
	}
	objects, err := client.ListObjects(ctx, bucket.Name, target.Key)
	if err != nil {
		return errCleanup
	}
	if len(objects) == 0 {
		return nil
	}
	if len(objects) != 1 || objects[0].Key != target.Key {
		return errCleanup
	}
	value, err := client.GetObject(ctx, bucket.Name, target.Key)
	if err != nil {
		return errCleanup
	}
	tags, err := client.GetObjectTags(ctx, bucket.Name, target.Key)
	if err != nil || value.Key != target.Key || value.Algorithm != sseAlgorithmKMS || !sameKeyIdentity(value.KMSKeyID, key) ||
		value.Size != int64(len(value.Body)) || !bytes.Equal(value.Body, target.Body) ||
		!equalStringMaps(value.Metadata, target.Metadata) || !equalStringMaps(tags, target.Tags) {
		return errCleanup
	}
	deleteErr := client.DeleteObject(ctx, bucket.Name, target.Key)
	if deleteErr != nil && !errors.Is(deleteErr, errMutationAmbiguous) {
		return errCleanup
	}
	return pollUntil(ctx, interval, func() (bool, error) {
		objects, err := client.ListObjects(ctx, bucket.Name, target.Key)
		if err != nil {
			return false, errCleanup
		}
		return len(objects) == 0, nil
	})
}

func cleanupArtifactBucket(ctx context.Context, client s3API, marker string, key *KMSKey, target *BucketState, interval time.Duration) error {
	buckets, err := client.ListBuckets(ctx, target.Name)
	if err != nil || countExactStrings(buckets, target.Name) != 1 {
		return errCleanup
	}
	state, err := client.GetBucketState(ctx, target.Name)
	if err != nil {
		return errCleanup
	}
	if target.Provisional {
		tagsSafe := len(state.Tags) == 0 || equalStringMaps(state.Tags, artifactLifecycleTags(marker, "artifact-bucket"))
		encryptionSafe := (state.Algorithm == "" && state.KMSKeyID == "") ||
			(state.Algorithm == sseAlgorithmKMS && sameKeyIdentity(state.KMSKeyID, key))
		if state.Name != target.Name || !tagsSafe || !encryptionSafe {
			return errCleanup
		}
	} else if !validArtifactBucket(state, marker, key) {
		return errCleanup
	}
	objects, err := client.ListObjects(ctx, target.Name, "")
	if err != nil || len(objects) != 0 {
		return errCleanup
	}
	deleteErr := client.DeleteBucket(ctx, target.Name)
	if deleteErr != nil && !errors.Is(deleteErr, errMutationAmbiguous) {
		return errCleanup
	}
	return pollUntil(ctx, interval, func() (bool, error) {
		buckets, err := client.ListBuckets(ctx, target.Name)
		if err != nil {
			return false, errCleanup
		}
		return countExactStrings(buckets, target.Name) == 0, nil
	})
}

func cleanupArtifactAlias(ctx context.Context, client kmsAPI, marker string, key *KMSKey, target *KMSAlias, interval time.Duration) error {
	aliases, err := client.ListAliases(ctx, target.Name)
	exact := exactAliases(aliases, target.Name)
	if err != nil || len(exact) != 1 || exact[0] != *target || !sameKeyIdentity(exact[0].KeyID, key) {
		return errCleanup
	}
	deleteErr := client.DeleteAlias(ctx, target.Name)
	if deleteErr != nil && !errors.Is(deleteErr, errMutationAmbiguous) {
		return errCleanup
	}
	return pollUntil(ctx, interval, func() (bool, error) {
		aliases, err := client.ListAliases(ctx, target.Name)
		if err != nil {
			return false, errCleanup
		}
		return len(exactAliases(aliases, target.Name)) == 0, nil
	})
}

func cleanupArtifactKey(ctx context.Context, client kmsAPI, marker string, target *KMSKey, interval time.Duration) error {
	current, err := proveArtifactKey(ctx, client, target.ID, marker, keyStateEnabled)
	if err != nil || current.ID != target.ID || current.ARN != target.ARN {
		return errCleanup
	}
	scheduled, scheduleErr := client.ScheduleKeyDeletion(ctx, target.ID, minimumDeletionWindowDays)
	if scheduleErr != nil && !errors.Is(scheduleErr, errMutationAmbiguous) {
		return errCleanup
	}
	if scheduleErr == nil && (scheduled.ID != target.ID || scheduled.ARN != target.ARN) {
		return errCleanup
	}
	return pollUntil(ctx, interval, func() (bool, error) {
		candidate, err := proveArtifactKey(ctx, client, target.ID, marker, keyStatePendingDeletion)
		if err == nil {
			*target = *candidate
			return true, nil
		}
		current, currentErr := proveArtifactKey(ctx, client, target.ID, marker, keyStateEnabled)
		if currentErr == nil && current.ID == target.ID {
			return false, nil
		}
		return false, errCleanup
	})
}

func AuditArtifactStore(ctx context.Context, kmsClient kmsAPI, s3Client s3API, marker, keyID string) error {
	if ctx == nil || kmsClient == nil || s3Client == nil || !markerPattern.MatchString(marker) || keyID == "" {
		return errConfiguration
	}
	aliases, err := kmsClient.ListAliases(ctx, artifactAliasName(marker))
	if err != nil || len(aliases) != 0 {
		return errProvider
	}
	buckets, err := s3Client.ListBuckets(ctx, artifactBucketName(marker))
	if err != nil || len(buckets) != 0 {
		return errProvider
	}
	keys, err := kmsClient.ListKeys(ctx)
	if err != nil {
		return errProvider
	}
	var exact []KMSKey
	for _, key := range keys {
		if strings.HasPrefix(key.Description, artifactResourcePrefix+marker) || key.Tags["zasp-marker"] == marker {
			exact = append(exact, key)
		}
	}
	if len(exact) != 1 || exact[0].ID != keyID {
		return errProvider
	}
	key, err := proveArtifactKey(ctx, kmsClient, keyID, marker, keyStatePendingDeletion)
	if err != nil || key.ID != keyID {
		return errProvider
	}
	return nil
}

func validArtifactBucket(state BucketState, marker string, key *KMSKey) bool {
	return state.Name == artifactBucketName(marker) && equalStringMaps(state.Tags, artifactLifecycleTags(marker, "artifact-bucket")) &&
		state.Algorithm == sseAlgorithmKMS && sameKeyIdentity(state.KMSKeyID, key)
}

func artifactDescription(marker string) string {
	return artifactResourcePrefix + marker + "-artifact-store"
}
func artifactAliasName(marker string) string {
	return "alias/" + artifactResourcePrefix + marker + "-key"
}
