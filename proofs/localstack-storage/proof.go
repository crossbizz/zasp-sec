package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	fixedRegion                  = "us-east-1"
	resourcePrefix               = "zasp-m0-07-"
	keyStateEnabled              = "Enabled"
	keyStatePendingDeletion      = "PendingDeletion"
	keySpecSymmetric             = "SYMMETRIC_DEFAULT"
	keyUsageEncryptDecrypt       = "ENCRYPT_DECRYPT"
	keyOriginAWSKMS              = "AWS_KMS"
	keyManagerCustomer           = "CUSTOMER"
	encryptionAlgorithmSymmetric = "SYMMETRIC_DEFAULT"
	sseAlgorithmKMS              = "aws:kms"
	minimumDeletionWindowDays    = int32(7)
)

var (
	errConfiguration     = errors.New("configuration rejected")
	errProvider          = errors.New("storage operation failed")
	errOwnership         = errors.New("storage ownership rejected")
	errEncryption        = errors.New("storage encryption rejected")
	errContent           = errors.New("storage content rejected")
	errCleanup           = errors.New("storage cleanup failed")
	errMutationRejected  = errors.New("storage mutation rejected")
	errMutationAmbiguous = errors.New("storage mutation outcome ambiguous")

	markerPattern  = regexp.MustCompile(`^[a-f0-9]{16}$`)
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	keyIDPattern   = regexp.MustCompile(`^[a-zA-Z0-9-]{8,128}$`)
)

type kmsAPI interface {
	ListKeys(context.Context) ([]KMSKey, error)
	CreateKey(context.Context, CreateKeyRequest) (KMSKey, error)
	DescribeKey(context.Context, string) (KMSKey, error)
	ListKeyTags(context.Context, string) (map[string]string, error)
	CreateAlias(context.Context, string, string) error
	ListAliases(context.Context, string) ([]KMSAlias, error)
	Encrypt(context.Context, CryptRequest) (Ciphertext, error)
	Decrypt(context.Context, DecryptRequest) (Plaintext, error)
	DeleteAlias(context.Context, string) error
	ScheduleKeyDeletion(context.Context, string, int32) (KMSKey, error)
}

type s3API interface {
	ListBuckets(context.Context, string) ([]string, error)
	CreateBucket(context.Context, string) error
	PutBucketTags(context.Context, string, map[string]string) error
	PutBucketEncryption(context.Context, string, string) error
	GetBucketState(context.Context, string) (BucketState, error)
	PutObject(context.Context, PutObjectRequest) (ObjectInfo, error)
	GetObject(context.Context, string, string) (ObjectValue, error)
	GetObjectTags(context.Context, string, string) (map[string]string, error)
	ListObjects(context.Context, string, string) ([]ObjectInfo, error)
	DeleteObject(context.Context, string, string) error
	DeleteBucket(context.Context, string) error
}

type secretsAPI interface {
	ListSecrets(context.Context, string, bool) ([]SecretInfo, error)
	CreateSecret(context.Context, CreateSecretRequest) (SecretInfo, error)
	DescribeSecret(context.Context, string) (SecretInfo, error)
	ListSecretVersions(context.Context, string) ([]SecretVersion, error)
	GetSecretValue(context.Context, string, string, string) (SecretValue, error)
	DeleteSecret(context.Context, string) error
}

type ProofOptions struct {
	Endpoint       string
	Marker         string
	KMS            kmsAPI
	S3             s3API
	Secrets        secretsAPI
	CleanupTimeout time.Duration
	PollInterval   time.Duration
}

type ProofResult struct{ KMSKeyID string }

type KMSKey struct {
	ID, ARN, Description, State, Spec, Usage, Origin, Manager string
	Enabled                                                   bool
	Tags                                                      map[string]string
}

type KMSAlias struct{ Name, KeyID string }
type CreateKeyRequest struct {
	Description string
	Tags        map[string]string
}
type CryptRequest struct {
	KeyID     string
	Plaintext []byte
	Context   map[string]string
}
type DecryptRequest struct {
	KeyID      string
	Ciphertext []byte
	Context    map[string]string
}
type Ciphertext struct {
	Blob             []byte
	KeyID, Algorithm string
}
type Plaintext struct {
	Value            []byte
	KeyID, Algorithm string
}
type BucketState struct {
	Name                string
	Tags                map[string]string
	Algorithm, KMSKeyID string
	Provisional         bool
}
type PutObjectRequest struct {
	Bucket, Key, KMSKeyID, ExpectedETag string
	Body                                []byte
	Metadata, Tags                      map[string]string
}
type ObjectInfo struct {
	Key, ETag, Algorithm, KMSKeyID string
	Size                           int64
	Metadata, Tags                 map[string]string
}
type ObjectValue struct {
	ObjectInfo
	Body []byte
}
type CreateSecretRequest struct {
	Name, KMSKeyID string
	Value          []byte
	Tags           map[string]string
}
type SecretInfo struct {
	Name, ARN, KMSKeyID, VersionID string
	Tags                           map[string]string
	Stages                         []string
	Deleted                        bool
}
type SecretVersion struct {
	ID     string
	Stages []string
}
type SecretValue struct {
	Name, ARN, KMSKeyID, VersionID string
	Stages                         []string
	Value                          []byte
}

type cleanupTargets struct {
	key    *KMSKey
	alias  *KMSAlias
	bucket *BucketState
	object *ObjectInfo
	secret *SecretInfo
}

func RunProof(ctx context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	if ctx == nil || options.KMS == nil || options.S3 == nil || options.Secrets == nil ||
		!markerPattern.MatchString(options.Marker) {
		return result, errConfiguration
	}
	if _, err := validateEndpoint(ctx, options.Endpoint, nil); err != nil {
		return result, errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 15 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 100 * time.Millisecond
	}

	targets := &cleanupTargets{}
	defer func() {
		panicked := recover() != nil
		cleanupErr := cleanupStorage(options, targets)
		if targets.key != nil {
			result.KMSKeyID = targets.key.ID
		}
		if cleanupErr != nil {
			resultErr = errCleanup
		} else if panicked {
			resultErr = errProvider
		}
	}()

	if err := preflight(ctx, options); err != nil {
		return result, err
	}

	key, err := createOwnedKey(ctx, options.KMS, options.Marker, targets)
	if err != nil {
		return result, err
	}

	if _, err := createOwnedAlias(ctx, options.KMS, options.Marker, key, targets); err != nil {
		return result, err
	}

	if err := proveKMSRoundTrip(ctx, options.KMS, options.Marker, key); err != nil {
		return result, err
	}

	bucket, err := createOwnedBucket(ctx, options.S3, options.Marker, key, targets)
	if err != nil {
		return result, err
	}
	targets.bucket = bucket

	object, err := putAndProveObject(ctx, options.S3, options.Marker, key, bucket, targets)
	if err != nil {
		return result, err
	}
	targets.object = object

	secret, err := createAndProveSecret(ctx, options.Secrets, options.Marker, key, targets)
	if err != nil {
		return result, err
	}
	targets.secret = secret
	return result, nil
}

func preflight(ctx context.Context, options ProofOptions) error {
	keys, err := options.KMS.ListKeys(ctx)
	if err != nil {
		return errProvider
	}
	for _, key := range keys {
		if strings.HasPrefix(key.Description, resourcePrefix+options.Marker) || key.Tags["zasp-marker"] == options.Marker {
			return errOwnership
		}
	}
	aliases, err := options.KMS.ListAliases(ctx, aliasName(options.Marker))
	if err != nil {
		return errProvider
	}
	if len(aliases) != 0 {
		return errOwnership
	}
	buckets, err := options.S3.ListBuckets(ctx, bucketName(options.Marker))
	if err != nil {
		return errProvider
	}
	if len(buckets) != 0 {
		return errOwnership
	}
	secrets, err := options.Secrets.ListSecrets(ctx, secretName(options.Marker), true)
	if err != nil {
		return errProvider
	}
	if len(secrets) != 0 {
		return errOwnership
	}
	return nil
}

func createOwnedKey(ctx context.Context, client kmsAPI, marker string, targets *cleanupTargets) (*KMSKey, error) {
	request := CreateKeyRequest{Description: description(marker), Tags: proofTags(marker, "kms-key")}
	created, createErr := client.CreateKey(ctx, request)
	if createErr == nil && validCreatedKeyCandidate(created, marker) {
		created.Tags = cloneStringMap(request.Tags)
		targets.key = &created
		owned, err := proveOwnedKey(ctx, client, created.ID, marker, keyStateEnabled)
		if err == nil && created.ID == owned.ID && created.ARN == owned.ARN {
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
		if candidate.Description != description(marker) {
			continue
		}
		owned, err := proveOwnedKey(ctx, client, candidate.ID, marker, keyStateEnabled)
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

func validCreatedKeyCandidate(key KMSKey, marker string) bool {
	return validKeyIdentity(key) && key.Description == description(marker)
}

func proveOwnedKey(ctx context.Context, client kmsAPI, keyID, marker, expectedState string) (*KMSKey, error) {
	key, err := client.DescribeKey(ctx, keyID)
	if err != nil {
		return nil, errProvider
	}
	if !validKeyIdentity(key) || key.Description != description(marker) || key.State != expectedState ||
		key.Spec != keySpecSymmetric || key.Usage != keyUsageEncryptDecrypt || key.Origin != keyOriginAWSKMS ||
		key.Manager != keyManagerCustomer || key.Enabled != (expectedState == keyStateEnabled) {
		return nil, errOwnership
	}
	tags, err := client.ListKeyTags(ctx, key.ID)
	if err != nil {
		return nil, errProvider
	}
	if !equalStringMaps(tags, proofTags(marker, "kms-key")) {
		return nil, errOwnership
	}
	key.Tags = cloneStringMap(tags)
	return &key, nil
}

func createOwnedAlias(ctx context.Context, client kmsAPI, marker string, key *KMSKey, targets *cleanupTargets) (*KMSAlias, error) {
	name := aliasName(marker)
	createErr := client.CreateAlias(ctx, name, key.ID)
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

func proveKMSRoundTrip(ctx context.Context, client kmsAPI, marker string, key *KMSKey) error {
	plaintext := []byte("synthetic-kms-round-trip-" + marker)
	cryptContext := map[string]string{"proof": "m0-07", "marker": marker, "role": "storage"}
	encrypted, err := client.Encrypt(ctx, CryptRequest{KeyID: key.ARN, Plaintext: plaintext, Context: cryptContext})
	if err != nil {
		return errProvider
	}
	if len(encrypted.Blob) == 0 || !sameKeyIdentity(encrypted.KeyID, key) || encrypted.Algorithm != encryptionAlgorithmSymmetric {
		return errEncryption
	}
	decrypted, err := client.Decrypt(ctx, DecryptRequest{KeyID: key.ARN, Ciphertext: encrypted.Blob, Context: cryptContext})
	if err != nil {
		return errProvider
	}
	if !bytes.Equal(decrypted.Value, plaintext) || !sameKeyIdentity(decrypted.KeyID, key) || decrypted.Algorithm != encryptionAlgorithmSymmetric {
		return errEncryption
	}
	return nil
}

func createOwnedBucket(ctx context.Context, client s3API, marker string, key *KMSKey, targets *cleanupTargets) (*BucketState, error) {
	name := bucketName(marker)
	if err := client.CreateBucket(ctx, name); err != nil {
		return nil, errOwnership
	}
	// Exact preflight absence plus a definite successful create is the narrow
	// provisional ownership proof. Retain it before non-atomic setup calls.
	targets.bucket = &BucketState{Name: name, Provisional: true}
	if err := client.PutBucketTags(ctx, name, proofTags(marker, "evidence-bucket")); err != nil {
		return nil, errProvider
	}
	if err := client.PutBucketEncryption(ctx, name, key.ARN); err != nil {
		return nil, errProvider
	}
	state, err := client.GetBucketState(ctx, name)
	if err != nil {
		return nil, errProvider
	}
	if !validBucketState(state, marker, key) {
		return nil, errOwnership
	}
	state.Provisional = false
	*targets.bucket = state
	return &state, nil
}

func putAndProveObject(ctx context.Context, client s3API, marker string, key *KMSKey, bucket *BucketState, targets *cleanupTargets) (*ObjectInfo, error) {
	request := expectedObjectRequest(marker, key, bucket.Name)
	put, putErr := client.PutObject(ctx, request)
	if putErr != nil {
		object, err := fetchAndProveObject(ctx, client, request, key)
		if err != nil {
			return nil, errProvider
		}
		targets.object = object
		return object, nil
	}
	// A definite successful write owns the exact requested location. Arm an
	// expected-state candidate before trusting any response identity fields.
	candidate := ObjectInfo{Key: request.Key, ETag: put.ETag, Algorithm: sseAlgorithmKMS, KMSKeyID: key.ARN, Metadata: cloneStringMap(request.Metadata), Tags: cloneStringMap(request.Tags)}
	targets.object = &candidate
	if !validPutObjectResult(put, request, key) {
		return nil, errEncryption
	}
	request.ExpectedETag = put.ETag
	object, err := fetchAndProveObject(ctx, client, request, key)
	if err != nil {
		return nil, err
	}
	*targets.object = *object
	return object, nil
}

func expectedObjectRequest(marker string, key *KMSKey, bucket string) PutObjectRequest {
	body := syntheticObject(marker)
	digest := sha256.Sum256(body)
	return PutObjectRequest{
		Bucket: bucket, Key: objectKey(marker), KMSKeyID: key.ARN, Body: body,
		Metadata: map[string]string{"organization_id": organizationID(marker), "sha256": hex.EncodeToString(digest[:]), "proof_marker": marker},
		Tags:     proofTags(marker, "evidence-object"),
	}
}

func fetchAndProveObject(ctx context.Context, client s3API, request PutObjectRequest, key *KMSKey) (*ObjectInfo, error) {
	value, err := client.GetObject(ctx, request.Bucket, request.Key)
	if err != nil {
		return nil, errProvider
	}
	tags, err := client.GetObjectTags(ctx, request.Bucket, request.Key)
	if err != nil {
		return nil, errProvider
	}
	value.Tags = cloneStringMap(tags)
	if !bytes.Equal(value.Body, request.Body) || !validObjectInfo(value.ObjectInfo, request, key) {
		return nil, errContent
	}
	objects, err := client.ListObjects(ctx, request.Bucket, "")
	if err != nil {
		return nil, errProvider
	}
	if len(objects) != 1 || objects[0].Key != request.Key {
		return nil, errContent
	}
	info := value.ObjectInfo
	return &info, nil
}

func createAndProveSecret(ctx context.Context, client secretsAPI, marker string, key *KMSKey, targets *cleanupTargets) (*SecretInfo, error) {
	request := CreateSecretRequest{Name: secretName(marker), KMSKeyID: key.ARN, Value: syntheticSecret(marker), Tags: proofTags(marker, "secret")}
	created, createErr := client.CreateSecret(ctx, request)
	var candidate SecretInfo
	if createErr == nil && created.Name == request.Name {
		candidate = created
	} else {
		secrets, err := client.ListSecrets(ctx, request.Name, false)
		if err != nil {
			return nil, errProvider
		}
		var exact []SecretInfo
		for _, secret := range secrets {
			if secret.Name == request.Name && validSecretIdentity(secret, marker, key) {
				exact = append(exact, secret)
			}
		}
		if len(exact) != 1 {
			if createErr != nil {
				return nil, errProvider
			}
			return nil, errOwnership
		}
		candidate = exact[0]
	}
	if candidate.Name != request.Name || candidate.ARN == "" || candidate.VersionID == "" {
		return nil, errOwnership
	}
	// Secret tags and key identity are atomic creation inputs. Keep the exact
	// provider-returned identity so cleanup can independently re-prove them.
	targets.secret = &candidate
	secret, err := client.DescribeSecret(ctx, candidate.ARN)
	if err != nil {
		return nil, errProvider
	}
	if !validSecretIdentity(secret, marker, key) {
		return nil, errOwnership
	}
	versions, err := client.ListSecretVersions(ctx, secret.ARN)
	if err != nil {
		return nil, errProvider
	}
	if len(versions) != 1 || versions[0].ID != secret.VersionID || !equalStringsAsSet(versions[0].Stages, []string{"AWSCURRENT"}) {
		return nil, errContent
	}
	value, err := client.GetSecretValue(ctx, secret.ARN, secret.VersionID, "AWSCURRENT")
	if err != nil {
		return nil, errProvider
	}
	if value.Name != secret.Name || value.ARN != secret.ARN || !sameKeyIdentity(value.KMSKeyID, key) || value.VersionID != secret.VersionID ||
		!equalStringsAsSet(value.Stages, []string{"AWSCURRENT"}) || !bytes.Equal(value.Value, request.Value) {
		return nil, errContent
	}
	*targets.secret = secret
	return &secret, nil
}

func cleanupStorage(options ProofOptions, targets *cleanupTargets) error {
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	failed := false
	if targets.secret != nil && cleanupSecret(ctx, options.Secrets, options.Marker, targets.key, targets.secret, options.PollInterval) != nil {
		failed = true
	}
	if targets.object != nil && cleanupObject(ctx, options.S3, options.Marker, targets.key, targets.bucket, targets.object, options.PollInterval) != nil {
		failed = true
	}
	if targets.bucket != nil && cleanupBucket(ctx, options.S3, options.Marker, targets.key, targets.bucket, options.PollInterval) != nil {
		failed = true
	}
	if targets.alias != nil && cleanupAlias(ctx, options.KMS, options.Marker, targets.key, targets.alias, options.PollInterval) != nil {
		failed = true
	}
	if targets.key != nil && cleanupKey(ctx, options.KMS, options.Marker, targets.key, options.PollInterval) != nil {
		failed = true
	}
	if failed {
		return errCleanup
	}
	return nil
}

func cleanupSecret(ctx context.Context, client secretsAPI, marker string, key *KMSKey, target *SecretInfo, pollInterval time.Duration) error {
	current, err := client.DescribeSecret(ctx, target.ARN)
	if err != nil || current.ARN != target.ARN || !validSecretIdentity(current, marker, key) {
		return errCleanup
	}
	if err := client.DeleteSecret(ctx, target.ARN); err != nil {
		return errCleanup
	}
	return pollUntil(ctx, pollInterval, func() (bool, error) {
		secrets, err := client.ListSecrets(ctx, secretName(marker), false)
		if err != nil {
			return false, errCleanup
		}
		return countExactSecrets(secrets, secretName(marker)) == 0, nil
	})
}

func cleanupObject(ctx context.Context, client s3API, marker string, key *KMSKey, bucket *BucketState, target *ObjectInfo, pollInterval time.Duration) error {
	state, err := client.GetBucketState(ctx, bucket.Name)
	if err != nil || !validBucketState(state, marker, key) {
		return errCleanup
	}
	value, err := client.GetObject(ctx, bucket.Name, target.Key)
	if err != nil {
		return errCleanup
	}
	tags, err := client.GetObjectTags(ctx, bucket.Name, target.Key)
	if err != nil {
		return errCleanup
	}
	value.Tags = tags
	expected := expectedObjectRequest(marker, key, bucket.Name)
	expected.ExpectedETag = target.ETag
	if !bytes.Equal(value.Body, expected.Body) || !validObjectInfo(value.ObjectInfo, expected, key) {
		return errCleanup
	}
	if err := client.DeleteObject(ctx, bucket.Name, target.Key); err != nil {
		return errCleanup
	}
	return pollUntil(ctx, pollInterval, func() (bool, error) {
		objects, err := client.ListObjects(ctx, bucket.Name, "")
		if err != nil {
			return false, errCleanup
		}
		return len(objects) == 0, nil
	})
}

func cleanupBucket(ctx context.Context, client s3API, marker string, key *KMSKey, target *BucketState, pollInterval time.Duration) error {
	buckets, err := client.ListBuckets(ctx, target.Name)
	if err != nil || countExactStrings(buckets, target.Name) != 1 {
		return errCleanup
	}
	state, err := client.GetBucketState(ctx, target.Name)
	if err != nil {
		return errCleanup
	}
	if target.Provisional {
		tagsSafe := len(state.Tags) == 0 || equalStringMaps(state.Tags, proofTags(marker, "evidence-bucket"))
		encryptionSafe := (state.Algorithm == "" && state.KMSKeyID == "") ||
			(state.Algorithm == sseAlgorithmKMS && sameKeyIdentity(state.KMSKeyID, key))
		if state.Name != target.Name || !tagsSafe || !encryptionSafe {
			return errCleanup
		}
	} else if !validBucketState(state, marker, key) {
		return errCleanup
	}
	objects, err := client.ListObjects(ctx, target.Name, "")
	if err != nil || len(objects) != 0 {
		return errCleanup
	}
	if err := client.DeleteBucket(ctx, target.Name); err != nil {
		return errCleanup
	}
	return pollUntil(ctx, pollInterval, func() (bool, error) {
		buckets, err = client.ListBuckets(ctx, target.Name)
		if err != nil {
			return false, errCleanup
		}
		return countExactStrings(buckets, target.Name) == 0, nil
	})
}

func cleanupAlias(ctx context.Context, client kmsAPI, marker string, key *KMSKey, target *KMSAlias, pollInterval time.Duration) error {
	aliases, err := client.ListAliases(ctx, target.Name)
	exact := exactAliases(aliases, target.Name)
	if err != nil || len(exact) != 1 || exact[0] != *target || !sameKeyIdentity(exact[0].KeyID, key) {
		return errCleanup
	}
	if err := client.DeleteAlias(ctx, target.Name); err != nil {
		return errCleanup
	}
	return pollUntil(ctx, pollInterval, func() (bool, error) {
		aliases, err = client.ListAliases(ctx, target.Name)
		if err != nil {
			return false, errCleanup
		}
		return len(exactAliases(aliases, target.Name)) == 0, nil
	})
}

func cleanupKey(ctx context.Context, client kmsAPI, marker string, target *KMSKey, pollInterval time.Duration) error {
	current, err := proveOwnedKey(ctx, client, target.ID, marker, keyStateEnabled)
	if err != nil || current.ID != target.ID || current.ARN != target.ARN {
		return errCleanup
	}
	scheduled, err := client.ScheduleKeyDeletion(ctx, target.ID, minimumDeletionWindowDays)
	if err != nil || scheduled.ID != target.ID || scheduled.ARN != target.ARN {
		return errCleanup
	}
	return pollUntil(ctx, pollInterval, func() (bool, error) {
		candidate, err := client.DescribeKey(ctx, target.ID)
		if err != nil || !validKeyIdentity(candidate) || candidate.ID != target.ID || candidate.ARN != target.ARN ||
			candidate.Description != description(marker) || candidate.Spec != keySpecSymmetric || candidate.Usage != keyUsageEncryptDecrypt ||
			candidate.Origin != keyOriginAWSKMS || candidate.Manager != keyManagerCustomer {
			return false, errCleanup
		}
		tags, err := client.ListKeyTags(ctx, target.ID)
		if err != nil || !equalStringMaps(tags, proofTags(marker, "kms-key")) {
			return false, errCleanup
		}
		if candidate.State == keyStateEnabled && candidate.Enabled {
			return false, nil
		}
		if candidate.State != keyStatePendingDeletion || candidate.Enabled {
			return false, errCleanup
		}
		candidate.Tags = tags
		*target = candidate
		return true, nil
	})
}

func pollUntil(ctx context.Context, interval time.Duration, check func() (bool, error)) error {
	for {
		ready, err := check()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errCleanup
		case <-timer.C:
		}
	}
}

func AuditStorage(ctx context.Context, kmsClient kmsAPI, s3Client s3API, secretsClient secretsAPI, marker, keyID string) error {
	if ctx == nil || kmsClient == nil || s3Client == nil || secretsClient == nil || !markerPattern.MatchString(marker) || keyID == "" {
		return errConfiguration
	}
	aliases, err := kmsClient.ListAliases(ctx, aliasName(marker))
	if err != nil || len(aliases) != 0 {
		return errProvider
	}
	buckets, err := s3Client.ListBuckets(ctx, bucketName(marker))
	if err != nil || len(buckets) != 0 {
		return errProvider
	}
	secrets, err := secretsClient.ListSecrets(ctx, secretName(marker), false)
	if err != nil || len(secrets) != 0 {
		return errProvider
	}
	keys, err := kmsClient.ListKeys(ctx)
	if err != nil {
		return errProvider
	}
	var exact []KMSKey
	for _, candidate := range keys {
		if strings.HasPrefix(candidate.Description, resourcePrefix+marker) || candidate.Tags["zasp-marker"] == marker {
			exact = append(exact, candidate)
		}
	}
	if len(exact) != 1 || exact[0].ID != keyID {
		return errProvider
	}
	key, err := proveOwnedKey(ctx, kmsClient, keyID, marker, keyStatePendingDeletion)
	if err != nil || key.ID != keyID {
		return errProvider
	}
	return nil
}

func validateEndpoint(ctx context.Context, raw string, resolver interface {
	LookupHost(context.Context, string) ([]string, error)
}) (validatedEndpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.Hostname() == "" || parsed.Port() == "" {
		return validatedEndpoint{}, errConfiguration
	}
	portNumber, err := net.LookupPort("tcp", parsed.Port())
	if err != nil || portNumber < 1024 || portNumber > 65535 {
		return validatedEndpoint{}, errConfiguration
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "0.0.0.0" || host == "::" {
		return validatedEndpoint{}, errConfiguration
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return validatedEndpoint{}, errConfiguration
		}
	} else {
		if host != "localhost" {
			return validatedEndpoint{}, errConfiguration
		}
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addresses, lookupErr := resolver.LookupHost(ctx, host)
		if lookupErr != nil || len(addresses) == 0 {
			return validatedEndpoint{}, errConfiguration
		}
		for _, address := range addresses {
			ip := net.ParseIP(address)
			if ip == nil || !ip.IsLoopback() {
				return validatedEndpoint{}, errConfiguration
			}
		}
	}
	parsed.Path = ""
	return validatedEndpoint{baseURL: parsed.String(), hostname: host, port: parsed.Port()}, nil
}

type validatedEndpoint struct{ baseURL, hostname, port string }

func validKeyIdentity(key KMSKey) bool {
	if !keyIDPattern.MatchString(key.ID) {
		return false
	}
	parts := strings.Split(key.ARN, ":")
	return len(parts) == 6 && parts[0] == "arn" && parts[1] == "aws" && parts[2] == "kms" && parts[3] == fixedRegion &&
		accountPattern.MatchString(parts[4]) && parts[5] == "key/"+key.ID
}

func sameKeyIdentity(value string, key *KMSKey) bool { return value == key.ID || value == key.ARN }
func validBucketState(state BucketState, marker string, key *KMSKey) bool {
	return state.Name == bucketName(marker) && equalStringMaps(state.Tags, proofTags(marker, "evidence-bucket")) &&
		state.Algorithm == sseAlgorithmKMS && sameKeyIdentity(state.KMSKeyID, key)
}
func validObjectInfo(info ObjectInfo, request PutObjectRequest, key *KMSKey) bool {
	providerETag := strings.TrimSpace(strings.Trim(info.ETag, `"`))
	expectedETag := strings.TrimSpace(strings.Trim(request.ExpectedETag, `"`))
	etagMatches := providerETag != "" && (expectedETag == "" || providerETag == expectedETag)
	return info.Key == request.Key && etagMatches && info.Algorithm == sseAlgorithmKMS &&
		sameKeyIdentity(info.KMSKeyID, key) && equalStringMaps(info.Metadata, request.Metadata) && equalStringMaps(info.Tags, request.Tags)
}
func validPutObjectResult(info ObjectInfo, request PutObjectRequest, key *KMSKey) bool {
	return info.Key == request.Key && strings.TrimSpace(strings.Trim(info.ETag, `"`)) != "" &&
		info.Algorithm == sseAlgorithmKMS && sameKeyIdentity(info.KMSKeyID, key)
}
func validSecretIdentity(secret SecretInfo, marker string, key *KMSKey) bool {
	if secret.Name != secretName(marker) || secret.Deleted || !sameKeyIdentity(secret.KMSKeyID, key) || !equalStringMaps(secret.Tags, proofTags(marker, "secret")) ||
		secret.VersionID == "" || !equalStringsAsSet(secret.Stages, []string{"AWSCURRENT"}) {
		return false
	}
	parts := strings.Split(secret.ARN, ":")
	return len(parts) == 7 && parts[0] == "arn" && parts[1] == "aws" && parts[2] == "secretsmanager" && parts[3] == fixedRegion &&
		accountPattern.MatchString(parts[4]) && parts[5] == "secret" && strings.HasPrefix(parts[6], secret.Name+"-") && len(parts[6]) > len(secret.Name)+1
}

func proofTags(marker, role string) map[string]string {
	return map[string]string{"zasp-proof": "m0-07", "zasp-marker": marker, "zasp-role": role}
}
func description(marker string) string { return resourcePrefix + marker + "-storage" }
func aliasName(marker string) string   { return "alias/" + resourcePrefix + marker + "-key" }
func bucketName(marker string) string  { return resourcePrefix + marker + "-evidence" }
func objectKey(marker string) string {
	return "organizations/" + organizationID(marker) + "/evidence/event-batch.json"
}
func secretName(marker string) string     { return resourcePrefix + marker + "-integration" }
func organizationID(marker string) string { return "org-" + marker }
func syntheticObject(marker string) []byte {
	return []byte(fmt.Sprintf(`{"kind":"normalized-event-archive","organization_id":"%s","version":"v1"}`, organizationID(marker)))
}
func syntheticSecret(marker string) []byte { return []byte("synthetic-integration-material-" + marker) }

func exactAliases(values []KMSAlias, name string) []KMSAlias {
	var out []KMSAlias
	for _, value := range values {
		if value.Name == name {
			out = append(out, value)
		}
	}
	return out
}
func countExactStrings(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}
func countExactSecrets(values []SecretInfo, target string) int {
	count := 0
	for _, value := range values {
		if value.Name == target {
			count++
		}
	}
	return count
}
func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
func equalStringsAsSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func errorCategory(err error) string {
	switch {
	case errors.Is(err, errConfiguration):
		return "configuration"
	case errors.Is(err, errOwnership):
		return "ownership"
	case errors.Is(err, errEncryption):
		return "encryption"
	case errors.Is(err, errContent):
		return "content"
	case errors.Is(err, errCleanup):
		return "cleanup"
	default:
		return "operation"
	}
}
