package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

const testMarker = "0123456789abcdef"

func TestRunProofRejectsAnIncompleteLifecycle(t *testing.T) {
	t.Parallel()

	if _, err := RunProof(context.Background(), ProofOptions{}); !errors.Is(err, errConfiguration) {
		t.Fatalf("RunProof error = %v, want configuration category", err)
	}
}

func TestRunProofCompletesEncryptedStorageLifecycleAndCleanup(t *testing.T) {
	t.Parallel()

	cloud := newFakeCloud(testMarker)
	result, err := RunProof(context.Background(), proofOptions(cloud))
	if err != nil {
		t.Fatalf("RunProof returned %v", err)
	}
	if result.KMSKeyID != cloud.key.ID {
		t.Fatal("proof did not retain the exact scheduled key for the final audit")
	}
	if cloud.secret != nil || cloud.bucket != nil || len(cloud.aliases) != 0 {
		t.Fatal("active proof resources remained after cleanup")
	}
	if cloud.key.State != keyStatePendingDeletion {
		t.Fatalf("key state = %q, want PendingDeletion", cloud.key.State)
	}
	assertSubsequence(t, cloud.operations, []string{
		"list-keys", "list-aliases", "list-buckets", "list-secrets",
		"create-key", "describe-key", "list-key-tags", "create-alias", "list-aliases",
		"encrypt", "decrypt", "create-bucket", "put-bucket-tags", "put-bucket-encryption",
		"get-bucket-state", "put-object", "get-object", "get-object-tags", "list-objects",
		"create-secret", "describe-secret", "list-secret-versions", "get-secret-value",
		"delete-secret", "delete-object", "delete-bucket", "delete-alias", "schedule-key-deletion",
	})
}

func TestRunProofRejectsEveryExactPrefixCollisionBeforeCreation(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*fakeCloud){
		"tagged key": func(c *fakeCloud) { c.key = c.expectedKey() },
		"alias":      func(c *fakeCloud) { c.aliases[c.aliasName()] = c.expectedKey().ID },
		"bucket":     func(c *fakeCloud) { c.bucket = &fakeBucket{name: c.bucketName()} },
		"secret":     func(c *fakeCloud) { secret := c.expectedSecret(); c.secret = &secret },
	}
	for name, seed := range tests {
		name, seed := name, seed
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cloud := newFakeCloud(testMarker)
			seed(cloud)
			if _, err := RunProof(context.Background(), proofOptions(cloud)); !errors.Is(err, errOwnership) {
				t.Fatalf("RunProof error = %v, want ownership category", err)
			}
			for _, operation := range cloud.operations {
				if len(operation) > 7 && operation[:7] == "create-" {
					t.Fatalf("creation followed collision: %v", cloud.operations)
				}
			}
		})
	}
}

func TestRunProofRejectsAnyResourceUnderItsGeneratedPrefix(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*fakeCloud){
		"alias suffix":  func(c *fakeCloud) { c.aliases[c.aliasName()+"-extra"] = "foreign-key" },
		"bucket suffix": func(c *fakeCloud) { c.bucket = &fakeBucket{name: c.bucketName() + "-extra"} },
		"secret suffix": func(c *fakeCloud) {
			secret := c.expectedSecret()
			secret.Name += "-extra"
			secret.ARN = "arn:aws:secretsmanager:us-east-1:000000000000:secret:" + secret.Name + "-AbCdEf"
			c.secret = &secret
		},
	}
	for name, seed := range tests {
		name, seed := name, seed
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cloud := newFakeCloud(testMarker)
			seed(cloud)
			if _, err := RunProof(context.Background(), proofOptions(cloud)); !errors.Is(err, errOwnership) {
				t.Fatalf("RunProof error = %v, want prefix ownership rejection", err)
			}
			if slices.Contains(cloud.operations, "create-key") {
				t.Fatal("creation followed a prefix-wide collision")
			}
		})
	}
}

func TestRunProofReconcilesOnlyAtomicallyOwnedAmbiguousCreates(t *testing.T) {
	t.Parallel()

	t.Run("KMS key and secret are recovered from exact atomic tags", func(t *testing.T) {
		cloud := newFakeCloud(testMarker)
		cloud.ambiguous["create-key"] = true
		cloud.ambiguous["create-secret"] = true
		if _, err := RunProof(context.Background(), proofOptions(cloud)); err != nil {
			t.Fatalf("RunProof returned %v", err)
		}
		if cloud.secret != nil || cloud.key.State != keyStatePendingDeletion {
			t.Fatal("reconciled resources were not safely cleaned")
		}
	})

	t.Run("S3 ambiguous create remains unmodified and undeleted", func(t *testing.T) {
		cloud := newFakeCloud(testMarker)
		cloud.ambiguous["create-bucket"] = true
		if _, err := RunProof(context.Background(), proofOptions(cloud)); !errors.Is(err, errOwnership) {
			t.Fatalf("RunProof error = %v, want ownership category", err)
		}
		if cloud.bucket == nil {
			t.Fatal("ambiguous bucket was destructively removed")
		}
		if slices.Contains(cloud.operations, "put-bucket-tags") || slices.Contains(cloud.operations, "delete-bucket") {
			t.Fatalf("ambiguous bucket was mutated: %v", cloud.operations)
		}
	})
}

func TestRunProofRetainsCreatedTargetsAcrossPostCreateFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"bucket tag":           "put-bucket-tags",
		"bucket encryption":    "put-bucket-encryption",
		"bucket state":         "get-bucket-state",
		"object read":          "get-object",
		"object tags":          "get-object-tags",
		"object listing":       "list-objects",
		"secret description":   "describe-secret",
		"secret versions":      "list-secret-versions",
		"secret value":         "get-secret-value",
		"alias downstream use": "encrypt",
	}
	for name, operation := range tests {
		name, operation := name, operation
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cloud := newFakeCloud(testMarker)
			cloud.failOnce[operation] = errProvider
			if _, err := RunProof(context.Background(), proofOptions(cloud)); !errors.Is(err, errProvider) && !errors.Is(err, errOwnership) {
				t.Fatalf("RunProof error = %v, want original proof failure", err)
			}
			if cloud.secret != nil || cloud.bucket != nil || len(cloud.aliases) != 0 || cloud.key.State != keyStatePendingDeletion {
				t.Fatalf("post-create failure stranded active state: secret=%t bucket=%t aliases=%d key_state=%q operations=%v", cloud.secret != nil, cloud.bucket != nil, len(cloud.aliases), cloud.key.State, cloud.operations)
			}
		})
	}
}

func TestRunProofRetainsNarrowCandidatesBeforePostCreateProof(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		configure func(*fakeCloud)
		cleanup   []string
	}{
		"key describe and reconciliation fail": {
			configure: func(c *fakeCloud) { c.failAt["describe-key"] = 1; c.failAt["list-keys"] = 2 },
			cleanup:   []string{"create-key", "describe-key", "list-keys", "describe-key", "list-key-tags", "schedule-key-deletion", "describe-key", "list-key-tags"},
		},
		"alias listing fails": {
			configure: func(c *fakeCloud) { c.failAt["list-aliases"] = 2 },
			cleanup:   []string{"create-alias", "list-aliases", "list-aliases", "delete-alias", "list-aliases", "describe-key", "list-key-tags", "schedule-key-deletion"},
		},
		"put response identity is invalid": {
			configure: func(c *fakeCloud) { c.invalidPutResponse = true },
			cleanup:   []string{"put-object", "get-bucket-state", "get-object", "get-object-tags", "delete-object", "list-objects", "get-bucket-state", "list-objects", "delete-bucket", "list-buckets"},
		},
	}
	for name, testCase := range tests {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cloud := newFakeCloud(testMarker)
			testCase.configure(cloud)
			if _, err := RunProof(context.Background(), proofOptions(cloud)); err == nil {
				t.Fatal("proof unexpectedly succeeded")
			}
			if cloud.secret != nil || cloud.bucket != nil || len(cloud.aliases) != 0 || cloud.key.State != keyStatePendingDeletion {
				t.Fatalf("post-create candidate was not cleaned: secret=%t bucket=%t aliases=%d key_state=%q", cloud.secret != nil, cloud.bucket != nil, len(cloud.aliases), cloud.key.State)
			}
			assertSubsequence(t, cloud.operations, testCase.cleanup)
		})
	}
}

func TestRunProofReconcilesAmbiguousPutObjectBeforeContinuing(t *testing.T) {
	t.Parallel()
	cloud := newFakeCloud(testMarker)
	cloud.ambiguous["put-object"] = true
	if _, err := RunProof(context.Background(), proofOptions(cloud)); err != nil {
		t.Fatalf("RunProof returned %v", err)
	}
	if cloud.bucket != nil || cloud.secret != nil || len(cloud.aliases) != 0 || cloud.key.State != keyStatePendingDeletion {
		t.Fatal("ambiguous object was not reconciled and cleaned")
	}
	assertSubsequence(t, cloud.operations, []string{
		"put-object", "get-object", "get-object-tags", "list-objects",
		"create-secret", "delete-secret", "get-bucket-state", "get-object", "get-object-tags", "delete-object", "list-objects",
	})
}

func TestRunProofRejectsWrongEncryptionIdentityAndContent(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*fakeCloud){
		"KMS decrypt mismatch":      func(c *fakeCloud) { c.wrongDecrypt = true },
		"object KMS key":            func(c *fakeCloud) { c.wrongObjectKey = true },
		"foreign object":            func(c *fakeCloud) { c.foreignObject = true },
		"secret KMS key":            func(c *fakeCloud) { c.wrongSecretKey = true },
		"secret current stage":      func(c *fakeCloud) { c.wrongSecretStage = true },
		"secret value":              func(c *fakeCloud) { c.wrongSecretValue = true },
		"managed or asymmetric key": func(c *fakeCloud) { c.wrongKeySemantics = true },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cloud := newFakeCloud(testMarker)
			mutate(cloud)
			if _, err := RunProof(context.Background(), proofOptions(cloud)); err == nil {
				t.Fatal("RunProof accepted a broken identity/encryption invariant")
			}
		})
	}
}

func TestRunProofAcceptsOpaqueButStableSSEKMSETag(t *testing.T) {
	t.Parallel()
	cloud := newFakeCloud(testMarker)
	cloud.opaqueETag = true
	if _, err := RunProof(context.Background(), proofOptions(cloud)); err != nil {
		t.Fatalf("RunProof rejected stable provider ETag: %v", err)
	}
}

func TestCleanupReconcilesEventuallyConsistentAbsenceAndPendingKey(t *testing.T) {
	t.Parallel()
	cloud := newFakeCloud(testMarker)
	cloud.eventual = map[string]int{"secret": 2, "object": 2, "bucket": 2, "alias": 2, "key": 2}
	options := proofOptions(cloud)
	options.PollInterval = time.Millisecond
	if _, err := RunProof(context.Background(), options); err != nil {
		t.Fatalf("RunProof did not reconcile bounded eventual state: %v", err)
	}
}

func TestRunProofReprovesOwnershipBeforeEveryDestructiveCall(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"secret": "describe-secret",
		"object": "get-object",
		"bucket": "get-bucket-state",
		"alias":  "list-aliases",
		"key":    "describe-key",
	}
	for resource, operation := range tests {
		resource, operation := resource, operation
		t.Run(resource, func(t *testing.T) {
			t.Parallel()
			cloud := newFakeCloud(testMarker)
			cloud.mutateAt[operation] = 2
			if resource == "alias" {
				cloud.mutateAt[operation] = 3
			}
			cloud.mutateResource = resource
			if _, err := RunProof(context.Background(), proofOptions(cloud)); !errors.Is(err, errCleanup) {
				t.Fatalf("RunProof error = %v, want cleanup precedence", err)
			}
			if slices.Contains(cloud.operations, "delete-"+resource) || (resource == "key" && slices.Contains(cloud.operations, "schedule-key-deletion")) {
				t.Fatalf("changed %s was destroyed: %v", resource, cloud.operations)
			}
		})
	}
}

func TestRunProofCleanupFailureOverridesProofFailureAndContinues(t *testing.T) {
	t.Parallel()

	cloud := newFakeCloud(testMarker)
	cloud.fail["get-secret-value"] = errProvider
	cloud.fail["delete-object"] = errProvider
	_, err := RunProof(context.Background(), proofOptions(cloud))
	if !errors.Is(err, errCleanup) {
		t.Fatalf("RunProof error = %v, want cleanup precedence", err)
	}
	for _, operation := range []string{"delete-alias", "schedule-key-deletion"} {
		if !slices.Contains(cloud.operations, operation) {
			t.Fatalf("cleanup stopped before %s: %v", operation, cloud.operations)
		}
	}
}

func TestRunProofRecoversPanicsAndUsesIndependentCleanupContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cloud := newFakeCloud(testMarker)
	cloud.panicAt = "get-secret-value"
	cloud.cancel = cancel
	options := proofOptions(cloud)
	options.CleanupTimeout = time.Second
	_, err := RunProof(ctx, options)
	if !errors.Is(err, errProvider) {
		t.Fatalf("RunProof error = %v, want provider category", err)
	}
	if cloud.key.State != keyStatePendingDeletion {
		t.Fatal("panic/cancellation bypassed independent cleanup")
	}
}

func TestAuditStorageRequiresZeroActiveResourcesAndExactPendingKey(t *testing.T) {
	t.Parallel()

	cloud := newFakeCloud(testMarker)
	result, err := RunProof(context.Background(), proofOptions(cloud))
	if err != nil {
		t.Fatalf("RunProof returned %v", err)
	}
	if err := AuditStorage(context.Background(), cloud, cloud, cloud, testMarker, result.KMSKeyID); err != nil {
		t.Fatalf("AuditStorage returned %v", err)
	}

	tests := map[string]func(*fakeCloud){
		"active alias":  func(c *fakeCloud) { c.aliases[c.aliasName()] = c.key.ID },
		"active bucket": func(c *fakeCloud) { c.bucket = &fakeBucket{name: c.bucketName()} },
		"active secret": func(c *fakeCloud) { secret := c.expectedSecret(); c.secret = &secret },
		"enabled key":   func(c *fakeCloud) { c.key.State = keyStateEnabled },
		"wrong key tags": func(c *fakeCloud) {
			c.key.Tags = map[string]string{"zasp-proof": "foreign"}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			cloud := newFakeCloud(testMarker)
			result, err := RunProof(context.Background(), proofOptions(cloud))
			if err != nil {
				t.Fatalf("RunProof returned %v", err)
			}
			mutate(cloud)
			if err := AuditStorage(context.Background(), cloud, cloud, cloud, testMarker, result.KMSKeyID); err == nil {
				t.Fatal("audit accepted an active or foreign resource")
			}
		})
	}
}

func TestAuditStorageRejectsEveryPrefixWideExtraAndDuplicateKey(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*fakeCloud){
		"alias suffix":  func(c *fakeCloud) { c.aliases[c.aliasName()+"-extra"] = c.key.ID },
		"bucket suffix": func(c *fakeCloud) { c.bucket = &fakeBucket{name: c.bucketName() + "-extra"} },
		"secret suffix": func(c *fakeCloud) {
			secret := c.expectedSecret()
			secret.Name += "-extra"
			secret.ARN = "arn:aws:secretsmanager:us-east-1:000000000000:secret:" + secret.Name + "-AbCdEf"
			c.secret = &secret
		},
		"duplicate tagged key": func(c *fakeCloud) { c.extraKeys = append(c.extraKeys, c.secondExpectedKey()) },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cloud := newFakeCloud(testMarker)
			result, err := RunProof(context.Background(), proofOptions(cloud))
			if err != nil {
				t.Fatalf("RunProof returned %v", err)
			}
			mutate(cloud)
			if err := AuditStorage(context.Background(), cloud, cloud, cloud, testMarker, result.KMSKeyID); err == nil {
				t.Fatal("audit accepted prefix-wide extra state")
			}
		})
	}
}

func proofOptions(cloud *fakeCloud) ProofOptions {
	return ProofOptions{
		Endpoint:       "http://127.0.0.1:49152",
		Marker:         testMarker,
		KMS:            cloud,
		S3:             cloud,
		Secrets:        cloud,
		CleanupTimeout: time.Second,
	}
}

type fakeCloud struct {
	marker                  string
	key                     KMSKey
	aliases                 map[string]string
	bucket                  *fakeBucket
	secret                  *SecretInfo
	operations              []string
	counts                  map[string]int
	fail                    map[string]error
	failOnce                map[string]error
	failAt                  map[string]int
	ambiguous               map[string]bool
	mutateAt                map[string]int
	mutateResource          string
	panicAt                 string
	cancel                  context.CancelFunc
	wrongDecrypt            bool
	wrongObjectKey          bool
	foreignObject           bool
	wrongSecretKey          bool
	wrongSecretStage        bool
	wrongSecretValue        bool
	wrongKeySemantics       bool
	opaqueETag              bool
	eventual                map[string]int
	invalidPutResponse      bool
	extraKeys               []KMSKey
	artifactAmbiguousBucket bool
}

type fakeBucket struct {
	name      string
	tags      map[string]string
	algorithm string
	keyID     string
	object    *ObjectValue
}

func newFakeCloud(marker string) *fakeCloud {
	return &fakeCloud{
		marker: marker, aliases: map[string]string{}, counts: map[string]int{},
		fail: map[string]error{}, failOnce: map[string]error{}, failAt: map[string]int{}, ambiguous: map[string]bool{}, mutateAt: map[string]int{}, eventual: map[string]int{},
	}
}

func (c *fakeCloud) step(operation string) error {
	c.operations = append(c.operations, operation)
	c.counts[operation]++
	if c.mutateAt[operation] == c.counts[operation] {
		switch c.mutateResource {
		case "secret":
			c.secret.Tags = map[string]string{"zasp-proof": "foreign"}
		case "object":
			c.bucket.object.Tags = map[string]string{"zasp-proof": "foreign"}
		case "bucket":
			c.bucket.tags = map[string]string{"zasp-proof": "foreign"}
		case "alias":
			c.aliases[c.aliasName()] = "foreign-key"
		case "key":
			c.key.Tags = map[string]string{"zasp-proof": "foreign"}
		}
	}
	if c.panicAt == operation {
		if c.cancel != nil {
			c.cancel()
		}
		panic("provider detail must not escape")
	}
	if err := c.failOnce[operation]; err != nil {
		delete(c.failOnce, operation)
		return err
	}
	if c.failAt[operation] == c.counts[operation] {
		return errProvider
	}
	return c.fail[operation]
}

func (c *fakeCloud) expectedKey() KMSKey {
	return KMSKey{
		ID:          "11111111-2222-3333-4444-555555555555",
		ARN:         "arn:aws:kms:us-east-1:000000000000:key/11111111-2222-3333-4444-555555555555",
		Description: c.description(), State: keyStateEnabled, Spec: keySpecSymmetric,
		Usage: keyUsageEncryptDecrypt, Origin: keyOriginAWSKMS, Manager: keyManagerCustomer,
		Enabled: true, Tags: proofTags(c.marker, "kms-key"),
	}
}

func (c *fakeCloud) expectedSecret() SecretInfo {
	return SecretInfo{
		Name: c.secretName(), ARN: "arn:aws:secretsmanager:us-east-1:000000000000:secret:" + c.secretName() + "-AbCdEf",
		KMSKeyID: c.key.ARN, Tags: proofTags(c.marker, "secret"), VersionID: "version-1", Stages: []string{"AWSCURRENT"},
	}
}

func (c *fakeCloud) secondExpectedKey() KMSKey {
	key := c.expectedKey()
	key.ID = "66666666-7777-8888-9999-000000000000"
	key.ARN = "arn:aws:kms:us-east-1:000000000000:key/" + key.ID
	return key
}

func (c *fakeCloud) description() string { return resourcePrefix + c.marker + "-storage" }
func (c *fakeCloud) aliasName() string   { return "alias/" + resourcePrefix + c.marker + "-key" }
func (c *fakeCloud) bucketName() string  { return resourcePrefix + c.marker + "-evidence" }
func (c *fakeCloud) secretName() string  { return resourcePrefix + c.marker + "-integration" }

func (c *fakeCloud) ListKeys(context.Context) ([]KMSKey, error) {
	if err := c.step("list-keys"); err != nil {
		return nil, err
	}
	result := make([]KMSKey, 0, 1+len(c.extraKeys))
	if c.key.ID != "" {
		result = append(result, cloneKey(c.key))
	}
	for _, key := range c.extraKeys {
		result = append(result, cloneKey(key))
	}
	return result, nil
}
func (c *fakeCloud) CreateKey(_ context.Context, request CreateKeyRequest) (KMSKey, error) {
	if err := c.step("create-key"); err != nil {
		return KMSKey{}, err
	}
	c.key = c.expectedKey()
	c.key.Description = request.Description
	c.key.Tags = cloneStringMap(request.Tags)
	if c.wrongKeySemantics {
		c.key.Spec, c.key.Manager = "RSA_2048", "AWS"
	}
	if !equalStringMaps(request.Tags, c.key.Tags) || request.Description != c.key.Description {
		return KMSKey{}, errProvider
	}
	if c.ambiguous["create-key"] {
		return KMSKey{}, errProvider
	}
	return cloneKey(c.key), nil
}
func (c *fakeCloud) DescribeKey(_ context.Context, keyID string) (KMSKey, error) {
	if err := c.step("describe-key"); err != nil {
		return KMSKey{}, err
	}
	if keyID == c.key.ID && c.eventual["key"] > 0 && slices.Contains(c.operations, "schedule-key-deletion") {
		c.eventual["key"]--
		if c.eventual["key"] == 0 {
			c.key.State, c.key.Enabled = keyStatePendingDeletion, false
		}
	}
	if keyID == c.key.ID {
		return cloneKey(c.key), nil
	}
	for _, key := range c.extraKeys {
		if keyID == key.ID {
			return cloneKey(key), nil
		}
	}
	return KMSKey{}, errProvider
}
func (c *fakeCloud) ListKeyTags(_ context.Context, keyID string) (map[string]string, error) {
	if err := c.step("list-key-tags"); err != nil {
		return nil, err
	}
	if keyID == c.key.ID {
		return cloneStringMap(c.key.Tags), nil
	}
	for _, key := range c.extraKeys {
		if keyID == key.ID {
			return cloneStringMap(key.Tags), nil
		}
	}
	return nil, errProvider
}
func (c *fakeCloud) CreateAlias(_ context.Context, alias, keyID string) error {
	if err := c.step("create-alias"); err != nil {
		return err
	}
	c.aliases[alias] = keyID
	return nil
}
func (c *fakeCloud) ListAliases(_ context.Context, prefix string) ([]KMSAlias, error) {
	if err := c.step("list-aliases"); err != nil {
		return nil, err
	}
	if c.eventual["alias"] > 0 && slices.Contains(c.operations, "delete-alias") {
		c.eventual["alias"]--
		if c.eventual["alias"] == 0 {
			delete(c.aliases, c.aliasName())
		}
	}
	var aliases []KMSAlias
	for name, keyID := range c.aliases {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			aliases = append(aliases, KMSAlias{Name: name, KeyID: keyID})
		}
	}
	return aliases, nil
}
func (c *fakeCloud) Encrypt(_ context.Context, request CryptRequest) (Ciphertext, error) {
	if err := c.step("encrypt"); err != nil {
		return Ciphertext{}, err
	}
	return Ciphertext{Blob: append([]byte("cipher:"), request.Plaintext...), KeyID: c.key.ARN, Algorithm: encryptionAlgorithmSymmetric}, nil
}
func (c *fakeCloud) Decrypt(_ context.Context, request DecryptRequest) (Plaintext, error) {
	if err := c.step("decrypt"); err != nil {
		return Plaintext{}, err
	}
	value := bytes.TrimPrefix(request.Ciphertext, []byte("cipher:"))
	if c.wrongDecrypt {
		value = []byte("wrong")
	}
	return Plaintext{Value: value, KeyID: c.key.ARN, Algorithm: encryptionAlgorithmSymmetric}, nil
}
func (c *fakeCloud) DeleteAlias(_ context.Context, alias string) error {
	if err := c.step("delete-alias"); err != nil {
		return err
	}
	if c.eventual["alias"] == 0 {
		delete(c.aliases, alias)
	}
	return nil
}
func (c *fakeCloud) ScheduleKeyDeletion(context.Context, string, int32) (KMSKey, error) {
	if err := c.step("schedule-key-deletion"); err != nil {
		return KMSKey{}, err
	}
	if c.eventual["key"] == 0 {
		c.key.State, c.key.Enabled = keyStatePendingDeletion, false
	}
	return cloneKey(c.key), nil
}

func (c *fakeCloud) ListBuckets(_ context.Context, prefix string) ([]string, error) {
	if err := c.step("list-buckets"); err != nil {
		return nil, err
	}
	if c.eventual["bucket"] > 0 && slices.Contains(c.operations, "delete-bucket") {
		c.eventual["bucket"]--
		if c.eventual["bucket"] == 0 {
			c.bucket = nil
		}
	}
	if c.bucket != nil && len(c.bucket.name) >= len(prefix) && c.bucket.name[:len(prefix)] == prefix {
		return []string{c.bucket.name}, nil
	}
	return nil, nil
}
func (c *fakeCloud) CreateBucket(_ context.Context, name string) error {
	if err := c.step("create-bucket"); err != nil {
		return err
	}
	c.bucket = &fakeBucket{name: name}
	if c.artifactAmbiguousBucket {
		return errMutationAmbiguous
	}
	if c.ambiguous["create-bucket"] {
		return errProvider
	}
	return nil
}
func (c *fakeCloud) PutBucketTags(_ context.Context, _ string, tags map[string]string) error {
	if err := c.step("put-bucket-tags"); err != nil {
		return err
	}
	c.bucket.tags = cloneStringMap(tags)
	return nil
}
func (c *fakeCloud) PutBucketEncryption(_ context.Context, _, keyID string) error {
	if err := c.step("put-bucket-encryption"); err != nil {
		return err
	}
	c.bucket.algorithm, c.bucket.keyID = sseAlgorithmKMS, keyID
	return nil
}
func (c *fakeCloud) GetBucketState(context.Context, string) (BucketState, error) {
	if err := c.step("get-bucket-state"); err != nil {
		return BucketState{}, err
	}
	return BucketState{Name: c.bucket.name, Tags: cloneStringMap(c.bucket.tags), Algorithm: c.bucket.algorithm, KMSKeyID: c.bucket.keyID}, nil
}
func (c *fakeCloud) PutObject(_ context.Context, request PutObjectRequest) (ObjectInfo, error) {
	if err := c.step("put-object"); err != nil {
		return ObjectInfo{}, err
	}
	keyID := request.KMSKeyID
	if c.wrongObjectKey {
		keyID = "foreign-key"
	}
	etag := "stable-provider-etag"
	if c.opaqueETag {
		etag = "opaque-provider-etag"
	}
	c.bucket.object = &ObjectValue{ObjectInfo: ObjectInfo{Key: request.Key, ETag: etag, Algorithm: sseAlgorithmKMS, KMSKeyID: keyID, Size: int64(len(request.Body)), Metadata: cloneStringMap(request.Metadata), Tags: cloneStringMap(request.Tags)}, Body: append([]byte(nil), request.Body...)}
	if c.ambiguous["put-object"] {
		return ObjectInfo{}, errMutationAmbiguous
	}
	created := cloneObjectInfo(c.bucket.object.ObjectInfo)
	created.Metadata, created.Tags = nil, nil // PutObject does not echo these fields.
	if c.invalidPutResponse {
		created.KMSKeyID = "foreign-key"
	}
	return created, nil
}
func (c *fakeCloud) GetObject(context.Context, string, string) (ObjectValue, error) {
	if err := c.step("get-object"); err != nil {
		return ObjectValue{}, err
	}
	if c.bucket == nil || c.bucket.object == nil {
		return ObjectValue{}, errProvider
	}
	value := cloneObjectValue(*c.bucket.object)
	return value, nil
}
func (c *fakeCloud) GetObjectTags(context.Context, string, string) (map[string]string, error) {
	if err := c.step("get-object-tags"); err != nil {
		return nil, err
	}
	if c.bucket == nil || c.bucket.object == nil {
		return nil, errProvider
	}
	return cloneStringMap(c.bucket.object.Tags), nil
}
func (c *fakeCloud) ListObjects(context.Context, string, string) ([]ObjectInfo, error) {
	if err := c.step("list-objects"); err != nil {
		return nil, err
	}
	if c.eventual["object"] > 0 && slices.Contains(c.operations, "delete-object") {
		c.eventual["object"]--
		if c.eventual["object"] == 0 {
			c.bucket.object = nil
		}
	}
	if c.bucket.object == nil {
		return nil, nil
	}
	objects := []ObjectInfo{cloneObjectInfo(c.bucket.object.ObjectInfo)}
	if c.foreignObject {
		objects = append(objects, ObjectInfo{Key: "foreign"})
	}
	return objects, nil
}
func (c *fakeCloud) DeleteObject(context.Context, string, string) error {
	if err := c.step("delete-object"); err != nil {
		return err
	}
	if c.eventual["object"] == 0 {
		c.bucket.object = nil
	}
	return nil
}
func (c *fakeCloud) DeleteBucket(context.Context, string) error {
	if err := c.step("delete-bucket"); err != nil {
		return err
	}
	if c.eventual["bucket"] == 0 {
		c.bucket = nil
	}
	return nil
}

func (c *fakeCloud) ListSecrets(_ context.Context, prefix string, includeDeleted bool) ([]SecretInfo, error) {
	if err := c.step("list-secrets"); err != nil {
		return nil, err
	}
	if c.eventual["secret"] > 0 && slices.Contains(c.operations, "delete-secret") {
		c.eventual["secret"]--
		if c.eventual["secret"] == 0 {
			c.secret = nil
		}
	}
	if c.secret == nil || (c.secret.Deleted && !includeDeleted) {
		return nil, nil
	}
	if len(c.secret.Name) >= len(prefix) && c.secret.Name[:len(prefix)] == prefix {
		return []SecretInfo{cloneSecret(*c.secret)}, nil
	}
	return nil, nil
}
func (c *fakeCloud) CreateSecret(_ context.Context, request CreateSecretRequest) (SecretInfo, error) {
	if err := c.step("create-secret"); err != nil {
		return SecretInfo{}, err
	}
	secret := c.expectedSecret()
	if c.wrongSecretKey {
		secret.KMSKeyID = "foreign-key"
	}
	if c.wrongSecretStage {
		secret.Stages = []string{"AWSPREVIOUS"}
	}
	c.secret = &secret
	if c.ambiguous["create-secret"] {
		return SecretInfo{}, errProvider
	}
	return cloneSecret(secret), nil
}
func (c *fakeCloud) DescribeSecret(context.Context, string) (SecretInfo, error) {
	if err := c.step("describe-secret"); err != nil {
		return SecretInfo{}, err
	}
	return cloneSecret(*c.secret), nil
}
func (c *fakeCloud) ListSecretVersions(context.Context, string) ([]SecretVersion, error) {
	if err := c.step("list-secret-versions"); err != nil {
		return nil, err
	}
	return []SecretVersion{{ID: c.secret.VersionID, Stages: append([]string(nil), c.secret.Stages...)}}, nil
}
func (c *fakeCloud) GetSecretValue(context.Context, string, string, string) (SecretValue, error) {
	if err := c.step("get-secret-value"); err != nil {
		return SecretValue{}, err
	}
	value := syntheticSecret(c.marker)
	if c.wrongSecretValue {
		value = []byte("wrong")
	}
	return SecretValue{Name: c.secret.Name, ARN: c.secret.ARN, KMSKeyID: c.secret.KMSKeyID, VersionID: c.secret.VersionID, Stages: append([]string(nil), c.secret.Stages...), Value: value}, nil
}
func (c *fakeCloud) DeleteSecret(context.Context, string) error {
	if err := c.step("delete-secret"); err != nil {
		return err
	}
	if c.eventual["secret"] == 0 {
		c.secret = nil
	}
	return nil
}

func cloneKey(value KMSKey) KMSKey { value.Tags = cloneStringMap(value.Tags); return value }
func cloneSecret(value SecretInfo) SecretInfo {
	value.Tags = cloneStringMap(value.Tags)
	value.Stages = append([]string(nil), value.Stages...)
	return value
}
func cloneObjectInfo(value ObjectInfo) ObjectInfo {
	value.Metadata = cloneStringMap(value.Metadata)
	value.Tags = cloneStringMap(value.Tags)
	return value
}
func cloneObjectValue(value ObjectValue) ObjectValue {
	value.ObjectInfo = cloneObjectInfo(value.ObjectInfo)
	value.Body = append([]byte(nil), value.Body...)
	return value
}

func assertSubsequence(t *testing.T, got, want []string) {
	t.Helper()
	position := 0
	for _, operation := range got {
		if position < len(want) && operation == want[position] {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("operations %v do not contain ordered subsequence %v", got, want)
	}
}

func TestErrorCategoriesAreFixedAndContainNoProviderDetails(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("wrapped: %w", errConfiguration), "configuration"},
		{fmt.Errorf("wrapped: %w", errOwnership), "ownership"},
		{fmt.Errorf("wrapped: %w", errEncryption), "encryption"},
		{fmt.Errorf("wrapped: %w", errContent), "content"},
		{fmt.Errorf("wrapped: %w", errCleanup), "cleanup"},
		{errors.New("sensitive provider detail"), "operation"},
	} {
		if got := errorCategory(test.err); got != test.want {
			t.Fatalf("category = %q, want %q", got, test.want)
		}
	}
}
