package s3driver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const providerSecret = "s3-provider-secret-must-not-escape"

func TestDriverPutIsCreateOnlyAndReconcilesLostAcknowledgement(t *testing.T) {
	client := &fakeS3{loseFirstPutResponse: true}
	driver := mustDriver(t, client)
	object := fixtureObject(t)

	created, err := driver.Put(context.Background(), object)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if created.VersionID != "version-1" || created.Key != object.Key || created.Scope != object.Scope || created.Reference != object.Reference || created.MediaType != object.MediaType || !bytes.Equal(created.Body, object.Body) {
		t.Fatalf("Put() = %#v", created)
	}
	client.assertExactCreateOnlyRequest(t, object)

	replayed, err := driver.Put(context.Background(), object)
	if err != nil || replayed.VersionID != created.VersionID {
		t.Fatalf("replay = %#v, %v", replayed, err)
	}
	if client.createdObjects() != 1 {
		t.Fatalf("created objects = %d, want 1", client.createdObjects())
	}

	changed := object
	changed.Body = []byte(`{"changed":true}`)
	changed.Size = int64(len(changed.Body))
	changed.SHA256 = sha256.Sum256(changed.Body)
	if _, err := driver.Put(context.Background(), changed); !errors.Is(err, ErrPut) || strings.Contains(err.Error(), providerSecret) {
		t.Fatalf("changed replay error = %q", err)
	}
}

func TestDriverGetPinsVersionAndValidatesEveryBoundary(t *testing.T) {
	client := &fakeS3{}
	driver := mustDriver(t, client)
	object := fixtureObject(t)
	created, err := driver.Put(context.Background(), object)
	if err != nil {
		t.Fatal(err)
	}
	got, err := driver.Get(context.Background(), created.DriverLocator)
	if err != nil || got.VersionID != "version-1" || got.SHA256 != object.SHA256 || !bytes.Equal(got.Body, object.Body) {
		t.Fatalf("Get() = %#v, %v", got, err)
	}
	if client.lastGetVersion() != "version-1" {
		t.Fatalf("Get version = %q", client.lastGetVersion())
	}

	for _, mutate := range []func(*storedObject){
		func(value *storedObject) { value.metadata["sha256"] = strings.Repeat("0", 64) },
		func(value *storedObject) { value.contentType = "text/plain" },
		func(value *storedObject) {
			value.kmsKey = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000000"
		},
		func(value *storedObject) { value.body = append(value.body, 'x') },
		func(value *storedObject) { value.version = "" },
	} {
		client.mutateStored(mutate)
		if _, err := driver.Get(context.Background(), created.DriverLocator); !errors.Is(err, ErrGet) {
			t.Fatalf("hostile Get error = %v", err)
		}
		client.restore(object)
	}
}

func TestDriverReadUsesThePersistedVersionAcrossNewerVersionsAndDeleteMarkers(t *testing.T) {
	client := &fakeS3{}
	driver := mustDriver(t, client)
	original := fixtureObject(t)
	created, err := driver.Put(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	newer := original
	newer.Body = []byte(`{"newer":true}`)
	newer.Size = int64(len(newer.Body))
	newer.SHA256 = sha256.Sum256(newer.Body)
	client.installLatest(newer, "version-2")

	got, err := driver.Get(context.Background(), created.DriverLocator)
	if err != nil || got.VersionID != "version-1" || !bytes.Equal(got.Body, original.Body) {
		t.Fatalf("version-pinned Get() = %#v, %v", got, err)
	}
	client.setCurrentUnavailable(true)
	got, err = driver.Get(context.Background(), created.DriverLocator)
	if err != nil || got.VersionID != "version-1" || !bytes.Equal(got.Body, original.Body) {
		t.Fatalf("delete-marker Get() = %#v, %v", got, err)
	}

	unversioned := created.DriverLocator
	unversioned.VersionID = ""
	before := client.totalCalls()
	if _, err := driver.Get(context.Background(), unversioned); !errors.Is(err, ErrArtifact) || client.totalCalls() != before {
		t.Fatalf("unversioned Get() = %v, calls delta=%d", err, client.totalCalls()-before)
	}
	missing := created.DriverLocator
	missing.VersionID = "version-missing"
	if _, err := driver.Get(context.Background(), missing); !errors.Is(err, ErrGet) {
		t.Fatalf("missing version error = %v", err)
	}
}

func TestDriverRejectsInvalidInputBeforeCloudAndNeverDeletesImmutableEvidence(t *testing.T) {
	client := &fakeS3{}
	driver := mustDriver(t, client)
	object := fixtureObject(t)
	invalid := []artifactstore.DriverObject{{}, object}
	invalid[1].Key += "-cross-scope"
	for _, candidate := range invalid {
		if _, err := driver.Put(context.Background(), candidate); !errors.Is(err, ErrArtifact) {
			t.Fatalf("invalid Put error = %v", err)
		}
	}
	if _, err := driver.Get(context.Background(), invalid[1].DriverLocator); !errors.Is(err, ErrArtifact) {
		t.Fatalf("invalid Get error = %v", err)
	}
	if err := driver.Delete(context.Background(), object.DriverLocator); !errors.Is(err, ErrImmutable) {
		t.Fatalf("Delete error = %v", err)
	}
	if client.totalCalls() != 0 {
		t.Fatalf("cloud calls = %d, want 0", client.totalCalls())
	}
}

func TestDriverUsesOneAttemptAndContainsCancellationProviderErrorsAndPanics(t *testing.T) {
	object := fixtureObject(t)
	for _, client := range []*fakeS3{
		{putErr: errors.New(providerSecret)},
		{panicPut: true},
	} {
		driver := mustDriver(t, client)
		_, err := driver.Put(context.Background(), object)
		if !errors.Is(err, ErrPut) || strings.Contains(err.Error(), providerSecret) {
			t.Fatalf("Put error = %q", err)
		}
		if !client.allCallsUsedOneAttempt() {
			t.Fatal("SDK retryer was not forced to one attempt")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	client := &fakeS3{}
	driver := mustDriver(t, client)
	if _, err := driver.Put(canceled, object); !errors.Is(err, ErrPut) || client.totalCalls() != 0 {
		t.Fatalf("canceled Put = %v, calls=%d", err, client.totalCalls())
	}
}

func TestNewRejectsHostileConfigurationAndTypedNilClient(t *testing.T) {
	valid := validConfig()
	var typedNil *fakeS3
	for _, candidate := range []struct {
		client API
		config Config
	}{
		{nil, valid}, {typedNil, valid}, {&fakeS3{}, Config{}},
		{&fakeS3{}, Config{Bucket: valid.Bucket, ExpectedBucketOwner: valid.ExpectedBucketOwner, KMSKeyARN: valid.KMSKeyARN, MaximumBytes: 64*1024*1024 + 1}},
		{&fakeS3{}, Config{Bucket: "s3://bucket", ExpectedBucketOwner: valid.ExpectedBucketOwner, KMSKeyARN: valid.KMSKeyARN, MaximumBytes: 1}},
		{&fakeS3{}, Config{Bucket: valid.Bucket, ExpectedBucketOwner: "*", KMSKeyARN: valid.KMSKeyARN, MaximumBytes: 1}},
		{&fakeS3{}, Config{Bucket: valid.Bucket, ExpectedBucketOwner: valid.ExpectedBucketOwner, KMSKeyARN: "alias/ambient", MaximumBytes: 1}},
	} {
		if _, err := New(candidate.client, candidate.config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("New(%#v) error = %v", candidate.config, err)
		}
	}
}

func mustDriver(t *testing.T, client API) *Driver {
	t.Helper()
	driver, err := New(client, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func validConfig() Config {
	return Config{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 1024}
}

func fixtureObject(t *testing.T) artifactstore.DriverObject {
	t.Helper()
	ids := make([]domain.ProductID, 4)
	for index := range ids {
		value, err := domain.ParseProductID("pid_00000000-0000-4000-8000-00000000000" + string(rune('1'+index)))
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = value
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	reference, err := domain.NewEvidenceRef(ids[3])
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"fixture":true}`)
	return artifactstore.DriverObject{
		DriverLocator: artifactstore.DriverLocator{Key: "organizations/" + ids[0].String() + "/workspaces/" + ids[1].String() + "/environments/" + ids[2].String() + "/artifacts/" + ids[3].String(), Scope: scope, Reference: reference},
		MediaType:     "application/json", Body: body, Size: int64(len(body)), SHA256: sha256.Sum256(body),
	}
}

type storedObject struct {
	body                                   []byte
	contentType, checksum, version, kmsKey string
	metadata                               map[string]string
}

type observedPut struct {
	bucket, key, owner, kmsKey, ifNoneMatch, contentType, checksum string
	contentLength                                                  int64
	metadata                                                       map[string]string
}

type fakeS3 struct {
	mu                                     sync.Mutex
	stored                                 *storedObject
	versions                               map[string]*storedObject
	currentUnavailable                     bool
	put                                    observedPut
	lastVersion                            string
	putCalls, headCalls, getCalls, created int
	loseFirstPutResponse                   bool
	putErr                                 error
	panicPut                               bool
	oneAttempt                             []bool
}

func (client *fakeS3) PutObject(ctx context.Context, input *s3.PutObjectInput, options ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.putCalls++
	client.oneAttempt = append(client.oneAttempt, oneAttempt(options))
	if client.panicPut {
		panic(providerSecret)
	}
	if client.putErr != nil {
		return nil, client.putErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	client.put = observedPut{bucket: aws.ToString(input.Bucket), key: aws.ToString(input.Key), owner: aws.ToString(input.ExpectedBucketOwner), kmsKey: aws.ToString(input.SSEKMSKeyId), ifNoneMatch: aws.ToString(input.IfNoneMatch), contentType: aws.ToString(input.ContentType), checksum: aws.ToString(input.ChecksumSHA256), contentLength: aws.ToInt64(input.ContentLength), metadata: cloneMap(input.Metadata)}
	if client.stored != nil {
		return nil, errors.New("precondition failed")
	}
	client.created++
	client.stored = &storedObject{body: bytes.Clone(body), contentType: aws.ToString(input.ContentType), checksum: aws.ToString(input.ChecksumSHA256), version: "version-1", kmsKey: aws.ToString(input.SSEKMSKeyId), metadata: cloneMap(input.Metadata)}
	if client.versions == nil {
		client.versions = map[string]*storedObject{}
	}
	client.versions[client.stored.version] = client.stored
	if client.loseFirstPutResponse {
		client.loseFirstPutResponse = false
		return nil, errors.New("lost acknowledgement")
	}
	return &s3.PutObjectOutput{VersionId: aws.String(client.stored.version), ChecksumSHA256: aws.String(client.stored.checksum), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(client.stored.kmsKey)}, nil
}

func (client *fakeS3) HeadObject(ctx context.Context, input *s3.HeadObjectInput, options ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.headCalls++
	client.oneAttempt = append(client.oneAttempt, oneAttempt(options))
	value := client.stored
	requestedVersion := aws.ToString(input.VersionId)
	if requestedVersion != "" {
		value = client.versions[requestedVersion]
	}
	if ctx.Err() != nil || value == nil || requestedVersion == "" && client.currentUnavailable {
		return nil, errors.New("unavailable")
	}
	return &s3.HeadObjectOutput{ContentLength: aws.Int64(int64(len(value.body))), ContentType: aws.String(value.contentType), ChecksumSHA256: aws.String(value.checksum), VersionId: aws.String(value.version), Metadata: cloneMap(value.metadata), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(value.kmsKey)}, nil
}

func (client *fakeS3) GetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.getCalls++
	client.oneAttempt = append(client.oneAttempt, oneAttempt(options))
	client.lastVersion = aws.ToString(input.VersionId)
	value := client.stored
	if requestedVersion := aws.ToString(input.VersionId); requestedVersion != "" {
		value = client.versions[requestedVersion]
	}
	if ctx.Err() != nil || value == nil {
		return nil, errors.New("unavailable")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(value.body)), ContentLength: aws.Int64(int64(len(value.body))), ContentType: aws.String(value.contentType), ChecksumSHA256: aws.String(value.checksum), VersionId: aws.String(value.version), Metadata: cloneMap(value.metadata), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(value.kmsKey)}, nil
}

func oneAttempt(options []func(*s3.Options)) bool {
	value := s3.Options{}
	for _, option := range options {
		option(&value)
	}
	return value.Retryer != nil && value.Retryer.MaxAttempts() == 1
}
func cloneMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
func (client *fakeS3) createdObjects() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.created
}
func (client *fakeS3) totalCalls() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.putCalls + client.headCalls + client.getCalls
}
func (client *fakeS3) lastGetVersion() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.lastVersion
}
func (client *fakeS3) allCallsUsedOneAttempt() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	for _, value := range client.oneAttempt {
		if !value {
			return false
		}
	}
	return len(client.oneAttempt) > 0
}
func (client *fakeS3) mutateStored(mutate func(*storedObject)) {
	client.mu.Lock()
	defer client.mu.Unlock()
	mutate(client.stored)
}
func (client *fakeS3) restore(object artifactstore.DriverObject) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.stored = &storedObject{body: bytes.Clone(object.Body), contentType: object.MediaType, checksum: base64.StdEncoding.EncodeToString(object.SHA256[:]), version: "version-1", kmsKey: validConfig().KMSKeyARN, metadata: metadata(object)}
	if client.versions == nil {
		client.versions = map[string]*storedObject{}
	}
	client.versions[client.stored.version] = client.stored
}
func (client *fakeS3) installLatest(object artifactstore.DriverObject, version string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	value := &storedObject{body: bytes.Clone(object.Body), contentType: object.MediaType, checksum: base64.StdEncoding.EncodeToString(object.SHA256[:]), version: version, kmsKey: validConfig().KMSKeyARN, metadata: metadata(object)}
	if client.versions == nil {
		client.versions = map[string]*storedObject{}
	}
	client.versions[version] = value
	client.stored = value
}
func (client *fakeS3) setCurrentUnavailable(value bool) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.currentUnavailable = value
}
func (client *fakeS3) assertExactCreateOnlyRequest(t *testing.T, object artifactstore.DriverObject) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	wantChecksum := base64.StdEncoding.EncodeToString(object.SHA256[:])
	if client.put.bucket != validConfig().Bucket || client.put.owner != validConfig().ExpectedBucketOwner || client.put.kmsKey != validConfig().KMSKeyARN || client.put.key != object.Key || client.put.ifNoneMatch != "*" || client.put.contentType != object.MediaType || client.put.contentLength != object.Size || client.put.checksum != wantChecksum || !equalTestMap(client.put.metadata, metadata(object)) {
		t.Fatalf("Put request = %#v", client.put)
	}
}
func equalTestMap(left, right map[string]string) bool {
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
