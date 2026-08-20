package s3driver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

const maximumArtifactBytes int64 = 64 * 1024 * 1024

var (
	ErrConfiguration = errors.New("s3 artifact configuration rejected")
	ErrArtifact      = errors.New("s3 artifact rejected")
	ErrPut           = errors.New("s3 artifact put failed")
	ErrGet           = errors.New("s3 artifact get failed")
	ErrImmutable     = errors.New("s3 artifact is immutable")

	bucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	ownerPattern   = regexp.MustCompile(`^[0-9]{12}$`)
	kmsKeyPattern  = regexp.MustCompile(`^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	versionPattern = regexp.MustCompile(`^[!-~]+$`)
)

type API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type Config struct {
	Bucket              string
	ExpectedBucketOwner string
	KMSKeyARN           string
	MaximumBytes        int64
}

type Driver struct {
	client API
	config Config
}

var _ artifactstore.Driver = (*Driver)(nil)
var _ artifactstore.DriverObjectReferencer = (*Driver)(nil)

func New(client API, config Config) (*Driver, error) {
	if nilInterface(client) || !bucketPattern.MatchString(config.Bucket) || !ownerPattern.MatchString(config.ExpectedBucketOwner) ||
		!kmsKeyPattern.MatchString(config.KMSKeyARN) || config.MaximumBytes <= 0 || config.MaximumBytes > maximumArtifactBytes {
		return nil, ErrConfiguration
	}
	return &Driver{client: client, config: config}, nil
}

func (driver *Driver) Put(ctx context.Context, object artifactstore.DriverObject) (result artifactstore.DriverObject, resultErr error) {
	defer containPanic(&result, &resultErr, ErrPut)
	if !driver.ready(ctx) {
		return artifactstore.DriverObject{}, ErrPut
	}
	if !driver.validObject(object) || object.VersionID != "" {
		return artifactstore.DriverObject{}, ErrArtifact
	}
	checksum := checksumText(object.SHA256)
	input := &s3.PutObjectInput{
		Bucket: aws.String(driver.config.Bucket), Key: aws.String(object.Key), Body: bytes.NewReader(bytes.Clone(object.Body)),
		ContentLength: aws.Int64(object.Size), ContentType: aws.String(object.MediaType), ChecksumSHA256: aws.String(checksum),
		ExpectedBucketOwner: aws.String(driver.config.ExpectedBucketOwner), IfNoneMatch: aws.String("*"),
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(driver.config.KMSKeyARN), Metadata: metadata(object),
	}
	output, putErr := driver.client.PutObject(ctx, input, oneAttemptOption)
	if ctx.Err() != nil {
		return artifactstore.DriverObject{}, ErrPut
	}
	var stored artifactstore.DriverObject
	var fetchErr error
	if putErr == nil && validPutOutput(output, driver.config.KMSKeyARN, checksum) {
		locator := object.DriverLocator
		locator.VersionID = aws.ToString(output.VersionId)
		stored, fetchErr = driver.fetch(ctx, locator)
	} else {
		stored, fetchErr = driver.discover(ctx, object.DriverLocator)
	}
	if fetchErr != nil || !sameContent(stored, object) {
		return artifactstore.DriverObject{}, ErrPut
	}
	return stored, nil
}

func (driver *Driver) Get(ctx context.Context, locator artifactstore.DriverLocator) (result artifactstore.DriverObject, resultErr error) {
	defer containPanic(&result, &resultErr, ErrGet)
	if !driver.ready(ctx) {
		return artifactstore.DriverObject{}, ErrGet
	}
	if !validLocator(locator) || !validVersion(locator.VersionID) {
		return artifactstore.DriverObject{}, ErrArtifact
	}
	return driver.fetch(ctx, locator)
}

func (driver *Driver) Delete(ctx context.Context, locator artifactstore.DriverLocator) error {
	if !driver.ready(ctx) {
		return ErrImmutable
	}
	if !validLocator(locator) {
		return ErrArtifact
	}
	return ErrImmutable
}

func (driver *Driver) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	if driver == nil || !validLocator(locator) || locator.VersionID == "" {
		return "", ErrArtifact
	}
	return "s3://" + driver.config.Bucket + "/" + locator.Key, nil
}

func (driver *Driver) fetch(ctx context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	head, err := driver.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(driver.config.Bucket), Key: aws.String(locator.Key), VersionId: aws.String(locator.VersionID), ExpectedBucketOwner: aws.String(driver.config.ExpectedBucketOwner), ChecksumMode: s3types.ChecksumModeEnabled,
	}, oneAttemptOption)
	if err != nil || ctx.Err() != nil || !validHead(head, driver.config) || aws.ToString(head.VersionId) != locator.VersionID {
		return artifactstore.DriverObject{}, ErrGet
	}
	output, err := driver.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(driver.config.Bucket), Key: aws.String(locator.Key), VersionId: aws.String(locator.VersionID), ExpectedBucketOwner: aws.String(driver.config.ExpectedBucketOwner), ChecksumMode: s3types.ChecksumModeEnabled,
	}, oneAttemptOption)
	if err != nil || ctx.Err() != nil || output == nil || output.Body == nil {
		return artifactstore.DriverObject{}, ErrGet
	}
	body, readErr := io.ReadAll(io.LimitReader(output.Body, driver.config.MaximumBytes+1))
	closeErr := output.Body.Close()
	if readErr != nil || closeErr != nil || ctx.Err() != nil || int64(len(body)) <= 0 || int64(len(body)) > driver.config.MaximumBytes {
		return artifactstore.DriverObject{}, ErrGet
	}
	digest := sha256.Sum256(body)
	object := artifactstore.DriverObject{DriverLocator: locator, MediaType: aws.ToString(output.ContentType), Body: body, Size: int64(len(body)), SHA256: digest}
	if !driver.validObject(object) || !validGet(output, head, object, driver.config) {
		return artifactstore.DriverObject{}, ErrGet
	}
	return cloneObject(object), nil
}

func (driver *Driver) discover(ctx context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	if !validLocator(locator) || locator.VersionID != "" {
		return artifactstore.DriverObject{}, ErrGet
	}
	head, err := driver.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(driver.config.Bucket), Key: aws.String(locator.Key), ExpectedBucketOwner: aws.String(driver.config.ExpectedBucketOwner), ChecksumMode: s3types.ChecksumModeEnabled,
	}, oneAttemptOption)
	if err != nil || ctx.Err() != nil || !validHead(head, driver.config) {
		return artifactstore.DriverObject{}, ErrGet
	}
	locator.VersionID = aws.ToString(head.VersionId)
	return driver.fetch(ctx, locator)
}

func (driver *Driver) ready(ctx context.Context) bool {
	return driver != nil && !nilInterface(driver.client) && ctx != nil && ctx.Err() == nil
}

func (driver *Driver) validObject(object artifactstore.DriverObject) bool {
	return driver != nil && validLocator(object.DriverLocator) && validMediaType(object.MediaType) && object.Size > 0 && object.Size <= driver.config.MaximumBytes &&
		object.Size == int64(len(object.Body)) && object.SHA256 == sha256.Sum256(object.Body) && (object.VersionID == "" || validVersion(object.VersionID))
}

func validLocator(locator artifactstore.DriverLocator) bool {
	if locator.Scope.Validate() != nil || locator.Reference.Validate() != nil {
		return false
	}
	want := "organizations/" + locator.OrganizationID().String() + "/workspaces/" + locator.WorkspaceID().String() + "/environments/" + locator.EnvironmentID().String() + "/artifacts/" + locator.Reference.String()
	return locator.Key == want && (locator.VersionID == "" || validVersion(locator.VersionID))
}

func validMediaType(value string) bool {
	switch value {
	case "application/json", "application/octet-stream", "application/gzip", "text/plain":
		return true
	default:
		return false
	}
}

func validPutOutput(output *s3.PutObjectOutput, kmsKeyARN, checksum string) bool {
	return output != nil && validVersion(aws.ToString(output.VersionId)) && aws.ToString(output.ChecksumSHA256) == checksum &&
		output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(output.SSEKMSKeyId) == kmsKeyARN
}

func validHead(output *s3.HeadObjectOutput, config Config) bool {
	return output != nil && output.ContentLength != nil && *output.ContentLength > 0 && *output.ContentLength <= config.MaximumBytes &&
		validMediaType(aws.ToString(output.ContentType)) && validVersion(aws.ToString(output.VersionId)) &&
		output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(output.SSEKMSKeyId) == config.KMSKeyARN &&
		validChecksumText(aws.ToString(output.ChecksumSHA256))
}

func validGet(output *s3.GetObjectOutput, head *s3.HeadObjectOutput, object artifactstore.DriverObject, config Config) bool {
	wantChecksum := checksumText(object.SHA256)
	return aws.ToString(output.VersionId) == object.VersionID && aws.ToString(output.VersionId) == aws.ToString(head.VersionId) &&
		aws.ToInt64(output.ContentLength) == object.Size && aws.ToInt64(head.ContentLength) == object.Size &&
		aws.ToString(output.ContentType) == object.MediaType && aws.ToString(head.ContentType) == object.MediaType &&
		aws.ToString(output.ChecksumSHA256) == wantChecksum && aws.ToString(head.ChecksumSHA256) == wantChecksum &&
		output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(output.SSEKMSKeyId) == config.KMSKeyARN &&
		equalMap(output.Metadata, metadata(object)) && equalMap(head.Metadata, metadata(object))
}

func metadata(object artifactstore.DriverObject) map[string]string {
	return map[string]string{
		"organization_id": object.OrganizationID().String(), "workspace_id": object.WorkspaceID().String(), "environment_id": object.EnvironmentID().String(),
		"artifact_id": object.Reference.String(), "media_type": object.MediaType, "sha256": hex.EncodeToString(object.SHA256[:]),
	}
}

func sameContent(left, right artifactstore.DriverObject) bool {
	return left.Key == right.Key && left.Scope == right.Scope && left.Reference == right.Reference && left.MediaType == right.MediaType && left.Size == right.Size && left.SHA256 == right.SHA256 && bytes.Equal(left.Body, right.Body)
}

func checksumText(digest [sha256.Size]byte) string {
	return base64.StdEncoding.EncodeToString(digest[:])
}
func validVersion(value string) bool {
	return len(value) >= 1 && len(value) <= 1024 && versionPattern.MatchString(value)
}
func validChecksumText(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.StdEncoding.EncodeToString(decoded) == value
}
func equalMap(left, right map[string]string) bool {
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
func cloneObject(object artifactstore.DriverObject) artifactstore.DriverObject {
	object.Body = bytes.Clone(object.Body)
	return object
}
func oneAttemptOption(options *s3.Options) { options.Retryer = aws.NopRetryer{} }

func containPanic(result *artifactstore.DriverObject, resultErr *error, stable error) {
	if recover() != nil {
		*result = artifactstore.DriverObject{}
		*resultErr = stable
	}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
