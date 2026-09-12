package sandboxcutover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type S3ReadAPI interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}
type ArtifactConfig struct {
	Binding                                ReleaseBinding
	Bucket, ExpectedBucketOwner, KMSKeyARN string
}

// S3ArtifactReader accepts an already resolved, trusted SDK client. It does not
// discover endpoints or authenticate release provenance. Configuration is copied
// and every Read requires the identical verified binding.
type S3ArtifactReader struct {
	api      S3ReadAPI
	config   ArtifactConfig
	receipts *artifactstore.Store
}

// The existing receipt driver includes Put in its interface. This private shim
// provides no write capability and refuses locally if that method is ever used.
type readOnlyArtifactS3 struct{ S3ReadAPI }

func (readOnlyArtifactS3) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, errRejected
}

func NewS3ArtifactReader(api S3ReadAPI, config ArtifactConfig) (*S3ArtifactReader, error) {
	if nilValue(api) || !validRelease(config.Binding) {
		return nil, errRejected
	}
	driver, err := s3driver.New(readOnlyArtifactS3{api}, s3driver.Config{Bucket: config.Bucket, ExpectedBucketOwner: config.ExpectedBucketOwner, KMSKeyARN: config.KMSKeyARN, MaximumBytes: 1 << 20})
	if err != nil {
		return nil, errRejected
	}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: 5 * time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		return nil, errRejected
	}
	return &S3ArtifactReader{api: api, config: config, receipts: store}, nil
}

func (reader *S3ArtifactReader) Read(ctx context.Context, binding ReleaseBinding, record ReceiptRecord) (receiptBytes, archive []byte, resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRejected
		}
		if resultErr != nil {
			clear(receiptBytes)
			clear(archive)
			receiptBytes, archive = nil, nil
		}
	}()
	if reader == nil || ctx == nil || ctx.Err() != nil || binding != reader.config.Binding || !artifactRecord(record) {
		return nil, nil, errRejected
	}
	locator, ok := artifactReceiptLocator(record.Binding.Scope, reader.config.Bucket, record.ReceiptReference, record.ReceiptVersion)
	if !ok {
		return nil, nil, errRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	artifact, err := reader.receipts.Get(ctx, locator)
	if err != nil {
		return nil, nil, errRejected
	}
	defer clear(artifact.Body)
	ref, err := reader.receipts.ObjectReference(artifact.Locator)
	if err != nil || ref != record.ReceiptReference || artifact.Locator != locator || artifact.MediaType != "application/json" || artifact.Size < 1 || artifact.Size > 1<<20 || artifact.Size != int64(len(artifact.Body)) || artifact.SHA256 != record.Binding.ReceiptDigest || sha256.Sum256(artifact.Body) != record.Binding.ReceiptDigest {
		return nil, nil, errRejected
	}
	receipt, err := runtimeprojection.DecodeReceipt(artifact.Body)
	if err != nil || receipt.Scope != record.Binding.Scope || receipt.BatchID != record.Binding.BatchID || receipt.Generation != record.Binding.Generation || receipt.ImplementationVersion != record.ProjectVersion {
		return nil, nil, errRejected
	}
	if len(receipt.Items) != len(record.EventIDs) {
		return nil, nil, errRejected
	}
	for i, item := range receipt.Items {
		if item.EventID.String() != record.EventIDs[i] {
			return nil, nil, errRejected
		}
	}
	key, ok := artifactArchiveKey(record, reader.config.Bucket, receipt.ArchiveReference)
	if !ok {
		return nil, nil, errRejected
	}
	archive, err = reader.readArchive(ctx, record.Binding.Scope, key, receipt.ArchiveVersionID, receipt.ArchiveDigest)
	if err != nil {
		return nil, nil, errRejected
	}
	documents, err := sessionsearch.BuildDocuments(record.Binding, artifact.Body, archive)
	if err != nil || len(documents) != len(record.DocumentIDs) || ctx.Err() != nil {
		return nil, archive, errRejected
	}
	for i, document := range documents {
		if document.DocumentID != record.DocumentIDs[i] {
			return nil, archive, errRejected
		}
	}
	return bytes.Clone(artifact.Body), archive, nil
}

func artifactRecord(r ReceiptRecord) bool {
	if !((r.ProjectVersion == "runtime-projection-v1" && r.CompleteVersion == "runtime-complete-v1") || (r.ProjectVersion == "runtime-projection-v2" && r.CompleteVersion == "runtime-complete-v2")) {
		return false
	}
	if r.Binding.Scope.Validate() != nil || r.Binding.BatchID.IsZero() || r.Binding.Generation < 1 || r.Binding.ReceiptDigest == ([32]byte{}) || !artifactVersion(r.ReceiptVersion) || (r.ProjectVersion != "runtime-projection-v1" && r.ProjectVersion != "runtime-projection-v2") || (r.CompleteVersion != "runtime-complete-v1" && r.CompleteVersion != "runtime-complete-v2") || len(r.EventIDs) < 1 || len(r.EventIDs) > 1000 || len(r.DocumentIDs) != len(r.EventIDs) {
		return false
	}
	seen := map[string]bool{}
	for i, value := range r.EventIDs {
		id, err := domain.ParseProductID(value)
		if err != nil || id.IsZero() || seen[value] || !digest(r.DocumentIDs[i]) {
			return false
		}
		seen[value] = true
	}
	return true
}

func artifactVersion(value string) bool {
	return len(value) > 0 && len(value) <= 1024 && strings.IndexFunc(value, func(r rune) bool { return r < 33 || r > 126 }) < 0
}
func artifactObjectKey(reference, bucket string) (string, bool) {
	u, err := url.Parse(reference)
	if err != nil || u.String() != reference || u.Scheme != "s3" || u.Host != bucket || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/") {
		return "", false
	}
	return strings.TrimPrefix(u.Path, "/"), true
}
func artifactReceiptLocator(scope domain.Scope, bucket, reference, version string) (artifactstore.Locator, bool) {
	key, ok := artifactObjectKey(reference, bucket)
	prefix := fmt.Sprintf("organizations/%s/workspaces/%s/environments/%s/artifacts/", scope.OrganizationID(), scope.WorkspaceID(), scope.EnvironmentID())
	if !ok || !strings.HasPrefix(key, prefix) || !artifactVersion(version) {
		return artifactstore.Locator{}, false
	}
	id, err := domain.ParseEvidenceRef(strings.TrimPrefix(key, prefix))
	return artifactstore.Locator{Scope: scope, Reference: id, VersionID: version}, err == nil
}
func artifactArchiveKey(record ReceiptRecord, bucket, reference string) (string, bool) {
	key, ok := artifactObjectKey(reference, bucket)
	parts := strings.Split(key, "/")
	scope := record.Binding.Scope
	if !ok || len(parts) != 8 || parts[0] != "runtime" || parts[1] != "v15" || parts[2] != scope.OrganizationID().String() || parts[3] != scope.WorkspaceID().String() || parts[4] != scope.EnvironmentID().String() || parts[6] != fmt.Sprintf("%020d", record.Binding.Generation) || parts[7] != record.Binding.BatchID.String()+".json" {
		return "", false
	}
	sensor, err := domain.ParseProductID(parts[5])
	return key, err == nil && !sensor.IsZero()
}
func (reader *S3ArtifactReader) readArchive(ctx context.Context, scope domain.Scope, key, version string, expected [32]byte) ([]byte, error) {
	if !artifactVersion(version) || expected == ([32]byte{}) {
		return nil, errRejected
	}
	metadata := map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "media_type": "application/json", "sha256": hex.EncodeToString(expected[:])}
	valid := func(size int64, media, returnedVersion string, encryption types.ServerSideEncryption, kms, checksum string, returnedMetadata map[string]string) bool {
		return size > 0 && size <= 64<<20 && media == "application/json" && returnedVersion == version && encryption == types.ServerSideEncryptionAwsKms && kms == reader.config.KMSKeyARN && checksum == base64.StdEncoding.EncodeToString(expected[:]) && reflect.DeepEqual(metadata, returnedMetadata)
	}
	oneAttempt := func(options *s3.Options) { options.Retryer = aws.NopRetryer{} }
	head, err := reader.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(reader.config.Bucket), Key: aws.String(key), VersionId: aws.String(version), ExpectedBucketOwner: aws.String(reader.config.ExpectedBucketOwner), ChecksumMode: types.ChecksumModeEnabled}, oneAttempt)
	if err != nil || ctx.Err() != nil || head == nil || !valid(aws.ToInt64(head.ContentLength), aws.ToString(head.ContentType), aws.ToString(head.VersionId), head.ServerSideEncryption, aws.ToString(head.SSEKMSKeyId), aws.ToString(head.ChecksumSHA256), head.Metadata) {
		return nil, errRejected
	}
	object, err := reader.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(reader.config.Bucket), Key: aws.String(key), VersionId: aws.String(version), ExpectedBucketOwner: aws.String(reader.config.ExpectedBucketOwner), ChecksumMode: types.ChecksumModeEnabled}, oneAttempt)
	closed := false
	if object != nil && object.Body != nil {
		defer func() {
			if !closed {
				_ = object.Body.Close()
			}
		}()
	}
	if err != nil || ctx.Err() != nil || object == nil || object.Body == nil {
		return nil, errRejected
	}
	body, readErr := io.ReadAll(io.LimitReader(object.Body, (64<<20)+1))
	closeErr := object.Body.Close()
	closed = true
	if readErr != nil || closeErr != nil || ctx.Err() != nil || int64(len(body)) != aws.ToInt64(head.ContentLength) || int64(len(body)) != aws.ToInt64(object.ContentLength) || !valid(int64(len(body)), aws.ToString(object.ContentType), aws.ToString(object.VersionId), object.ServerSideEncryption, aws.ToString(object.SSEKMSKeyId), aws.ToString(object.ChecksumSHA256), object.Metadata) || sha256.Sum256(body) != expected {
		clear(body)
		return nil, errRejected
	}
	return body, nil
}
