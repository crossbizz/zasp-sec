package s3rawstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

var (
	bucketPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	ownerPattern      = regexp.MustCompile(`^[0-9]{12}$`)
	kmsPattern        = regexp.MustCompile(`^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]{8,128}$`)
	versionPattern    = regexp.MustCompile(`^[!-~]+$`)
	generationPattern = regexp.MustCompile(`^[0-9]{20}$`)
)

type API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

type Config struct {
	Bucket              string
	ExpectedBucketOwner string
	KMSKeyARN           string
	MaximumBytes        int64
	OperationTimeout    time.Duration
}

type Store struct {
	api    API
	config Config
}

func New(api API, config Config) (*Store, error) {
	if nilValue(api) || !bucketPattern.MatchString(config.Bucket) || !ownerPattern.MatchString(config.ExpectedBucketOwner) || !kmsPattern.MatchString(config.KMSKeyARN) || config.MaximumBytes <= 0 || config.MaximumBytes > 64<<20 || config.OperationTimeout <= 0 || config.OperationTimeout > 30*time.Second {
		return nil, runtimeevent.ErrProductionIngest
	}
	return &Store{api: api, config: config}, nil
}

func (store *Store) Put(ctx context.Context, request runtimeevent.RawArtifactPut) (artifact runtimeevent.RawArtifact, resultErr error) {
	defer func() {
		if recover() != nil {
			artifact = runtimeevent.RawArtifact{}
			resultErr = runtimeevent.ErrProductionIngestUnknown
		}
	}()
	if store == nil || nilValue(store.api) || ctx == nil || ctx.Err() != nil || !validPut(request, store.config.MaximumBytes) {
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngest
	}
	body := bytes.Clone(request.Body)
	defer clear(body)
	bounded, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	checksum := checksumText(request.ContentDigest)
	output, putErr := store.api.PutObject(bounded, &s3.PutObjectInput{
		Bucket: aws.String(store.config.Bucket), Key: aws.String(request.Key), Body: bytes.NewReader(body), ContentLength: aws.Int64(int64(len(body))), ContentType: aws.String(request.MediaType),
		ChecksumSHA256: aws.String(checksum), ExpectedBucketOwner: aws.String(store.config.ExpectedBucketOwner), IfNoneMatch: aws.String("*"), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(store.config.KMSKeyARN), Metadata: rawMetadata(request),
	}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	versionID := ""
	if putErr == nil && validPutOutput(output, store.config.KMSKeyARN, checksum) {
		versionID = aws.ToString(output.VersionId)
	}
	head, headErr := store.api.HeadObject(bounded, &s3.HeadObjectInput{Bucket: aws.String(store.config.Bucket), Key: aws.String(request.Key), VersionId: optionalString(versionID), ExpectedBucketOwner: aws.String(store.config.ExpectedBucketOwner), ChecksumMode: s3types.ChecksumModeEnabled}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if headErr != nil || !validHead(head, request, store.config) || versionID != "" && aws.ToString(head.VersionId) != versionID {
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestUnknown
	}
	versionID = aws.ToString(head.VersionId)
	return runtimeevent.RawArtifact{Scope: request.Scope, Key: request.Key, Reference: "s3://" + store.config.Bucket + "/" + request.Key, VersionID: versionID, ContentDigest: request.ContentDigest, Size: int64(len(request.Body)), MediaType: request.MediaType, KMSKeyARN: store.config.KMSKeyARN}, nil
}

func (store *Store) Inspect(ctx context.Context, request runtimeevent.RawArtifactInspect) (artifact runtimeevent.RawArtifact, resultErr error) {
	defer func() {
		if recover() != nil {
			artifact = runtimeevent.RawArtifact{}
			resultErr = runtimeevent.ErrProductionIngestUnavailable
		}
	}()
	if store == nil || nilValue(store.api) || ctx == nil || ctx.Err() != nil || !validInspect(request, store.config.MaximumBytes) {
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngest
	}
	bounded, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	head, headErr := store.api.HeadObject(bounded, &s3.HeadObjectInput{Bucket: aws.String(store.config.Bucket), Key: aws.String(request.Key), ExpectedBucketOwner: aws.String(store.config.ExpectedBucketOwner), ChecksumMode: s3types.ChecksumModeEnabled}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if headErr != nil {
		if missingObject(headErr) {
			return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestArtifactNotFound
		}
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestUnavailable
	}
	if !validHeadInspect(head, request, store.config) {
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestArtifactDrift
	}
	return runtimeevent.RawArtifact{Scope: request.Scope, Key: request.Key, Reference: "s3://" + store.config.Bucket + "/" + request.Key, VersionID: aws.ToString(head.VersionId), ContentDigest: request.ContentDigest, Size: request.Size, MediaType: request.MediaType, KMSKeyARN: store.config.KMSKeyARN}, nil
}

func missingObject(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	switch apiError.ErrorCode() {
	case "NoSuchKey", "NoSuchVersion", "NotFound":
		return true
	default:
		return false
	}
}

func validPut(request runtimeevent.RawArtifactPut, maximumBytes int64) bool {
	return request.Scope.Validate() == nil && validRuntimeKey(request.Scope, request.Key) && request.MediaType == "application/json" && len(request.Body) > 0 && int64(len(request.Body)) <= maximumBytes && request.ContentDigest != [sha256.Size]byte{} && request.ContentDigest == sha256.Sum256(request.Body)
}

func validInspect(request runtimeevent.RawArtifactInspect, maximumBytes int64) bool {
	return request.Scope.Validate() == nil && validRuntimeKey(request.Scope, request.Key) && request.MediaType == "application/json" && request.Size > 0 && request.Size <= maximumBytes && request.ContentDigest != [sha256.Size]byte{}
}

func validRuntimeKey(scope domain.Scope, key string) bool {
	parts := strings.Split(key, "/")
	if len(parts) != 8 || parts[0] != "runtime" || parts[1] != "v15" || parts[2] != scope.OrganizationID().String() || parts[3] != scope.WorkspaceID().String() || parts[4] != scope.EnvironmentID().String() || !generationPattern.MatchString(parts[6]) || parts[6] == "00000000000000000000" || !strings.HasSuffix(parts[7], ".json") {
		return false
	}
	sensorID, sensorErr := domain.ParseProductID(parts[5])
	batchID, batchErr := domain.ParseProductID(strings.TrimSuffix(parts[7], ".json"))
	return sensorErr == nil && batchErr == nil && !sensorID.IsZero() && !batchID.IsZero()
}

func validPutOutput(output *s3.PutObjectOutput, kmsKey, checksum string) bool {
	return output != nil && validVersion(aws.ToString(output.VersionId)) && aws.ToString(output.ChecksumSHA256) == checksum && output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(output.SSEKMSKeyId) == kmsKey
}

func validHead(output *s3.HeadObjectOutput, request runtimeevent.RawArtifactPut, config Config) bool {
	return output != nil && validVersion(aws.ToString(output.VersionId)) && aws.ToInt64(output.ContentLength) == int64(len(request.Body)) && aws.ToString(output.ContentType) == request.MediaType && aws.ToString(output.ChecksumSHA256) == checksumText(request.ContentDigest) && output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(output.SSEKMSKeyId) == config.KMSKeyARN && exactMap(output.Metadata, rawMetadata(request))
}

func validHeadInspect(output *s3.HeadObjectOutput, request runtimeevent.RawArtifactInspect, config Config) bool {
	metadata := rawMetadata(runtimeevent.RawArtifactPut{Scope: request.Scope, Key: request.Key, MediaType: request.MediaType, ContentDigest: request.ContentDigest})
	return output != nil && validVersion(aws.ToString(output.VersionId)) && aws.ToInt64(output.ContentLength) == request.Size && aws.ToString(output.ContentType) == request.MediaType && aws.ToString(output.ChecksumSHA256) == checksumText(request.ContentDigest) && output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(output.SSEKMSKeyId) == config.KMSKeyARN && exactMap(output.Metadata, metadata)
}

func validVersion(value string) bool {
	return len(value) >= 1 && len(value) <= 1024 && versionPattern.MatchString(value)
}

func rawMetadata(request runtimeevent.RawArtifactPut) map[string]string {
	return map[string]string{"organization_id": request.Scope.OrganizationID().String(), "workspace_id": request.Scope.WorkspaceID().String(), "environment_id": request.Scope.EnvironmentID().String(), "media_type": request.MediaType, "sha256": hex.EncodeToString(request.ContentDigest[:])}
}

func checksumText(digest [sha256.Size]byte) string {
	return base64.StdEncoding.EncodeToString(digest[:])
}
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return aws.String(value)
}
func exactMap(left, right map[string]string) bool {
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
func nilValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ runtimeevent.RawArtifactAuthority = (*Store)(nil)
var _ runtimeevent.RawArtifactInspector = (*Store)(nil)
