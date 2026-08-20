package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type runtimeArchiveAPI interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type runtimeArchiveExecutorConfig struct {
	API           runtimeArchiveAPI
	Bucket        string
	ExpectedOwner string
	KMSKeyARN     string
	MaximumBytes  int64
}

type runtimeArchiveExecutor struct{ config runtimeArchiveExecutorConfig }

type runtimeArchivedBatchReader interface {
	Read(context.Context, runtimeevent.StageLease) ([]byte, error)
}

func newRuntimeArchiveExecutor(config runtimeArchiveExecutorConfig) (*runtimeArchiveExecutor, error) {
	if nilWorkerDependency(config.API) || !workerBucketPattern.MatchString(config.Bucket) || !workerAccountPattern.MatchString(config.ExpectedOwner) || !workerKMSPattern.MatchString(config.KMSKeyARN) || config.MaximumBytes < 1 || config.MaximumBytes > 64<<20 {
		return nil, errRuntimeUnavailable
	}
	return &runtimeArchiveExecutor{config: config}, nil
}

func (executor *runtimeArchiveExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errRuntimeStageRetryable
		}
	}()
	body, err := executor.Read(ctx, lease)
	if err != nil {
		return runtimeStageEffect{}, err
	}
	digest := sha256.Sum256(body)
	clear(body)
	return runtimeStageEffect{EffectDigest: digest, ResultReference: lease.InputReference, ResultVersionID: lease.InputVersionID, ResultDigest: digest}, nil
}

func (executor *runtimeArchiveExecutor) Read(ctx context.Context, lease runtimeevent.StageLease) ([]byte, error) {
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageArchive) && !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageIndex) {
		return nil, errRuntimeStageMalformed
	}
	key, ok := runtimeArchiveKey(lease, executor.config.Bucket)
	if !ok {
		return nil, errRuntimeStageMalformed
	}
	head, err := executor.config.API.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(executor.config.Bucket), Key: aws.String(key), VersionId: aws.String(lease.InputVersionID), ExpectedBucketOwner: aws.String(executor.config.ExpectedOwner), ChecksumMode: types.ChecksumModeEnabled}, runtimeArchiveOneAttempt)
	if err != nil || ctx.Err() != nil {
		return nil, runtimeArchiveReadError(ctx, err)
	}
	if !validRuntimeArchiveHead(head, lease, executor.config) {
		return nil, errRuntimeStageMalformed
	}
	output, err := executor.config.API.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(executor.config.Bucket), Key: aws.String(key), VersionId: aws.String(lease.InputVersionID), ExpectedBucketOwner: aws.String(executor.config.ExpectedOwner), ChecksumMode: types.ChecksumModeEnabled}, runtimeArchiveOneAttempt)
	if err != nil || output == nil || output.Body == nil || ctx.Err() != nil {
		return nil, runtimeArchiveReadError(ctx, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(output.Body, executor.config.MaximumBytes+1))
	closeErr := output.Body.Close()
	if readErr != nil || closeErr != nil || ctx.Err() != nil {
		clear(body)
		return nil, runtimeArchiveReadError(ctx, readErr)
	}
	digest := sha256.Sum256(body)
	valid := int64(len(body)) >= 1 && int64(len(body)) <= executor.config.MaximumBytes && validRuntimeArchiveGet(output, lease, executor.config, digest) && subtle.ConstantTimeCompare(digest[:], lease.InputDigest[:]) == 1
	if !valid {
		clear(body)
		return nil, errRuntimeStageMalformed
	}
	return body, nil
}

func runtimeArchiveKey(lease runtimeevent.StageLease, bucket string) (string, bool) {
	parsed, err := url.Parse(lease.InputReference)
	if err != nil || parsed == nil || parsed.String() != lease.InputReference || parsed.Scheme != "s3" || parsed.Host != bucket || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || !strings.HasPrefix(parsed.Path, "/") {
		return "", false
	}
	key := strings.TrimPrefix(parsed.Path, "/")
	parts := strings.Split(key, "/")
	if len(parts) != 8 || parts[0] != "runtime" || parts[1] != "v15" || parts[2] != lease.Scope.OrganizationID().String() || parts[3] != lease.Scope.WorkspaceID().String() || parts[4] != lease.Scope.EnvironmentID().String() || parts[6] != runtimeGenerationKey(lease.Generation) || parts[7] != lease.BatchID.String()+".json" {
		return "", false
	}
	sensorID, sensorErr := domain.ParseProductID(parts[5])
	return key, sensorErr == nil && !sensorID.IsZero()
}

func runtimeGenerationKey(generation int64) string {
	if generation < 1 {
		return ""
	}
	value := "00000000000000000000" + int64Text(generation)
	return value[len(value)-20:]
}

func validRuntimeArchiveHead(output *s3.HeadObjectOutput, lease runtimeevent.StageLease, config runtimeArchiveExecutorConfig) bool {
	if output == nil || aws.ToInt64(output.ContentLength) < 1 || aws.ToInt64(output.ContentLength) > config.MaximumBytes || aws.ToString(output.ContentType) != "application/json" || aws.ToString(output.VersionId) != lease.InputVersionID || output.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(output.SSEKMSKeyId) != config.KMSKeyARN || aws.ToString(output.ChecksumSHA256) != base64.StdEncoding.EncodeToString(lease.InputDigest[:]) {
		return false
	}
	return exactRuntimeArchiveMetadata(output.Metadata, runtimeArchiveMetadata(lease.Scope, lease.InputDigest))
}

func validRuntimeArchiveGet(output *s3.GetObjectOutput, lease runtimeevent.StageLease, config runtimeArchiveExecutorConfig, digest [sha256.Size]byte) bool {
	if output == nil || aws.ToInt64(output.ContentLength) < 1 || aws.ToInt64(output.ContentLength) > config.MaximumBytes || aws.ToString(output.ContentType) != "application/json" || aws.ToString(output.VersionId) != lease.InputVersionID || output.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(output.SSEKMSKeyId) != config.KMSKeyARN || aws.ToString(output.ChecksumSHA256) != base64.StdEncoding.EncodeToString(digest[:]) {
		return false
	}
	return exactRuntimeArchiveMetadata(output.Metadata, runtimeArchiveMetadata(lease.Scope, digest))
}

func runtimeArchiveMetadata(scope domain.Scope, digest [sha256.Size]byte) map[string]string {
	return map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "media_type": "application/json", "sha256": hex.EncodeToString(digest[:])}
}

func exactRuntimeArchiveMetadata(left, right map[string]string) bool {
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

func runtimeArchiveOneAttempt(options *s3.Options) { options.Retryer = aws.NopRetryer{} }

func runtimeArchiveReadError(ctx context.Context, providerErr error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var apiError smithy.APIError
	if errors.As(providerErr, &apiError) {
		switch apiError.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "ExpiredToken", "InvalidAccessKeyId", "SignatureDoesNotMatch":
			return errRuntimeStageDenied
		case "NoSuchBucket", "NoSuchKey", "NoSuchVersion", "NotFound":
			return errRuntimeStageMalformed
		}
	}
	return errRuntimeStageRetryable
}

func int64Text(value int64) string {
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(bytes.Clone(buffer[position:]))
}

var _ runtimeStageExecutor = (*runtimeArchiveExecutor)(nil)
var _ runtimeArchivedBatchReader = (*runtimeArchiveExecutor)(nil)
