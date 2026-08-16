package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

type hostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}
type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type sdkBundle struct {
	KMS       kmsAPI
	S3        s3API
	Secrets   secretsAPI
	transport *http.Transport
}

func newSDKClients(ctx context.Context, rawEndpoint string) (*sdkBundle, error) {
	endpoint, err := validateEndpoint(ctx, rawEndpoint, nil)
	if err != nil {
		return nil, errConfiguration
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: loopbackDialerWithResolver(endpoint, net.DefaultResolver), DisableKeepAlives: true,
		ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 1 << 20,
	}
	httpClient := &http.Client{Timeout: 20 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	retryer := awsretry.NewStandard(func(options *awsretry.StandardOptions) {
		options.MaxAttempts = 2
		options.MaxBackoff = 500 * time.Millisecond
	})
	credentials := aws.CredentialsProviderFunc(staticLocalCredentials)
	kmsClient := kms.New(kms.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint.baseURL), HTTPClient: httpClient, Credentials: credentials, Retryer: retryer, RetryMaxAttempts: 2})
	s3Client := s3.New(s3.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint.baseURL), HTTPClient: httpClient, Credentials: credentials, Retryer: retryer, RetryMaxAttempts: 2, UsePathStyle: true})
	secretsClient := secretsmanager.New(secretsmanager.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint.baseURL), HTTPClient: httpClient, Credentials: credentials, Retryer: retryer, RetryMaxAttempts: 2})
	return &sdkBundle{KMS: &sdkKMS{client: kmsClient}, S3: &sdkS3{client: s3Client}, Secrets: &sdkSecrets{client: secretsClient}, transport: transport}, nil
}

func (b *sdkBundle) Close() {
	if b != nil && b.transport != nil {
		b.transport.CloseIdleConnections()
	}
}

func staticLocalCredentials(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test", Source: "zasp-localstack-storage-proof"}, nil
}

func loopbackDialerWithResolver(endpoint validatedEndpoint, resolver hostResolver) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	return loopbackDialerWithResolverAndDialer(endpoint, resolver, dialer.DialContext)
}

func loopbackDialerWithResolverAndDialer(endpoint validatedEndpoint, resolver hostResolver, dial dialContextFunc) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != endpoint.port {
			return nil, errConfiguration
		}
		addresses, err := resolver.LookupHost(ctx, strings.Trim(host, "[]"))
		if err != nil || len(addresses) == 0 {
			return nil, errConfiguration
		}
		for _, candidate := range addresses {
			ip := net.ParseIP(candidate)
			if ip == nil || !ip.IsLoopback() {
				return nil, errConfiguration
			}
		}
		var lastErr error
		for _, candidate := range addresses {
			connection, err := dial(ctx, network, net.JoinHostPort(candidate, port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

type sdkKMS struct{ client *kms.Client }

func (s *sdkKMS) ListKeys(ctx context.Context) ([]KMSKey, error) {
	paginator := kms.NewListKeysPaginator(s.client, &kms.ListKeysInput{})
	var result []KMSKey
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil || page == nil {
			return nil, errProvider
		}
		for _, entry := range page.Keys {
			if entry.KeyId == nil {
				return nil, errProvider
			}
			key, err := s.DescribeKey(ctx, *entry.KeyId)
			if err != nil {
				return nil, errProvider
			}
			tags, err := s.ListKeyTags(ctx, key.ID)
			if err != nil {
				return nil, errProvider
			}
			key.Tags = tags
			result = append(result, key)
		}
	}
	return result, nil
}

func (s *sdkKMS) CreateKey(ctx context.Context, request CreateKeyRequest) (KMSKey, error) {
	output, err := s.client.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String(request.Description), KeySpec: kmstypes.KeySpecSymmetricDefault, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, Origin: kmstypes.OriginTypeAwsKms, Tags: toKMSTags(request.Tags)}, func(options *kms.Options) {
		options.Retryer = aws.NopRetryer{}
		options.RetryMaxAttempts = 1
	})
	if err != nil || output == nil || output.KeyMetadata == nil {
		return KMSKey{}, errProvider
	}
	return fromKMSMetadata(*output.KeyMetadata), nil
}

func (s *sdkKMS) DescribeKey(ctx context.Context, keyID string) (KMSKey, error) {
	output, err := s.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil || output == nil || output.KeyMetadata == nil {
		return KMSKey{}, errProvider
	}
	return fromKMSMetadata(*output.KeyMetadata), nil
}

func (s *sdkKMS) ListKeyTags(ctx context.Context, keyID string) (map[string]string, error) {
	result := map[string]string{}
	paginator := kms.NewListResourceTagsPaginator(s.client, &kms.ListResourceTagsInput{KeyId: aws.String(keyID)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil || page == nil {
			return nil, errProvider
		}
		for _, tag := range page.Tags {
			if tag.TagKey == nil || tag.TagValue == nil {
				return nil, errProvider
			}
			if _, exists := result[*tag.TagKey]; exists {
				return nil, errProvider
			}
			result[*tag.TagKey] = *tag.TagValue
		}
	}
	return result, nil
}

func (s *sdkKMS) CreateAlias(ctx context.Context, alias, keyID string) error {
	_, err := s.client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(alias), TargetKeyId: aws.String(keyID)})
	if err != nil {
		return classifyMutationError(err)
	}
	return nil
}

func (s *sdkKMS) ListAliases(ctx context.Context, prefix string) ([]KMSAlias, error) {
	paginator := kms.NewListAliasesPaginator(s.client, &kms.ListAliasesInput{})
	var result []KMSAlias
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil || page == nil {
			return nil, errProvider
		}
		for _, alias := range page.Aliases {
			if alias.AliasName == nil || !strings.HasPrefix(*alias.AliasName, prefix) {
				continue
			}
			if alias.TargetKeyId == nil {
				return nil, errProvider
			}
			result = append(result, KMSAlias{Name: *alias.AliasName, KeyID: *alias.TargetKeyId})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (s *sdkKMS) Encrypt(ctx context.Context, request CryptRequest) (Ciphertext, error) {
	output, err := s.client.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(request.KeyID), Plaintext: request.Plaintext, EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault, EncryptionContext: cloneStringMap(request.Context)})
	if err != nil || output == nil || output.KeyId == nil {
		return Ciphertext{}, errProvider
	}
	return Ciphertext{Blob: append([]byte(nil), output.CiphertextBlob...), KeyID: *output.KeyId, Algorithm: string(output.EncryptionAlgorithm)}, nil
}

func (s *sdkKMS) Decrypt(ctx context.Context, request DecryptRequest) (Plaintext, error) {
	output, err := s.client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(request.KeyID), CiphertextBlob: request.Ciphertext, EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault, EncryptionContext: cloneStringMap(request.Context)})
	if err != nil || output == nil || output.KeyId == nil {
		return Plaintext{}, errProvider
	}
	return Plaintext{Value: append([]byte(nil), output.Plaintext...), KeyID: *output.KeyId, Algorithm: string(output.EncryptionAlgorithm)}, nil
}

func (s *sdkKMS) DeleteAlias(ctx context.Context, alias string) error {
	_, err := s.client.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String(alias)})
	if err != nil {
		return classifyMutationError(err)
	}
	return nil
}

func (s *sdkKMS) ScheduleKeyDeletion(ctx context.Context, keyID string, days int32) (KMSKey, error) {
	output, err := s.client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(keyID), PendingWindowInDays: aws.Int32(days)})
	if err != nil {
		return KMSKey{}, classifyMutationError(err)
	}
	if output == nil || output.KeyId == nil {
		return KMSKey{}, errMutationAmbiguous
	}
	key, err := s.DescribeKey(ctx, *output.KeyId)
	if err != nil {
		return KMSKey{}, errProvider
	}
	return key, nil
}

func fromKMSMetadata(value kmstypes.KeyMetadata) KMSKey {
	return KMSKey{ID: aws.ToString(value.KeyId), ARN: aws.ToString(value.Arn), Description: aws.ToString(value.Description), State: string(value.KeyState), Spec: string(value.KeySpec), Usage: string(value.KeyUsage), Origin: string(value.Origin), Manager: string(value.KeyManager), Enabled: value.Enabled}
}
func toKMSTags(values map[string]string) []kmstypes.Tag {
	result := make([]kmstypes.Tag, 0, len(values))
	for _, key := range sortedKeys(values) {
		result = append(result, kmstypes.Tag{TagKey: aws.String(key), TagValue: aws.String(values[key])})
	}
	return result
}

type sdkS3 struct{ client *s3.Client }

func (s *sdkS3) ListBuckets(ctx context.Context, prefix string) ([]string, error) {
	paginator := s3.NewListBucketsPaginator(s.client, &s3.ListBucketsInput{Prefix: aws.String(prefix)})
	var result []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil || page == nil {
			return nil, errProvider
		}
		for _, bucket := range page.Buckets {
			if bucket.Name == nil {
				return nil, errProvider
			}
			if strings.HasPrefix(*bucket.Name, prefix) {
				result = append(result, *bucket.Name)
			}
		}
	}
	sort.Strings(result)
	return result, nil
}

func (s *sdkS3) CreateBucket(ctx context.Context, name string) error {
	_, err := s.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(name)})
	if err != nil {
		return classifyMutationError(err)
	}
	return nil
}
func (s *sdkS3) PutBucketTags(ctx context.Context, name string, tags map[string]string) error {
	values := make([]s3types.Tag, 0, len(tags))
	for _, key := range sortedKeys(tags) {
		values = append(values, s3types.Tag{Key: aws.String(key), Value: aws.String(tags[key])})
	}
	_, err := s.client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(name), Tagging: &s3types.Tagging{TagSet: values}})
	if err != nil {
		return errProvider
	}
	return nil
}
func (s *sdkS3) PutBucketEncryption(ctx context.Context, name, keyID string) error {
	_, err := s.client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{Bucket: aws.String(name), ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String(keyID)}}}}})
	if err != nil {
		return errProvider
	}
	return nil
}
func (s *sdkS3) GetBucketState(ctx context.Context, name string) (BucketState, error) {
	state := BucketState{Name: name, Tags: map[string]string{}}
	tagOutput, err := s.client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(name)})
	if err != nil && !isAPIErrorCode(err, "NoSuchTagSet") {
		return BucketState{}, errProvider
	}
	if err == nil {
		if tagOutput == nil {
			return BucketState{}, errProvider
		}
		for _, tag := range tagOutput.TagSet {
			if tag.Key == nil || tag.Value == nil {
				return BucketState{}, errProvider
			}
			if _, exists := state.Tags[*tag.Key]; exists {
				return BucketState{}, errProvider
			}
			state.Tags[*tag.Key] = *tag.Value
		}
	}
	encryption, err := s.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(name)})
	if err != nil && !isAPIErrorCode(err, "ServerSideEncryptionConfigurationNotFoundError") {
		return BucketState{}, errProvider
	}
	if err == nil {
		if encryption == nil || encryption.ServerSideEncryptionConfiguration == nil || len(encryption.ServerSideEncryptionConfiguration.Rules) != 1 || encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault == nil {
			return BucketState{}, errProvider
		}
		defaults := encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
		state.Algorithm, state.KMSKeyID = string(defaults.SSEAlgorithm), aws.ToString(defaults.KMSMasterKeyID)
	}
	return state, nil
}

func (s *sdkS3) PutObject(ctx context.Context, request PutObjectRequest) (ObjectInfo, error) {
	encodedTags := url.Values{}
	for _, key := range sortedKeys(request.Tags) {
		encodedTags.Set(key, request.Tags[key])
	}
	output, err := s.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(request.Bucket), Key: aws.String(request.Key), Body: bytes.NewReader(request.Body), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(request.KMSKeyID), Metadata: cloneStringMap(request.Metadata), Tagging: aws.String(encodedTags.Encode()), ContentLength: aws.Int64(int64(len(request.Body)))})
	if err != nil {
		return ObjectInfo{}, classifyMutationError(err)
	}
	if output == nil {
		return ObjectInfo{}, errMutationAmbiguous
	}
	return ObjectInfo{Key: request.Key, ETag: aws.ToString(output.ETag), Algorithm: string(output.ServerSideEncryption), KMSKeyID: aws.ToString(output.SSEKMSKeyId), Size: int64(len(request.Body))}, nil
}

func (s *sdkS3) GetObject(ctx context.Context, bucket, key string) (ObjectValue, error) {
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), ChecksumMode: s3types.ChecksumModeEnabled})
	if err != nil || output == nil || output.Body == nil {
		return ObjectValue{}, errProvider
	}
	body, readErr := io.ReadAll(io.LimitReader(output.Body, maximumArtifactBytes+1))
	closeErr := output.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maximumArtifactBytes || output.ContentLength == nil || *output.ContentLength != int64(len(body)) {
		return ObjectValue{}, errProvider
	}
	return ObjectValue{ObjectInfo: ObjectInfo{Key: key, ETag: aws.ToString(output.ETag), Algorithm: string(output.ServerSideEncryption), KMSKeyID: aws.ToString(output.SSEKMSKeyId), Size: *output.ContentLength, Metadata: cloneStringMap(output.Metadata)}, Body: body}, nil
}

func (s *sdkS3) GetObjectTags(ctx context.Context, bucket, key string) (map[string]string, error) {
	output, err := s.client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil || output == nil {
		return nil, errProvider
	}
	result := map[string]string{}
	for _, tag := range output.TagSet {
		if tag.Key == nil || tag.Value == nil {
			return nil, errProvider
		}
		if _, exists := result[*tag.Key]; exists {
			return nil, errProvider
		}
		result[*tag.Key] = *tag.Value
	}
	return result, nil
}

func (s *sdkS3) ListObjects(ctx context.Context, bucket, prefix string) ([]ObjectInfo, error) {
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix)})
	var result []ObjectInfo
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil || page == nil {
			return nil, errProvider
		}
		for _, object := range page.Contents {
			if object.Key == nil || object.Size == nil {
				return nil, errProvider
			}
			result = append(result, ObjectInfo{Key: *object.Key, ETag: aws.ToString(object.ETag), Size: *object.Size})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}
func (s *sdkS3) DeleteObject(ctx context.Context, bucket, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return classifyMutationError(err)
	}
	return nil
}

func classifyMutationError(err error) error {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		return errMutationRejected
	}
	return errMutationAmbiguous
}
func (s *sdkS3) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := s.client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	if err != nil {
		return classifyMutationError(err)
	}
	return nil
}

type sdkSecrets struct{ client *secretsmanager.Client }

func (s *sdkSecrets) ListSecrets(ctx context.Context, prefix string, includeDeleted bool) ([]SecretInfo, error) {
	paginator := secretsmanager.NewListSecretsPaginator(s.client, &secretsmanager.ListSecretsInput{IncludePlannedDeletion: aws.Bool(includeDeleted), Filters: []secretstypes.Filter{{Key: secretstypes.FilterNameStringTypeName, Values: []string{prefix}}}})
	var result []SecretInfo
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil || page == nil {
			return nil, errProvider
		}
		for _, entry := range page.SecretList {
			if entry.Name == nil || !strings.HasPrefix(*entry.Name, prefix) {
				continue
			}
			converted, err := fromSecretListEntry(entry)
			if err != nil {
				return nil, errProvider
			}
			result = append(result, converted)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
func (s *sdkSecrets) CreateSecret(ctx context.Context, request CreateSecretRequest) (SecretInfo, error) {
	output, err := s.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(request.Name), KmsKeyId: aws.String(request.KMSKeyID), SecretBinary: append([]byte(nil), request.Value...), Tags: toSecretTags(request.Tags)})
	if err != nil || output == nil || output.ARN == nil || output.Name == nil || output.VersionId == nil {
		return SecretInfo{}, errProvider
	}
	return SecretInfo{Name: *output.Name, ARN: *output.ARN, KMSKeyID: request.KMSKeyID, VersionID: *output.VersionId, Tags: cloneStringMap(request.Tags), Stages: []string{"AWSCURRENT"}}, nil
}
func (s *sdkSecrets) DescribeSecret(ctx context.Context, id string) (SecretInfo, error) {
	output, err := s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(id)})
	if err != nil || output == nil || output.ARN == nil || output.Name == nil || output.KmsKeyId == nil {
		return SecretInfo{}, errProvider
	}
	versionID, stages, ok := exactCurrentVersion(output.VersionIdsToStages)
	if !ok {
		return SecretInfo{}, errProvider
	}
	tags, err := fromSecretTags(output.Tags)
	if err != nil {
		return SecretInfo{}, errProvider
	}
	return SecretInfo{Name: *output.Name, ARN: *output.ARN, KMSKeyID: *output.KmsKeyId, VersionID: versionID, Tags: tags, Stages: stages, Deleted: output.DeletedDate != nil}, nil
}
func (s *sdkSecrets) ListSecretVersions(ctx context.Context, id string) ([]SecretVersion, error) {
	paginator := secretsmanager.NewListSecretVersionIdsPaginator(s.client, &secretsmanager.ListSecretVersionIdsInput{SecretId: aws.String(id), IncludeDeprecated: aws.Bool(true)})
	var result []SecretVersion
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil || page == nil {
			return nil, errProvider
		}
		for _, version := range page.Versions {
			if version.VersionId == nil {
				return nil, errProvider
			}
			result = append(result, SecretVersion{ID: *version.VersionId, Stages: append([]string(nil), version.VersionStages...)})
		}
	}
	return result, nil
}
func (s *sdkSecrets) GetSecretValue(ctx context.Context, id, versionID, stage string) (SecretValue, error) {
	output, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id), VersionId: aws.String(versionID), VersionStage: aws.String(stage)})
	if err != nil || output == nil || output.ARN == nil || output.Name == nil || output.VersionId == nil || len(output.SecretBinary) == 0 || output.SecretString != nil {
		return SecretValue{}, errProvider
	}
	described, err := s.DescribeSecret(ctx, id)
	if err != nil {
		return SecretValue{}, errProvider
	}
	return SecretValue{Name: *output.Name, ARN: *output.ARN, KMSKeyID: described.KMSKeyID, VersionID: *output.VersionId, Stages: append([]string(nil), output.VersionStages...), Value: append([]byte(nil), output.SecretBinary...)}, nil
}
func (s *sdkSecrets) DeleteSecret(ctx context.Context, id string) error {
	_, err := s.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: aws.String(id), ForceDeleteWithoutRecovery: aws.Bool(true)})
	if err != nil {
		return errProvider
	}
	return nil
}

func fromSecretListEntry(entry secretstypes.SecretListEntry) (SecretInfo, error) {
	versionID, stages, _ := exactCurrentVersion(entry.SecretVersionsToStages)
	tags, err := fromSecretTags(entry.Tags)
	if err != nil {
		return SecretInfo{}, errProvider
	}
	return SecretInfo{Name: aws.ToString(entry.Name), ARN: aws.ToString(entry.ARN), KMSKeyID: aws.ToString(entry.KmsKeyId), VersionID: versionID, Tags: tags, Stages: stages, Deleted: entry.DeletedDate != nil}, nil
}
func toSecretTags(values map[string]string) []secretstypes.Tag {
	result := make([]secretstypes.Tag, 0, len(values))
	for _, key := range sortedKeys(values) {
		result = append(result, secretstypes.Tag{Key: aws.String(key), Value: aws.String(values[key])})
	}
	return result
}
func fromSecretTags(values []secretstypes.Tag) (map[string]string, error) {
	result := map[string]string{}
	for _, tag := range values {
		if tag.Key == nil || tag.Value == nil {
			return nil, errProvider
		}
		if _, exists := result[*tag.Key]; exists {
			return nil, errProvider
		}
		result[*tag.Key] = *tag.Value
	}
	return result, nil
}
func exactCurrentVersion(values map[string][]string) (string, []string, bool) {
	var id string
	var stages []string
	for candidate, labels := range values {
		if equalStringsAsSet(labels, []string{"AWSCURRENT"}) {
			if id != "" {
				return "", nil, false
			}
			id, stages = candidate, append([]string(nil), labels...)
		}
	}
	return id, stages, id != ""
}
func sortedKeys(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
func isAPIErrorCode(err error, code string) bool {
	var apiError interface {
		error
		ErrorCode() string
	}
	return errors.As(err, &apiError) && apiError.ErrorCode() == code
}
