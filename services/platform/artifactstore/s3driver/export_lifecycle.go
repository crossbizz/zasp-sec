package s3driver

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

// ExportReadAPI deliberately cannot write. Reconciliation is never a Put retry.
type ExportReadAPI interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}
type ExportCleanupAPI interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}
type exportReadAdapter struct{ ExportReadAPI }

func (exportReadAdapter) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, ErrImmutable
}

type ExportVerifier struct{ driver *Driver }

func NewExportVerifier(client ExportReadAPI, config Config) (*ExportVerifier, error) {
	if nilInterface(client) {
		return nil, ErrConfiguration
	}
	d, err := NewExport(exportReadAdapter{client}, config)
	if err != nil {
		return nil, err
	}
	return &ExportVerifier{d}, nil
}
func (v *ExportVerifier) Verify(ctx context.Context, intent artifactstore.DriverObject) (result artifactstore.DriverObject, resultErr error) {
	defer containPanic(&result, &resultErr, ErrGet)
	if v == nil || !v.driver.ready(ctx) || !v.driver.validObject(intent) || intent.VersionID != "" {
		return result, ErrArtifact
	}
	stored, err := v.driver.discover(ctx, intent.DriverLocator)
	if err != nil || !sameContent(stored, intent) {
		return result, ErrGet
	}
	return stored, nil
}

type ExportCleanup struct {
	client ExportCleanupAPI
	config Config
}

func NewExportCleanup(client ExportCleanupAPI, config Config) (*ExportCleanup, error) {
	if nilInterface(client) || !bucketPattern.MatchString(config.Bucket) || !ownerPattern.MatchString(config.ExpectedBucketOwner) || !kmsKeyPattern.MatchString(config.KMSKeyARN) || config.MaximumBytes <= 0 || config.MaximumBytes > maximumArtifactBytes {
		return nil, ErrConfiguration
	}
	return &ExportCleanup{client, config}, nil
}

// DeleteExact never deletes a current key or bypasses a retention/legal hold.
// Only an explicit missing-version response after this pinned request can free
// accounting. HTTP denial, generic 404, timeout and delete success alone cannot.
func (c *ExportCleanup) DeleteExact(ctx context.Context, locator artifactstore.DriverLocator) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrImmutable
		}
	}()
	if c == nil || nilInterface(c.client) || ctx == nil || ctx.Err() != nil || !validVersion(locator.VersionID) || !(&Driver{config: c.config, export: true}).validLocator(locator) {
		return ErrArtifact
	}
	_, _ = c.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.config.Bucket), Key: aws.String(locator.Key), VersionId: aws.String(locator.VersionID), ExpectedBucketOwner: aws.String(c.config.ExpectedBucketOwner)}, oneAttemptOption)
	if ctx.Err() != nil {
		return ErrImmutable
	}
	// HEAD cannot distinguish a missing version from generic HTTP404. GET has a
	// typed NoSuchVersion error, and also recovers a lost DELETE response or an
	// object already removed by lifecycle. The range bounds any successful body.
	out, err := c.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.config.Bucket), Key: aws.String(locator.Key), VersionId: aws.String(locator.VersionID), ExpectedBucketOwner: aws.String(c.config.ExpectedBucketOwner), Range: aws.String("bytes=0-0")}, oneAttemptOption)
	if out != nil && out.Body != nil {
		if out.Body.Close() != nil {
			return ErrImmutable
		}
	}
	var api smithy.APIError
	if ctx.Err() == nil && errors.As(err, &api) && api.ErrorCode() == "NoSuchVersion" {
		return nil
	}
	return ErrImmutable
}
