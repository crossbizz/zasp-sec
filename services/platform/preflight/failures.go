package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// These are SDK operation names. They are deliberately distinct from IAM action
// names: HeadBucket uses s3:ListBucket, and GetCallerIdentity needs no IAM allow.
var operationHints = map[string]string{
	"sts:GetCallerIdentity":         "verify selected credentials, expected role and network; GetCallerIdentity requires no identity-policy allow",
	"s3:HeadBucket":                 "verify bucket owner/region and inspect s3:ListBucket plus bucket or endpoint policy denies",
	"s3:GetBucketVersioning":        "verify versioning is enabled and inspect s3:GetBucketVersioning on the exact bucket",
	"s3:GetBucketEncryption":        "verify exact KMS encryption and Bucket Keys; inspect s3:GetEncryptionConfiguration on the exact bucket",
	"kms:DescribeKey":               "verify the exact enabled customer key and inspect kms:DescribeKey and key policy",
	"secretsmanager:GetSecretValue": "verify exact current secret version; inspect secretsmanager:GetSecretValue and relevant KMS decrypt grants",
	"sqs:GetQueueAttributes":        "verify exact queue/DLQ ARN, KMS and redrive configuration; inspect sqs:GetQueueAttributes on this queue",
}

var errMalformedProviderObservation = errors.New("provider observation malformed")

func failureOutcome(err error) string {
	if errors.Is(err, errMalformedProviderObservation) {
		return "malformed"
	}
	if err == nil {
		return "binding_mismatch"
	}
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) && (response.HTTPStatusCode() == 401 || response.HTTPStatusCode() == 403) {
		return "denied"
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedException", "InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "UnrecognizedClientException", "SignatureDoesNotMatch":
			return "denied"
		case "NoSuchBucket", "NoSuchKey", "NotFound", "NotFoundException", "ResourceNotFoundException", "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue":
			return "binding_mismatch"
		}
	}
	var malformed *smithy.DeserializationError
	if errors.As(err, &malformed) {
		return "malformed"
	}
	var netError net.Error
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netError) {
		return "unreachable"
	}
	return "unreachable"
}
func singleTargetDigest(target any) string {
	b, _ := json.Marshal(target)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (r *Runner) failure(report *Report, name, operation string, target any, err error, matched bool) {
	if matched {
		return
	}
	hint, ok := operationHints[operation]
	if !ok {
		return
	}
	for i := range report.Checks {
		for j := range report.Checks[i].Observations {
			o := &report.Checks[i].Observations[j]
			if o.Name == name && len(o.Failures) < 32 {
				o.Failures = append(o.Failures, Failure{Operation: operation, Hint: hint, TargetDigest: singleTargetDigest(target), Outcome: failureOutcome(err)})
				return
			}
		}
	}
}
func probeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
