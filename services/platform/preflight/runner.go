package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/cloudreadiness"
)

func (r *Runner) Run(ctx context.Context, mode string) (report Report, resultErr error) {
	if r == nil || r.http == nil || ctx == nil || !validConfig(r.config) || (mode != "before-install" && mode != "installed") {
		return Report{}, ErrRejected
	}
	report = initialReport(r.config, mode)
	defer func() {
		if recover() != nil {
			resultErr = ErrRejected
		}
		finishReport(&report)
	}()
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	credentials, e := r.credentials(bounded)
	if e != nil {
		r.record(&report, "iam_role", false, "credentials_unavailable", "none", r.config.Credentials.ExpectedRoleARN, false)
		return report, ErrRejected
	}
	defer func() { credentials = aws.Credentials{} }()
	identity := "operator"
	if r.config.Credentials.Kind == "workload_web_identity" {
		identity = "workload"
	}
	sdk := aws.Config{Region: r.config.Deployment.Region, HTTPClient: r.http, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		if credentials.CanExpire && !credentials.Expires.After(time.Now().Add(time.Minute)) {
			return aws.Credentials{}, ErrRejected
		}
		return credentials, nil
	}), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	roleCtx, roleCancel := context.WithTimeout(bounded, 10*time.Second)
	output, roleErr := sts.NewFromConfig(sdk).GetCallerIdentity(roleCtx, &sts.GetCallerIdentityInput{})
	// Query protocol decoders may accept character-only XML as an empty output.
	// Missing identity fields are malformed observations, not a different role.
	if roleErr == nil && (output == nil || aws.ToString(output.Account) == "" || aws.ToString(output.Arn) == "") {
		roleErr = errMalformedProviderObservation
	}
	roleReady := roleErr == nil && roleCtx.Err() == nil && cloudreadiness.Role(output, r.config.Deployment.Partition, r.config.Deployment.AccountID, r.config.Credentials.ExpectedRoleARN)
	r.failure(&report, "iam_role", "sts:GetCallerIdentity", r.config.Credentials.ExpectedRoleARN, probeError(roleCtx, roleErr), roleReady)
	roleCancel()
	r.record(&report, "iam_role", roleReady, "identity_mismatch_or_unavailable", identity, r.config.Credentials.ExpectedRoleARN, true)
	if !roleReady {
		return report, ErrRejected
	}
	r.buckets(bounded, &report, sdk, identity)
	r.secrets(bounded, &report, sdk, identity)
	r.queues(bounded, &report, sdk, identity)
	// Remaining original requirements have no connected probe in this batch.
	// They remain unobserved and prevent readiness; successful metadata is not
	// deployed end-to-end verification or exercised write/consume authority.
	return report, ErrRejected
}
func (r *Runner) record(report *Report, name string, passed bool, code, identity string, target any, attempted bool) {
	digestBytes, _ := json.Marshal(target)
	digest := sha256.Sum256(digestBytes)
	for i := range report.Checks {
		for j := range report.Checks[i].Observations {
			o := &report.Checks[i].Observations[j]
			if o.Name != name {
				continue
			}
			o.Status = "fail"
			o.Kind = "provider-read"
			o.Code = code
			o.IdentityKind = identity
			o.TargetDigest = hex.EncodeToString(digest[:])
			if attempted {
				now := time.Now().UTC()
				o.ObservedAt = &now
			} else {
				o.Kind = "unobserved"
			}
			if passed {
				o.Status = "pass"
				o.Code = "observed_exact_target"
			}
			return
		}
	}
}
func (r *Runner) buckets(ctx context.Context, report *Report, sdk aws.Config, identity string) {
	if len(r.config.AWS.Buckets) == 0 {
		return
	}
	s3api := s3.NewFromConfig(sdk)
	kmsapi := kms.NewFromConfig(sdk)
	bucketsReady, keysReady, hasEvidence := true, true, false
	for _, b := range r.config.AWS.Buckets {
		hasEvidence = hasEvidence || b.Class == "evidence"
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, e := s3api.HeadBucket(c, &s3.HeadBucketInput{Bucket: aws.String(b.Name), ExpectedBucketOwner: aws.String(b.Owner)})
		ok := e == nil && c.Err() == nil && cloudreadiness.BucketHead(out, b.Region)
		r.failure(report, "s3_evidence", "s3:HeadBucket", b, probeError(c, e), ok)
		cancel()
		if ok {
			c, cancel = context.WithTimeout(ctx, 10*time.Second)
			v, e := s3api.GetBucketVersioning(c, &s3.GetBucketVersioningInput{Bucket: aws.String(b.Name), ExpectedBucketOwner: aws.String(b.Owner)})
			ok = e == nil && c.Err() == nil && cloudreadiness.BucketVersioning(v)
			r.failure(report, "s3_evidence", "s3:GetBucketVersioning", b, probeError(c, e), ok)
			cancel()
		}
		if ok {
			c, cancel = context.WithTimeout(ctx, 10*time.Second)
			enc, e := s3api.GetBucketEncryption(c, &s3.GetBucketEncryptionInput{Bucket: aws.String(b.Name), ExpectedBucketOwner: aws.String(b.Owner)})
			ok = e == nil && c.Err() == nil && cloudreadiness.BucketEncryption(enc, b.KMSKeyARN)
			r.failure(report, "s3_evidence", "s3:GetBucketEncryption", b, probeError(c, e), ok)
			cancel()
		}
		bucketsReady = bucketsReady && ok
		c, cancel = context.WithTimeout(ctx, 10*time.Second)
		key, e := kmsapi.DescribeKey(c, &kms.DescribeKeyInput{KeyId: aws.String(b.KMSKeyARN)})
		keyReady := e == nil && c.Err() == nil && cloudreadiness.Key(key, b.KMSKeyARN, b.Owner)
		r.failure(report, "kms", "kms:DescribeKey", b.KMSKeyARN, probeError(c, e), keyReady)
		cancel()
		keysReady = keysReady && keyReady
	}
	if hasEvidence {
		r.record(report, "s3_evidence", bucketsReady, "bucket_binding_or_configuration_unavailable", identity, r.config.AWS.Buckets, true)
	} else {
		// Raw receipts must still be inspected, but cannot stand in for the original
		// required evidence bucket. Keep it explicitly unobserved, with any actual
		// raw-bucket operation failures preserved separately.
		for i := range report.Checks {
			for j := range report.Checks[i].Observations {
				o := &report.Checks[i].Observations[j]
				if o.Name == "s3_evidence" {
					o.Code = "evidence_bucket_unconfigured"
				}
			}
		}
	}
	r.record(report, "kms", keysReady, "key_binding_or_configuration_unavailable", identity, r.config.AWS.Buckets, true)
}
func (r *Runner) secrets(ctx context.Context, report *Report, sdk aws.Config, identity string) {
	if len(r.config.AWS.Secrets) == 0 {
		return
	}
	api := secretsmanager.NewFromConfig(sdk)
	ready := true
	for _, s := range r.config.AWS.Secrets {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, e := api.GetSecretValue(c, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.ARN), VersionStage: aws.String("AWSCURRENT")})
		ok := e == nil && c.Err() == nil && out != nil
		if ok {
			current := false
			for _, stage := range out.VersionStages {
				current = current || stage == "AWSCURRENT"
			}
			text := out.SecretString != nil && len(aws.ToString(out.SecretString)) > 0 && len(aws.ToString(out.SecretString)) <= 32768 && len(out.SecretBinary) == 0
			binary := out.SecretString == nil && len(out.SecretBinary) > 0 && len(out.SecretBinary) <= 32768
			ok = aws.ToString(out.ARN) == s.ARN && current && aws.ToString(out.VersionId) != "" && (text || binary)
		}
		r.failure(report, "secrets", "secretsmanager:GetSecretValue", s.ARN, probeError(c, e), ok)
		// Provider strings are transient immutable SDK values; they are never placed
		// in results, errors, logging or evidence. Clear mutable binary buffers.
		if out != nil {
			clear(out.SecretBinary)
			out.SecretBinary = nil
			out.SecretString = nil
		}
		cancel()
		ready = ready && ok
	}
	r.record(report, "secrets", ready, "secret_binding_or_current_version_unavailable", identity, r.config.AWS.Secrets, true)
}
func (r *Runner) queues(ctx context.Context, report *Report, sdk aws.Config, identity string) {
	if len(r.config.AWS.Queues) == 0 {
		return
	}
	api := sqs.NewFromConfig(sdk)
	ready, dlqReady := true, true
	for _, q := range r.config.AWS.Queues {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, e := api.GetQueueAttributes(c, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(q.URL), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn, sqstypes.QueueAttributeNameRedrivePolicy, sqstypes.QueueAttributeNameKmsMasterKeyId}})
		ok := e == nil && c.Err() == nil && out != nil && out.Attributes[string(sqstypes.QueueAttributeNameQueueArn)] == q.ARN && out.Attributes[string(sqstypes.QueueAttributeNameKmsMasterKeyId)] == q.KMSKeyARN
		if ok {
			ok = redriveMatches(out.Attributes[string(sqstypes.QueueAttributeNameRedrivePolicy)], q)
		}
		r.failure(report, "queues", "sqs:GetQueueAttributes", queueTarget(q.URL, q.ARN, q.KMSKeyARN), probeError(c, e), ok)
		cancel()
		ready = ready && ok
		c, cancel = context.WithTimeout(ctx, 10*time.Second)
		dlq, e := api.GetQueueAttributes(c, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(q.DeadLetterURL), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn, sqstypes.QueueAttributeNameKmsMasterKeyId}})
		dlqOK := e == nil && c.Err() == nil && dlq != nil && dlq.Attributes[string(sqstypes.QueueAttributeNameQueueArn)] == q.DeadLetterARN && dlq.Attributes[string(sqstypes.QueueAttributeNameKmsMasterKeyId)] == q.KMSKeyARN
		r.failure(report, "dead_letter_queue", "sqs:GetQueueAttributes", queueTarget(q.DeadLetterURL, q.DeadLetterARN, q.KMSKeyARN), probeError(c, e), dlqOK)
		dlqReady = dlqReady && dlqOK
		cancel()
	}
	r.record(report, "queues", ready, "queue_binding_or_redrive_unavailable", identity, r.config.AWS.Queues, true)
	r.record(report, "dead_letter_queue", dlqReady, "dead_letter_binding_unavailable", identity, r.config.AWS.Queues, true)
}
func redriveMatches(raw string, q Queue) bool {
	if len(raw) == 0 || len(raw) > 4096 || !uniqueJSON([]byte(raw)) {
		return false
	}
	var value struct {
		DeadLetterTargetARN string          `json:"deadLetterTargetArn"`
		MaximumReceiveCount json.RawMessage `json:"maxReceiveCount"`
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil || value.DeadLetterTargetARN != q.DeadLetterARN {
		return false
	}
	var n int
	if json.Unmarshal(value.MaximumReceiveCount, &n) != nil {
		var s string
		if json.Unmarshal(value.MaximumReceiveCount, &s) != nil {
			return false
		}
		var parsed json.Number = json.Number(s)
		number, e := parsed.Int64()
		if e != nil || number < 1 || number > 1000 {
			return false
		}
		n = int(number)
	}
	return n == q.MaximumReceiveCount
}

func queueTarget(url, arn, key string) any {
	return struct {
		URL       string `json:"url"`
		ARN       string `json:"arn"`
		KMSKeyARN string `json:"kms_key_arn"`
	}{url, arn, key}
}
