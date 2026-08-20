package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue/sqsdriver"
)

var outboxWebTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

type outboxAssumeRoleAPI interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type outboxQueueReadinessAPI interface {
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

type outboxWebIdentityProvider struct {
	client    outboxAssumeRoleAPI
	roleARN   string
	tokenFile string
	timeout   time.Duration
	session   string
}

func (provider *outboxWebIdentityProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if provider == nil || provider.client == nil || ctx == nil || ctx.Err() != nil || !workerProjectionRolePattern.MatchString(provider.roleARN) || provider.tokenFile == "" || provider.timeout < time.Second || provider.timeout > 30*time.Second || !validOutboxSession(provider.session) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	file, err := os.Open(provider.tokenFile)
	if err != nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(token) < 64 || len(token) > 16384 || !outboxWebTokenPattern.Match(token) || strings.TrimSpace(string(token)) != string(token) {
		clear(token)
		return aws.Credentials{}, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	duration := int32(900)
	session := provider.session
	if session == "" {
		session = "zasp-outbox-worker"
	}
	result, assumeErr := provider.client.AssumeRoleWithWebIdentity(bounded, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn: aws.String(provider.roleARN), RoleSessionName: aws.String(session), WebIdentityToken: aws.String(string(token)), DurationSeconds: &duration,
	})
	clear(token)
	if assumeErr != nil || result == nil || result.Credentials == nil || result.Credentials.AccessKeyId == nil || result.Credentials.SecretAccessKey == nil || result.Credentials.SessionToken == nil || result.Credentials.Expiration == nil || !result.Credentials.Expiration.After(time.Now().Add(time.Minute)) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	return aws.Credentials{AccessKeyID: *result.Credentials.AccessKeyId, SecretAccessKey: *result.Credentials.SecretAccessKey, SessionToken: *result.Credentials.SessionToken, CanExpire: true, Expires: result.Credentials.Expiration.UTC(), Source: "zasp-outbox-web-identity"}, nil
}

func validOutboxSession(value string) bool {
	switch value {
	case "", "zasp-outbox-worker", "zasp-runtime-outbox-worker", "zasp-runtime-coordinator", "zasp-runtime-archive-worker", "zasp-runtime-index-worker", "zasp-runtime-correlation-worker", "zasp-runtime-projection-worker", "zasp-runtime-complete-worker":
		return true
	default:
		return false
	}
}

type productionOutboxPublisher struct {
	publisher outboxPublisher
	ready     func(context.Context) error
	close     func() error
}

type cachedOutboxReadiness struct {
	mu        sync.Mutex
	check     func(context.Context) error
	ttl       time.Duration
	checkedAt time.Time
	now       func() time.Time
}

func newCachedOutboxReadiness(check func(context.Context) error, ttl time.Duration) (*cachedOutboxReadiness, error) {
	if check == nil || ttl < time.Second || ttl > time.Minute {
		return nil, errRuntimeUnavailable
	}
	now := time.Now
	return &cachedOutboxReadiness{check: check, ttl: ttl, checkedAt: now(), now: now}, nil
}

func (readiness *cachedOutboxReadiness) Ready(ctx context.Context) error {
	if readiness == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	readiness.mu.Lock()
	defer readiness.mu.Unlock()
	now := readiness.now()
	elapsed := now.Sub(readiness.checkedAt)
	if elapsed >= 0 && elapsed < readiness.ttl {
		return nil
	}
	if err := readiness.check(ctx); err != nil {
		return errRuntimeUnavailable
	}
	readiness.checkedAt = now
	return nil
}

func newProductionOutboxPublisher(ctx context.Context, config workerRuntimeConfig) (productionOutboxPublisher, error) {
	if ctx == nil || ctx.Err() != nil || !validOutboxAWSAuthority(config) {
		return productionOutboxPublisher{}, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaxResponseHeaderBytes: 1 << 20}
	client := &http.Client{Transport: transport, Timeout: minDuration(config.LeaseDuration/3, 30*time.Second), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: client, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	session := "zasp-outbox-worker"
	if config.Mode == workerModeRuntimeOutbox {
		session = "zasp-runtime-outbox-worker"
	}
	provider := &outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.OutboxRoleARN, tokenFile: config.OutboxTokenFile, timeout: minDuration(config.LeaseDuration/3, 30*time.Second), session: session}
	credentials := aws.NewCredentialsCache(provider)
	if _, err := credentials.Retrieve(ctx); err != nil {
		transport.CloseIdleConnections()
		return productionOutboxPublisher{}, errRuntimeUnavailable
	}
	base.Credentials = credentials
	sqsClient := sqs.NewFromConfig(base)
	liveCheck := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		if _, err := credentials.Retrieve(readyCtx); err != nil || outboxQueueReady(readyCtx, sqsClient, config) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := liveCheck(ctx); err != nil {
		transport.CloseIdleConnections()
		return productionOutboxPublisher{}, errRuntimeUnavailable
	}
	readiness, err := newCachedOutboxReadiness(liveCheck, 30*time.Second)
	if err != nil {
		transport.CloseIdleConnections()
		return productionOutboxPublisher{}, errRuntimeUnavailable
	}
	queueURL, _, ok := outboxQueueAuthority(config)
	if !ok {
		transport.CloseIdleConnections()
		return productionOutboxPublisher{}, errRuntimeUnavailable
	}
	driver, err := sqsdriver.New(sqsClient, sqsdriver.Config{QueueURL: queueURL, ReceiveWaitSeconds: 0, VisibilityTimeoutSeconds: int32(config.LeaseDuration / time.Second), MaximumReceiveCount: 5})
	if err != nil {
		transport.CloseIdleConnections()
		return productionOutboxPublisher{}, errRuntimeUnavailable
	}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		transport.CloseIdleConnections()
		return productionOutboxPublisher{}, errRuntimeUnavailable
	}
	closePublisher := func() error {
		drainCtx, cancel := context.WithTimeout(context.Background(), minDuration(config.ShutdownTimeout, config.LeaseDuration/2))
		defer cancel()
		err := driver.Drain(drainCtx)
		transport.CloseIdleConnections()
		return err
	}
	return productionOutboxPublisher{publisher: queue, ready: readiness.Ready, close: closePublisher}, nil
}

func outboxQueueReady(ctx context.Context, api outboxQueueReadinessAPI, config workerRuntimeConfig) error {
	if ctx == nil || ctx.Err() != nil || api == nil || !validOutboxAWSAuthority(config) {
		return errRuntimeUnavailable
	}
	queueURL, queueName, ok := outboxQueueAuthority(config)
	if !ok {
		return errRuntimeUnavailable
	}
	output, err := api.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(queueURL), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn, sqstypes.QueueAttributeNameRedrivePolicy}})
	if err != nil || output == nil || len(output.Attributes) != 2 {
		return errRuntimeUnavailable
	}
	parsed, parseErr := url.Parse(queueURL)
	if parseErr != nil || parsed == nil {
		return errRuntimeUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 2 {
		return errRuntimeUnavailable
	}
	queueARN := "arn:aws:sqs:" + config.AWSRegion + ":" + parts[0] + ":" + queueName
	if output.Attributes[string(sqstypes.QueueAttributeNameQueueArn)] != queueARN {
		return errRuntimeUnavailable
	}
	var redrive struct {
		DeadLetterTargetARN string `json:"deadLetterTargetArn"`
		MaximumReceiveCount string `json:"maxReceiveCount"`
	}
	raw := []byte(output.Attributes[string(sqstypes.QueueAttributeNameRedrivePolicy)])
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&redrive) != nil || decoder.Decode(&struct{}{}) != io.EOF || redrive.DeadLetterTargetARN != queueARN+"-dlq" || redrive.MaximumReceiveCount != "5" {
		return errRuntimeUnavailable
	}
	return nil
}

var _ aws.CredentialsProvider = (*outboxWebIdentityProvider)(nil)
