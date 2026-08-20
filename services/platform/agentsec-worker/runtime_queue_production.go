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

type runtimeQueueAPI interface {
	sqsdriver.Client
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

type runtimeIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type productionRuntimeQueueDependencies struct {
	Queue     runtimeDeliveryQueue
	ready     func(context.Context) error
	close     func() error
	closeOnce sync.Once
	closeErr  error
}

func newProductionRuntimeQueue(ctx context.Context, config workerRuntimeConfig) (*productionRuntimeQueueDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validRuntimeCoordinatorAWSAuthority(config) {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: minDuration(config.LeaseDuration/3, 30*time.Second), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RuntimeRoleARN, tokenFile: config.RuntimeTokenFile, timeout: minDuration(config.LeaseDuration/3, 30*time.Second), session: "zasp-runtime-coordinator"}
	credentials := aws.NewCredentialsCache(provider)
	if _, err := credentials.Retrieve(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	base.Credentials = credentials
	queueAPI := sqs.NewFromConfig(base)
	identityAPI := sts.NewFromConfig(base)
	liveCheck := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		if _, err := credentials.Retrieve(readyCtx); err != nil || readyProductionRuntimeQueue(readyCtx, queueAPI, identityAPI, config) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := liveCheck(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	driver, err := sqsdriver.New(queueAPI, sqsdriver.Config{QueueURL: config.RuntimeQueueURL, ReceiveWaitSeconds: min(int32(config.PollInterval/time.Second), 20), VisibilityTimeoutSeconds: int32(config.LeaseDuration / time.Second), MaximumReceiveCount: 5})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	dependencies := &productionRuntimeQueueDependencies{Queue: queue, ready: liveCheck}
	dependencies.close = func() error {
		drainCtx, cancel := context.WithTimeout(context.Background(), minDuration(config.ShutdownTimeout, config.LeaseDuration/2))
		defer cancel()
		err := driver.Drain(drainCtx)
		transport.CloseIdleConnections()
		if err != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	return dependencies, nil
}

func (dependencies *productionRuntimeQueueDependencies) Ready(ctx context.Context) error {
	if dependencies == nil || dependencies.ready == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return dependencies.ready(ctx)
}

func (dependencies *productionRuntimeQueueDependencies) Close() error {
	if dependencies == nil {
		return nil
	}
	dependencies.closeOnce.Do(func() {
		if dependencies.close != nil {
			dependencies.closeErr = dependencies.close()
		}
	})
	return dependencies.closeErr
}

func readyProductionRuntimeQueue(ctx context.Context, queue runtimeQueueAPI, identity runtimeIdentityAPI, config workerRuntimeConfig) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(queue) || nilWorkerDependency(identity) || !validRuntimeCoordinatorAWSAuthority(config) {
		return errRuntimeUnavailable
	}
	output, err := queue.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(config.RuntimeQueueURL), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn, sqstypes.QueueAttributeNameRedrivePolicy}}, func(options *sqs.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || output == nil || len(output.Attributes) != 2 || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	parsed, parseErr := url.Parse(config.RuntimeQueueURL)
	parts := []string(nil)
	if parseErr == nil && parsed != nil {
		parts = strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	}
	if len(parts) != 2 {
		return errRuntimeUnavailable
	}
	queueARN := "arn:aws:sqs:" + config.AWSRegion + ":" + parts[0] + ":agentsec-runtime-events"
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
	caller, err := identity.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	roleName := config.RuntimeRoleARN[strings.LastIndex(config.RuntimeRoleARN, "/")+1:]
	if err != nil || caller == nil || aws.ToString(caller.Account) != parts[0] || !strings.HasPrefix(aws.ToString(caller.Arn), "arn:aws:sts::"+parts[0]+":assumed-role/"+roleName+"/") || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}
