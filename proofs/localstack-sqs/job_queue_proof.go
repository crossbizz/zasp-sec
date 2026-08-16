package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const (
	jobQueuePrefix = "zasp-m1-13-"
)

type jobQueueProofClient interface {
	queueAPI
	jobBatchAPI
}

type JobQueueProofOptions struct {
	Endpoint       string
	Marker         string
	Client         jobQueueProofClient
	CleanupTimeout time.Duration
	PollInterval   time.Duration
}

type JobQueueProofResult struct {
	Publish     int
	Consume     int
	Acknowledge int
	Scoped      bool
	Redrive     bool
	Empty       bool
	Cleanup     bool
	Audit       bool
}

type jobQueueTarget struct {
	name       string
	role       string
	marker     string
	attributes map[string]string
	attempted  bool
	uncertain  bool
	owned      *ownedQueue
}

type queueMutationError struct {
	definitive bool
}

func (err queueMutationError) Error() string {
	return errProvider.Error()
}

func (err queueMutationError) Unwrap() error {
	return errProvider
}

func definitiveMutationError() error {
	return queueMutationError{definitive: true}
}

func ambiguousMutationError() error {
	return queueMutationError{}
}

func mutationIsDefinitive(err error) bool {
	var classified queueMutationError
	return errors.As(err, &classified) && classified.definitive
}

func classifyQueueMutationError(err error) error {
	if err == nil {
		return nil
	}
	var status interface{ HTTPStatusCode() int }
	if errors.As(err, &status) {
		code := status.HTTPStatusCode()
		if code >= 300 && code <= 599 {
			return definitiveMutationError()
		}
	}
	return ambiguousMutationError()
}

func RunJobQueueProof(ctx context.Context, options JobQueueProofOptions) (result JobQueueProofResult, resultErr error) {
	if ctx == nil || jobNilInterface(options.Client) || !markerPattern.MatchString(options.Marker) {
		return JobQueueProofResult{}, errConfiguration
	}
	if _, err := validateDisposableJobEndpoint(ctx, options.Endpoint); err != nil {
		return JobQueueProofResult{}, errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 15 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 100 * time.Millisecond
	}

	prefix := jobQueuePrefix + options.Marker
	dlq := &jobQueueTarget{name: prefix + "-dlq", role: "dlq", marker: options.Marker}
	source := &jobQueueTarget{name: prefix + "-source", role: "source", marker: options.Marker}
	targets := []*jobQueueTarget{source, dlq}
	defer func() {
		panicked := recover() != nil
		attempted := source.attempted || dlq.attempted
		if attempted {
			cleanup, audit := safeJobQueueCleanup(options, prefix, targets)
			result.Cleanup = cleanup
			result.Audit = audit
			if !cleanup || !audit {
				resultErr = errCleanup
				return
			}
		}
		if panicked {
			resultErr = errProvider
		}
	}()

	if err := requireJobQueuePrefixAbsent(ctx, options.Client, prefix); err != nil {
		return JobQueueProofResult{}, err
	}
	if err := createJobQueue(ctx, options, dlq); err != nil {
		return JobQueueProofResult{}, err
	}

	sourcePolicy, err := encodeExactJSON(redrivePolicy{
		DeadLetterTargetARN: dlq.owned.arn,
		MaxReceiveCount:     maxReceiveCount,
	})
	if err != nil {
		return JobQueueProofResult{}, errPolicy
	}
	source.attributes = map[string]string{redrivePolicyAttribute: sourcePolicy}
	if err := createJobQueue(ctx, options, source); err != nil {
		return JobQueueProofResult{}, err
	}
	if source.owned.account != dlq.owned.account {
		return JobQueueProofResult{}, errOwnership
	}

	allowPolicy, err := encodeExactJSON(redriveAllowPolicy{
		RedrivePermission: "byQueue",
		SourceQueueARNs:   []string{source.owned.arn},
	})
	if err != nil {
		return JobQueueProofResult{}, errPolicy
	}
	if err := options.Client.SetQueueAttributes(ctx, dlq.owned.url, map[string]string{
		redriveAllowPolicyAttribute: allowPolicy,
	}); err != nil {
		attributes, readErr := options.Client.GetQueueAttributes(ctx, dlq.owned.url)
		if readErr != nil || attributes[redriveAllowPolicyAttribute] != allowPolicy {
			return JobQueueProofResult{}, errProvider
		}
	}
	if err := assertRedrivePolicies(ctx, options.Client, source.owned, dlq.owned); err != nil {
		return JobQueueProofResult{}, err
	}
	result.Redrive = true

	driver, err := newSQSJobDriver(options.Client, source.owned.url)
	if err != nil {
		return JobQueueProofResult{}, errConfiguration
	}
	queue, err := jobqueue.New(driver, jobqueue.Config{
		OperationTimeout:     10 * time.Second,
		MaximumBatchMessages: 10,
		MaximumMessageBytes:  64 * 1024,
		MaximumBatchBytes:    128 * 1024,
	})
	if err != nil {
		return JobQueueProofResult{}, errConfiguration
	}
	jobs, err := proofJobs()
	if err != nil {
		return JobQueueProofResult{}, errMessage
	}
	published, err := queue.PublishBatch(ctx, jobs)
	if err != nil || len(published.JobIDs) != len(jobs) {
		return JobQueueProofResult{}, errMessage
	}
	for index, jobID := range published.JobIDs {
		if jobID != jobs[index].JobID {
			return JobQueueProofResult{}, errMessage
		}
	}
	result.Publish = len(published.JobIDs)

	deliveries, err := receiveJobBatch(ctx, queue, jobs, options.PollInterval)
	if err != nil {
		return JobQueueProofResult{}, err
	}
	for index, delivery := range deliveries {
		if delivery.Job.Scope != jobs[index].Scope || delivery.Job.JobID != jobs[index].JobID ||
			delivery.Job.Kind != jobs[index].Kind || string(delivery.Job.Payload) != string(jobs[index].Payload) {
			return JobQueueProofResult{}, errMessage
		}
	}
	result.Consume = len(deliveries)
	result.Scoped = true

	receipts := make([]jobqueue.Receipt, len(deliveries))
	for index, delivery := range deliveries {
		receipts[index] = delivery.Receipt
	}
	if err := queue.AcknowledgeBatch(ctx, receipts); err != nil {
		return JobQueueProofResult{}, errMessage
	}
	result.Acknowledge = len(receipts)
	for range 2 {
		empty, err := queue.ConsumeBatch(ctx, len(jobs))
		if err != nil || len(empty) != 0 {
			return JobQueueProofResult{}, errMessage
		}
	}
	result.Empty = true
	return result, nil
}

func createJobQueue(ctx context.Context, options JobQueueProofOptions, target *jobQueueTarget) error {
	target.attempted = true
	target.uncertain = true
	returnedURL, createErr := options.Client.CreateQueue(
		ctx,
		target.name,
		cloneStringMap(target.attributes),
		jobProofTags(target.marker, target.role),
	)
	if createErr != nil && mutationIsDefinitive(createErr) {
		target.attempted = false
		target.uncertain = false
		return errProvider
	}

	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), options.CleanupTimeout)
	defer cancel()
	if createErr == nil && returnedURL != "" {
		owned, err := proveOwnedJobQueue(
			reconcileCtx, options.Client, options.Endpoint, returnedURL,
			target.name, target.role, target.marker, target.attributes,
		)
		if err == nil {
			target.owned = owned
			target.uncertain = false
			return nil
		}
	}
	for {
		owned, _, err := reconcileJobQueue(reconcileCtx, options, target)
		if err == nil && owned != nil {
			target.owned = owned
			target.uncertain = false
			return nil
		}
		if err != nil {
			return err
		}
		if waitErr := waitFor(reconcileCtx, options.PollInterval); waitErr != nil {
			return errProvider
		}
	}
}

func reconcileJobQueue(ctx context.Context, options JobQueueProofOptions, target *jobQueueTarget) (*ownedQueue, bool, error) {
	urls, err := options.Client.ListQueues(ctx, target.name)
	if err != nil {
		return nil, false, nil
	}
	exact := exactQueueURLs(urls, target.name)
	if len(exact) == 0 {
		return nil, true, nil
	}
	if len(exact) != 1 {
		return nil, false, errOwnership
	}
	owned, err := proveOwnedJobQueue(
		ctx, options.Client, options.Endpoint, exact[0],
		target.name, target.role, target.marker, target.attributes,
	)
	if err != nil {
		if errors.Is(err, errOwnership) {
			return nil, false, errOwnership
		}
		return nil, false, nil
	}
	return owned, false, nil
}

func proveOwnedJobQueue(
	ctx context.Context,
	client queueAPI,
	endpoint string,
	queueURL string,
	name string,
	role string,
	marker string,
	expectedAttributes map[string]string,
) (*ownedQueue, error) {
	account, err := validateDisposableJobQueueURL(ctx, endpoint, queueURL, name, nil)
	if err != nil {
		return nil, errOwnership
	}
	attributes, err := client.GetQueueAttributes(ctx, queueURL)
	if err != nil {
		return nil, errProvider
	}
	arn := attributes[queueARNAttribute]
	if err := validateQueueARN(arn, account, name); err != nil {
		return nil, errOwnership
	}
	if fifo := attributes[fifoQueueAttribute]; fifo != "" && fifo != "false" {
		return nil, errOwnership
	}
	for key, expected := range expectedAttributes {
		if attributes[key] != expected {
			return nil, errOwnership
		}
	}
	tags, err := client.ListQueueTags(ctx, queueURL)
	if err != nil {
		return nil, errProvider
	}
	if !equalStringMaps(tags, jobProofTags(marker, role)) {
		return nil, errOwnership
	}
	return &ownedQueue{name: name, role: role, url: queueURL, arn: arn, account: account, marker: marker}, nil
}

func safeJobQueueCleanup(options JobQueueProofOptions, prefix string, targets []*jobQueueTarget) (cleanup bool, audit bool) {
	defer func() {
		if recover() != nil {
			cleanup = false
			audit = false
		}
	}()
	cleanup = true
	rearmCtx, cancelRearm := context.WithTimeout(context.WithoutCancel(context.Background()), options.CleanupTimeout)
	for _, target := range targets {
		if target.attempted && target.uncertain && !rearmUncertainJobQueueTarget(rearmCtx, options, target) {
			cleanup = false
		}
	}
	cancelRearm()

	ctx, cancelCleanup := context.WithTimeout(context.WithoutCancel(context.Background()), options.CleanupTimeout)
	defer cancelCleanup()
	for _, target := range targets {
		if !target.attempted {
			continue
		}
		if !cleanupJobQueueTarget(ctx, options, target) {
			cleanup = false
		}
	}
	if !cleanup {
		return false, false
	}
	if err := auditJobQueuePrefix(ctx, options.Client, prefix); err != nil {
		return true, false
	}
	return true, true
}

func rearmUncertainJobQueueTarget(ctx context.Context, options JobQueueProofOptions, target *jobQueueTarget) (success bool) {
	defer func() {
		if recover() != nil {
			success = false
		}
	}()
	sawAbsent := false
	sawUnresolved := false
	for {
		owned, absent, err := reconcileJobQueue(ctx, options, target)
		if err != nil {
			return false
		}
		if owned != nil {
			target.owned = owned
			target.uncertain = false
			return true
		}
		sawAbsent = sawAbsent || absent
		sawUnresolved = sawUnresolved || !absent
		if waitErr := waitFor(ctx, options.PollInterval); waitErr != nil {
			if sawAbsent && !sawUnresolved {
				target.uncertain = false
				return true
			}
			return false
		}
	}
}

func cleanupJobQueueTarget(ctx context.Context, options JobQueueProofOptions, target *jobQueueTarget) (success bool) {
	defer func() {
		if recover() != nil {
			success = false
		}
	}()
	owned, absent, err := reconcileJobQueue(ctx, options, target)
	if target.owned != nil {
		fresh, freshErr := proveOwnedJobQueue(
			ctx, options.Client, options.Endpoint, target.owned.url,
			target.name, target.role, target.marker, target.attributes,
		)
		if freshErr == nil && fresh.url == target.owned.url && fresh.arn == target.owned.arn &&
			fresh.account == target.owned.account {
			owned, absent, err = fresh, false, nil
		} else if absent {
			owned, err = nil, nil
		} else {
			err = errOwnership
		}
	}
	if err != nil {
		return false
	}
	if absent {
		return true
	}
	if owned == nil {
		return false
	}
	_ = options.Client.DeleteQueue(ctx, owned.url)
	return waitQueueAbsent(ctx, options.Client, owned, options.PollInterval) == nil
}

func requireJobQueuePrefixAbsent(ctx context.Context, client queueAPI, prefix string) error {
	urls, err := client.ListQueues(ctx, prefix)
	if err != nil {
		return errProvider
	}
	if len(urls) != 0 {
		return errOwnership
	}
	return nil
}

func auditJobQueuePrefix(ctx context.Context, client queueAPI, prefix string) error {
	urls, err := client.ListQueues(ctx, prefix)
	if err != nil || len(urls) != 0 {
		return errCleanup
	}
	return nil
}

func jobProofTags(marker, role string) map[string]string {
	return map[string]string{
		"zasp-proof":        "m1-13",
		"zasp-proof-marker": marker,
		"zasp-proof-role":   role,
	}
}

func validateDisposableJobEndpoint(_ context.Context, raw string) (validatedEndpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.Opaque != "" {
		return validatedEndpoint{}, errConfiguration
	}
	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(parsed.Port())
	if ip == nil || !ip.IsLoopback() || portErr != nil || port < 1024 || port > 65535 || port == 4566 {
		return validatedEndpoint{}, errConfiguration
	}
	parsed.Path = ""
	return validatedEndpoint{baseURL: parsed.String(), hostname: host, port: parsed.Port()}, nil
}

func validateDisposableJobQueueURL(
	ctx context.Context,
	endpoint string,
	rawQueueURL string,
	expectedName string,
	resolver hostResolver,
) (string, error) {
	base, err := validateDisposableJobEndpoint(ctx, endpoint)
	if err != nil {
		return "", errOwnership
	}
	parsed, err := url.Parse(rawQueueURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Port() != base.port {
		return "", errOwnership
	}
	host := strings.ToLower(parsed.Hostname())
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return "", errOwnership
		}
	} else {
		addresses, lookupErr := resolver.LookupHost(ctx, host)
		if lookupErr != nil || len(addresses) == 0 {
			return "", errOwnership
		}
		for _, address := range addresses {
			ip := net.ParseIP(address)
			if ip == nil || !ip.IsLoopback() {
				return "", errOwnership
			}
		}
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	account, pathName := "", ""
	switch {
	case len(parts) == 2:
		account, pathName = parts[0], parts[1]
	case len(parts) == 4 && parts[0] == "queue" && parts[1] == fixedRegion:
		account, pathName = parts[2], parts[3]
	default:
		return "", errOwnership
	}
	decodedName, decodeErr := url.PathUnescape(pathName)
	if decodeErr != nil || pathName != decodedName || decodedName != expectedName || !accountPattern.MatchString(account) {
		return "", errOwnership
	}
	return account, nil
}

func newDisposableJobSDKQueueClient(ctx context.Context, rawEndpoint string) (*sdkQueueClient, error) {
	endpoint, err := validateDisposableJobEndpoint(ctx, rawEndpoint)
	if err != nil {
		return nil, errConfiguration
	}
	return newSDKQueueClientFromEndpoint(endpoint), nil
}

func proofJobs() ([]jobqueue.Job, error) {
	organizationID, err := domain.ParseProductID("pid_10000000-0000-4000-8000-000000000001")
	if err != nil {
		return nil, err
	}
	workspaceID, err := domain.ParseProductID("pid_20000000-0000-4000-8000-000000000002")
	if err != nil {
		return nil, err
	}
	environmentID, err := domain.ParseProductID("pid_30000000-0000-4000-8000-000000000003")
	if err != nil {
		return nil, err
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		return nil, err
	}
	jobOne, err := domain.ParseProductID("pid_40000000-0000-4000-8000-000000000004")
	if err != nil {
		return nil, err
	}
	jobTwo, err := domain.ParseProductID("pid_50000000-0000-4000-8000-000000000005")
	if err != nil {
		return nil, err
	}
	return []jobqueue.Job{
		{Scope: scope, JobID: jobOne, Kind: "evidence.collect", Payload: []byte(`{"action":"scan"}`)},
		{Scope: scope, JobID: jobTwo, Kind: "event.correlate", Payload: []byte(`{"attempt":1}`)},
	}, nil
}

func receiveJobBatch(ctx context.Context, queue *jobqueue.Queue, expectedJobs []jobqueue.Job, pollInterval time.Duration) ([]jobqueue.Delivery, error) {
	expected := make(map[domain.ProductID]jobqueue.Job, len(expectedJobs))
	for _, job := range expectedJobs {
		expected[job.JobID] = job
	}
	collected := make(map[domain.ProductID]jobqueue.Delivery, len(expectedJobs))
	for {
		deliveries, err := queue.ConsumeBatch(ctx, len(expectedJobs)-len(collected))
		if err != nil {
			return nil, errMessage
		}
		for _, delivery := range deliveries {
			job, exists := expected[delivery.Job.JobID]
			if !exists || delivery.Job.Scope != job.Scope || delivery.Job.Kind != job.Kind ||
				string(delivery.Job.Payload) != string(job.Payload) {
				return nil, errMessage
			}
			if _, duplicate := collected[delivery.Job.JobID]; duplicate {
				return nil, errMessage
			}
			collected[delivery.Job.JobID] = delivery
		}
		if len(collected) == len(expectedJobs) {
			ordered := make([]jobqueue.Delivery, len(expectedJobs))
			for index, job := range expectedJobs {
				ordered[index] = collected[job.JobID]
			}
			return ordered, nil
		}
		if err := waitFor(ctx, pollInterval); err != nil {
			return nil, errProvider
		}
	}
}

func formatJobQueueChildSuccess(result JobQueueProofResult) string {
	return fmt.Sprintf(
		"LocalStack job queue passed: publish=%d consume=%d acknowledge=%d scoped=%t redrive=%t empty=%t cleanup=%t audit=%t.",
		result.Publish, result.Consume, result.Acknowledge, result.Scoped, result.Redrive,
		result.Empty, result.Cleanup, result.Audit,
	)
}
