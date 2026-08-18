package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/queuedefinition"
)

const queueDefinitionsAuditPrefix = "zasp-m1-33-"

type queueDefinitionsProofClient interface {
	ListQueues(context.Context, string) ([]string, error)
	CreateQueue(context.Context, string, map[string]string, map[string]string) (string, error)
	GetQueueAttributes(context.Context, string) (map[string]string, error)
	ListQueueTags(context.Context, string) (map[string]string, error)
	SetQueueAttributes(context.Context, string, map[string]string) error
	DeleteQueue(context.Context, string) error
}

type QueueDefinitionsProofOptions struct {
	Endpoint       string
	Marker         string
	Client         queueDefinitionsProofClient
	CleanupTimeout time.Duration
	PollInterval   time.Duration
}

type QueueDefinitionsProofResult struct {
	Queues    int
	DLQs      int
	Schemas   int
	Retention bool
	Redrive   bool
	Cleanup   bool
	Audit     bool
}

type queueDefinitionTarget struct {
	definition         queuedefinition.Definition
	name               string
	role               string
	pair               string
	attributes         map[string]string
	proposedAttributes map[string]string
	attempted          bool
	uncertain          bool
	owned              *ownedQueue
}

func RunQueueDefinitionsProof(
	ctx context.Context,
	options QueueDefinitionsProofOptions,
) (result QueueDefinitionsProofResult, resultErr error) {
	if ctx == nil || jobNilInterface(options.Client) || !markerPattern.MatchString(options.Marker) {
		return QueueDefinitionsProofResult{}, errConfiguration
	}
	if _, err := validateDisposableJobEndpoint(ctx, options.Endpoint); err != nil {
		return QueueDefinitionsProofResult{}, errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 20 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 100 * time.Millisecond
	}
	dlqs, sources, allTargets, err := queueDefinitionTargets()
	if err != nil {
		return QueueDefinitionsProofResult{}, errConfiguration
	}

	lifecycleStarted := false
	defer func() {
		panicked := recover() != nil
		if lifecycleStarted {
			cleanup, audit := safeQueueDefinitionsCleanup(options, append(sources, dlqs...))
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

	if err := requireQueueDefinitionsUniverseAbsent(ctx, options.Client); err != nil {
		return QueueDefinitionsProofResult{}, err
	}
	lifecycleStarted = true

	for _, target := range dlqs {
		if err := createQueueDefinitionTarget(ctx, options, target); err != nil {
			return QueueDefinitionsProofResult{}, err
		}
	}
	for index, target := range sources {
		dlq := dlqs[index]
		if dlq.owned == nil {
			return QueueDefinitionsProofResult{}, errOwnership
		}
		redrive, err := encodeExactJSON(redrivePolicy{
			DeadLetterTargetARN: dlq.owned.arn,
			MaxReceiveCount:     strconv.Itoa(target.definition.Settings().MaxReceiveCount),
		})
		if err != nil {
			return QueueDefinitionsProofResult{}, errPolicy
		}
		target.attributes[redrivePolicyAttribute] = redrive
		if err := createQueueDefinitionTarget(ctx, options, target); err != nil {
			return QueueDefinitionsProofResult{}, err
		}
		if target.owned == nil || target.owned.account != dlq.owned.account {
			return QueueDefinitionsProofResult{}, errOwnership
		}
		allow, err := encodeExactJSON(redriveAllowPolicy{
			RedrivePermission: "byQueue",
			SourceQueueARNs:   []string{target.owned.arn},
		})
		if err != nil {
			return QueueDefinitionsProofResult{}, errPolicy
		}
		if err := setQueueDefinitionAttributes(ctx, options, dlq, map[string]string{
			redriveAllowPolicyAttribute: allow,
		}); err != nil {
			return QueueDefinitionsProofResult{}, err
		}
	}

	if err := proveQueueDefinitionsInventory(ctx, options, allTargets); err != nil {
		return QueueDefinitionsProofResult{}, err
	}
	result.Queues = len(sources)
	result.DLQs = len(dlqs)
	result.Schemas = len(queuedefinition.Definitions())
	result.Retention = true
	result.Redrive = true
	return result, nil
}

func queueDefinitionTargets() (
	dlqs []*queueDefinitionTarget,
	sources []*queueDefinitionTarget,
	all []*queueDefinitionTarget,
	err error,
) {
	definitions := queuedefinition.Definitions()
	if len(definitions) != 3 {
		return nil, nil, nil, errConfiguration
	}
	for _, definition := range definitions {
		if definition.Validate() != nil {
			return nil, nil, nil, errConfiguration
		}
		settings := definition.Settings()
		dlq := &queueDefinitionTarget{
			definition: definition,
			name:       definition.DeadLetterName(),
			role:       "dlq",
			pair:       definition.Name(),
			attributes: queueDefinitionScalarAttributes(
				settings.DeadLetterRetentionSeconds,
				settings.DeadLetterVisibilityTimeoutSeconds,
				settings,
			),
		}
		source := &queueDefinitionTarget{
			definition: definition,
			name:       definition.Name(),
			role:       "source",
			pair:       definition.DeadLetterName(),
			attributes: queueDefinitionScalarAttributes(
				settings.MessageRetentionSeconds,
				settings.VisibilityTimeoutSeconds,
				settings,
			),
		}
		dlqs = append(dlqs, dlq)
		sources = append(sources, source)
	}
	all = append(append([]*queueDefinitionTarget(nil), dlqs...), sources...)
	return dlqs, sources, all, nil
}

func queueDefinitionScalarAttributes(retention int, visibility int, settings queuedefinition.Settings) map[string]string {
	return map[string]string{
		"DelaySeconds":                  strconv.Itoa(settings.DelaySeconds),
		"MaximumMessageSize":            strconv.Itoa(settings.MaximumMessageBytes),
		"MessageRetentionPeriod":        strconv.Itoa(retention),
		"ReceiveMessageWaitTimeSeconds": strconv.Itoa(settings.ReceiveWaitSeconds),
		"VisibilityTimeout":             strconv.Itoa(visibility),
	}
}

func createQueueDefinitionTarget(
	ctx context.Context,
	options QueueDefinitionsProofOptions,
	target *queueDefinitionTarget,
) error {
	target.attempted = true
	target.uncertain = true
	returnedURL, createErr := callQueueDefinitionCreate(
		options.Client,
		ctx,
		target.name,
		cloneStringMap(target.attributes),
		queueDefinitionProofTags(options.Marker, target),
	)
	if createErr != nil && mutationIsDefinitive(createErr) {
		target.attempted = false
		target.uncertain = false
		return errProvider
	}
	if createErr == nil && returnedURL != "" {
		owned, _, err := proveQueueDefinitionTarget(
			ctx, options, target, returnedURL, []map[string]string{target.attributes},
		)
		if err == nil {
			target.owned = owned
			target.uncertain = false
			return nil
		}
	}

	reconcileCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	for {
		owned, absent, err := reconcileQueueDefinitionTarget(reconcileCtx, options, target)
		if err != nil {
			return err
		}
		if owned != nil {
			target.owned = owned
			target.uncertain = false
			return nil
		}
		_ = absent
		if waitFor(reconcileCtx, options.PollInterval) != nil {
			return errProvider
		}
	}
}

func setQueueDefinitionAttributes(
	ctx context.Context,
	options QueueDefinitionsProofOptions,
	target *queueDefinitionTarget,
	attributes map[string]string,
) error {
	if target.owned == nil {
		return errOwnership
	}
	proposed := cloneStringMap(target.attributes)
	for key, value := range attributes {
		proposed[key] = value
	}
	target.proposedAttributes = proposed
	mutationErr := callQueueDefinitionSetAttributes(
		options.Client,
		ctx,
		target.owned.url,
		cloneStringMap(attributes),
	)
	if mutationErr != nil && mutationIsDefinitive(mutationErr) {
		target.proposedAttributes = nil
		return errProvider
	}

	reconcileCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	for {
		owned, variant, err := proveQueueDefinitionTarget(
			reconcileCtx,
			options,
			target,
			target.owned.url,
			[]map[string]string{target.attributes, proposed},
		)
		if err == nil && variant == 1 && sameOwnedQueue(owned, target.owned) {
			target.attributes = proposed
			target.proposedAttributes = nil
			target.owned = owned
			return nil
		}
		if err != nil && errors.Is(err, errOwnership) {
			return errOwnership
		}
		if waitFor(reconcileCtx, options.PollInterval) != nil {
			return errProvider
		}
	}
}

func reconcileQueueDefinitionTarget(
	ctx context.Context,
	options QueueDefinitionsProofOptions,
	target *queueDefinitionTarget,
) (*ownedQueue, bool, error) {
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
	variants := []map[string]string{target.attributes}
	if target.proposedAttributes != nil {
		variants = append(variants, target.proposedAttributes)
	}
	owned, _, err := proveQueueDefinitionTarget(ctx, options, target, exact[0], variants)
	if err != nil {
		if errors.Is(err, errOwnership) {
			return nil, false, errOwnership
		}
		return nil, false, nil
	}
	return owned, false, nil
}

func proveQueueDefinitionTarget(
	ctx context.Context,
	options QueueDefinitionsProofOptions,
	target *queueDefinitionTarget,
	queueURL string,
	attributeVariants []map[string]string,
) (*ownedQueue, int, error) {
	account, err := validateDisposableJobQueueURL(ctx, options.Endpoint, queueURL, target.name, nil)
	if err != nil {
		return nil, -1, errOwnership
	}
	attributes, err := options.Client.GetQueueAttributes(ctx, queueURL)
	if err != nil {
		return nil, -1, errProvider
	}
	arn := attributes[queueARNAttribute]
	if validateQueueARN(arn, account, target.name) != nil {
		return nil, -1, errOwnership
	}
	if fifo := attributes[fifoQueueAttribute]; fifo != "" && fifo != "false" {
		return nil, -1, errOwnership
	}
	matchedVariant := -1
	for index, expected := range attributeVariants {
		if queueDefinitionAttributesMatch(attributes, expected) {
			matchedVariant = index
			break
		}
	}
	if matchedVariant < 0 {
		return nil, -1, errOwnership
	}
	tags, err := options.Client.ListQueueTags(ctx, queueURL)
	if err != nil {
		return nil, -1, errProvider
	}
	if !equalStringMaps(tags, queueDefinitionProofTags(options.Marker, target)) {
		return nil, -1, errOwnership
	}
	return &ownedQueue{
		name: target.name, role: target.role, url: queueURL,
		arn: arn, account: account, marker: options.Marker,
	}, matchedVariant, nil
}

func queueDefinitionAttributesMatch(actual map[string]string, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	for _, policy := range []string{redrivePolicyAttribute, redriveAllowPolicyAttribute} {
		if _, expectedPolicy := expected[policy]; !expectedPolicy && actual[policy] != "" {
			return false
		}
	}
	return true
}

func queueDefinitionProofTags(marker string, target *queueDefinitionTarget) map[string]string {
	return map[string]string{
		"zasp-proof":        "m1-33",
		"zasp-proof-marker": marker,
		"zasp-proof-role":   target.role,
		"zasp-queue-kind":   string(target.definition.Kind()),
		"zasp-schema-id":    target.definition.SchemaID(),
		"zasp-paired-queue": target.pair,
	}
}

func proveQueueDefinitionsInventory(
	ctx context.Context,
	options QueueDefinitionsProofOptions,
	targets []*queueDefinitionTarget,
) error {
	urls, err := options.Client.ListQueues(ctx, "")
	if err != nil {
		return errProvider
	}
	if len(urls) != len(targets) {
		return errOwnership
	}
	seen := make(map[string]bool, len(targets))
	account := ""
	for _, target := range targets {
		exact := exactQueueURLs(urls, target.name)
		if len(exact) != 1 || seen[target.name] {
			return errOwnership
		}
		seen[target.name] = true
		owned, _, err := proveQueueDefinitionTarget(
			ctx, options, target, exact[0], []map[string]string{target.attributes},
		)
		if err != nil {
			return err
		}
		if target.owned == nil || !sameOwnedQueue(owned, target.owned) {
			return errOwnership
		}
		if account == "" {
			account = owned.account
		} else if account != owned.account {
			return errOwnership
		}
		target.owned = owned
	}
	if len(seen) != len(targets) {
		return errOwnership
	}
	prefixed, err := options.Client.ListQueues(ctx, queueDefinitionsAuditPrefix)
	if err != nil {
		return errProvider
	}
	if len(prefixed) != 0 {
		return errOwnership
	}
	return nil
}

func requireQueueDefinitionsUniverseAbsent(ctx context.Context, client queueDefinitionsProofClient) error {
	urls, err := client.ListQueues(ctx, "")
	if err != nil {
		return errProvider
	}
	if len(urls) != 0 {
		return errOwnership
	}
	prefixed, err := client.ListQueues(ctx, queueDefinitionsAuditPrefix)
	if err != nil {
		return errProvider
	}
	if len(prefixed) != 0 {
		return errOwnership
	}
	return nil
}

func safeQueueDefinitionsCleanup(
	options QueueDefinitionsProofOptions,
	targets []*queueDefinitionTarget,
) (cleanup bool, audit bool) {
	defer func() {
		if recover() != nil {
			cleanup = false
			audit = false
		}
	}()
	cleanup = true
	for _, target := range targets {
		if target.attempted && target.uncertain && !rearmQueueDefinitionTarget(options, target) {
			cleanup = false
		}
	}
	targetTimeout := options.CleanupTimeout / time.Duration(len(targets))
	if targetTimeout < options.PollInterval {
		targetTimeout = options.PollInterval
	}
	for _, target := range targets {
		if !target.attempted {
			continue
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), targetTimeout)
		targetClean := cleanupQueueDefinitionTarget(cleanupCtx, options, target)
		cancel()
		if !targetClean {
			cleanup = false
		}
	}
	auditCtx, auditCancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer auditCancel()
	audit = auditQueueDefinitionsAbsence(auditCtx, options.Client)
	return cleanup, audit
}

func rearmQueueDefinitionTarget(options QueueDefinitionsProofOptions, target *queueDefinitionTarget) (success bool) {
	defer func() {
		if recover() != nil {
			success = false
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	sawAbsent := false
	sawUnresolved := false
	for {
		owned, absent, err := reconcileQueueDefinitionTarget(ctx, options, target)
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
		if waitFor(ctx, options.PollInterval) != nil {
			if sawAbsent && !sawUnresolved {
				target.uncertain = false
				return true
			}
			return false
		}
	}
}

func cleanupQueueDefinitionTarget(
	ctx context.Context,
	options QueueDefinitionsProofOptions,
	target *queueDefinitionTarget,
) (success bool) {
	defer func() {
		if recover() != nil {
			success = false
		}
	}()
	owned, absent, err := reconcileQueueDefinitionTarget(ctx, options, target)
	if err != nil {
		return false
	}
	if absent {
		return true
	}
	if owned == nil {
		return false
	}
	if target.owned != nil && !sameOwnedQueue(owned, target.owned) {
		return false
	}
	target.owned = owned
	deleteErr := callQueueDefinitionDelete(options.Client, ctx, owned.url)
	if deleteErr != nil && mutationIsDefinitive(deleteErr) {
		return false
	}
	return waitQueueDefinitionAbsent(ctx, options.Client, target.name, options.PollInterval)
}

func callQueueDefinitionCreate(
	client queueDefinitionsProofClient,
	ctx context.Context,
	name string,
	attributes map[string]string,
	tags map[string]string,
) (queueURL string, err error) {
	defer func() {
		if recover() != nil {
			queueURL = ""
			err = ambiguousMutationError()
		}
	}()
	return client.CreateQueue(ctx, name, attributes, tags)
}

func callQueueDefinitionSetAttributes(
	client queueDefinitionsProofClient,
	ctx context.Context,
	queueURL string,
	attributes map[string]string,
) (err error) {
	defer func() {
		if recover() != nil {
			err = ambiguousMutationError()
		}
	}()
	return client.SetQueueAttributes(ctx, queueURL, attributes)
}

func callQueueDefinitionDelete(
	client queueDefinitionsProofClient,
	ctx context.Context,
	queueURL string,
) (err error) {
	defer func() {
		if recover() != nil {
			err = ambiguousMutationError()
		}
	}()
	return client.DeleteQueue(ctx, queueURL)
}

func waitQueueDefinitionAbsent(
	ctx context.Context,
	client queueDefinitionsProofClient,
	name string,
	pollInterval time.Duration,
) bool {
	for {
		urls, err := client.ListQueues(ctx, name)
		if err == nil && len(exactQueueURLs(urls, name)) == 0 {
			return true
		}
		if waitFor(ctx, pollInterval) != nil {
			return false
		}
	}
}

func auditQueueDefinitionsAbsence(ctx context.Context, client queueDefinitionsProofClient) bool {
	urls, err := client.ListQueues(ctx, "")
	if err != nil || len(urls) != 0 {
		return false
	}
	prefixed, err := client.ListQueues(ctx, queueDefinitionsAuditPrefix)
	return err == nil && len(prefixed) == 0
}

func sameOwnedQueue(left *ownedQueue, right *ownedQueue) bool {
	return left != nil && right != nil && left.name == right.name && left.role == right.role &&
		left.url == right.url && left.arn == right.arn && left.account == right.account &&
		left.marker == right.marker
}

func formatQueueDefinitionsChildSuccess(result QueueDefinitionsProofResult) string {
	return fmt.Sprintf(
		"LocalStack queue definitions passed: queues=%d dlqs=%d schemas=%d retention=%t redrive=%t cleanup=%t audit=%t.",
		result.Queues, result.DLQs, result.Schemas, result.Retention, result.Redrive, result.Cleanup, result.Audit,
	)
}
