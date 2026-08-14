package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	fixedRegion                 = "us-east-1"
	queuePrefix                 = "zasp-m0-06-"
	queueARNAttribute           = "QueueArn"
	fifoQueueAttribute          = "FifoQueue"
	redrivePolicyAttribute      = "RedrivePolicy"
	redriveAllowPolicyAttribute = "RedriveAllowPolicy"
	messageBatchEntryID         = "event-batch"
	deleteBatchEntryID          = "received-batch"
	organizationAttribute       = "organization_id"
	workspaceAttribute          = "workspace_id"
	environmentAttribute        = "environment_id"
	batchIDAttribute            = "batch_id"
	eventCountAttribute         = "event_count"
	digestAttribute             = "body_sha256"
	maxReceiveCount             = "3"
)

var (
	errConfiguration = errors.New("configuration rejected")
	errProvider      = errors.New("SQS operation failed")
	errOwnership     = errors.New("queue ownership rejected")
	errPolicy        = errors.New("redrive policy rejected")
	errMessage       = errors.New("event batch rejected")
	errCleanup       = errors.New("queue cleanup failed")

	markerPattern  = regexp.MustCompile(`^[a-f0-9]{16}$`)
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	idPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{2,79}$`)
)

type hostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

type queueAPI interface {
	ListQueues(context.Context, string) ([]string, error)
	CreateQueue(context.Context, string, map[string]string, map[string]string) (string, error)
	GetQueueAttributes(context.Context, string) (map[string]string, error)
	ListQueueTags(context.Context, string) (map[string]string, error)
	SetQueueAttributes(context.Context, string, map[string]string) error
	SendMessageBatch(context.Context, string, outgoingMessage) (batchSendResult, error)
	ReceiveMessages(context.Context, string) ([]receivedMessage, error)
	DeleteMessageBatch(context.Context, string, string) (batchDeleteResult, error)
	DeleteQueue(context.Context, string) error
}

type ProofOptions struct {
	Endpoint       string
	Marker         string
	Client         queueAPI
	CleanupTimeout time.Duration
	PollInterval   time.Duration
}

type validatedEndpoint struct {
	baseURL  string
	hostname string
	port     string
}

type ownedQueue struct {
	name    string
	role    string
	url     string
	arn     string
	account string
	marker  string
}

type messageAttribute struct {
	DataType string
	Value    string
}

type outgoingMessage struct {
	ID         string
	Body       string
	Attributes map[string]messageAttribute
}

type batchSendResult struct {
	SuccessfulIDs []string
	FailedIDs     []string
	MessageID     string
	BodyDigest    string
}

type receivedMessage struct {
	Body          string
	Attributes    map[string]messageAttribute
	MessageID     string
	ReceiptHandle string
	BodyDigest    string
}

type batchDeleteResult struct {
	SuccessfulIDs []string
	FailedIDs     []string
}

type eventEnvelope struct {
	Version        string            `json:"version"`
	BatchID        string            `json:"batch_id"`
	OrganizationID string            `json:"organization_id"`
	WorkspaceID    string            `json:"workspace_id"`
	EnvironmentID  string            `json:"environment_id"`
	Events         []normalizedEvent `json:"events"`
}

type normalizedEvent struct {
	EventID        string `json:"event_id"`
	OrganizationID string `json:"organization_id"`
	Kind           string `json:"kind"`
	Sequence       int    `json:"sequence"`
}

type redrivePolicy struct {
	DeadLetterTargetARN string `json:"deadLetterTargetArn"`
	MaxReceiveCount     string `json:"maxReceiveCount"`
}

type redriveAllowPolicy struct {
	RedrivePermission string   `json:"redrivePermission"`
	SourceQueueARNs   []string `json:"sourceQueueArns"`
}

func RunProof(ctx context.Context, options ProofOptions) (resultErr error) {
	if ctx == nil || options.Client == nil || !markerPattern.MatchString(options.Marker) {
		return errConfiguration
	}
	if _, err := validateEndpoint(ctx, options.Endpoint, nil); err != nil {
		return errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 15 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 100 * time.Millisecond
	}

	var source, dlq *ownedQueue
	defer func() {
		panicked := recover() != nil
		cleanupErr := safeCleanup(options, source, dlq)
		if cleanupErr != nil {
			resultErr = errCleanup
		} else if panicked {
			resultErr = errProvider
		}
	}()

	prefix := queuePrefix + options.Marker
	if err := requireNoExactQueues(ctx, options.Client, prefix, prefix+"-source", prefix+"-dlq"); err != nil {
		return err
	}

	dlqName := prefix + "-dlq"
	var err error
	dlq, err = createOwnedQueue(ctx, options.Client, options.Endpoint, dlqName, "dlq", options.Marker, nil)
	if err != nil {
		return err
	}

	sourceName := prefix + "-source"
	sourcePolicy, err := encodeExactJSON(redrivePolicy{DeadLetterTargetARN: dlq.arn, MaxReceiveCount: maxReceiveCount})
	if err != nil {
		return errPolicy
	}
	source, err = createOwnedQueue(ctx, options.Client, options.Endpoint, sourceName, "source", options.Marker,
		map[string]string{redrivePolicyAttribute: sourcePolicy})
	if err != nil {
		return err
	}
	if source.account != dlq.account {
		return errOwnership
	}

	allowPolicy, err := encodeExactJSON(redriveAllowPolicy{
		RedrivePermission: "byQueue", SourceQueueARNs: []string{source.arn},
	})
	if err != nil {
		return errPolicy
	}
	if err := options.Client.SetQueueAttributes(ctx, dlq.url, map[string]string{
		redriveAllowPolicyAttribute: allowPolicy,
	}); err != nil {
		return errProvider
	}
	if err := assertRedrivePolicies(ctx, options.Client, source, dlq); err != nil {
		return err
	}

	body, envelope, err := buildEnvelope(options.Marker)
	if err != nil {
		return errMessage
	}
	digest := sha256.Sum256([]byte(body))
	digestHex := hex.EncodeToString(digest[:])
	attributes := expectedMessageAttributes(envelope, digestHex)
	sendResult, err := options.Client.SendMessageBatch(ctx, source.url, outgoingMessage{
		ID: messageBatchEntryID, Body: body, Attributes: attributes,
	})
	if err != nil {
		return errProvider
	}
	if len(sendResult.SuccessfulIDs) != 1 || sendResult.SuccessfulIDs[0] != messageBatchEntryID ||
		len(sendResult.FailedIDs) != 0 || sendResult.MessageID == "" ||
		(sendResult.BodyDigest != "" && !strings.EqualFold(sendResult.BodyDigest, md5Hex(body))) {
		return errMessage
	}

	received, err := receiveOne(ctx, options.Client, source.url, options.PollInterval)
	if err != nil {
		return err
	}
	if received.MessageID != sendResult.MessageID || received.ReceiptHandle == "" || received.Body != body ||
		(received.BodyDigest != "" && !strings.EqualFold(received.BodyDigest, md5Hex(body))) ||
		!equalMessageAttributes(received.Attributes, attributes) {
		return errMessage
	}
	if err := validateEnvelope(received.Body, envelope); err != nil {
		return errMessage
	}
	deleteResult, err := options.Client.DeleteMessageBatch(ctx, source.url, received.ReceiptHandle)
	if err != nil {
		return errProvider
	}
	if len(deleteResult.SuccessfulIDs) != 1 || deleteResult.SuccessfulIDs[0] != deleteBatchEntryID || len(deleteResult.FailedIDs) != 0 {
		return errMessage
	}
	for range 2 {
		messages, err := options.Client.ReceiveMessages(ctx, source.url)
		if err != nil {
			return errProvider
		}
		if len(messages) != 0 {
			return errMessage
		}
	}
	return nil
}

func validateEndpoint(ctx context.Context, raw string, resolver hostResolver) (validatedEndpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.Hostname() == "" || parsed.Port() != "4566" || parsed.Opaque != "" {
		return validatedEndpoint{}, errConfiguration
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "0.0.0.0" || host == "::" {
		return validatedEndpoint{}, errConfiguration
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsLoopback() {
			return validatedEndpoint{}, errConfiguration
		}
	} else {
		if host != "localhost" {
			return validatedEndpoint{}, errConfiguration
		}
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addresses, lookupErr := resolver.LookupHost(ctx, host)
		if lookupErr != nil || len(addresses) == 0 {
			return validatedEndpoint{}, errConfiguration
		}
		for _, address := range addresses {
			resolved := net.ParseIP(address)
			if resolved == nil || !resolved.IsLoopback() {
				return validatedEndpoint{}, errConfiguration
			}
		}
	}
	parsed.Path = ""
	return validatedEndpoint{baseURL: parsed.String(), hostname: host, port: parsed.Port()}, nil
}

func createOwnedQueue(ctx context.Context, client queueAPI, endpoint, name, role, marker string, attributes map[string]string) (*ownedQueue, error) {
	tags := proofTags(marker, role)
	returnedURL, createErr := client.CreateQueue(ctx, name, cloneStringMap(attributes), tags)
	if createErr == nil && returnedURL != "" {
		owned, err := proveOwnedQueue(ctx, client, endpoint, returnedURL, name, role, marker, attributes)
		if err == nil {
			return owned, nil
		}
	}

	urls, listErr := client.ListQueues(ctx, name)
	if listErr != nil {
		return nil, errProvider
	}
	exact := exactQueueURLs(urls, name)
	if len(exact) != 1 {
		if createErr == nil {
			return nil, errOwnership
		}
		return nil, errProvider
	}
	owned, err := proveOwnedQueue(ctx, client, endpoint, exact[0], name, role, marker, attributes)
	if err != nil {
		return nil, errOwnership
	}
	return owned, nil
}

func proveOwnedQueue(ctx context.Context, client queueAPI, endpoint, queueURL, name, role, marker string, expectedAttributes map[string]string) (*ownedQueue, error) {
	account, err := validateQueueURL(ctx, endpoint, queueURL, name, nil)
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
	if !equalStringMaps(tags, proofTags(marker, role)) {
		return nil, errOwnership
	}
	return &ownedQueue{name: name, role: role, url: queueURL, arn: arn, account: account, marker: marker}, nil
}

func validateQueueURL(ctx context.Context, endpoint, rawQueueURL, expectedName string, resolver hostResolver) (string, error) {
	base, err := validateEndpoint(ctx, endpoint, resolver)
	if err != nil {
		return "", errOwnership
	}
	parsed, err := url.Parse(rawQueueURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != base.port {
		return "", errOwnership
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", errOwnership
	}
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

func validateQueueARN(arn, account, name string) error {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws" || parts[2] != "sqs" ||
		parts[3] != fixedRegion || parts[4] != account || parts[5] != name {
		return errOwnership
	}
	return nil
}

func assertRedrivePolicies(ctx context.Context, client queueAPI, source, dlq *ownedQueue) error {
	dlqAttributes, err := client.GetQueueAttributes(ctx, dlq.url)
	if err != nil {
		return errProvider
	}
	var allow redriveAllowPolicy
	if err := decodeExactJSON(dlqAttributes[redriveAllowPolicyAttribute], &allow); err != nil ||
		allow.RedrivePermission != "byQueue" || len(allow.SourceQueueARNs) != 1 || allow.SourceQueueARNs[0] != source.arn {
		return errPolicy
	}
	sourceAttributes, err := client.GetQueueAttributes(ctx, source.url)
	if err != nil {
		return errProvider
	}
	var redrive redrivePolicy
	if err := decodeExactJSON(sourceAttributes[redrivePolicyAttribute], &redrive); err != nil ||
		redrive.DeadLetterTargetARN != dlq.arn || redrive.MaxReceiveCount != maxReceiveCount {
		return errPolicy
	}
	if fifo := sourceAttributes[fifoQueueAttribute]; fifo != "" && fifo != "false" {
		return errPolicy
	}
	if fifo := dlqAttributes[fifoQueueAttribute]; fifo != "" && fifo != "false" {
		return errPolicy
	}
	return nil
}

func buildEnvelope(marker string) (string, eventEnvelope, error) {
	if !markerPattern.MatchString(marker) {
		return "", eventEnvelope{}, errMessage
	}
	envelope := eventEnvelope{
		Version:        "1",
		BatchID:        "batch-" + marker,
		OrganizationID: "org-" + marker,
		WorkspaceID:    "workspace-" + marker,
		EnvironmentID:  "environment-" + marker,
		Events: []normalizedEvent{
			{EventID: "event-" + marker + "-01", OrganizationID: "org-" + marker, Kind: "agent.tool.called", Sequence: 1},
			{EventID: "event-" + marker + "-02", OrganizationID: "org-" + marker, Kind: "agent.tool.completed", Sequence: 2},
		},
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return "", eventEnvelope{}, errMessage
	}
	if err := validateEnvelope(string(body), envelope); err != nil {
		return "", eventEnvelope{}, err
	}
	return string(body), envelope, nil
}

func validateEnvelope(body string, expected eventEnvelope) error {
	var actual eventEnvelope
	if err := decodeExactJSON(body, &actual); err != nil {
		return errMessage
	}
	if actual.Version != "1" || !idPattern.MatchString(actual.BatchID) || !idPattern.MatchString(actual.OrganizationID) ||
		!idPattern.MatchString(actual.WorkspaceID) || !idPattern.MatchString(actual.EnvironmentID) || len(actual.Events) < 2 {
		return errMessage
	}
	for index, event := range actual.Events {
		if event.OrganizationID != actual.OrganizationID || event.Sequence != index+1 ||
			!idPattern.MatchString(event.EventID) || event.Kind == "" {
			return errMessage
		}
	}
	want, err := json.Marshal(expected)
	if err != nil || !bytes.Equal([]byte(body), want) {
		return errMessage
	}
	return nil
}

func expectedMessageAttributes(envelope eventEnvelope, digest string) map[string]messageAttribute {
	return map[string]messageAttribute{
		organizationAttribute: {DataType: "String", Value: envelope.OrganizationID},
		workspaceAttribute:    {DataType: "String", Value: envelope.WorkspaceID},
		environmentAttribute:  {DataType: "String", Value: envelope.EnvironmentID},
		batchIDAttribute:      {DataType: "String", Value: envelope.BatchID},
		eventCountAttribute:   {DataType: "Number", Value: fmt.Sprintf("%d", len(envelope.Events))},
		digestAttribute:       {DataType: "String", Value: digest},
	}
}

func receiveOne(ctx context.Context, client queueAPI, queueURL string, pollInterval time.Duration) (receivedMessage, error) {
	for {
		messages, err := client.ReceiveMessages(ctx, queueURL)
		if err != nil {
			return receivedMessage{}, errProvider
		}
		if len(messages) == 1 {
			return messages[0], nil
		}
		if len(messages) > 1 {
			return receivedMessage{}, errMessage
		}
		if err := waitFor(ctx, pollInterval); err != nil {
			return receivedMessage{}, errProvider
		}
	}
}

func safeCleanup(options ProofOptions, source, dlq *ownedQueue) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCleanup
		}
	}()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), options.CleanupTimeout)
	defer cancel()
	failed := false
	for _, target := range []*ownedQueue{source, dlq} {
		if target == nil {
			continue
		}
		fresh, err := proveOwnedQueue(ctx, options.Client, options.Endpoint, target.url, target.name, target.role, target.marker, nil)
		if err != nil || fresh.url != target.url || fresh.arn != target.arn || fresh.account != target.account {
			failed = true
			continue
		}
		_ = options.Client.DeleteQueue(ctx, target.url)
		if err := waitQueueAbsent(ctx, options.Client, target, options.PollInterval); err != nil {
			failed = true
		}
	}
	if failed {
		return errCleanup
	}
	return nil
}

func waitQueueAbsent(ctx context.Context, client queueAPI, target *ownedQueue, pollInterval time.Duration) error {
	for {
		urls, err := client.ListQueues(ctx, target.name)
		if err == nil && len(exactQueueURLs(urls, target.name)) == 0 {
			return nil
		}
		if waitErr := waitFor(ctx, pollInterval); waitErr != nil {
			return errCleanup
		}
	}
}

func AuditNoQueues(ctx context.Context, client queueAPI, marker string) error {
	if ctx == nil || client == nil || !markerPattern.MatchString(marker) {
		return errConfiguration
	}
	prefix := queuePrefix + marker
	urls, err := client.ListQueues(ctx, prefix)
	if err != nil {
		return errCleanup
	}
	if len(exactQueueURLs(urls, prefix+"-source")) != 0 || len(exactQueueURLs(urls, prefix+"-dlq")) != 0 {
		return errCleanup
	}
	return nil
}

func requireNoExactQueues(ctx context.Context, client queueAPI, prefix string, names ...string) error {
	urls, err := client.ListQueues(ctx, prefix)
	if err != nil {
		return errProvider
	}
	for _, name := range names {
		if len(exactQueueURLs(urls, name)) != 0 {
			return errOwnership
		}
	}
	return nil
}

func exactQueueURLs(urls []string, name string) []string {
	var exact []string
	for _, raw := range urls {
		if _, err := url.Parse(raw); err != nil {
			continue
		}
		if queueNameFromURL(raw) == name {
			exact = append(exact, raw)
		}
	}
	sort.Strings(exact)
	return exact
}

func proofTags(marker, role string) map[string]string {
	return map[string]string{
		"zasp-proof":        "m0-06",
		"zasp-proof-marker": marker,
		"zasp-proof-role":   role,
	}
}

func encodeExactJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func decodeExactJSON(raw string, target any) error {
	if raw == "" {
		return errors.New("empty JSON")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw string) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := readUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func readUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func waitFor(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func equalStringMaps(left, right map[string]string) bool {
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

func equalMessageAttributes(left, right map[string]messageAttribute) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value || value.Value == "" {
			return false
		}
	}
	return true
}

func md5Hex(value string) string {
	digest := md5.Sum([]byte(value))
	return hex.EncodeToString(digest[:])
}
