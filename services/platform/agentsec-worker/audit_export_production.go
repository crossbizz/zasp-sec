package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/auditexportconfig"
	"github.com/zasp-ai/zasp-sec/services/platform/awsclient"
	platformconfig "github.com/zasp-ai/zasp-sec/services/platform/config"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue/sqsdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type auditExportProductionClients struct {
	credentials aws.CredentialsProvider
	queue       runtimeQueueAPI
	identity    runtimeIdentityAPI
	artifacts   map[string]s3driver.API
	transport   *http.Transport
}

func newAuditExportCredentialCache(provider aws.CredentialsProvider) aws.CredentialsProvider {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &auditExportCredentialCache{provider: provider, gate: gate}
}

// AWS's general cache deliberately detaches its refresh context. This runtime
// owns refreshes synchronously, including a canceled caller waiting for the gate.
type auditExportCredentialCache struct {
	provider    aws.CredentialsProvider
	gate        chan struct{}
	credentials aws.Credentials
}

func (c *auditExportCredentialCache) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || nilWorkerDependency(c.provider) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	select {
	case <-c.gate:
	case <-ctx.Done():
		return aws.Credentials{}, errRuntimeUnavailable
	}
	defer func() { c.gate <- struct{}{} }()
	if ctx.Err() != nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	if c.credentials.Expires.After(time.Now().Add(time.Minute)) {
		return c.credentials, nil
	}
	credentials, err := c.provider.Retrieve(ctx)
	if err != nil || ctx.Err() != nil || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || credentials.SessionToken == "" || !credentials.CanExpire || !credentials.Expires.After(time.Now().Add(time.Minute)) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	c.credentials = credentials
	return credentials, nil
}

func composeAuditExportWorkerRuntime(ctx context.Context, config workerRuntimeConfig, database recoveryJSONDatabase, clients *auditExportProductionClients) (workerRuntimeDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validWorkerRuntimeConfig(config) || config.AuditExports == nil || nilWorkerDependency(database) || clients == nil || clients.transport == nil || nilWorkerDependency(clients.credentials) || nilWorkerDependency(clients.queue) || nilWorkerDependency(clients.identity) || len(clients.artifacts) != len(config.AuditExports.Policies) {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	// Capture trusted values; neither a caller-owned map nor a later queue message
	// can replace the revision, role or provider identity used by this runtime.
	copyConfig := *config.AuditExports
	copyConfig.Policies = append([]migrations.AuditExportConfiguration(nil), copyConfig.Policies...)
	config.AuditExports = &copyConfig
	for _, policy := range copyConfig.Policies {
		if nilWorkerDependency(clients.artifacts[policy.PolicyID]) {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
	}
	readiness := []func(context.Context) error{}
	executors := map[string]*auditExportExecutor{}
	var outbox *postgresAuditExportOutboxAuthority
	if config.Mode == workerModeAuditExportOutbox {
		var err error
		outbox, err = newPostgresAuditExportOutboxAuthorityContext(ctx, database)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		readiness = append(readiness, outbox.Ready)
	} else {
		for _, policy := range copyConfig.Policies {
			driver, err := s3driver.NewExport(clients.artifacts[policy.PolicyID], s3driver.Config{Bucket: policy.Bucket, ExpectedBucketOwner: policy.ExpectedBucketOwner, KMSKeyARN: policy.KMSKeyARN, MaximumBytes: audit.ExportMaximumChunkBytes})
			if err != nil {
				return workerRuntimeDependencies{}, errRuntimeUnavailable
			}
			store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: config.ProviderTimeout, MaximumBytes: audit.ExportMaximumChunkBytes})
			if err != nil {
				return workerRuntimeDependencies{}, errRuntimeUnavailable
			}
			executor, err := newAuditExportExecutorContext(ctx, auditExportExecutorConfig{Database: database, Policy: auditExportTrustedPolicy{Configuration: policy, Store: store}, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), RetrySeconds: 30, NewLeaseToken: newAuditExportProductionToken})
			if err != nil {
				return workerRuntimeDependencies{}, errRuntimeUnavailable
			}
			executors[policy.PolicyID] = executor
			readiness = append(readiness, executor.authority.Ready)
		}
	}
	credentials, queueAPI, identityAPI := clients.credentials, clients.queue, clients.identity
	liveCheck := func(parent context.Context) error {
		if parent == nil || parent.Err() != nil {
			return errRuntimeUnavailable
		}
		bounded, cancel := context.WithTimeout(parent, config.ProviderTimeout)
		defer cancel()
		creds, err := credentials.Retrieve(bounded)
		if err != nil || bounded.Err() != nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" || !creds.CanExpire || !creds.Expires.After(time.Now()) {
			return errRuntimeUnavailable
		}
		return readyAuditExportProductionQueue(bounded, config, queueAPI, identityAPI)
	}
	if liveCheck(ctx) != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	driver, err := sqsdriver.New(queueAPI, sqsdriver.Config{QueueURL: copyConfig.QueueURL, ReceiveWaitSeconds: min(int32(config.PollInterval/time.Second), 20), VisibilityTimeoutSeconds: int32(config.LeaseDuration / time.Second), MaximumReceiveCount: auditExportMaximumReceiveCount})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: config.ProviderTimeout, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	var processor workerProcessor
	if outbox != nil {
		processor, err = newAuditExportOutboxProcessor(auditExportOutboxProcessorConfig{Authority: outbox, Publisher: queue, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, RetrySeconds: 30, NewLeaseToken: newAuditExportProductionToken})
	} else {
		processor, err = newAuditExportDispatcher(queue, executors, config.BatchSize, config.LeaseDuration)
	}
	if err != nil || ctx.Err() != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	runtime := &auditExportProductionRuntime{processor: processor, driver: driver, transport: clients.transport, shutdown: config.ShutdownTimeout, ready: func(ctx context.Context) error {
		for _, ready := range readiness {
			if ready(ctx) != nil {
				return errRuntimeUnavailable
			}
		}
		return liveCheck(ctx)
	}}
	return workerRuntimeDependencies{Processor: runtime, Ready: runtime.Ready, Close: runtime.Close}, nil
}

func newAuditExportProductionToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errWorkerExecution
	}
	token := hex.EncodeToString(value[:])
	if !validAuditExportLeaseToken(token) {
		return "", errWorkerExecution
	}
	return token, nil
}

type auditExportProductionRuntime struct {
	mu          sync.Mutex
	closed      bool
	next        uint64
	cancelers   map[uint64]context.CancelFunc
	active      sync.WaitGroup
	processor   workerProcessor
	ready       func(context.Context) error
	driver      *sqsdriver.Driver
	transport   *http.Transport
	shutdown    time.Duration
	closeOnce   sync.Once
	closeMu     sync.Mutex
	closeDone   chan struct{}
	cleanupDone bool
}

func (r *auditExportProductionRuntime) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}
func (r *auditExportProductionRuntime) begin(ctx context.Context) (context.Context, func(), error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, errRuntimeUnavailable
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, nil, errRuntimeUnavailable
	}
	bounded, cancel := context.WithCancel(ctx)
	if r.cancelers == nil {
		r.cancelers = map[uint64]context.CancelFunc{}
	}
	r.next++
	id := r.next
	r.cancelers[id] = cancel
	r.active.Add(1)
	r.mu.Unlock()
	return bounded, func() { cancel(); r.mu.Lock(); delete(r.cancelers, id); r.mu.Unlock(); r.active.Done() }, nil
}
func (r *auditExportProductionRuntime) Ready(ctx context.Context) error {
	ctx, end, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer end()
	if r.ready(ctx) != nil || ctx.Err() != nil || r.isClosed() {
		return errRuntimeUnavailable
	}
	return nil
}
func (r *auditExportProductionRuntime) RunOnce(ctx context.Context) error {
	ctx, end, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer end()
	if r.ready(ctx) != nil || ctx.Err() != nil || r.isClosed() {
		return errRuntimeUnavailable
	}
	if err := r.processor.RunOnce(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || r.isClosed() {
		return errRuntimeUnavailable
	}
	return nil
}
func (r *auditExportProductionRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	if r.cleanupDone {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		for _, cancel := range r.cancelers {
			cancel()
		}
		r.mu.Unlock()
		r.closeDone = make(chan struct{})
		go func() { r.active.Wait(); close(r.closeDone) }()
	})
	ctx, cancel := context.WithTimeout(context.Background(), r.shutdown)
	defer cancel()
	select {
	case <-r.closeDone:
	case <-ctx.Done():
		// Keep clients alive under unjoined borrowers. A later Close can finish
		// cleanup after the same retained join completes; admission stays closed.
		return errRuntimeUnavailable
	}
	if r.driver.Drain(ctx) != nil {
		return errRuntimeUnavailable
	}
	r.transport.CloseIdleConnections()
	r.cleanupDone = true
	return nil
}

func newAuditExportProductionClients(config workerRuntimeConfig) (*auditExportProductionClients, error) {
	if !validWorkerRuntimeConfig(config) || config.AuditExports == nil {
		return nil, errRuntimeUnavailable
	}
	region, err := platformconfig.ParseAWSRegion(config.AWSRegion)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	// This constructor performs no network I/O. S3 authority is exercised only by
	// intent-bound operations, never by a synthetic startup write or bucket probe.
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: config.ProviderTimeout, MaxResponseHeaderBytes: 1 << 20}
	client := &http.Client{Transport: transport, Timeout: config.ProviderTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	role, session := auditExportProductionRole(config)
	base := aws.Config{Region: region.String(), HTTPClient: client, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	credentials := newAuditExportCredentialCache(&outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: role, tokenFile: config.AuditExports.TokenFile, timeout: config.ProviderTimeout, session: session})
	base.Credentials = credentials
	result := &auditExportProductionClients{credentials: credentials, queue: sqs.NewFromConfig(base), identity: sts.NewFromConfig(base), artifacts: make(map[string]s3driver.API, len(config.AuditExports.Policies)), transport: transport}
	for _, policy := range config.AuditExports.Policies {
		parts := strings.Split(policy.KMSKeyARN, ":")
		if len(parts) != 6 {
			transport.CloseIdleConnections()
			return nil, errRuntimeUnavailable
		}
		storageRegion, err := platformconfig.ParseAWSRegion(parts[3])
		if err != nil {
			transport.CloseIdleConnections()
			return nil, errRuntimeUnavailable
		}
		clients, err := awsclient.New(awsclient.Options{Mode: awsclient.ModeProduction, Region: storageRegion, Credentials: credentials, HTTPClient: client})
		if err != nil {
			transport.CloseIdleConnections()
			return nil, errRuntimeUnavailable
		}
		result.artifacts[policy.PolicyID] = clients.S3()
	}
	return result, nil
}

func readyAuditExportProductionQueue(ctx context.Context, config workerRuntimeConfig, queue runtimeQueueAPI, identity runtimeIdentityAPI) error {
	if ctx == nil || ctx.Err() != nil || !validAuditExportWorkerConfiguration(config) || config.AuditExports == nil || nilWorkerDependency(queue) || nilWorkerDependency(identity) {
		return errRuntimeUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, config.ProviderTimeout)
	defer cancel()
	role, session := auditExportProductionRole(config)
	account := strings.Split(role, ":")[4]
	arn := "arn:aws:sqs:" + config.AWSRegion + ":" + account + ":" + auditExportPhysicalQueue
	output, err := queue.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(config.AuditExports.QueueURL), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn, sqstypes.QueueAttributeNameRedrivePolicy}}, func(options *sqs.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || output == nil || ctx.Err() != nil || len(output.Attributes) != 2 || output.Attributes[string(sqstypes.QueueAttributeNameQueueArn)] != arn {
		return errRuntimeUnavailable
	}
	raw := []byte(output.Attributes[string(sqstypes.QueueAttributeNameRedrivePolicy)])
	if _, err := auditExportWorkerObject(raw, 1024, "deadLetterTargetArn", "maxReceiveCount"); err != nil {
		return errRuntimeUnavailable
	}
	var redrive struct {
		Target string          `json:"deadLetterTargetArn"`
		Count  json.RawMessage `json:"maxReceiveCount"`
	}
	if json.Unmarshal(raw, &redrive) != nil || redrive.Target != arn+"-dlq" || string(redrive.Count) != "20" && string(redrive.Count) != `"20"` {
		return errRuntimeUnavailable
	}
	caller, err := identity.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	roleName := role[strings.LastIndex(role, "/")+1:]
	if err != nil || caller == nil || ctx.Err() != nil || aws.ToString(caller.Account) != account || aws.ToString(caller.Arn) != "arn:aws:sts::"+account+":assumed-role/"+roleName+"/"+session {
		return errRuntimeUnavailable
	}
	return nil
}

func auditExportProductionRole(config workerRuntimeConfig) (string, string) {
	if config.Mode == workerModeAuditExportOutbox {
		return config.AuditExports.PublisherRoleARN, "zasp-audit-export-outbox"
	}
	return config.AuditExports.WriterRoleARN, "zasp-audit-export-worker"
}

const auditExportPhysicalQueue = "agentsec-audit-exports"

// Queue delivery/redrive budget, not the SQL execution-attempt budget. A DLQ
// message does not establish a failed export and needs monitored/manual redrive.
const auditExportMaximumReceiveCount = 20

type auditExportWorkerConfiguration struct {
	QueueURL, WriterRoleARN, PublisherRoleARN, TokenFile string
	Policies                                             []migrations.AuditExportConfiguration
}

func loadAuditExportWorkerConfiguration(getenv func(string) string, mode workerMode) (*auditExportWorkerConfiguration, error) {
	config := &auditExportWorkerConfiguration{QueueURL: getenv("ZASP_AUDIT_EXPORT_QUEUE_URL"), WriterRoleARN: getenv("ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN"), PublisherRoleARN: getenv("ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN"), TokenFile: getenv("ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE")}
	policies := getenv("ZASP_AUDIT_EXPORT_POLICIES_JSON")
	reader, cursor := getenv("ZASP_AUDIT_EXPORT_READER_ROLE_ARN"), getenv("ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY")
	if mode != workerModeAuditExport && mode != workerModeAuditExportOutbox {
		for _, value := range []string{config.QueueURL, config.WriterRoleARN, config.PublisherRoleARN, config.TokenFile, policies, reader, cursor} {
			if value != "" {
				return nil, errWorkerConfiguration
			}
		}
		return nil, nil
	}
	if reader != "" || cursor != "" {
		return nil, errWorkerConfiguration
	}
	if mode == workerModeAuditExport {
		var err error
		config.Policies, err = auditexportconfig.ParsePolicies([]byte(policies))
		if err != nil {
			return nil, errWorkerConfiguration
		}
	} else if policies != "" {
		return nil, errWorkerConfiguration
	}
	return config, nil
}

func validAuditExportWorkerConfiguration(config workerRuntimeConfig) bool {
	if config.Mode != workerModeAuditExport && config.Mode != workerModeAuditExportOutbox {
		return config.AuditExports == nil
	}
	exports := config.AuditExports
	if exports == nil || config.LeaseDuration < 60*time.Second || config.LeaseDuration > 300*time.Second || config.BatchSize < 1 || config.BatchSize > 10 || config.ProviderTimeout < time.Second || config.ProviderTimeout > 30*time.Second || exports.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !workerRegionPattern.MatchString(config.AWSRegion) {
		return false
	}
	// Registered LOGIN identity is deliberately distinct from the fixed NOLOGIN
	// capability role. Fresh SQL readiness verifies the actual registered binding.
	database, err := url.Parse(config.PostgresDSN)
	if err != nil || database.User == nil || !regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`).MatchString(database.User.Username()) || database.User.Username() == "zasp_audit_export_worker" || database.User.Username() == "zasp_audit_export_outbox" {
		return false
	}
	role := exports.WriterRoleARN
	if config.Mode == workerModeAuditExport {
		if exports.PublisherRoleARN != "" || len(exports.Policies) < 1 || len(exports.Policies) > 64 {
			return false
		}
		seen := make(map[string]bool, len(exports.Policies))
		for _, policy := range exports.Policies {
			if _, err := migrations.AuditExportPolicyDigest(policy); err != nil || policy.ExpectedCurrentPolicyID != "" || seen[policy.PolicyID] {
				return false
			}
			seen[policy.PolicyID] = true
		}
	} else {
		if exports.WriterRoleARN != "" || len(exports.Policies) != 0 {
			return false
		}
		role = exports.PublisherRoleARN
	}
	roleParts := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(role)
	queue, err := url.Parse(exports.QueueURL)
	if err != nil || len(roleParts) != 2 || !validSQSURL(exports.QueueURL) || queue.Hostname() != "sqs."+config.AWSRegion+".amazonaws.com" || strings.TrimPrefix(queue.Path, "/") != roleParts[1]+"/"+auditExportPhysicalQueue {
		return false
	}
	for _, value := range []string{config.DiscoveryQueueURL, config.RuntimeQueueURL, config.RedTeamQueueURL, config.AttackLabQueueURL, config.RecoveryQueueURL, config.RecoveryRoleARN, config.RecoveryTokenFile, config.RuntimeRoleARN, config.RuntimeTokenFile, config.RuntimeStageRoleARN, config.RuntimeStageTokenFile, config.RuntimeStageVersion, config.DiscoveryRoleARN, config.DiscoveryTokenFile, config.ProjectionRoleARN, config.ProjectionTokenFile, config.OutboxRoleARN, config.OutboxTokenFile, config.RedTeamRoleARN, config.RedTeamTokenFile, config.AttackLabRoleARN, config.AttackLabTokenFile, config.EvidenceBucket, config.EvidenceOwner, config.EvidenceKMSKeyARN, config.Neo4jCredential, config.GatewaySigningPrivateFile, config.SecurityAgentPlannerToken, config.RecoveryNeonSecretReference, config.RecoveryKubernetesToken, config.AttackLabKubernetesToken, config.AttackLabSigningKeyFile} {
		if value != "" {
			return false
		}
	}
	return true
}
