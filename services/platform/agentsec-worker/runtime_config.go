package main

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

type workerMode string

const (
	workerModeOutbox           workerMode = "outbox"
	workerModeDiscovery        workerMode = "discovery"
	workerModeScheduler        workerMode = "scheduler"
	workerModeProjectionRisk   workerMode = "projection-risk"
	workerModeProjectionGraph  workerMode = "projection-graph"
	workerModeProjectionSearch workerMode = "projection-search"
)

var (
	errWorkerConfiguration = errors.New("worker runtime configuration rejected")
	workerIdentityPattern  = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,127}$`)
)

type workerRuntimeConfig struct {
	Mode              workerMode
	ProjectionKind    string
	PostgresDSN       string
	DatabaseAuthority string
	WorkerID          string
	PollInterval      time.Duration
	LeaseDuration     time.Duration
	BatchSize         int
	ShutdownTimeout   time.Duration
	DiscoveryQueueURL string
	AWSRegion         string
	EvidenceBucket    string
	EvidenceOwner     string
	EvidenceKMSKeyARN string
	ParserVersion     string
	ToolVersion       string
	OpenSearchURL     string
	OpenSearchIndex   string
	Neo4jURI          string
	Neo4jCredential   string
}

func loadWorkerRuntimeConfig(getenv func(string) string) (workerRuntimeConfig, error) {
	if getenv == nil {
		return workerRuntimeConfig{}, errWorkerConfiguration
	}
	poll, pollErr := time.ParseDuration(getenv("ZASP_POLL_INTERVAL"))
	lease, leaseErr := time.ParseDuration(getenv("ZASP_LEASE_DURATION"))
	shutdown, shutdownErr := time.ParseDuration(getenv("ZASP_SHUTDOWN_TIMEOUT"))
	batch, batchErr := strconv.Atoi(getenv("ZASP_BATCH_SIZE"))
	config := workerRuntimeConfig{
		Mode: workerMode(getenv("ZASP_WORKER_MODE")), PostgresDSN: getenv("ZASP_POSTGRES_DSN"),
		DatabaseAuthority: getenv("ZASP_DATABASE_AUTHORITY"), WorkerID: getenv("ZASP_WORKER_ID"),
		PollInterval: poll, LeaseDuration: lease, BatchSize: batch, ShutdownTimeout: shutdown,
		DiscoveryQueueURL: getenv("ZASP_DISCOVERY_QUEUE_URL"), AWSRegion: getenv("ZASP_AWS_REGION"), EvidenceBucket: getenv("ZASP_EVIDENCE_BUCKET"), EvidenceOwner: getenv("ZASP_EVIDENCE_BUCKET_OWNER"),
		EvidenceKMSKeyARN: getenv("ZASP_EVIDENCE_KMS_KEY_ARN"), ParserVersion: getenv("ZASP_DISCOVERY_PARSER_VERSION"), ToolVersion: getenv("ZASP_DISCOVERY_TOOL_VERSION"),
		OpenSearchURL: getenv("ZASP_OPENSEARCH_ENDPOINT"), OpenSearchIndex: getenv("ZASP_OPENSEARCH_INDEX"), Neo4jURI: getenv("ZASP_NEO4J_URI"), Neo4jCredential: getenv("ZASP_NEO4J_CREDENTIAL_REFERENCE"),
	}
	config.ProjectionKind = projectionKind(config.Mode)
	if pollErr != nil || leaseErr != nil || shutdownErr != nil || batchErr != nil || !validWorkerRuntimeConfig(config) {
		return workerRuntimeConfig{}, errWorkerConfiguration
	}
	return config, nil
}

func validWorkerRuntimeConfig(config workerRuntimeConfig) bool {
	parsed, err := url.Parse(config.PostgresDSN)
	if err != nil || parsed.String() != config.PostgresDSN || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" || parsed.User == nil || parsed.Hostname() == "" || parsed.Path == "" || parsed.Fragment != "" {
		return false
	}
	wantAuthority := map[workerMode]string{
		workerModeOutbox: "zasp_outbox_worker", workerModeDiscovery: "zasp_discovery_worker", workerModeScheduler: "zasp_discovery_scheduler",
		workerModeProjectionRisk: "zasp_projection_risk_worker", workerModeProjectionGraph: "zasp_projection_graph_worker", workerModeProjectionSearch: "zasp_projection_search_worker",
	}[config.Mode]
	return wantAuthority != "" && config.DatabaseAuthority == wantAuthority && workerIdentityPattern.MatchString(config.WorkerID) && validModeDependencies(config) &&
		config.PollInterval >= 50*time.Millisecond && config.PollInterval <= time.Minute && config.LeaseDuration >= 5*time.Second && config.LeaseDuration <= 15*time.Minute &&
		config.BatchSize >= 1 && config.BatchSize <= 64 && config.ShutdownTimeout >= time.Second && config.ShutdownTimeout <= time.Minute && config.ShutdownTimeout < config.LeaseDuration
}

var (
	workerRegionPattern    = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`)
	workerBucketPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	workerAccountPattern   = regexp.MustCompile(`^[0-9]{12}$`)
	workerKMSPattern       = regexp.MustCompile(`^arn:aws:kms:[a-z]{2}(?:-gov)?-[a-z]+-[0-9]:[0-9]{12}:key/[0-9a-f-]{36}$`)
	workerVersionPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
	workerIndexPattern     = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,127}$`)
	workerReferencePattern = regexp.MustCompile(`^ref:neo4j/[a-z0-9][a-z0-9_./:-]{2,255}$`)
)

func validModeDependencies(config workerRuntimeConfig) bool {
	switch config.Mode {
	case workerModeOutbox:
		return validSQSURL(config.DiscoveryQueueURL)
	case workerModeDiscovery:
		return validSQSURL(config.DiscoveryQueueURL) && workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && workerKMSPattern.MatchString(config.EvidenceKMSKeyARN) && workerVersionPattern.MatchString(config.ParserVersion) && workerVersionPattern.MatchString(config.ToolVersion)
	case workerModeProjectionSearch:
		return validPrivateHTTPSURL(config.OpenSearchURL) && workerIndexPattern.MatchString(config.OpenSearchIndex)
	case workerModeProjectionGraph:
		parsed, err := url.Parse(config.Neo4jURI)
		return err == nil && parsed.Scheme == "neo4j+s" && parsed.Hostname() != "" && parsed.Port() == "7687" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && workerReferencePattern.MatchString(config.Neo4jCredential)
	case workerModeScheduler:
		return workerVersionPattern.MatchString(config.ParserVersion) && workerVersionPattern.MatchString(config.ToolVersion)
	case workerModeProjectionRisk:
		return true
	default:
		return false
	}
}

func validSQSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && regexp.MustCompile(`^sqs\.[a-z0-9-]+\.amazonaws\.com$`).MatchString(parsed.Hostname()) && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && regexp.MustCompile(`^/[0-9]{12}/[A-Za-z0-9_-]{1,80}$`).MatchString(parsed.Path)
}

func validPrivateHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func projectionKind(mode workerMode) string {
	switch mode {
	case workerModeProjectionRisk:
		return "risk"
	case workerModeProjectionGraph:
		return "graph"
	case workerModeProjectionSearch:
		return "search"
	default:
		return ""
	}
}
