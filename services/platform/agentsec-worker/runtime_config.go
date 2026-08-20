package main

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
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
	Mode                   workerMode
	ProjectionKind         string
	PostgresDSN            string
	DatabaseAuthority      string
	WorkerID               string
	PollInterval           time.Duration
	LeaseDuration          time.Duration
	BatchSize              int
	ShutdownTimeout        time.Duration
	DiscoveryQueueURL      string
	AWSRegion              string
	EvidenceBucket         string
	EvidenceOwner          string
	EvidenceKMSKeyARN      string
	ParserVersion          string
	ToolVersion            string
	OpenSearchURL          string
	OpenSearchIndex        string
	Neo4jURI               string
	Neo4jCredential        string
	ProjectionRoleARN      string
	ProjectionTokenFile    string
	ProjectionSecretPrefix string
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
		ProjectionRoleARN: getenv("ZASP_PROJECTION_ROLE_ARN"), ProjectionTokenFile: getenv("ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE"), ProjectionSecretPrefix: getenv("ZASP_PROJECTION_SECRET_PREFIX"),
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
	workerRegionPattern         = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`)
	workerBucketPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	workerAccountPattern        = regexp.MustCompile(`^[0-9]{12}$`)
	workerKMSPattern            = regexp.MustCompile(`^arn:aws:kms:[a-z]{2}(?:-gov)?-[a-z]+-[0-9]:[0-9]{12}:key/[0-9a-f-]{36}$`)
	workerVersionPattern        = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
	workerProjectionRolePattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
	workerSecretPrefixPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_./-]{2,127}$`)
	projectionNeo4jIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,127}$`)
)

func validModeDependencies(config workerRuntimeConfig) bool {
	switch config.Mode {
	case workerModeOutbox:
		return validSQSURL(config.DiscoveryQueueURL)
	case workerModeDiscovery:
		return validSQSURL(config.DiscoveryQueueURL) && workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && workerKMSPattern.MatchString(config.EvidenceKMSKeyARN) && workerVersionPattern.MatchString(config.ParserVersion) && workerVersionPattern.MatchString(config.ToolVersion)
	case workerModeProjectionSearch:
		return validProjectionAWSAuthority(config) && validOpenSearchEndpoint(config.OpenSearchURL, config.AWSRegion) && config.OpenSearchIndex == "zasp-inventory-v1"
	case workerModeProjectionGraph:
		parsed, err := url.Parse(config.Neo4jURI)
		return validProjectionAWSAuthority(config) && validProjectionSecretPrefix(config.ProjectionSecretPrefix) && err == nil && parsed.Scheme == "neo4j+s" && parsed.Hostname() != "" && parsed.Port() == "7687" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && validNeo4jReference(config.Neo4jCredential)
	case workerModeScheduler:
		return workerVersionPattern.MatchString(config.ParserVersion) && workerVersionPattern.MatchString(config.ToolVersion)
	case workerModeProjectionRisk:
		return true
	default:
		return false
	}
}

func validProjectionAWSAuthority(config workerRuntimeConfig) bool {
	return workerRegionPattern.MatchString(config.AWSRegion) && workerProjectionRolePattern.MatchString(config.ProjectionRoleARN) && config.ProjectionTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
}

func validOpenSearchEndpoint(value, region string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.String() != value || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	host := parsed.Hostname()
	suffix := "." + region + ".es.amazonaws.com"
	name := strings.TrimSuffix(host, suffix)
	return strings.HasSuffix(host, suffix) && regexp.MustCompile(`^(?:search|vpc)-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(name)
}

func validProjectionSecretPrefix(value string) bool {
	return workerSecretPrefixPattern.MatchString(value) && !strings.Contains(value, "//") && !strings.Contains(value, "..") && !strings.HasSuffix(value, "/")
}

func validNeo4jReference(value string) bool {
	return strings.HasPrefix(value, "ref:neo4j/") && projectionNeo4jIDPattern.MatchString(strings.TrimPrefix(value, "ref:neo4j/"))
}

func validSQSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && regexp.MustCompile(`^sqs\.[a-z0-9-]+\.amazonaws\.com$`).MatchString(parsed.Hostname()) && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && regexp.MustCompile(`^/[0-9]{12}/[A-Za-z0-9_-]{1,80}$`).MatchString(parsed.Path)
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
