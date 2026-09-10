package main

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type workerMode string

const (
	workerModeOutbox               workerMode = "outbox"
	workerModeRuntimeOutbox        workerMode = "runtime-outbox"
	workerModeRedTeamOutbox        workerMode = "red-team-outbox"
	workerModeAttackLabOutbox      workerMode = "attack-lab-outbox"
	workerModeAttackLabController  workerMode = "attack-lab-controller"
	workerModeRedTeam              workerMode = "red-team"
	workerModeRuntimeCoordinator   workerMode = "runtime-coordinator"
	workerModeRuntimeArchive       workerMode = "runtime-archive"
	workerModeRuntimeIndex         workerMode = "runtime-index"
	workerModeRuntimeCorrelation   workerMode = "runtime-correlation"
	workerModeRuntimeProjection    workerMode = "runtime-projection"
	workerModeRuntimeComplete      workerMode = "runtime-complete"
	workerModeDiscovery            workerMode = "discovery"
	workerModeScheduler            workerMode = "scheduler"
	workerModeProjectionRisk       workerMode = "projection-risk"
	workerModeProjectionGraph      workerMode = "projection-graph"
	workerModeProjectionSearch     workerMode = "projection-search"
	workerModeSecurityAgent        workerMode = "security-agent"
	workerModeSecurityAgentAction  workerMode = "security-agent-action"
	workerModeRecoveryOutbox       workerMode = "recovery-outbox"
	workerModeRecovery             workerMode = "recovery"
	workerModePolicyDeployment     workerMode = "policy-deployment"
	workerModeProjectionGraphInit  workerMode = "projection-graph-init"
	workerModeProjectionSearchInit workerMode = "projection-search-init"
)

var (
	errWorkerConfiguration = errors.New("worker runtime configuration rejected")
	workerIdentityPattern  = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,127}$`)
)

type workerRuntimeConfig struct {
	Mode                         workerMode
	ProjectionKind               string
	PostgresDSN                  string
	DatabaseAuthority            string
	WorkerID                     string
	PollInterval                 time.Duration
	LeaseDuration                time.Duration
	BatchSize                    int
	ShutdownTimeout              time.Duration
	DiscoveryQueueURL            string
	RuntimeQueueURL              string
	RedTeamQueueURL              string
	AttackLabQueueURL            string
	RecoveryQueueURL             string
	RecoveryOutboxTopic          string
	RecoveryOperationKind        string
	RecoveryRoleARN              string
	RecoveryTokenFile            string
	RecoverySigningKMSKeyARN     string
	RecoveryNeonProjectID        string
	RecoveryNeonBranchID         string
	RecoveryNeonSecretReference  string
	RecoveryKubernetesURL        string
	RecoveryKubernetesToken      string
	RecoveryKubernetesCA         string
	RecoveryRunnerImage          string
	RecoveryRunnerServiceAccount string
	RecoveryNeonEgressCIDRs      []string
	RuntimeRoleARN               string
	RuntimeTokenFile             string
	RuntimeStageRoleARN          string
	RuntimeStageTokenFile        string
	RuntimeStageVersion          string
	AWSRegion                    string
	EvidenceBucket               string
	EvidenceOwner                string
	EvidenceKMSKeyARN            string
	ParserVersion                string
	ToolVersion                  string
	DiscoveryRoleARN             string
	DiscoveryTokenFile           string
	DiscoverySecretPrefix        string
	AWSCollectorVersion          string
	KubernetesCollectorVersion   string
	GitHubCollectorVersion       string
	OktaCollectorVersion         string
	KubernetesEgressCIDRs        []string
	GitHubAppID                  string
	GitHubPrivateKeyReference    string
	OktaClientID                 string
	OktaClientSecretReference    string
	ProviderTimeout              time.Duration
	DiscoveryReadinessTimeout    time.Duration
	OpenSearchURL                string
	OpenSearchIndex              string
	Neo4jURI                     string
	Neo4jCredential              string
	Neo4jExpectedPrincipal       string
	Neo4jExpectedRole            string
	ProjectionRoleARN            string
	ProjectionTokenFile          string
	ProjectionSecretPrefix       string
	OutboxRoleARN                string
	OutboxTokenFile              string
	RedTeamRoleARN               string
	RedTeamTokenFile             string
	RedTeamTargetEndpoint        string
	RedTeamTargetTokenFile       string
	RedTeamTargetCAFile          string
	RedTeamRunnerTimeout         time.Duration
	AttackLabRoleARN             string
	AttackLabTokenFile           string
	AttackLabNamespace           string
	AttackLabRunnerService       string
	AttackLabRunnerTestRoleARN   string
	AttackLabRunnerImage         string
	AttackLabSecurityGroup       string
	AttackLabKubernetesURL       string
	AttackLabKubernetesToken     string
	AttackLabKubernetesCA        string
	AttackLabProxyEndpoint       string
	AttackLabProxyCAFile         string
	AttackLabSigningKeyFile      string
	AttackLabOperationTimeout    time.Duration
	GatewaySigningKeyID          string
	GatewaySigningPrivateFile    string
	SecurityAgentPlannerEndpoint string
	SecurityAgentPlannerModel    string
	SecurityAgentPlannerToken    string
	SecurityAgentPlannerTimeout  time.Duration
	SecurityAgentPlannerTokens   int
	SecurityAgentPlannerPolicy   string
}

func loadProjectionInitConfig(getenv func(string) string) (workerRuntimeConfig, error) {
	if getenv == nil {
		return workerRuntimeConfig{}, errWorkerConfiguration
	}
	timeout, err := time.ParseDuration(getenv("ZASP_PROJECTION_INIT_TIMEOUT"))
	config := workerRuntimeConfig{
		Mode: workerMode(getenv("ZASP_WORKER_MODE")), AWSRegion: getenv("ZASP_AWS_REGION"),
		ProjectionRoleARN: getenv("ZASP_PROJECTION_INIT_ROLE_ARN"), ProjectionTokenFile: getenv("ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE"),
		LeaseDuration: timeout, ShutdownTimeout: timeout, OpenSearchURL: getenv("ZASP_OPENSEARCH_ENDPOINT"), OpenSearchIndex: getenv("ZASP_OPENSEARCH_INDEX"),
		ProjectionSecretPrefix: getenv("ZASP_PROJECTION_SECRET_PREFIX"), Neo4jURI: getenv("ZASP_NEO4J_URI"), Neo4jCredential: getenv("ZASP_NEO4J_SCHEMA_CREDENTIAL_REFERENCE"),
	}
	if err != nil || !validProjectionInitConfig(config) {
		return workerRuntimeConfig{}, errWorkerConfiguration
	}
	return config, nil
}

func validProjectionInitConfig(config workerRuntimeConfig) bool {
	if config.Mode != workerModeProjectionSearchInit && config.Mode != workerModeProjectionGraphInit || config.LeaseDuration < 3*time.Second || config.LeaseDuration > 30*time.Second || !validProjectionAWSAuthority(config) {
		return false
	}
	if config.Mode == workerModeProjectionSearchInit {
		return validOpenSearchEndpoint(config.OpenSearchURL, config.AWSRegion) && config.OpenSearchIndex == "zasp-inventory-v1"
	}
	parsed, err := url.Parse(config.Neo4jURI)
	return validProjectionSecretPrefix(config.ProjectionSecretPrefix) && err == nil && parsed.Scheme == "neo4j+s" && parsed.Hostname() != "" && parsed.Port() == "7687" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && validNeo4jReference(config.Neo4jCredential)
}

func loadWorkerRuntimeConfig(getenv func(string) string) (workerRuntimeConfig, error) {
	if getenv == nil {
		return workerRuntimeConfig{}, errWorkerConfiguration
	}
	poll, pollErr := time.ParseDuration(getenv("ZASP_POLL_INTERVAL"))
	lease, leaseErr := time.ParseDuration(getenv("ZASP_LEASE_DURATION"))
	shutdown, shutdownErr := time.ParseDuration(getenv("ZASP_SHUTDOWN_TIMEOUT"))
	providerTimeout, providerTimeoutErr := time.ParseDuration(getenv("ZASP_PROVIDER_TIMEOUT"))
	discoveryReadinessTimeout, discoveryReadinessTimeoutErr := time.ParseDuration(getenv("ZASP_DISCOVERY_READINESS_TIMEOUT"))
	redTeamRunnerTimeout, redTeamRunnerTimeoutErr := time.ParseDuration(getenv("ZASP_RED_TEAM_RUNNER_TIMEOUT"))
	attackLabOperationTimeout, attackLabOperationTimeoutErr := time.ParseDuration(getenv("ZASP_ATTACK_LAB_OPERATION_TIMEOUT"))
	plannerTimeout, plannerTimeoutErr := time.ParseDuration(getenv("ZASP_SECURITY_AGENT_PLANNER_TIMEOUT"))
	plannerTokens, plannerTokensErr := strconv.Atoi(getenv("ZASP_SECURITY_AGENT_PLANNER_MAX_TOKENS"))
	batch, batchErr := strconv.Atoi(getenv("ZASP_BATCH_SIZE"))
	config := workerRuntimeConfig{
		Mode: workerMode(getenv("ZASP_WORKER_MODE")), PostgresDSN: getenv("ZASP_POSTGRES_DSN"),
		DatabaseAuthority: getenv("ZASP_DATABASE_AUTHORITY"), WorkerID: getenv("ZASP_WORKER_ID"),
		PollInterval: poll, LeaseDuration: lease, BatchSize: batch, ShutdownTimeout: shutdown,
		DiscoveryQueueURL: getenv("ZASP_DISCOVERY_QUEUE_URL"), RuntimeQueueURL: getenv("ZASP_RUNTIME_QUEUE_URL"), RedTeamQueueURL: getenv("ZASP_RED_TEAM_QUEUE_URL"), AttackLabQueueURL: getenv("ZASP_ATTACK_LAB_QUEUE_URL"), RecoveryQueueURL: getenv("ZASP_RECOVERY_QUEUE_URL"), RecoveryOutboxTopic: getenv("ZASP_RECOVERY_OUTBOX_TOPIC"), RecoveryOperationKind: getenv("ZASP_RECOVERY_OPERATION_KIND"), AWSRegion: getenv("ZASP_AWS_REGION"), EvidenceBucket: getenv("ZASP_EVIDENCE_BUCKET"), EvidenceOwner: getenv("ZASP_EVIDENCE_BUCKET_OWNER"),
		EvidenceKMSKeyARN: getenv("ZASP_EVIDENCE_KMS_KEY_ARN"), ParserVersion: getenv("ZASP_DISCOVERY_PARSER_VERSION"), ToolVersion: getenv("ZASP_DISCOVERY_TOOL_VERSION"),
		RecoveryRoleARN: getenv("ZASP_RECOVERY_ROLE_ARN"), RecoveryTokenFile: getenv("ZASP_RECOVERY_WEB_IDENTITY_TOKEN_FILE"), RecoverySigningKMSKeyARN: getenv("ZASP_RECOVERY_SIGNING_KMS_KEY_ARN"), RecoveryNeonProjectID: getenv("ZASP_RECOVERY_NEON_PROJECT_ID"), RecoveryNeonBranchID: getenv("ZASP_RECOVERY_NEON_BRANCH_ID"),
		RecoveryNeonSecretReference: getenv("ZASP_RECOVERY_NEON_SECRET_REFERENCE"), RecoveryKubernetesURL: getenv("ZASP_RECOVERY_KUBERNETES_ENDPOINT"), RecoveryKubernetesToken: getenv("ZASP_RECOVERY_KUBERNETES_TOKEN_FILE"), RecoveryKubernetesCA: getenv("ZASP_RECOVERY_KUBERNETES_CA_FILE"), RecoveryRunnerImage: getenv("ZASP_RECOVERY_RUNNER_IMAGE"), RecoveryRunnerServiceAccount: getenv("ZASP_RECOVERY_RUNNER_SERVICE_ACCOUNT"), RecoveryNeonEgressCIDRs: parseWorkerCIDRs(getenv("ZASP_RECOVERY_NEON_EGRESS_CIDRS")),
		DiscoveryRoleARN: getenv("ZASP_DISCOVERY_ROLE_ARN"), DiscoveryTokenFile: getenv("ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE"), DiscoverySecretPrefix: getenv("ZASP_DISCOVERY_SECRET_PREFIX"),
		AWSCollectorVersion: getenv("ZASP_DISCOVERY_AWS_COLLECTOR_VERSION"), KubernetesCollectorVersion: getenv("ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION"), GitHubCollectorVersion: getenv("ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION"), OktaCollectorVersion: getenv("ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION"),
		KubernetesEgressCIDRs: parseWorkerCIDRs(getenv("ZASP_KUBERNETES_EGRESS_CIDRS")), GitHubAppID: getenv("ZASP_GITHUB_APP_ID"), GitHubPrivateKeyReference: getenv("ZASP_GITHUB_PRIVATE_KEY_REFERENCE"),
		OktaClientID: getenv("ZASP_OKTA_CLIENT_ID"), OktaClientSecretReference: getenv("ZASP_OKTA_CLIENT_SECRET_REFERENCE"), ProviderTimeout: providerTimeout, DiscoveryReadinessTimeout: discoveryReadinessTimeout,
		OpenSearchURL: getenv("ZASP_OPENSEARCH_ENDPOINT"), OpenSearchIndex: getenv("ZASP_OPENSEARCH_INDEX"), Neo4jURI: getenv("ZASP_NEO4J_URI"), Neo4jCredential: getenv("ZASP_NEO4J_CREDENTIAL_REFERENCE"),
		Neo4jExpectedPrincipal: getenv("ZASP_NEO4J_EXPECTED_PRINCIPAL"), Neo4jExpectedRole: getenv("ZASP_NEO4J_EXPECTED_ROLE"),
		ProjectionRoleARN: getenv("ZASP_PROJECTION_ROLE_ARN"), ProjectionTokenFile: getenv("ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE"), ProjectionSecretPrefix: getenv("ZASP_PROJECTION_SECRET_PREFIX"),
		OutboxRoleARN: getenv("ZASP_OUTBOX_ROLE_ARN"), OutboxTokenFile: getenv("ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE"),
		RedTeamRoleARN: getenv("ZASP_RED_TEAM_ROLE_ARN"), RedTeamTokenFile: getenv("ZASP_RED_TEAM_WEB_IDENTITY_TOKEN_FILE"), RedTeamTargetEndpoint: getenv("ZASP_RED_TEAM_TARGET_ENDPOINT"), RedTeamTargetTokenFile: getenv("ZASP_RED_TEAM_TARGET_TOKEN_FILE"), RedTeamTargetCAFile: getenv("ZASP_RED_TEAM_TARGET_CA_FILE"), RedTeamRunnerTimeout: redTeamRunnerTimeout,
		AttackLabRunnerTestRoleARN: getenv("ZASP_ATTACK_LAB_RUNNER_TEST_ROLE_ARN"), AttackLabRoleARN: getenv("ZASP_ATTACK_LAB_ROLE_ARN"), AttackLabTokenFile: getenv("ZASP_ATTACK_LAB_WEB_IDENTITY_TOKEN_FILE"), AttackLabNamespace: getenv("ZASP_ATTACK_LAB_NAMESPACE"), AttackLabRunnerService: getenv("ZASP_ATTACK_LAB_RUNNER_SERVICE_ACCOUNT"), AttackLabRunnerImage: getenv("ZASP_ATTACK_LAB_RUNNER_IMAGE"),
		AttackLabSecurityGroup: getenv("ZASP_ATTACK_LAB_SECURITY_GROUP_ID"),
		AttackLabKubernetesURL: getenv("ZASP_ATTACK_LAB_KUBERNETES_ENDPOINT"), AttackLabKubernetesToken: getenv("ZASP_ATTACK_LAB_KUBERNETES_TOKEN_FILE"), AttackLabKubernetesCA: getenv("ZASP_ATTACK_LAB_KUBERNETES_CA_FILE"), AttackLabProxyEndpoint: getenv("ZASP_ATTACK_LAB_PROXY_ENDPOINT"), AttackLabProxyCAFile: getenv("ZASP_ATTACK_LAB_PROXY_CA_FILE"), AttackLabSigningKeyFile: getenv("ZASP_ATTACK_LAB_EGRESS_SIGNING_KEY_FILE"), AttackLabOperationTimeout: attackLabOperationTimeout,
		GatewaySigningKeyID: getenv("ZASP_GATEWAY_SIGNING_KEY_ID"), GatewaySigningPrivateFile: getenv("ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE"),
		SecurityAgentPlannerEndpoint: getenv("ZASP_SECURITY_AGENT_PLANNER_ENDPOINT"), SecurityAgentPlannerModel: getenv("ZASP_SECURITY_AGENT_PLANNER_MODEL"), SecurityAgentPlannerToken: getenv("ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE"), SecurityAgentPlannerTimeout: plannerTimeout, SecurityAgentPlannerTokens: plannerTokens, SecurityAgentPlannerPolicy: getenv("ZASP_SECURITY_AGENT_PLANNER_POLICY_VERSION"),
		RuntimeRoleARN: getenv("ZASP_RUNTIME_ROLE_ARN"), RuntimeTokenFile: getenv("ZASP_RUNTIME_WEB_IDENTITY_TOKEN_FILE"),
		RuntimeStageRoleARN: getenv("ZASP_RUNTIME_STAGE_ROLE_ARN"), RuntimeStageTokenFile: getenv("ZASP_RUNTIME_STAGE_WEB_IDENTITY_TOKEN_FILE"), RuntimeStageVersion: getenv("ZASP_RUNTIME_STAGE_VERSION"),
	}
	config.ProjectionKind = projectionKind(config.Mode)
	if pollErr != nil || leaseErr != nil || shutdownErr != nil || batchErr != nil || config.Mode == workerModeDiscovery && (providerTimeoutErr != nil || discoveryReadinessTimeoutErr != nil) || config.Mode == workerModeRedTeam && redTeamRunnerTimeoutErr != nil || config.Mode == workerModeAttackLabController && attackLabOperationTimeoutErr != nil || config.Mode == workerModeSecurityAgent && (plannerTimeoutErr != nil || plannerTokensErr != nil) || !validWorkerRuntimeConfig(config) {
		return workerRuntimeConfig{}, errWorkerConfiguration
	}
	return config, nil
}

func parseWorkerCIDRs(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func validWorkerRuntimeConfig(config workerRuntimeConfig) bool {
	parsed, err := url.Parse(config.PostgresDSN)
	if err != nil || parsed.String() != config.PostgresDSN || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" || parsed.User == nil || parsed.Hostname() == "" || parsed.Path == "" || parsed.Fragment != "" {
		return false
	}
	wantAuthority := map[workerMode]string{
		workerModeOutbox: "zasp_outbox_worker", workerModeRuntimeOutbox: "zasp_outbox_worker", workerModeRedTeamOutbox: "zasp_red_team_outbox_worker", workerModeAttackLabOutbox: "zasp_attack_lab_outbox_worker", workerModeAttackLabController: "zasp_attack_lab_controller", workerModeRedTeam: "zasp_red_team_worker", workerModeDiscovery: "zasp_discovery_worker", workerModeScheduler: "zasp_discovery_scheduler",
		workerModeRuntimeCoordinator: "zasp_runtime_coordinator",
		workerModeRuntimeArchive:     "zasp_runtime_archive_worker",
		workerModeRuntimeIndex:       "zasp_runtime_index_worker",
		workerModeRuntimeCorrelation: "zasp_runtime_correlation_worker",
		workerModeRuntimeProjection:  "zasp_runtime_projection_worker",
		workerModeRuntimeComplete:    "zasp_runtime_coordinator",
		workerModeProjectionRisk:     "zasp_projection_risk_worker", workerModeProjectionGraph: "zasp_projection_graph_worker", workerModeProjectionSearch: "zasp_projection_search_worker",
		workerModeSecurityAgent:       "zasp_security_agent_worker",
		workerModeSecurityAgentAction: "zasp_security_agent_action_worker",
		workerModeRecoveryOutbox:      "zasp_recovery_outbox_worker",
		workerModeRecovery:            "zasp_recovery_worker",
		workerModePolicyDeployment:    "zasp_policy_deployment_worker",
	}[config.Mode]
	return wantAuthority != "" && config.DatabaseAuthority == wantAuthority && workerIdentityPattern.MatchString(config.WorkerID) && validModeDependencies(config) &&
		config.PollInterval >= 50*time.Millisecond && config.PollInterval <= time.Minute && config.LeaseDuration >= 5*time.Second && config.LeaseDuration <= 15*time.Minute &&
		config.BatchSize >= 1 && config.BatchSize <= 64 && (config.Mode != workerModeDiscovery && config.Mode != workerModeAttackLabController && config.Mode != workerModeRuntimeCoordinator && config.Mode != workerModeRuntimeArchive && config.Mode != workerModeRuntimeIndex && config.Mode != workerModeRuntimeCorrelation && config.Mode != workerModeRuntimeProjection && config.Mode != workerModeRuntimeComplete || config.BatchSize <= 10) && (config.Mode != workerModeRecovery && config.Mode != workerModeRecoveryOutbox || config.BatchSize <= 25) && config.ShutdownTimeout >= time.Second && config.ShutdownTimeout <= time.Minute && config.ShutdownTimeout < config.LeaseDuration
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
	projectionPrincipalPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	recoveryNeonProjectPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)
	recoveryNeonBranchPattern   = regexp.MustCompile(`^br-[a-z0-9][a-z0-9-]{1,62}$`)
)

func validModeDependencies(config workerRuntimeConfig) bool {
	switch config.Mode {
	case workerModeOutbox, workerModeRuntimeOutbox, workerModeRedTeamOutbox, workerModeAttackLabOutbox, workerModeRecoveryOutbox:
		return validOutboxAWSAuthority(config)
	case workerModeRecovery:
		return validRecoveryRuntimeAuthority(config)
	case workerModeRedTeam:
		return validRedTeamRuntimeAuthority(config)
	case workerModeAttackLabController:
		return validAttackLabRuntimeAuthority(config)
	case workerModeRuntimeCoordinator:
		return validRuntimeCoordinatorAWSAuthority(config)
	case workerModeRuntimeArchive:
		return validRuntimeArchiveAWSAuthority(config)
	case workerModeRuntimeIndex:
		return validRuntimeIndexAWSAuthority(config)
	case workerModeRuntimeCorrelation:
		return validRuntimeCorrelationAWSAuthority(config)
	case workerModeRuntimeProjection:
		return validRuntimeProjectionAWSAuthority(config)
	case workerModeRuntimeComplete:
		return validRuntimeCompleteAWSAuthority(config)
	case workerModeDiscovery:
		return validDiscoveryRuntimeAuthority(config)
	case workerModeProjectionSearch:
		return validProjectionAWSAuthority(config) && validOpenSearchEndpoint(config.OpenSearchURL, config.AWSRegion) && config.OpenSearchIndex == "zasp-inventory-v1"
	case workerModeProjectionGraph:
		parsed, err := url.Parse(config.Neo4jURI)
		return validProjectionAWSAuthority(config) && validProjectionSecretPrefix(config.ProjectionSecretPrefix) && err == nil && parsed.Scheme == "neo4j+s" && parsed.Hostname() != "" && parsed.Port() == "7687" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && validNeo4jReference(config.Neo4jCredential) && projectionPrincipalPattern.MatchString(config.Neo4jExpectedPrincipal) && projectionPrincipalPattern.MatchString(config.Neo4jExpectedRole)
	case workerModeScheduler:
		return workerVersionPattern.MatchString(config.ParserVersion) && workerVersionPattern.MatchString(config.ToolVersion)
	case workerModeProjectionRisk:
		return true
	case workerModeSecurityAgent:
		return config.LeaseDuration >= 30*time.Second && config.LeaseDuration <= 5*time.Minute && config.BatchSize <= 25 && config.SecurityAgentPlannerEndpoint == "https://openrouter.ai/api/v1/chat/completions" && config.SecurityAgentPlannerModel == "openai/gpt-5-mini" && config.SecurityAgentPlannerToken == "/var/run/secrets/zasp-security-agent/openrouter-api-token" && config.SecurityAgentPlannerTimeout >= time.Second && config.SecurityAgentPlannerTimeout <= 30*time.Second && config.SecurityAgentPlannerTokens >= 1 && config.SecurityAgentPlannerTokens <= 4096 && config.SecurityAgentPlannerPolicy == "security-agent-planner-v1" && config.DiscoveryQueueURL == "" && config.RuntimeQueueURL == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == "" && config.RuntimeRoleARN == "" && config.RuntimeStageRoleARN == ""
	case workerModeSecurityAgentAction:
		return config.LeaseDuration >= 30*time.Second && config.LeaseDuration <= 5*time.Minute && config.BatchSize <= 25 && regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`).MatchString(config.GatewaySigningKeyID) && config.GatewaySigningPrivateFile == "/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key" && config.DiscoveryQueueURL == "" && config.RuntimeQueueURL == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == "" && config.RuntimeRoleARN == "" && config.RuntimeStageRoleARN == ""
	case workerModePolicyDeployment:
		return config.LeaseDuration >= 30*time.Second && config.LeaseDuration <= 5*time.Minute && config.BatchSize <= 25 && regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`).MatchString(config.GatewaySigningKeyID) && config.GatewaySigningPrivateFile == "/var/run/secrets/zasp-policy-deployment/gateway-signing-private-key" && config.DiscoveryQueueURL == "" && config.RuntimeQueueURL == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == "" && config.RuntimeRoleARN == "" && config.RuntimeStageRoleARN == ""
	default:
		return false
	}
}

func validRuntimeArchiveAWSAuthority(config workerRuntimeConfig) bool {
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RuntimeStageRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	return len(role) == 2 && len(kms) == 3 && workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && role[1] == config.EvidenceOwner && kms[1] == config.AWSRegion && kms[2] == config.EvidenceOwner && config.RuntimeStageTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && config.RuntimeStageVersion == "runtime-archive-v1" && config.RuntimeQueueURL == "" && config.DiscoveryQueueURL == "" && config.RuntimeRoleARN == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == ""
}

func validRuntimeIndexAWSAuthority(config workerRuntimeConfig) bool {
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RuntimeStageRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	return len(role) == 2 && len(kms) == 3 && workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && role[1] == config.EvidenceOwner && kms[1] == config.AWSRegion && kms[2] == config.EvidenceOwner && config.RuntimeStageTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && config.RuntimeStageVersion == "runtime-index-v1" && validOpenSearchEndpoint(config.OpenSearchURL, config.AWSRegion) && config.OpenSearchIndex == "zasp-runtime-events-v1" && config.RuntimeQueueURL == "" && config.DiscoveryQueueURL == "" && config.RuntimeRoleARN == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == ""
}

func validRuntimeCorrelationAWSAuthority(config workerRuntimeConfig) bool {
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RuntimeStageRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	return len(role) == 2 && len(kms) == 3 && workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && role[1] == config.EvidenceOwner && kms[1] == config.AWSRegion && kms[2] == config.EvidenceOwner && config.RuntimeStageTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && (config.RuntimeStageVersion == "runtime-correlation-v1" || config.RuntimeStageVersion == "runtime-correlation-v2") && validRuntimeGraphAuthority(config) && config.OpenSearchURL == "" && config.OpenSearchIndex == "" && config.RuntimeQueueURL == "" && config.DiscoveryQueueURL == "" && config.RuntimeRoleARN == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == ""
}

func validRuntimeProjectionAWSAuthority(config workerRuntimeConfig) bool {
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RuntimeStageRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	return len(role) == 2 && len(kms) == 3 && workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && role[1] == config.EvidenceOwner && kms[1] == config.AWSRegion && kms[2] == config.EvidenceOwner && config.RuntimeStageTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && config.RuntimeStageVersion == "runtime-projection-v1" && validRuntimeGraphAuthority(config) && config.OpenSearchURL == "" && config.OpenSearchIndex == "" && config.RuntimeQueueURL == "" && config.DiscoveryQueueURL == "" && config.RuntimeRoleARN == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == ""
}

func validRuntimeGraphAuthority(config workerRuntimeConfig) bool {
	parsed, err := url.Parse(config.Neo4jURI)
	return err == nil && parsed.Scheme == "neo4j+s" && parsed.Hostname() != "" && parsed.Port() == "7687" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && validProjectionSecretPrefix(config.ProjectionSecretPrefix) && validNeo4jReference(config.Neo4jCredential) && projectionPrincipalPattern.MatchString(config.Neo4jExpectedPrincipal) && projectionPrincipalPattern.MatchString(config.Neo4jExpectedRole)
}

func validRuntimeCompleteAWSAuthority(config workerRuntimeConfig) bool {
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RuntimeStageRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	return len(role) == 2 && len(kms) == 3 && workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && role[1] == config.EvidenceOwner && kms[1] == config.AWSRegion && kms[2] == config.EvidenceOwner && config.RuntimeStageTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && config.RuntimeStageVersion == "runtime-complete-v1" && config.OpenSearchURL == "" && config.OpenSearchIndex == "" && config.RuntimeQueueURL == "" && config.DiscoveryQueueURL == "" && config.RuntimeRoleARN == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == ""
}

func validRuntimeCoordinatorAWSAuthority(config workerRuntimeConfig) bool {
	queue, err := url.Parse(config.RuntimeQueueURL)
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RuntimeRoleARN)
	if err != nil || queue == nil || !validSQSURL(config.RuntimeQueueURL) || len(role) != 2 || !workerRegionPattern.MatchString(config.AWSRegion) || config.RuntimeTokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || config.DiscoveryQueueURL != "" || config.OutboxRoleARN != "" || config.OutboxTokenFile != "" || config.DiscoveryRoleARN != "" || config.ProjectionRoleARN != "" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(queue.Path, "/"), "/")
	return len(parts) == 2 && parts[0] == role[1] && parts[1] == "agentsec-runtime-events" && queue.Hostname() == "sqs."+config.AWSRegion+".amazonaws.com"
}

func validDiscoveryRuntimeAuthority(config workerRuntimeConfig) bool {
	queue, queueErr := url.Parse(config.DiscoveryQueueURL)
	role := discoveryAWSRolePattern.FindStringSubmatch(config.DiscoveryRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	if queueErr != nil || queue == nil || !validSQSURL(config.DiscoveryQueueURL) || len(role) != 2 || len(kms) != 3 {
		return false
	}
	queueParts := strings.Split(strings.TrimPrefix(queue.Path, "/"), "/")
	if len(queueParts) != 2 || queueParts[1] != "agentsec-discovery-jobs" {
		return false
	}
	if queue.Hostname() != "sqs."+config.AWSRegion+".amazonaws.com" || queueParts[0] != role[1] || role[1] != config.EvidenceOwner || kms[1] != config.AWSRegion || kms[2] != config.EvidenceOwner {
		return false
	}
	for _, version := range []string{config.AWSCollectorVersion, config.KubernetesCollectorVersion, config.GitHubCollectorVersion, config.OktaCollectorVersion, config.ParserVersion, config.ToolVersion} {
		if !workerVersionPattern.MatchString(version) {
			return false
		}
	}
	return workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) &&
		config.DiscoveryTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && validDiscoverySecretRoot(config.DiscoverySecretPrefix) &&
		validDiscoveryCIDRs(config.KubernetesEgressCIDRs) && discoveryGitHubAppIDPattern.MatchString(config.GitHubAppID) && validDiscoveryCredentialReference(config.GitHubPrivateKeyReference, "ref:github/") &&
		discoveryOktaClientIDPattern.MatchString(config.OktaClientID) && validDiscoveryCredentialReference(config.OktaClientSecretReference, "ref:okta/") &&
		config.ProviderTimeout >= 100*time.Millisecond && config.ProviderTimeout <= 30*time.Second && config.DiscoveryReadinessTimeout >= time.Second && config.DiscoveryReadinessTimeout <= 10*time.Second
}

func validOutboxAWSAuthority(config workerRuntimeConfig) bool {
	queueURL, queueName, ok := outboxQueueAuthority(config)
	roleARN, tokenFile := outboxRoleAuthority(config)
	queue, err := url.Parse(queueURL)
	if !ok || err != nil || !validSQSURL(queueURL) || !workerRegionPattern.MatchString(config.AWSRegion) || !workerProjectionRolePattern.MatchString(roleARN) || tokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" {
		return false
	}
	queueParts := strings.Split(strings.TrimPrefix(queue.Path, "/"), "/")
	roleParts := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/`).FindStringSubmatch(roleARN)
	return len(queueParts) == 2 && len(roleParts) == 2 && queueParts[0] == roleParts[1] && queueParts[1] == queueName && queue.Hostname() == "sqs."+config.AWSRegion+".amazonaws.com"
}

func outboxRoleAuthority(config workerRuntimeConfig) (string, string) {
	if config.Mode == workerModeRecoveryOutbox {
		return config.RecoveryRoleARN, config.RecoveryTokenFile
	}
	return config.OutboxRoleARN, config.OutboxTokenFile
}

func outboxQueueAuthority(config workerRuntimeConfig) (string, string, bool) {
	switch config.Mode {
	case workerModeOutbox:
		return config.DiscoveryQueueURL, "agentsec-discovery-jobs", config.RuntimeQueueURL == ""
	case workerModeRuntimeOutbox:
		return config.RuntimeQueueURL, "agentsec-runtime-events", config.DiscoveryQueueURL == ""
	case workerModeRedTeamOutbox:
		return config.RedTeamQueueURL, "agentsec-red-team-tests", config.DiscoveryQueueURL == "" && config.RuntimeQueueURL == "" && config.AttackLabQueueURL == ""
	case workerModeAttackLabOutbox:
		return config.AttackLabQueueURL, "agentsec-attack-lab-jobs", config.DiscoveryQueueURL == "" && config.RuntimeQueueURL == "" && config.RedTeamQueueURL == ""
	case workerModeRecoveryOutbox:
		name := ""
		if config.RecoveryOutboxTopic == recoveryBackupOutboxTopic {
			name = "agentsec-recovery-backup-jobs"
		} else if config.RecoveryOutboxTopic == recoveryRestoreOutboxTopic {
			name = "agentsec-recovery-restore-jobs"
		}
		return config.RecoveryQueueURL, name, name != "" && config.DiscoveryQueueURL == "" && config.RuntimeQueueURL == "" && config.RedTeamQueueURL == "" && config.AttackLabQueueURL == "" && config.OutboxRoleARN == "" && config.OutboxTokenFile == "" && config.DiscoveryRoleARN == "" && config.DiscoveryTokenFile == "" && config.ProjectionRoleARN == "" && config.ProjectionTokenFile == "" && config.RuntimeRoleARN == "" && config.RuntimeTokenFile == "" && config.RuntimeStageRoleARN == "" && config.RuntimeStageTokenFile == "" && config.RedTeamRoleARN == "" && config.RedTeamTokenFile == "" && config.AttackLabRoleARN == "" && config.AttackLabTokenFile == "" && config.RecoveryOperationKind == "" && config.EvidenceBucket == "" && config.EvidenceOwner == "" && config.EvidenceKMSKeyARN == "" && config.RecoverySigningKMSKeyARN == "" && config.RecoveryNeonProjectID == "" && config.RecoveryNeonBranchID == ""
	default:
		return "", "", false
	}
}

func validRecoveryRuntimeAuthority(config workerRuntimeConfig) bool {
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RecoveryRoleARN)
	encryption := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	signing := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.RecoverySigningKMSKeyARN)
	queue, queueErr := url.Parse(config.RecoveryQueueURL)
	queueParts := []string(nil)
	if queueErr == nil && queue != nil {
		queueParts = strings.Split(strings.TrimPrefix(queue.Path, "/"), "/")
	}
	expectedQueue := "agentsec-recovery-" + config.RecoveryOperationKind + "-jobs"
	if !stringInWorker(config.RecoveryOperationKind, "backup", "restore") || len(role) != 2 || len(encryption) != 3 || len(signing) != 3 || config.EvidenceKMSKeyARN == config.RecoverySigningKMSKeyARN || !workerRegionPattern.MatchString(config.AWSRegion) || !workerBucketPattern.MatchString(config.EvidenceBucket) || !workerAccountPattern.MatchString(config.EvidenceOwner) || role[1] != config.EvidenceOwner || encryption[1] != config.AWSRegion || encryption[2] != config.EvidenceOwner || signing[1] != config.AWSRegion || signing[2] != config.EvidenceOwner || config.RecoveryTokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !recoveryNeonProjectPattern.MatchString(config.RecoveryNeonProjectID) || !recoveryNeonBranchPattern.MatchString(config.RecoveryNeonBranchID) || queueErr != nil || queue == nil || !validSQSURL(config.RecoveryQueueURL) || queue.Hostname() != "sqs."+config.AWSRegion+".amazonaws.com" || len(queueParts) != 2 || queueParts[0] != role[1] || queueParts[1] != expectedQueue || config.RecoveryOutboxTopic != "" || config.DiscoveryQueueURL != "" || config.RuntimeQueueURL != "" || config.RedTeamQueueURL != "" || config.AttackLabQueueURL != "" || config.OutboxRoleARN != "" || config.OutboxTokenFile != "" || config.DiscoveryRoleARN != "" || config.DiscoveryTokenFile != "" || config.ProjectionRoleARN != "" || config.ProjectionTokenFile != "" || config.RuntimeRoleARN != "" || config.RuntimeTokenFile != "" || config.RuntimeStageRoleARN != "" || config.RuntimeStageTokenFile != "" || config.RedTeamRoleARN != "" || config.RedTeamTokenFile != "" || config.AttackLabRoleARN != "" || config.AttackLabTokenFile != "" {
		return false
	}
	if config.RecoveryOperationKind == "backup" {
		return config.RecoveryNeonSecretReference == "" && config.RecoveryKubernetesURL == "" && config.RecoveryKubernetesToken == "" && config.RecoveryKubernetesCA == "" && config.RecoveryRunnerImage == "" && config.RecoveryRunnerServiceAccount == "" && len(config.RecoveryNeonEgressCIDRs) == 0
	}
	image := regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.amazonaws\.com/zasp/agentsec-worker@sha256:[a-f0-9]{64}$`).FindStringSubmatch(config.RecoveryRunnerImage)
	parsedPostgres, postgresErr := url.Parse(config.PostgresDSN)
	return postgresErr == nil && regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.neon\.tech$`).MatchString(parsedPostgres.Hostname()) && config.RecoveryNeonSecretReference == "ref:neon/project-api-key" && config.RecoveryKubernetesURL == "https://kubernetes.default.svc" && config.RecoveryKubernetesToken == "/var/run/secrets/kubernetes.io/serviceaccount/token" && config.RecoveryKubernetesCA == "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" && config.RecoveryRunnerServiceAccount == "agentsec-recovery-runner" && len(image) == 3 && image[1] == config.EvidenceOwner && image[2] == config.AWSRegion && validRecoveryNeonCIDRs(config.RecoveryNeonEgressCIDRs)
}

func validRecoveryNeonCIDRs(values []string) bool {
	if len(values) < 1 || len(values) > 16 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil || network.String() != value || network.IP.IsUnspecified() || network.IP.IsLoopback() || network.IP.IsMulticast() || network.IP.IsLinkLocalUnicast() {
			return false
		}
		ones, bits := network.Mask.Size()
		if bits != 32 && bits != 128 || bits == 32 && ones < 24 || bits == 128 && ones < 64 {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validRedTeamRuntimeAuthority(config workerRuntimeConfig) bool {
	queue, queueErr := url.Parse(config.RedTeamQueueURL)
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.RedTeamRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	if queueErr != nil || queue == nil || !validSQSURL(config.RedTeamQueueURL) || len(role) != 2 || len(kms) != 3 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(queue.Path, "/"), "/")
	return len(parts) == 2 && parts[0] == role[1] && parts[1] == "agentsec-red-team-tests" && queue.Hostname() == "sqs."+config.AWSRegion+".amazonaws.com" &&
		workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && role[1] == config.EvidenceOwner && kms[1] == config.AWSRegion && kms[2] == config.EvidenceOwner &&
		config.RedTeamTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && redTeamTargetEndpointPattern.MatchString(config.RedTeamTargetEndpoint) && config.RedTeamTargetTokenFile == "/var/run/secrets/zasp-red-team/adapter-token" && config.RedTeamTargetCAFile == "/var/run/secrets/zasp-red-team/adapter-ca.crt" && config.RedTeamRunnerTimeout >= 30*time.Second && config.RedTeamRunnerTimeout <= 15*time.Minute
}

func validAttackLabRuntimeAuthority(config workerRuntimeConfig) bool {
	queue, queueErr := url.Parse(config.AttackLabQueueURL)
	role := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`).FindStringSubmatch(config.AttackLabRoleARN)
	kms := regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key/[0-9a-f-]{36}$`).FindStringSubmatch(config.EvidenceKMSKeyARN)
	image := regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.amazonaws\.com/zasp/attack-lab-runner@sha256:[a-f0-9]{64}$`).FindStringSubmatch(config.AttackLabRunnerImage)
	if queueErr != nil || queue == nil || !validSQSURL(config.AttackLabQueueURL) || len(role) != 2 || len(kms) != 3 || len(image) != 3 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(queue.Path, "/"), "/")
	return len(parts) == 2 && parts[0] == role[1] && parts[1] == "agentsec-attack-lab-jobs" && queue.Hostname() == "sqs."+config.AWSRegion+".amazonaws.com" &&
		workerRegionPattern.MatchString(config.AWSRegion) && workerBucketPattern.MatchString(config.EvidenceBucket) && workerAccountPattern.MatchString(config.EvidenceOwner) && role[1] == config.EvidenceOwner && kms[1] == config.AWSRegion && kms[2] == config.EvidenceOwner && image[1] == config.EvidenceOwner && image[2] == config.AWSRegion &&
		config.AttackLabTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && config.AttackLabNamespace == "zasp-attack-lab" && config.AttackLabRunnerService == "agentsec-attack-lab-runner" &&
		validAttackLabTestRole(config.AttackLabRunnerTestRoleARN, config.EvidenceOwner) && config.AttackLabRunnerTestRoleARN != config.AttackLabRoleARN &&
		attackLabKubernetesSecurityGroupPattern.MatchString(config.AttackLabSecurityGroup) &&
		config.AttackLabKubernetesURL == "https://kubernetes.default.svc" && config.AttackLabKubernetesToken == "/var/run/secrets/kubernetes.io/serviceaccount/token" && config.AttackLabKubernetesCA == "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" &&
		config.AttackLabProxyEndpoint == "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress" && config.AttackLabProxyCAFile == "/var/run/secrets/zasp-attack-lab/proxy-ca.crt" && config.AttackLabSigningKeyFile == "/var/run/secrets/zasp-attack-lab/egress-signing-key" &&
		config.AttackLabOperationTimeout >= time.Second && config.AttackLabOperationTimeout <= 30*time.Second && config.DiscoveryQueueURL == "" && config.RuntimeQueueURL == "" && config.RedTeamQueueURL == "" && config.OutboxRoleARN == "" && config.DiscoveryRoleARN == "" && config.ProjectionRoleARN == "" && config.RuntimeRoleARN == "" && config.RuntimeStageRoleARN == ""
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
	const prefix = "ref:neo4j/auth/"
	return strings.HasPrefix(value, prefix) && projectionNeo4jIDPattern.MatchString(strings.TrimPrefix(value, prefix))
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
