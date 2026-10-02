package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresDSNEnvironment                  = "ZASP_POSTGRES_DSN"
	migrationTimeoutEnvironment             = "ZASP_MIGRATION_TIMEOUT"
	migrationPrincipalEnvironment           = "ZASP_MIGRATION_DB_PRINCIPAL"
	discoveryAPIPrincipalEnvironment        = "ZASP_DISCOVERY_API_DB_PRINCIPAL"
	discoveryWorkerPrincipalEnvironment     = "ZASP_DISCOVERY_WORKER_DB_PRINCIPAL"
	runtimeIngestPrincipalEnvironment       = "ZASP_RUNTIME_INGEST_DB_PRINCIPAL"
	runtimeWorkerPrincipalEnvironment       = "ZASP_RUNTIME_WORKER_DB_PRINCIPAL"
	outboxWorkerPrincipalEnvironment        = "ZASP_OUTBOX_WORKER_DB_PRINCIPAL"
	runtimeGatewayPrincipalEnvironment      = "ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL"
	discoverySchedulerPrincipalEnvironment  = "ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL"
	projectionRiskPrincipalEnvironment      = "ZASP_PROJECTION_RISK_DB_PRINCIPAL"
	projectionGraphPrincipalEnvironment     = "ZASP_PROJECTION_GRAPH_DB_PRINCIPAL"
	projectionSearchPrincipalEnvironment    = "ZASP_PROJECTION_SEARCH_DB_PRINCIPAL"
	runtimeCoordinatorPrincipalEnvironment  = "ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL"
	runtimeArchivePrincipalEnvironment      = "ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL"
	runtimeIndexPrincipalEnvironment        = "ZASP_RUNTIME_INDEX_DB_PRINCIPAL"
	runtimeCorrelationPrincipalEnvironment  = "ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL"
	runtimeProjectionPrincipalEnvironment   = "ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL"
	gatewayControlPrincipalEnvironment      = "ZASP_GATEWAY_CONTROL_DB_PRINCIPAL"
	securityAgentAPIPrincipalEnvironment    = "ZASP_SECURITY_AGENT_API_DB_PRINCIPAL"
	securityAgentWorkerPrincipalEnvironment = "ZASP_SECURITY_AGENT_WORKER_DB_PRINCIPAL"
	securityAgentActionPrincipalEnvironment = "ZASP_SECURITY_AGENT_ACTION_DB_PRINCIPAL"
	redTeamWorkerPrincipalEnvironment       = "ZASP_RED_TEAM_WORKER_DB_PRINCIPAL"
	redTeamOutboxPrincipalEnvironment       = "ZASP_RED_TEAM_OUTBOX_DB_PRINCIPAL"
	redTeamAdapterPrincipalEnvironment      = "ZASP_RED_TEAM_ADAPTER_DB_PRINCIPAL"
	attackLabControllerPrincipalEnvironment = "ZASP_ATTACK_LAB_CONTROLLER_DB_PRINCIPAL"
	attackLabOutboxPrincipalEnvironment     = "ZASP_ATTACK_LAB_OUTBOX_DB_PRINCIPAL"
	attackLabProxyPrincipalEnvironment      = "ZASP_ATTACK_LAB_PROXY_DB_PRINCIPAL"
	recoveryWorkerPrincipalEnvironment      = "ZASP_RECOVERY_WORKER_DB_PRINCIPAL"
	recoveryOutboxPrincipalEnvironment      = "ZASP_RECOVERY_OUTBOX_DB_PRINCIPAL"
	policyDeploymentPrincipalEnvironment    = "ZASP_POLICY_DEPLOYMENT_DB_PRINCIPAL"
)

var errInvalidMigrationCommand = errors.New("invalid release migration command")
var errReleasePrincipalRegistration = errors.New("release principal registration failed")
var databasePrincipalPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)

type discoveryPrincipalRegistration struct {
	migration, api, discovery, ingest, runtime, outbox, gateway, scheduler, projectionRisk, projectionGraph, projectionSearch string
	runtimeCoordinator, runtimeArchive, runtimeIndex, runtimeCorrelation, runtimeProjection, gatewayControl                   string
	securityAgentAPI, securityAgentWorker, securityAgentAction                                                                string
	redTeamWorker, redTeamOutbox, redTeamAdapter                                                                              string
	attackLabController, attackLabOutbox, attackLabProxy                                                                      string
	recoveryWorker, recoveryOutbox, policyDeployment                                                                          string
}

type principalQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type releaseMigrationRunner interface {
	Version(context.Context) (int64, error)
	Up(context.Context) error
	UpCore(context.Context) error
	UpWorkflows(context.Context) error
	UpWorkflowReceipts(context.Context) error
	UpWorkflowReceiptSafety(context.Context) error
	UpWorkflowReceiptProvenance(context.Context) error
	DownWorkflowReceiptProvenance(context.Context) error
	UpProductionAdministration(context.Context) error
	DownProductionAdministration(context.Context) error
	UpAPITokenRevealGrants(context.Context) error
	DownAPITokenRevealGrants(context.Context) error
	UpProductionRiskProjection(context.Context) error
	DownProductionRiskProjection(context.Context) error
	UpProductionDiscovery(context.Context) error
	DownProductionDiscovery(context.Context) error
	UpConnectorAuthorization(context.Context) error
	DownConnectorAuthorization(context.Context) error
	UpReferenceAuthorization(context.Context) error
	DownReferenceAuthorization(context.Context) error
	UpProductionDiscoveryExecution(context.Context) error
	DownProductionDiscoveryExecution(context.Context) error
	UpProductionTypedInventoryCutover(context.Context) error
	DownProductionTypedInventoryCutover(context.Context) error
	UpProductionRuntimeDataPlane(context.Context) error
	DownProductionRuntimeDataPlane(context.Context) error
	UpProductionRuntimeGatewayReconciliation(context.Context) error
	DownProductionRuntimeGatewayReconciliation(context.Context) error
	UpProductionRuntimeIngestReconciliation(context.Context) error
	DownProductionRuntimeIngestReconciliation(context.Context) error
	UpProductionSecurityAgentExecution(context.Context) error
	DownProductionSecurityAgentExecution(context.Context) error
	UpProductionIdentityAdministration(context.Context) error
	DownProductionIdentityAdministration(context.Context) error
	UpProductionSecurityAgentControls(context.Context) error
	DownProductionSecurityAgentControls(context.Context) error
	UpProductionSecurityAgentAutonomousResponse(context.Context) error
	DownProductionSecurityAgentAutonomousResponse(context.Context) error
	UpProductionSecurityAgentTemporaryPolicy(context.Context) error
	DownProductionSecurityAgentTemporaryPolicy(context.Context) error
	UpProductionSecurityAgentConnectorRevocation(context.Context) error
	DownProductionSecurityAgentConnectorRevocation(context.Context) error
	UpProductionSecurityAgentSessionIsolation(context.Context) error
	DownProductionSecurityAgentSessionIsolation(context.Context) error
	UpProductionRedTeamExecution(context.Context) error
	DownProductionRedTeamExecution(context.Context) error
	UpProductionAttackLabExecution(context.Context) error
	DownProductionAttackLabExecution(context.Context) error
	UpProductionRecovery(context.Context) error
	DownProductionRecovery(context.Context) error
	UpProductionPolicyDeployment(context.Context) error
	DownProductionPolicyDeployment(context.Context) error
	UpProductionHomeAttention(context.Context) error
	DownProductionHomeAttention(context.Context) error
	UpProductionApprovalNotification(context.Context) error
	DownProductionApprovalNotification(context.Context) error
	UpProductionWorkflowCompatibility(context.Context) error
	DownProductionWorkflowCompatibility(context.Context) error
	UpProductionSecurityAgentPlanner(context.Context) error
	DownProductionSecurityAgentPlanner(context.Context) error
	UpProductionSecurityAgentAttackPath(context.Context) error
	DownProductionSecurityAgentAttackPath(context.Context) error
	UpProductionIntegrationSetup(context.Context) error
	DownProductionIntegrationSetup(context.Context) error
	UpProductionIntegrationWebhook(context.Context) error
	DownProductionIntegrationWebhook(context.Context) error
	UpProductionRuntimeQueueReplay(context.Context) error
	DownProductionRuntimeQueueReplay(context.Context) error
	UpProductionRedTeamSafety(context.Context) error
	DownProductionRedTeamSafety(context.Context) error
	UpProductionRedTeamInvocation(context.Context) error
	DownProductionRedTeamInvocation(context.Context) error
	UpProductionRedTeamArtifacts(context.Context) error
	DownProductionRedTeamArtifacts(context.Context) error
	UpProductionRuntimeSessions(context.Context) error
	DownProductionRuntimeSessions(context.Context) error
	UpProductionRuntimeSessionReads(context.Context) error
	DownProductionRuntimeSessionReads(context.Context) error
	UpProductionRuntimeSessionSearch(context.Context) error
	DownProductionRuntimeSessionSearch(context.Context) error
	UpProductionRuntimeSessionQuery(context.Context) error
	DownProductionRuntimeSessionQuery(context.Context) error
	UpProductionRuntimeSessionEvidence(context.Context) error
	DownProductionRuntimeSessionEvidence(context.Context) error
	UpProductionRuntimeEnrollmentPairing(context.Context) error
	DownProductionRuntimeEnrollmentPairing(context.Context) error
	UpProductionReconciliationLanePlan(context.Context) error
	DownProductionReconciliationLanePlan(context.Context) error
	UpProductionRuntimeCandidateAuthority(context.Context) error
	DownProductionRuntimeCandidateAuthority(context.Context) error
	UpProductionRuntimeAcceptance(context.Context) error
	DownProductionRuntimeAcceptance(context.Context) error
	UpProductionRuntimeCorrelationRouting(context.Context) error
	DownProductionRuntimeCorrelationRouting(context.Context) error
	UpProductionRuntimeSandboxBinding(context.Context) error
	DownProductionRuntimeSandboxBinding(context.Context) error
	UpProductionRuntimePrecision(context.Context) error
	UpProductionAuditExports(context.Context) error
	DownProductionAuditExports(context.Context) error
	UpProductionSecurityAgentBudgets(context.Context) error
	DownProductionSecurityAgentBudgets(context.Context) error
	UpProductionSecurityAgentRunContext(context.Context) error
	DownProductionSecurityAgentRunContext(context.Context) error
	UpProductionSecurityAgentExistingTests(context.Context) error
	DownProductionSecurityAgentExistingTests(context.Context) error
	UpProductionCompliance(context.Context) error
	DownProductionCompliance(context.Context) error
	UpProductionSecurityAgentAttackLab(context.Context) error
	DownProductionSecurityAgentAttackLab(context.Context) error
	UpProductionSecurityAgentExports(context.Context) error
	DownProductionSecurityAgentExports(context.Context) error
	UpProductionSecurityAgentWebhooks(context.Context) error
	DownProductionSecurityAgentWebhooks(context.Context) error
	UpProductionDiscoveryScheduleReplay(context.Context) error
	DownProductionDiscoveryScheduleReplay(context.Context) error
	DownWorkflowReceiptSafety(context.Context) error
	DownWorkflowReceipts(context.Context) error
	DownWorkflows(context.Context) error
	DownCore(context.Context) error
	Down(context.Context) error
}

func main() {
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	timeout, err := loadMigrationTimeout(os.Getenv)
	if err != nil {
		log.Fatal("release migration configuration rejected")
	}
	ctx, cancel := context.WithTimeout(signalCtx, timeout)
	defer cancel()
	arguments := os.Args[1:]
	var verifierKey *authorization.AttestationKey
	var verifierPrincipal string
	var identityRegistration *identityVerifierRegistration
	var workerRegistration *workerVerifierRegistration
	var temporalRegistration *temporalPrincipalRegistration
	if len(arguments) > 0 && arguments[0] == "register-temporal-executor-principals" {
		temporalRegistration, err = loadTemporalPrincipalRegistration(arguments, os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	if len(arguments) > 0 && (arguments[0] == "register-worker-authorization-verifier" || arguments[0] == "register-compensation-authorization-verifier") {
		workerRegistration, err = loadWorkerVerifierRegistration(arguments, os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	if len(arguments) > 0 && (arguments[0] == "register-identity-session-verifier" || arguments[0] == "register-identity-webhook-verifier") {
		identityRegistration, err = loadIdentityVerifierRegistration(arguments, os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	if len(arguments) > 0 && arguments[0] == "register-authorization-verifier" {
		verifierPrincipal = os.Getenv(migrationPrincipalEnvironment)
		if len(arguments) != 1 || !databasePrincipalPattern.MatchString(verifierPrincipal) {
			log.Fatal("release migration configuration rejected")
		}
		verifierKey, err = authorization.NewAttestationKey([]byte(os.Getenv("ZASP_WORKFLOW_SIGNING_KEY")))
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	var globalCommand string
	var globalRequest *migrations.GlobalExecutionControlRequest
	if len(arguments) > 0 && (arguments[0] == "security-agent-global-read" || arguments[0] == "security-agent-global-set") {
		globalCommand = arguments[0]
		globalRequest, err = parseGlobalExecutionControlCommand(arguments, os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	var exportConfiguration *migrations.AuditExportConfiguration
	if len(arguments) > 0 && arguments[0] == "configure-audit-exports" {
		if len(arguments) != 1 {
			log.Fatal("release migration configuration rejected")
		}
		configuration, err := loadAuditExportConfiguration(os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
		exportConfiguration = &configuration
	}
	var registration discoveryPrincipalRegistration
	var exportAPI string
	if len(arguments) > 0 && arguments[0] == "register-audit-export-api" {
		if len(arguments) != 1 {
			log.Fatal("release migration configuration rejected")
		}
		exportAPI = os.Getenv(discoveryAPIPrincipalEnvironment)
		if !databasePrincipalPattern.MatchString(exportAPI) {
			log.Fatal("release migration configuration rejected")
		}
	}
	var exportExecutor, exportOutbox string
	if len(arguments) > 0 && arguments[0] == "register-audit-export-workers" {
		if len(arguments) != 1 {
			log.Fatal("release migration configuration rejected")
		}
		exportExecutor, exportOutbox, err = loadAuditExportWorkerRegistration(os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	var complianceExecutor, complianceCleanup string
	var attackLabReconciler string
	if len(arguments) > 0 && arguments[0] == "register-security-agent-attack-lab-reconciler" {
		if len(arguments) != 1 {
			log.Fatal("release migration configuration rejected")
		}
		attackLabReconciler, err = loadAttackLabReconcilerRegistration(os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	if len(arguments) > 0 && arguments[0] == "register-compliance-workers" {
		if len(arguments) != 1 {
			log.Fatal("release migration configuration rejected")
		}
		complianceExecutor, complianceCleanup, err = loadComplianceWorkerRegistration(os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	if isForwardMigration(arguments) {
		if authorizationProfileCommand(arguments[0]) {
			registration.migration = os.Getenv(migrationPrincipalEnvironment)
			if !databasePrincipalPattern.MatchString(registration.migration) {
				err = errInvalidMigrationCommand
			}
		} else {
			registration, err = loadDiscoveryPrincipalRegistration(os.Getenv)
		}
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	dsn := os.Getenv(postgresDSNEnvironment)
	if dsn == "" {
		log.Fatal("release migration configuration rejected")
	}
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		log.Fatal("release migration database unavailable")
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		log.Fatal("release migration failed")
	}
	if globalCommand != "" {
		var result migrations.GlobalExecutionControlResult
		if globalCommand == "security-agent-global-read" {
			result, err = runner.ReadGlobalExecutionControl(ctx)
		} else {
			result, err = runner.SetGlobalExecutionControl(ctx, *globalRequest)
		}
		if err != nil {
			log.Fatal("release migration failed")
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			log.Fatal("release migration output failed")
		}
		return
	}
	if temporalRegistration != nil {
		err = registerTemporalPrincipals(ctx, connection, temporalRegistration)
	} else if workerRegistration != nil {
		err = registerWorkerVerifier(ctx, connection, workerRegistration)
	} else if identityRegistration != nil {
		err = registerIdentityVerifier(ctx, connection, identityRegistration)
	} else if verifierKey != nil {
		err = registerAuthorizationVerifier(ctx, connection, verifierPrincipal, verifierKey)
	} else if len(arguments) == 1 && arguments[0] == "configure-temporal-test-selector" {
		err = configureTemporalTestSelector(ctx, connection, os.Getenv("ZASP_TEST_SELECTOR_CONFIGURATION"))
	} else if exportConfiguration != nil {
		err = runner.ConfigureAuditExports(ctx, *exportConfiguration)
	} else if exportAPI != "" {
		err = runner.RegisterAuditExportAPI(ctx, exportAPI)
	} else if exportExecutor != "" {
		err = runner.RegisterAuditExportWorkers(ctx, exportExecutor, exportOutbox)
	} else if complianceExecutor != "" {
		err = runner.RegisterComplianceWorkers(ctx, complianceExecutor, complianceCleanup)
	} else if attackLabReconciler != "" {
		err = runner.RegisterSecurityAgentAttackLabReconciler(ctx, attackLabReconciler)
	} else {
		err = runReleaseMigration(ctx, &registeredReleaseMigrationRunner{releaseMigrationRunner: runner, queryer: connection, registration: registration}, arguments)
	}
	if err != nil {
		log.Fatal("release migration failed")
	}
	if isForwardMigration(arguments) {
		if err := registerForwardRelease(ctx, connection, registration, arguments); err != nil {
			log.Fatal("release principal registration or readiness failed")
		}
	}
}

func registerAuthorizationVerifier(ctx context.Context, queryer principalQueryer, principal string, key *authorization.AttestationKey) error {
	var accepted bool
	if err := queryer.QueryRow(ctx, `SELECT session_user=$1`, principal).Scan(&accepted); err != nil || !accepted {
		return errReleasePrincipalRegistration
	}
	// SQL also requires the registered migration authority. A caller-controlled
	// principal name cannot grant registration to an API login.
	if err := queryer.QueryRow(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier()).Scan(&accepted); err != nil || !accepted {
		return errReleasePrincipalRegistration
	}
	return nil
}

func registerForwardRelease(ctx context.Context, queryer principalQueryer, registration discoveryPrincipalRegistration, arguments []string) error {
	if !isForwardMigration(arguments) {
		return errInvalidMigrationCommand
	}
	if arguments[0] == "up-authorization-inventory-profile" {
		return registerAuthorizationInventoryProfile(ctx, queryer, registration)
	}
	if arguments[0] == "up-authorization-identity-profile" || arguments[0] == "up-authorization-temporal-identity-profile" {
		var ready bool
		mode := "canonical61-authorization79-80-v1"
		if arguments[0] == "up-authorization-temporal-identity-profile" {
			mode = migrations.AuthorizationTemporalProfileName
		}
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE name=$2) AND zasp_authorization80_identity.structural_ready($3)`, registration.migration, mode, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-authorization-audit-profile" || arguments[0] == "up-authorization-temporal-audit-profile" {
		var ready bool
		mode := "canonical61-authorization79-80-v1"
		if arguments[0] == "up-authorization-temporal-audit-profile" {
			mode = migrations.AuthorizationTemporalProfileName
		}
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE name=$2 AND audit_mode=$3) AND zasp_authorization80.ready($4) AND zasp_authorization80_audit.catalog_ready()`, registration.migration, mode, migrations.AuthorizationAuditProfileName, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-authorization-runtime-profile" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_temporal.ready() AND zasp_authorization80_identity.structural_ready($2)`, registration.migration, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-automatic-sources" || arguments[0] == "up-temporal-finding-response" {
		statement := `SELECT session_user=$1 AND zasp_temporal77.ready($2,$3)`
		checksum, fingerprint := migrations.TemporalAutomaticSourcesChecksum(), migrations.TemporalAutomaticSourcesFingerprint()
		if arguments[0] == "up-temporal-finding-response" {
			statement = `SELECT session_user=$1 AND zasp_temporal78.ready($2,$3)`
			checksum, fingerprint = migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()
		}
		var ready bool
		if err := queryer.QueryRow(ctx, statement, registration.migration, checksum, fingerprint).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-single-recovery" {
		if ctx == nil || ctx.Err() != nil {
			return errReleasePrincipalRegistration
		}
		metadata := migrations.ProductionTemporalSingleRecoveryMetadata()
		if ctx.Err() != nil {
			return errReleasePrincipalRegistration
		}
		var ready bool
		if err := queryer.QueryRow(ctx, migrations.TemporalSingleRecoveryReadySourceSQL, metadata.ReadyBodyDigest).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal_single_recovery.ready($2)`, registration.migration, metadata.Checksum).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-authorization-worker-profile" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_temporal.ready()`, registration.migration).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-authorization-temporal-profile" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization80_temporal.ready()`, registration.migration).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-authorization-enforcement" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization80.ready($2)`, registration.migration, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-authorization-projection" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.ready($2)`, registration.migration, migrations.ProductionAuthorizationProjection().Checksum()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-human-admission" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal76.ready($2,$3)`, registration.migration, migrations.ProductionTemporalHumanAdmission().Checksum(), migrations.TemporalHumanAdmissionFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-test-selector" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal75.ready($2,$3)`, registration.migration, migrations.ProductionTemporalTestSelector().Checksum(), migrations.TemporalTestSelectorFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-test-executor" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal74.ready($2,$3)`, registration.migration, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-admission" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal73.ready($2,$3)`, registration.migration, migrations.ProductionTemporalAdmission().Checksum(), migrations.TemporalAdmissionFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-discovery" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal72.ready($2,$3)`, registration.migration, migrations.ProductionTemporalDiscovery().Checksum(), migrations.TemporalDiscoveryFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-legacy-tests" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal71.ready($2,$3)`, registration.migration, migrations.ProductionTemporalLegacyTests().Checksum(), migrations.TemporalLegacyTestsFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-compatibility" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal70.ready($2,$3)`, registration.migration, migrations.ProductionTemporalCompatibility().Checksum(), migrations.TemporalCompatibilityFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-workflow" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal69.ready($2,$3)`, registration.migration, migrations.ProductionTemporalWorkflow().Checksum(), migrations.TemporalWorkflowFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-executor" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal68.ready($2,$3)`, registration.migration, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-domain" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal67.ready($2,$3)`, registration.migration, migrations.ProductionTemporalDomain().Checksum(), migrations.TemporalDomainFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-ownership" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal66.ready($2,$3)`, registration.migration, migrations.ProductionTemporalOwnership().Checksum(), migrations.TemporalOwnershipFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if arguments[0] == "up-temporal-outbox" {
		var ready bool
		if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal65.ready($2,$3)`, registration.migration, migrations.ProductionTemporalOutbox().Checksum(), migrations.TemporalOutboxFingerprint()).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
		return nil
	}
	if err := registerReleasePrincipals(ctx, queryer, registration); err != nil {
		return err
	}
	var statement, checksum, fingerprint string
	switch arguments[0] {
	case "up-to-51":
		statement = `SELECT zasp_production_runtime_precision_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()
	case "up-to-52":
		statement = `SELECT zasp_production_audit_exports_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()
	case "up-to-53":
		statement = `SELECT zasp_production_security_agent_budgets_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionSecurityAgentBudgets().Checksum(), migrations.SecurityAgentBudgetCandidateFingerprint()
	case "up-to-54":
		statement = `SELECT zasp_production_security_agent_run_context_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionSecurityAgentRunContext().Checksum(), migrations.SecurityAgentRunContextFingerprint()
	case "up-to-55":
		statement = `SELECT zasp_production_security_agent_existing_tests_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()
	case "up-to-56":
		statement = `SELECT zasp_compliance_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()
	case "up-to-57":
		statement = `SELECT zasp_sa_attack_lab_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionSecurityAgentAttackLab().Checksum(), migrations.SecurityAgentAttackLabFingerprint()
	case "up-to-58":
		statement = `SELECT zasp_sa_export_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
	case "up-to-59":
		statement = `SELECT zasp_sa_webhook_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionSecurityAgentWebhooks().Checksum(), migrations.SecurityAgentWebhooksFingerprint()
	case "up-to-60":
		statement = `SELECT zasp_discovery_schedule_replay_readiness($1,$2)`
		checksum, fingerprint = migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()
	default:
		return nil
	}
	var ready bool
	if err := queryer.QueryRow(ctx, statement, checksum, fingerprint).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

func registerReleasePrincipals(ctx context.Context, queryer principalQueryer, registration discoveryPrincipalRegistration) error {
	if ctx == nil || ctx.Err() != nil || queryer == nil {
		return errReleasePrincipalRegistration
	}
	var ready bool
	checks := []struct {
		statement string
		arguments []any
	}{
		{`SELECT session_user=$1`, []any{registration.migration}},
		{`SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, []any{registration.migration, registration.api, registration.discovery, registration.ingest, registration.runtime, registration.outbox, registration.gateway}},
		{`SELECT zasp_execution_register_principals($1,$2,$3,$4,$5,$6)`, []any{registration.migration, registration.scheduler, registration.discovery, registration.projectionRisk, registration.projectionGraph, registration.projectionSearch}},
		{`SELECT zasp_runtime_register_principals($1,$2,$3,$4,$5,$6,$7)`, []any{registration.migration, registration.runtimeCoordinator, registration.runtimeArchive, registration.runtimeIndex, registration.runtimeCorrelation, registration.runtimeProjection, registration.gatewayControl}},
		{statement: `SELECT zasp_runtime_principals_ready()`},
		{`SELECT zasp_security_agent_register_principals($1,$2,$3)`, []any{registration.migration, registration.securityAgentAPI, registration.securityAgentWorker}},
		{statement: `SELECT zasp_security_agent_principals_ready()`},
		{`SELECT zasp_security_agent_register_action_principal($1,$2)`, []any{registration.migration, registration.securityAgentAction}},
		{`SELECT zasp_red_team_register_principals($1,$2,$3,$4)`, []any{registration.migration, registration.redTeamWorker, registration.redTeamOutbox, registration.redTeamAdapter}},
		{statement: `SELECT zasp_red_team_principals_ready()`},
		{`SELECT zasp_attack_lab_register_principals($1,$2,$3,$4)`, []any{registration.migration, registration.attackLabController, registration.attackLabOutbox, registration.attackLabProxy}},
		{statement: `SELECT zasp_attack_lab_principals_ready()`},
		{`SELECT zasp_recovery_register_principals($1,$2,$3)`, []any{registration.migration, registration.recoveryWorker, registration.recoveryOutbox}},
		{statement: `SELECT zasp_recovery_principals_ready()`},
		{`SELECT zasp_policy_deployment_register_principal($1,$2)`, []any{registration.migration, registration.policyDeployment}},
		{`SELECT zasp_policy_deployment_execution_readiness($1,$2)`, []any{migrations.ProductionPolicyDeployment().Checksum(), migrations.ProductionPolicyDeploymentSemanticFingerprint()}},
	}
	for _, check := range checks {
		ready = false
		if err := queryer.QueryRow(ctx, check.statement, check.arguments...).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
	}
	return nil
}

func loadDiscoveryPrincipalRegistration(getenv func(string) string) (discoveryPrincipalRegistration, error) {
	if getenv == nil {
		return discoveryPrincipalRegistration{}, errInvalidMigrationCommand
	}
	registration := discoveryPrincipalRegistration{
		migration: getenv(migrationPrincipalEnvironment),
		api:       getenv(discoveryAPIPrincipalEnvironment), discovery: getenv(discoveryWorkerPrincipalEnvironment),
		ingest: getenv(runtimeIngestPrincipalEnvironment), runtime: getenv(runtimeWorkerPrincipalEnvironment),
		outbox: getenv(outboxWorkerPrincipalEnvironment), gateway: getenv(runtimeGatewayPrincipalEnvironment),
		scheduler: getenv(discoverySchedulerPrincipalEnvironment), projectionRisk: getenv(projectionRiskPrincipalEnvironment),
		projectionGraph: getenv(projectionGraphPrincipalEnvironment), projectionSearch: getenv(projectionSearchPrincipalEnvironment),
		runtimeCoordinator: getenv(runtimeCoordinatorPrincipalEnvironment), runtimeArchive: getenv(runtimeArchivePrincipalEnvironment),
		runtimeIndex: getenv(runtimeIndexPrincipalEnvironment), runtimeCorrelation: getenv(runtimeCorrelationPrincipalEnvironment),
		runtimeProjection: getenv(runtimeProjectionPrincipalEnvironment), gatewayControl: getenv(gatewayControlPrincipalEnvironment),
		securityAgentAPI: getenv(securityAgentAPIPrincipalEnvironment), securityAgentWorker: getenv(securityAgentWorkerPrincipalEnvironment),
		securityAgentAction: getenv(securityAgentActionPrincipalEnvironment),
		redTeamWorker:       getenv(redTeamWorkerPrincipalEnvironment), redTeamOutbox: getenv(redTeamOutboxPrincipalEnvironment), redTeamAdapter: getenv(redTeamAdapterPrincipalEnvironment),
		attackLabController: getenv(attackLabControllerPrincipalEnvironment), attackLabOutbox: getenv(attackLabOutboxPrincipalEnvironment), attackLabProxy: getenv(attackLabProxyPrincipalEnvironment),
		recoveryWorker: getenv(recoveryWorkerPrincipalEnvironment), recoveryOutbox: getenv(recoveryOutboxPrincipalEnvironment), policyDeployment: getenv(policyDeploymentPrincipalEnvironment),
	}
	values := []string{registration.migration, registration.api, registration.discovery, registration.ingest, registration.runtime, registration.outbox, registration.gateway, registration.scheduler, registration.projectionRisk, registration.projectionGraph, registration.projectionSearch, registration.runtimeCoordinator, registration.runtimeArchive, registration.runtimeIndex, registration.runtimeCorrelation, registration.runtimeProjection, registration.gatewayControl, registration.securityAgentAPI, registration.securityAgentWorker, registration.securityAgentAction, registration.redTeamWorker, registration.redTeamOutbox, registration.redTeamAdapter, registration.attackLabController, registration.attackLabOutbox, registration.attackLabProxy, registration.recoveryWorker, registration.recoveryOutbox, registration.policyDeployment}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !databasePrincipalPattern.MatchString(value) {
			return discoveryPrincipalRegistration{}, errInvalidMigrationCommand
		}
		if _, exists := seen[value]; exists {
			return discoveryPrincipalRegistration{}, errInvalidMigrationCommand
		}
		seen[value] = struct{}{}
	}
	return registration, nil
}

func loadMigrationTimeout(getenv func(string) string) (time.Duration, error) {
	if getenv == nil {
		return 0, errInvalidMigrationCommand
	}
	timeout, err := time.ParseDuration(getenv(migrationTimeoutEnvironment))
	if err != nil || timeout <= 0 || timeout > 30*time.Minute {
		return 0, errInvalidMigrationCommand
	}
	return timeout, nil
}

func (r *registeredReleaseMigrationRunner) UpProductionTemporalSingleRecovery(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionTemporalSingleRecovery(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalSingleRecovery(ctx)
}

func isForwardMigration(arguments []string) bool {
	if len(arguments) == 1 && arguments[0] == "up-temporal-single-recovery" {
		return true
	}
	if len(arguments) == 1 && (arguments[0] == "up-authorization-runtime-profile" || arguments[0] == "up-temporal-automatic-sources" || arguments[0] == "up-temporal-finding-response") {
		return true
	}
	if len(arguments) == 1 && authorizationProfileCommand(arguments[0]) {
		return true
	}
	if len(arguments) == 1 && arguments[0] == "up-authorization-enforcement" {
		return true
	}
	if len(arguments) == 1 && arguments[0] == "up-authorization-projection" {
		return true
	}
	if len(arguments) == 1 && arguments[0] == "up-temporal-human-admission" {
		return true
	}
	if len(arguments) == 1 && arguments[0] == "up-temporal-test-selector" {
		return true
	}
	if len(arguments) == 1 && arguments[0] == "up-temporal-test-executor" {
		return true
	}
	if len(arguments) == 1 && arguments[0] == "up-temporal-admission" {
		return true
	}
	if len(arguments) == 1 && arguments[0] == "up-temporal-discovery" {
		return true
	}
	if len(arguments) == 1 && (arguments[0] == "up-temporal-outbox" || arguments[0] == "up-temporal-ownership" || arguments[0] == "up-temporal-domain" || arguments[0] == "up-temporal-executor" || arguments[0] == "up-temporal-workflow" || arguments[0] == "up-temporal-compatibility" || arguments[0] == "up-temporal-legacy-tests") {
		return true
	}
	return len(arguments) == 1 && (arguments[0] == "up" || arguments[0] == "up-to-48" || arguments[0] == "up-to-49" || arguments[0] == "up-to-50" || arguments[0] == "up-to-51" || arguments[0] == "up-to-52" || arguments[0] == "up-to-53" || arguments[0] == "up-to-54" || arguments[0] == "up-to-55" || arguments[0] == "up-to-56" || arguments[0] == "up-to-57" || arguments[0] == "up-to-58" || arguments[0] == "up-to-59" || arguments[0] == "up-to-60")
}

func runReleaseMigration(ctx context.Context, runner releaseMigrationRunner, arguments []string) error {
	if ctx == nil || runner == nil || len(arguments) != 1 {
		return errInvalidMigrationCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	version, err := runner.Version(ctx)
	if err != nil {
		return err
	}
	switch arguments[0] {
	case "up-temporal-single-recovery":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalSingleRecovery(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalSingleRecovery(ctx)
	case "up-authorization-runtime-profile":
		extension, ok := runner.(interface{ UpAuthorizationRuntimeProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpAuthorizationRuntimeProfile(ctx)
	case "up-temporal-automatic-sources":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalAutomaticSources(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalAutomaticSources(ctx)
	case "up-temporal-finding-response":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalFindingResponse(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalFindingResponse(ctx)
	case "up-authorization-worker-profile":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationWorkerProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationWorkerProfile(ctx)
	case "up-authorization-inventory-profile":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationInventoryProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationInventoryProfile(ctx)
	case "up-authorization-identity-profile":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationIdentityProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationIdentityProfile(ctx)
	case "up-authorization-temporal-identity-profile":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationTemporalIdentityProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationTemporalIdentityProfile(ctx)
	case "up-authorization-audit-profile":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationAuditProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationAuditProfile(ctx)
	case "up-authorization-temporal-audit-profile":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationTemporalAuditProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationTemporalAuditProfile(ctx)
	case "up-authorization-temporal-profile":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationTemporalProfile(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationTemporalProfile(ctx)
	case "up-authorization-enforcement":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationEnforcement(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationEnforcement(ctx)
	case "up-authorization-projection":
		if version < 25 || version > 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionAuthorizationProjection(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionAuthorizationProjection(ctx)
	case "up-temporal-human-admission":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalHumanAdmission(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalHumanAdmission(ctx)
	case "up-temporal-test-selector":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalTestSelector(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalTestSelector(ctx)
	case "up-temporal-test-executor":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalTestExecutor(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalTestExecutor(ctx)
	case "up-temporal-admission":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalAdmission(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalAdmission(ctx)
	case "up-temporal-discovery":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalDiscovery(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalDiscovery(ctx)
	case "up-temporal-legacy-tests":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalLegacyTests(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalLegacyTests(ctx)
	case "up-temporal-compatibility":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalCompatibility(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalCompatibility(ctx)
	case "up-temporal-workflow":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalWorkflow(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalWorkflow(ctx)
	case "up-temporal-executor":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalExecutor(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalExecutor(ctx)
	case "up-temporal-domain":
		if version != 60 && version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalDomain(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalDomain(ctx)
	case "up-temporal-outbox":
		if version != 60 && version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalOutbox(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalOutbox(ctx)
	case "up-temporal-ownership":
		if version != 61 {
			return migrations.ErrInvalidState
		}
		extension, ok := runner.(interface{ UpProductionTemporalOwnership(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return extension.UpProductionTemporalOwnership(ctx)
	case "up", "up-to-48", "up-to-49", "up-to-50", "up-to-51", "up-to-52", "up-to-53", "up-to-54", "up-to-55", "up-to-56", "up-to-57", "up-to-58", "up-to-59", "up-to-60":
		if version == 0 {
			if err := runner.Up(ctx); err != nil {
				return err
			}
			version = 1
		}
		if version == 1 {
			if err := runner.UpCore(ctx); err != nil {
				return err
			}
			version = 2
		}
		if version == 2 {
			if err := runner.UpWorkflows(ctx); err != nil {
				return err
			}
			version = 3
		}
		if version == 3 {
			if err := runner.UpWorkflowReceipts(ctx); err != nil {
				return err
			}
			version = 4
		}
		if version == 4 {
			if err := runner.UpWorkflowReceiptSafety(ctx); err != nil {
				return err
			}
			version = 5
		}
		if version == 5 {
			if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
				return err
			}
			version = 6
		}
		if version == 6 {
			if err := runner.UpProductionAdministration(ctx); err != nil {
				return err
			}
			version = 7
		}
		if version == 7 {
			if err := runner.UpAPITokenRevealGrants(ctx); err != nil {
				return err
			}
			version = 8
		}
		if version == 8 {
			if err := runner.UpProductionRiskProjection(ctx); err != nil {
				return err
			}
			version = 9
		}
		if version == 9 {
			if err := runner.UpProductionDiscovery(ctx); err != nil {
				return err
			}
			version = 10
		}
		if version == 10 {
			if err := runner.UpConnectorAuthorization(ctx); err != nil {
				return err
			}
			version = 11
		}
		if version == 11 {
			if err := runner.UpReferenceAuthorization(ctx); err != nil {
				return err
			}
			version = 12
		}
		if version == 12 {
			if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
				return err
			}
			version = 13
		}
		if version == 13 {
			if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
				return err
			}
			version = 14
		}
		if version == 14 {
			if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
				return err
			}
			version = 15
		}
		if version == 15 {
			if err := runner.UpProductionRuntimeGatewayReconciliation(ctx); err != nil {
				return err
			}
			version = 16
		}
		if version == 16 {
			if err := runner.UpProductionRuntimeIngestReconciliation(ctx); err != nil {
				return err
			}
			version = 17
		}
		if version == 17 {
			if err := runner.UpProductionSecurityAgentExecution(ctx); err != nil {
				return err
			}
			version = 18
		}
		if version == 18 {
			if err := runner.UpProductionIdentityAdministration(ctx); err != nil {
				return err
			}
			version = 19
		}
		if version == 19 {
			if err := runner.UpProductionSecurityAgentControls(ctx); err != nil {
				return err
			}
			version = 20
		}
		if version == 20 {
			if err := runner.UpProductionSecurityAgentAutonomousResponse(ctx); err != nil {
				return err
			}
			version = 21
		}
		if version == 21 {
			if err := runner.UpProductionSecurityAgentTemporaryPolicy(ctx); err != nil {
				return err
			}
			version = 22
		}
		if version == 22 {
			if err := runner.UpProductionSecurityAgentConnectorRevocation(ctx); err != nil {
				return err
			}
			version = 23
		}
		if version == 23 {
			if err := runner.UpProductionSecurityAgentSessionIsolation(ctx); err != nil {
				return err
			}
			version = 24
		}
		if version == 24 {
			if err := runner.UpProductionRedTeamExecution(ctx); err != nil {
				return err
			}
			version = 25
		}
		if version == 25 {
			if err := runner.UpProductionAttackLabExecution(ctx); err != nil {
				return err
			}
			version = 26
		}
		if version == 26 {
			if err := runner.UpProductionRecovery(ctx); err != nil {
				return err
			}
			version = 27
		}
		if version == 27 {
			if err := runner.UpProductionPolicyDeployment(ctx); err != nil {
				return err
			}
			version = 28
		}
		if version == 28 {
			if err := runner.UpProductionHomeAttention(ctx); err != nil {
				return err
			}
			version = 29
		}
		if version == 29 {
			if err := runner.UpProductionApprovalNotification(ctx); err != nil {
				return err
			}
			version = 30
		}
		if version == 30 {
			if err := runner.UpProductionWorkflowCompatibility(ctx); err != nil {
				return err
			}
			version = 31
		}
		if version == 31 {
			if err := runner.UpProductionSecurityAgentPlanner(ctx); err != nil {
				return err
			}
			version = 32
		}
		if version == 32 {
			if err := runner.UpProductionSecurityAgentAttackPath(ctx); err != nil {
				return err
			}
			version = 33
		}
		if version == 33 {
			if err := runner.UpProductionIntegrationSetup(ctx); err != nil {
				return err
			}
			version = 34
		}
		if version == 34 {
			if err := runner.UpProductionIntegrationWebhook(ctx); err != nil {
				return err
			}
			version = 35
		}
		if version == 35 {
			if err := runner.UpProductionRuntimeQueueReplay(ctx); err != nil {
				return err
			}
			version = 36
		}
		if version == 36 {
			if err := runner.UpProductionRedTeamSafety(ctx); err != nil {
				return err
			}
			version = 37
		}
		if version == 37 {
			if err := runner.UpProductionRedTeamInvocation(ctx); err != nil {
				return err
			}
			version = 38
		}
		if version == 38 {
			if err := runner.UpProductionRedTeamArtifacts(ctx); err != nil {
				return err
			}
			version = 39
		}
		if version == 39 {
			if err := runner.UpProductionRuntimeSessions(ctx); err != nil {
				return err
			}
			version = 40
		}
		if version == 40 {
			if err := runner.UpProductionRuntimeSessionReads(ctx); err != nil {
				return err
			}
			version = 41
		}
		if version == 41 {
			if err := runner.UpProductionRuntimeSessionSearch(ctx); err != nil {
				return err
			}
			version = 42
		}
		if version == 42 {
			if err := runner.UpProductionRuntimeSessionQuery(ctx); err != nil {
				return err
			}
			version = 43
		}
		if version == 43 {
			if err := runner.UpProductionRuntimeSessionEvidence(ctx); err != nil {
				return err
			}
			version = 44
		}
		if version == 44 {
			if err := runner.UpProductionRuntimeEnrollmentPairing(ctx); err != nil {
				return err
			}
			version = 45
		}
		if version == 45 {
			if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
				return err
			}
			version = 46
		}
		if version == 46 {
			if err := runner.UpProductionRuntimeCandidateAuthority(ctx); err != nil {
				return err
			}
			version = 47
		}
		if version == 47 {
			if err := runner.UpProductionRuntimeAcceptance(ctx); err != nil {
				return err
			}
			version = 48
		}
		target := int64(49)
		if arguments[0] == "up-to-48" {
			target = 48
		} else if arguments[0] == "up-to-50" {
			target = 50
		} else if arguments[0] == "up-to-51" {
			target = 51
		} else if arguments[0] == "up-to-52" {
			target = 52
		} else if arguments[0] == "up-to-53" {
			target = 53
		} else if arguments[0] == "up-to-54" {
			target = 54
		} else if arguments[0] == "up-to-55" {
			target = 55
		} else if arguments[0] == "up-to-56" {
			target = 56
		} else if arguments[0] == "up-to-57" {
			target = 57
		} else if arguments[0] == "up-to-58" {
			target = 58
		} else if arguments[0] == "up-to-59" {
			target = 59
		} else if arguments[0] == "up-to-60" {
			target = 60
		}
		if version == 48 && target >= 49 {
			if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
				return err
			}
			version = 49
		}
		if version == 49 && target >= 50 {
			if err := runner.UpProductionRuntimeSandboxBinding(ctx); err != nil {
				return err
			}
			version = 50
		}
		if version == 50 && target >= 51 {
			if err := runner.UpProductionRuntimePrecision(ctx); err != nil {
				return err
			}
			version = 51
		}
		if version == 51 && target >= 52 {
			if err := runner.UpProductionAuditExports(ctx); err != nil {
				return err
			}
			version = 52
		}
		if version == 52 && target >= 53 {
			if err := runner.UpProductionSecurityAgentBudgets(ctx); err != nil {
				return err
			}
			version = 53
		}
		if version == 53 && target >= 54 {
			if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
				return err
			}
			version = 54
		}
		if version == 54 && target >= 55 {
			if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
				return err
			}
			version = 55
		}
		if version == 55 && target >= 56 {
			if err := runner.UpProductionCompliance(ctx); err != nil {
				return err
			}
			version = 56
		}
		if version == 56 && target >= 57 {
			if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
				return err
			}
			version = 57
		}
		if version == 57 && target >= 58 {
			if err := runner.UpProductionSecurityAgentExports(ctx); err != nil {
				return err
			}
			version = 58
		}
		if version == 58 && target >= 59 {
			webhooks, ok := runner.(interface{ UpProductionSecurityAgentWebhooks(context.Context) error })
			if !ok {
				return migrations.ErrInvalidState
			}
			if err := webhooks.UpProductionSecurityAgentWebhooks(ctx); err != nil {
				return err
			}
			version = 59
		}
		if version == 59 && target == 60 {
			if err := runner.UpProductionDiscoveryScheduleReplay(ctx); err != nil {
				return err
			}
			version = 60
		}
		if version != target {
			return migrations.ErrInvalidState
		}
	case "down-from-60":
		if version != 60 {
			return migrations.ErrInvalidState
		}
		return runner.DownProductionDiscoveryScheduleReplay(ctx)
	case "down-from-59":
		if version != 59 {
			return migrations.ErrInvalidState
		}
		webhooks, ok := runner.(interface{ DownProductionSecurityAgentWebhooks(context.Context) error })
		if !ok {
			return migrations.ErrInvalidState
		}
		return webhooks.DownProductionSecurityAgentWebhooks(ctx)
	case "down-from-58":
		if version != 58 {
			return migrations.ErrInvalidState
		}
		return runner.DownProductionSecurityAgentExports(ctx)
	case "down-from-57":
		if version != 57 {
			return migrations.ErrInvalidState
		}
		return runner.DownProductionSecurityAgentAttackLab(ctx)
	case "down-to-55":
		if version == 56 {
			if err := runner.DownProductionCompliance(ctx); err != nil {
				return err
			}
			version = 55
		}
		if version != 55 {
			return migrations.ErrInvalidState
		}
	case "down-to-54":
		if version == 55 {
			if err := runner.DownProductionSecurityAgentExistingTests(ctx); err != nil {
				return err
			}
			version = 54
		}
		if version != 54 {
			return migrations.ErrInvalidState
		}
	case "down-to-53":
		if version == 54 {
			if err := runner.DownProductionSecurityAgentRunContext(ctx); err != nil {
				return err
			}
			version = 53
		}
		if version != 53 {
			return migrations.ErrInvalidState
		}
	case "down-to-52":
		if version == 53 {
			if err := runner.DownProductionSecurityAgentBudgets(ctx); err != nil {
				return err
			}
			version = 52
		}
		if version != 52 {
			return migrations.ErrInvalidState
		}
	case "down-to-51":
		if version == 52 {
			if err := runner.DownProductionAuditExports(ctx); err != nil {
				return err
			}
			version = 51
		}
		if version != 51 {
			return migrations.ErrInvalidState
		}
	case "down-to-49":
		if version == 50 {
			if err := runner.DownProductionRuntimeSandboxBinding(ctx); err != nil {
				return err
			}
			version = 49
		}
		if version != 49 {
			return migrations.ErrInvalidState
		}
	case "down":
		if version == 49 {
			if err := runner.DownProductionRuntimeCorrelationRouting(ctx); err != nil {
				return err
			}
			version = 48
		}
		if version == 48 {
			if err := runner.DownProductionRuntimeAcceptance(ctx); err != nil {
				return err
			}
			version = 47
		}
		if version == 47 {
			if err := runner.DownProductionRuntimeCandidateAuthority(ctx); err != nil {
				return err
			}
			version = 46
		}
		if version == 46 {
			if err := runner.DownProductionReconciliationLanePlan(ctx); err != nil {
				return err
			}
			version = 45
		}
		if version == 45 {
			if err := runner.DownProductionRuntimeEnrollmentPairing(ctx); err != nil {
				return err
			}
			version = 44
		}
		if version == 44 {
			if err := runner.DownProductionRuntimeSessionEvidence(ctx); err != nil {
				return err
			}
			version = 43
		}
		if version == 43 {
			if err := runner.DownProductionRuntimeSessionQuery(ctx); err != nil {
				return err
			}
			version = 42
		}
		if version == 42 {
			if err := runner.DownProductionRuntimeSessionSearch(ctx); err != nil {
				return err
			}
			version = 41
		}
		if version == 41 {
			if err := runner.DownProductionRuntimeSessionReads(ctx); err != nil {
				return err
			}
			version = 40
		}
		if version == 40 {
			if err := runner.DownProductionRuntimeSessions(ctx); err != nil {
				return err
			}
			version = 39
		}
		if version == 39 {
			if err := runner.DownProductionRedTeamArtifacts(ctx); err != nil {
				return err
			}
			version = 38
		}
		if version == 38 {
			if err := runner.DownProductionRedTeamInvocation(ctx); err != nil {
				return err
			}
			version = 37
		}
		if version == 37 {
			if err := runner.DownProductionRedTeamSafety(ctx); err != nil {
				return err
			}
			version = 36
		}
		if version == 36 {
			if err := runner.DownProductionRuntimeQueueReplay(ctx); err != nil {
				return err
			}
			version = 35
		}
		if version == 35 {
			if err := runner.DownProductionIntegrationWebhook(ctx); err != nil {
				return err
			}
			version = 34
		}
		if version == 34 {
			if err := runner.DownProductionIntegrationSetup(ctx); err != nil {
				return err
			}
			version = 33
		}
		if version == 33 {
			if err := runner.DownProductionSecurityAgentAttackPath(ctx); err != nil {
				return err
			}
			version = 32
		}
		if version == 32 {
			if err := runner.DownProductionSecurityAgentPlanner(ctx); err != nil {
				return err
			}
			version = 31
		}
		if version == 31 {
			if err := runner.DownProductionWorkflowCompatibility(ctx); err != nil {
				return err
			}
			version = 30
		}
		if version == 30 {
			if err := runner.DownProductionApprovalNotification(ctx); err != nil {
				return err
			}
			version = 29
		}
		if version == 29 {
			if err := runner.DownProductionHomeAttention(ctx); err != nil {
				return err
			}
			version = 28
		}
		if version == 28 {
			if err := runner.DownProductionPolicyDeployment(ctx); err != nil {
				return err
			}
			version = 27
		}
		if version == 27 {
			if err := runner.DownProductionRecovery(ctx); err != nil {
				return err
			}
			version = 26
		}
		if version == 26 {
			if err := runner.DownProductionAttackLabExecution(ctx); err != nil {
				return err
			}
			version = 25
		}
		if version == 25 {
			if err := runner.DownProductionRedTeamExecution(ctx); err != nil {
				return err
			}
			version = 24
		}
		if version == 24 {
			if err := runner.DownProductionSecurityAgentSessionIsolation(ctx); err != nil {
				return err
			}
			version = 23
		}
		if version == 23 {
			if err := runner.DownProductionSecurityAgentConnectorRevocation(ctx); err != nil {
				return err
			}
			version = 22
		}
		if version == 22 {
			if err := runner.DownProductionSecurityAgentTemporaryPolicy(ctx); err != nil {
				return err
			}
			version = 21
		}
		if version == 21 {
			if err := runner.DownProductionSecurityAgentAutonomousResponse(ctx); err != nil {
				return err
			}
			version = 20
		}
		if version == 20 {
			if err := runner.DownProductionSecurityAgentControls(ctx); err != nil {
				return err
			}
			version = 19
		}
		if version == 19 {
			if err := runner.DownProductionIdentityAdministration(ctx); err != nil {
				return err
			}
			version = 18
		}
		if version == 18 {
			if err := runner.DownProductionSecurityAgentExecution(ctx); err != nil {
				return err
			}
			version = 17
		}
		if version == 17 {
			if err := runner.DownProductionRuntimeIngestReconciliation(ctx); err != nil {
				return err
			}
			version = 16
		}
		if version == 16 {
			if err := runner.DownProductionRuntimeGatewayReconciliation(ctx); err != nil {
				return err
			}
			version = 15
		}
		if version == 15 {
			if err := runner.DownProductionRuntimeDataPlane(ctx); err != nil {
				return err
			}
			version = 14
		}
		if version == 14 {
			if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
				return err
			}
			version = 13
		}
		if version == 13 {
			if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
				return err
			}
			version = 12
		}
		if version == 12 {
			if err := runner.DownReferenceAuthorization(ctx); err != nil {
				return err
			}
			version = 11
		}
		if version == 11 {
			if err := runner.DownConnectorAuthorization(ctx); err != nil {
				return err
			}
			version = 10
		}
		if version == 10 {
			if err := runner.DownProductionDiscovery(ctx); err != nil {
				return err
			}
			version = 9
		}
		if version == 9 {
			if err := runner.DownProductionRiskProjection(ctx); err != nil {
				return err
			}
			version = 8
		}
		if version == 8 {
			if err := runner.DownAPITokenRevealGrants(ctx); err != nil {
				return err
			}
			version = 7
		}
		if version == 7 {
			if err := runner.DownProductionAdministration(ctx); err != nil {
				return err
			}
			version = 6
		}
		if version == 6 {
			if err := runner.DownWorkflowReceiptProvenance(ctx); err != nil {
				return err
			}
			version = 5
		}
		if version == 5 {
			if err := runner.DownWorkflowReceiptSafety(ctx); err != nil {
				return err
			}
			version = 4
		}
		if version == 4 {
			if err := runner.DownWorkflowReceipts(ctx); err != nil {
				return err
			}
			version = 3
		}
		if version == 3 {
			if err := runner.DownWorkflows(ctx); err != nil {
				return err
			}
			version = 2
		}
		if version == 2 {
			if err := runner.DownCore(ctx); err != nil {
				return err
			}
			version = 1
		}
		if version == 1 {
			if err := runner.Down(ctx); err != nil {
				return err
			}
			version = 0
		}
		if version != 0 {
			return migrations.ErrInvalidState
		}
	default:
		return errInvalidMigrationCommand
	}
	actual, err := runner.Version(ctx)
	if err != nil {
		return err
	}
	if actual != version {
		return migrations.ErrInvalidState
	}
	return nil
}

type migrationDatabase struct{ connection *pgx.Conn }

func (database *migrationDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return database.connection.QueryRow(ctx, statement, arguments...)
}

func (database *migrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	transaction, err := database.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &migrationTransaction{transaction: transaction}, nil
}

type migrationTransaction struct{ transaction pgx.Tx }

func (transaction *migrationTransaction) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return transaction.transaction.QueryRow(ctx, statement, arguments...)
}

func (transaction *migrationTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := transaction.transaction.Exec(ctx, statement, arguments...)
	return err
}

func (transaction *migrationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction *migrationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
