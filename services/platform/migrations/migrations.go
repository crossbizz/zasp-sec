package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"
)

const (
	baselineVersion                     = int64(1)
	baselineName                        = "schema_versions"
	coreVersion                         = int64(2)
	coreName                            = "production_core"
	workflowVersion                     = int64(3)
	workflowName                        = "production_workflows"
	receiptVersion                      = int64(4)
	receiptName                         = "workflow_receipts"
	safetyVersion                       = int64(5)
	safetyName                          = "workflow_receipt_safety"
	provenanceVersion                   = int64(6)
	provenanceName                      = "workflow_receipt_provenance"
	administrationVersion               = int64(7)
	administrationName                  = "production_administration"
	revealGrantsVersion                 = int64(8)
	revealGrantsName                    = "api_token_reveal_grants"
	riskProjectionVersion               = int64(9)
	riskProjectionName                  = "production_risk_projection"
	discoveryVersion                    = int64(10)
	discoveryName                       = "production_discovery"
	connectorVersion                    = int64(11)
	connectorName                       = "connector_authorization"
	referenceVersion                    = int64(12)
	referenceName                       = "reference_authorization"
	executionVersion                    = int64(13)
	executionName                       = "production_discovery_execution"
	typedInventoryVersion               = int64(14)
	typedInventoryName                  = "typed_inventory_cutover"
	runtimeDataPlaneVersion             = int64(15)
	runtimeDataPlaneName                = "runtime_data_plane"
	runtimeGatewayReconciliationVersion = int64(16)
	runtimeGatewayReconciliationName    = "runtime_gateway_reconciliation"
	rollbackTimeout                     = 5 * time.Second

	tableExistsSQL                                 = "SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL"
	countRowsSQL                                   = `SELECT count(*) FROM "public"."zasp_schema_versions"`
	readRowSQL                                     = `SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`
	readVersionSQL                                 = `SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`
	lockTableSQL                                   = `LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`
	lockWorkflowMutationsSQL                       = `LOCK TABLE "public"."zasp_workflow_idempotency" IN ACCESS EXCLUSIVE MODE`
	lockAdministrationSQL                          = `LOCK TABLE "public"."zasp_identity_memberships", "public"."zasp_product_sessions", "public"."zasp_product_api_tokens", "public"."zasp_organizations", "public"."zasp_workspaces", "public"."zasp_environments", "public"."zasp_group_mappings", "public"."zasp_admin_audit", "public"."zasp_session_events", "public"."zasp_compliance_controls", "public"."zasp_compliance_evidence", "public"."zasp_data_controls" IN ACCESS EXCLUSIVE MODE`
	lockRevealGrantsSQL                            = `LOCK TABLE "public"."zasp_admin_idempotency", "public"."zasp_api_token_reveal_grants", "public"."zasp_product_api_tokens" IN ACCESS EXCLUSIVE MODE`
	lockRiskProjectionSQL                          = `LOCK TABLE "public"."zasp_risk_findings", "public"."zasp_risk_finding_evidence", "public"."zasp_risk_finding_factors", "public"."zasp_risk_attack_paths", "public"."zasp_risk_attack_path_nodes", "public"."zasp_risk_attack_path_evidence", "public"."zasp_risk_break_options", "public"."zasp_workflow_idempotency", "public"."zasp_workflow_audit", "public"."zasp_workflow_receipts" IN ACCESS EXCLUSIVE MODE`
	lockDiscoverySQL                               = `LOCK TABLE "public"."zasp_discovery_principal_bindings", "public"."zasp_integrations", "public"."zasp_integration_connections", "public"."zasp_discovery_schedules", "public"."zasp_discovery_syncs", "public"."zasp_discovery_jobs", "public"."zasp_discovery_snapshots", "public"."zasp_discovery_cursors", "public"."zasp_inventory_entities", "public"."zasp_inventory_source_observations", "public"."zasp_inventory_relationships", "public"."zasp_inventory_evidence", "public"."zasp_sensors", "public"."zasp_sensor_tokens", "public"."zasp_sensor_heartbeats", "public"."zasp_runtime_batches", "public"."zasp_runtime_stages", "public"."zasp_discovery_outbox", "public"."zasp_projection_work", "public"."zasp_gateway_devices", "public"."zasp_gateway_enrollment_tokens", "public"."zasp_gateway_credentials", "public"."zasp_gateway_policy_subscriptions" IN ACCESS EXCLUSIVE MODE`
	lockConnectorSQL                               = `LOCK TABLE "public"."zasp_connector_oauth_attempts", "public"."zasp_connector_effects", "public"."zasp_connector_credentials", "public"."zasp_connector_audit" IN ACCESS EXCLUSIVE MODE`
	lockExecutionSQL                               = `LOCK TABLE "public"."zasp_discovery_execution_principals", "public"."zasp_discovery_connection_subjects", "public"."zasp_discovery_execution_quotas", "public"."zasp_discovery_generation_reservations", "public"."zasp_discovery_job_authorities", "public"."zasp_discovery_job_checkpoints", "public"."zasp_discovery_upgrade_transitions", "public"."zasp_discovery_snapshot_inputs", "public"."zasp_discovery_snapshot_projection_items", "public"."zasp_discovery_projection_cursors" IN ACCESS EXCLUSIVE MODE`
	lockTypedInventorySQL                          = `LOCK TABLE "public"."zasp_inventory_cutover_state" IN ACCESS EXCLUSIVE MODE`
	lockRuntimeDataPlaneSQL                        = `LOCK TABLE "public"."zasp_runtime_data_plane_state" IN ACCESS EXCLUSIVE MODE`
	lockRuntimeGatewayReconciliationSQL            = `LOCK TABLE "public"."zasp_runtime_gateway_reconciliation_state" IN ACCESS EXCLUSIVE MODE`
	insertRowSQL                                   = `INSERT INTO "public"."zasp_schema_versions" ("version", "name", "checksum") VALUES ($1, $2, $3)`
	deleteRowSQL                                   = `DELETE FROM "public"."zasp_schema_versions" WHERE "version" = $1 AND "name" = $2 AND "checksum" = $3`
	referenceAuthorizationReadinessSQL             = `SELECT zasp_reference_authorization_readiness($1,$2)`
	discoveryExecutionReadinessSQL                 = `SELECT zasp_execution_readiness($1,$2)`
	typedInventoryReadinessSQL                     = `SELECT zasp_inventory_readiness($1,$2)`
	runtimeDataPlaneReadinessSQL                   = `SELECT zasp_runtime_data_plane_readiness($1,$2)`
	runtimeGatewayReconciliationReadinessSQL       = `SELECT zasp_runtime_gateway_reconciliation_readiness($1,$2)`
	typedInventoryRollbackAllowedSQL               = `SELECT NOT EXISTS (SELECT 1 FROM "public"."zasp_inventory_cutover_state" WHERE "phase" = 'cutover')`
	runtimeDataPlaneRollbackAllowedSQL             = `SELECT NOT EXISTS (SELECT 1 FROM "public"."zasp_runtime_data_plane_state" WHERE "used_at" IS NOT NULL)`
	runtimeGatewayReconciliationRollbackAllowedSQL = `SELECT NOT EXISTS (SELECT 1 FROM "public"."zasp_runtime_gateway_reconciliation_state" WHERE "used_at" IS NOT NULL)`
)

var (
	ErrInvalidContext  = errors.New("invalid migration context")
	ErrInvalidDatabase = errors.New("invalid migration database")
	ErrInvalidRunner   = errors.New("invalid migration runner")
	ErrInvalidState    = errors.New("invalid migration state")
	ErrDatabase        = errors.New("migration database failed")
)

//go:embed sql/0001_schema_versions.up.sql
var baselineUpSQL string

//go:embed sql/0001_schema_versions.down.sql
var baselineDownSQL string

//go:embed sql/0002_production_core.up.sql
var coreUpSQL string

//go:embed sql/0002_production_core.down.sql
var coreDownSQL string

//go:embed sql/0003_production_workflows.up.sql
var workflowUpSQL string

//go:embed sql/0003_production_workflows.down.sql
var workflowDownSQL string

//go:embed sql/0004_workflow_receipts.up.sql
var receiptUpSQL string

//go:embed sql/0004_workflow_receipts.down.sql
var receiptDownSQL string

//go:embed sql/0005_workflow_receipt_safety.up.sql
var safetyUpSQL string

//go:embed sql/0005_workflow_receipt_safety.down.sql
var safetyDownSQL string

//go:embed sql/0006_workflow_receipt_provenance.up.sql
var provenanceUpSQL string

//go:embed sql/0006_workflow_receipt_provenance.down.sql
var provenanceDownSQL string

//go:embed sql/0007_production_administration.up.sql
var administrationUpSQL string

//go:embed sql/0007_production_administration.down.sql
var administrationDownSQL string

//go:embed sql/0008_api_token_reveal_grants.up.sql
var revealGrantsUpSQL string

//go:embed sql/0008_api_token_reveal_grants.down.sql
var revealGrantsDownSQL string

//go:embed sql/0009_production_risk_projection.up.sql
var riskProjectionUpSQL string

//go:embed sql/0009_production_risk_projection.down.sql
var riskProjectionDownSQL string

//go:embed sql/0010_production_discovery.up.sql
var discoveryUpSQL string

//go:embed sql/0010_production_discovery.down.sql
var discoveryDownSQL string

//go:embed sql/0011_connector_authorization.up.sql
var connectorUpSQL string

//go:embed sql/0011_connector_authorization.down.sql
var connectorDownSQL string

//go:embed sql/0011_v10_rollback_normalization.sql
var connectorV10RollbackNormalizationSQL string

//go:embed sql/0012_reference_authorization.up.sql
var referenceUpSQL string

//go:embed sql/0012_reference_authorization.down.sql
var referenceDownSQL string

//go:embed sql/0013_production_discovery_execution.up.sql
var executionUpSQL string

//go:embed sql/0013_production_discovery_execution.down.sql
var executionDownSQL string

//go:embed sql/0014_typed_inventory_cutover.up.sql
var typedInventoryUpSQL string

//go:embed sql/0014_typed_inventory_cutover.down.sql
var typedInventoryDownSQL string

//go:embed sql/0015_runtime_data_plane.up.sql
var runtimeDataPlaneUpSQL string

//go:embed sql/0015_runtime_data_plane.down.sql
var runtimeDataPlaneDownSQL string

//go:embed sql/0016_runtime_gateway_reconciliation.up.sql
var runtimeGatewayReconciliationUpSQL string

//go:embed sql/0016_runtime_gateway_reconciliation.down.sql
var runtimeGatewayReconciliationDownSQL string

type Metadata struct {
	version  int64
	name     string
	checksum string
	up       string
	down     string
}

func Baseline() Metadata {
	up := strings.TrimSpace(baselineUpSQL)
	down := strings.TrimSpace(baselineDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{
		version:  baselineVersion,
		name:     baselineName,
		checksum: hex.EncodeToString(digest[:]),
		up:       up,
		down:     down,
	}
}

func ProductionCore() Metadata {
	up := strings.TrimSpace(coreUpSQL)
	down := strings.TrimSpace(coreDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{
		version:  coreVersion,
		name:     coreName,
		checksum: hex.EncodeToString(digest[:]),
		up:       up,
		down:     down,
	}
}

func ProductionWorkflows() Metadata {
	up := strings.TrimSpace(workflowUpSQL)
	down := strings.TrimSpace(workflowDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: workflowVersion, name: workflowName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func WorkflowReceipts() Metadata {
	up := strings.TrimSpace(receiptUpSQL)
	down := strings.TrimSpace(receiptDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: receiptVersion, name: receiptName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func WorkflowReceiptSafety() Metadata {
	up := strings.TrimSpace(safetyUpSQL)
	down := strings.TrimSpace(safetyDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: safetyVersion, name: safetyName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func WorkflowReceiptProvenance() Metadata {
	up := strings.TrimSpace(provenanceUpSQL)
	down := strings.TrimSpace(provenanceDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: provenanceVersion, name: provenanceName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionAdministration() Metadata {
	up := strings.TrimSpace(administrationUpSQL)
	down := strings.TrimSpace(administrationDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: administrationVersion, name: administrationName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func APITokenRevealGrants() Metadata {
	up := strings.TrimSpace(revealGrantsUpSQL)
	down := strings.TrimSpace(revealGrantsDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: revealGrantsVersion, name: revealGrantsName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRiskProjection() Metadata {
	up := strings.TrimSpace(riskProjectionUpSQL)
	down := strings.TrimSpace(riskProjectionDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: riskProjectionVersion, name: riskProjectionName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionDiscovery() Metadata {
	up := strings.TrimSpace(discoveryUpSQL)
	down := strings.TrimSpace(discoveryDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: discoveryVersion, name: discoveryName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ConnectorAuthorization() Metadata {
	up := strings.TrimSpace(connectorUpSQL)
	down := strings.TrimSpace(connectorDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: connectorVersion, name: connectorName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ReferenceAuthorization() Metadata {
	up := strings.TrimSpace(referenceUpSQL)
	down := strings.TrimSpace(referenceDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: referenceVersion, name: referenceName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionDiscoveryExecution() Metadata {
	up := strings.TrimSpace(executionUpSQL)
	down := strings.TrimSpace(executionDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: executionVersion, name: executionName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionTypedInventoryCutover() Metadata {
	up := strings.TrimSpace(typedInventoryUpSQL)
	down := strings.TrimSpace(typedInventoryDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: typedInventoryVersion, name: typedInventoryName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeDataPlane() Metadata {
	up := strings.TrimSpace(runtimeDataPlaneUpSQL)
	down := strings.TrimSpace(runtimeDataPlaneDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: runtimeDataPlaneVersion, name: runtimeDataPlaneName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeGatewayReconciliation() Metadata {
	up := strings.TrimSpace(runtimeGatewayReconciliationUpSQL)
	down := strings.TrimSpace(runtimeGatewayReconciliationDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: runtimeGatewayReconciliationVersion, name: runtimeGatewayReconciliationName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionWorkflowsSemanticFingerprint() string {
	const marker = "'production_workflows_fingerprint', '"
	start := strings.Index(workflowUpSQL, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	if len(workflowUpSQL) < start+64 {
		return ""
	}
	value := workflowUpSQL[start : start+64]
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || len(workflowUpSQL) == start+64 || workflowUpSQL[start+64] != '\'' {
		return ""
	}
	return value
}

func WorkflowReceiptsSemanticFingerprint() string {
	return semanticFingerprint(receiptUpSQL, "production_workflow_receipts_fingerprint")
}

func WorkflowReceiptSafetySemanticFingerprint() string {
	return semanticFingerprint(safetyUpSQL, "production_workflow_receipt_safety_fingerprint")
}

func WorkflowReceiptProvenanceSemanticFingerprint() string {
	return semanticFingerprint(provenanceUpSQL, "production_workflow_receipt_provenance_fingerprint")
}

func ProductionAdministrationSemanticFingerprint() string {
	return semanticFingerprint(administrationUpSQL, "production_administration_fingerprint")
}

func APITokenRevealGrantsSemanticFingerprint() string {
	return semanticFingerprint(revealGrantsUpSQL, "api_token_reveal_grants_fingerprint")
}

func ProductionRiskProjectionSemanticFingerprint() string {
	return semanticFingerprint(riskProjectionUpSQL, "production_risk_projection_fingerprint")
}

func ProductionDiscoverySemanticFingerprint() string {
	return semanticFingerprint(discoveryUpSQL, "production_discovery_fingerprint")
}

func ConnectorAuthorizationSemanticFingerprint() string {
	return semanticFingerprint(connectorUpSQL, "connector_authorization_fingerprint")
}

func ReferenceAuthorizationSemanticFingerprint() string {
	return semanticFingerprint(referenceUpSQL, "reference_authorization_fingerprint")
}

func ProductionDiscoveryExecutionSemanticFingerprint() string {
	return semanticFingerprint(executionUpSQL, "production_discovery_execution_fingerprint")
}

func ProductionTypedInventoryCutoverSemanticFingerprint() string {
	return semanticFingerprint(typedInventoryUpSQL, "typed_inventory_cutover_fingerprint")
}

func ProductionRuntimeDataPlaneSemanticFingerprint() string {
	return semanticFingerprint(runtimeDataPlaneUpSQL, "runtime_data_plane_fingerprint")
}

func ProductionRuntimeGatewayReconciliationSemanticFingerprint() string {
	return semanticFingerprint(runtimeGatewayReconciliationUpSQL, "runtime_gateway_reconciliation_fingerprint")
}

func semanticFingerprint(source, key string) string {
	marker := "'" + key + "', '"
	start := strings.Index(source, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	if len(source) < start+64 {
		return ""
	}
	value := source[start : start+64]
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || len(source) == start+64 || source[start+64] != '\'' {
		return ""
	}
	return value
}

func (metadata Metadata) Version() int64   { return metadata.version }
func (metadata Metadata) Name() string     { return metadata.name }
func (metadata Metadata) Checksum() string { return metadata.checksum }
func (metadata Metadata) UpSQL() string    { return metadata.up }
func (metadata Metadata) DownSQL() string  { return metadata.down }

type State struct {
	applied  bool
	version  int64
	name     string
	checksum string
}

func (state State) Applied() bool    { return state.applied }
func (state State) Version() int64   { return state.version }
func (state State) Name() string     { return state.name }
func (state State) Checksum() string { return state.checksum }

type Row interface {
	Scan(...any) error
}

type Queryer interface {
	QueryRow(context.Context, string, ...any) Row
}

type Transaction interface {
	Queryer
	Exec(context.Context, string, ...any) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type Database interface {
	Queryer
	Begin(context.Context) (Transaction, error)
}

type Runner struct {
	database Database
}

func NewRunner(database Database) (*Runner, error) {
	if nilInterface(database) {
		return nil, ErrInvalidDatabase
	}
	return &Runner{database: database}, nil
}

func (runner *Runner) State(ctx context.Context) (State, error) {
	if runner == nil || nilInterface(runner.database) {
		return State{}, ErrInvalidRunner
	}
	if ctx == nil {
		return State{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	return readState(ctx, runner.database)
}

// Version returns the exact release target installed in the database: zero for
// an empty database through the exact current production release. Any partial,
// extra, or checksum-drifted state is rejected.
func (runner *Runner) Version(ctx context.Context) (int64, error) {
	if runner == nil || nilInterface(runner.database) {
		return 0, ErrInvalidRunner
	}
	if ctx == nil {
		return 0, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	present, err := tablePresent(ctx, runner.database)
	if err != nil || !present {
		return 0, err
	}
	var count int64
	if err := scanRow(ctx, runner.database, countRowsSQL, nil, &count); err != nil {
		return 0, fixedDatabaseError(ctx, err)
	}
	if count < 1 || count > 16 {
		return 0, ErrInvalidState
	}
	metadata := []Metadata{Baseline()}
	if count >= 2 {
		metadata = append(metadata, ProductionCore())
	}
	if count == 3 {
		metadata = append(metadata, ProductionWorkflows())
	} else if count == 4 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts())
	} else if count == 5 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety())
	} else if count == 6 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance())
	} else if count == 7 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration())
	} else if count == 8 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants())
	} else if count == 9 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection())
	} else if count == 10 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery())
	} else if count == 11 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization())
	} else if count == 12 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization())
	} else if count == 13 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution())
	} else if count == 14 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover())
	} else if count == 15 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane())
	} else if count == 16 {
		metadata = append(metadata, ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation())
	}
	for _, expected := range metadata {
		var version int64
		var name, checksum string
		if err := scanRow(ctx, runner.database, readVersionSQL, []any{expected.Version()}, &version, &name, &checksum); err != nil {
			return 0, fixedDatabaseError(ctx, err)
		}
		if version != expected.Version() || name != expected.Name() || checksum != expected.Checksum() {
			return 0, ErrInvalidState
		}
	}
	return count, nil
}

func (runner *Runner) Up(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		state, err := readState(ctx, transaction)
		if err != nil {
			return err
		}
		if state.Applied() {
			return ErrInvalidState
		}
		metadata := Baseline()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err = readState(ctx, transaction)
		if err != nil {
			return err
		}
		if !state.Applied() {
			return ErrInvalidState
		}
		return nil
	})
}

// UpCore applies the first production data boundary only when the immutable
// baseline is the database's exact current state. Release tooling calls this
// explicitly; the API process never mutates its schema during startup.
func (runner *Runner) UpCore(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		state, err := readState(ctx, transaction)
		if err != nil {
			return err
		}
		baseline := Baseline()
		if !state.Applied() || state.Version() != baseline.Version() || state.Name() != baseline.Name() || state.Checksum() != baseline.Checksum() {
			return ErrInvalidState
		}
		metadata := ProductionCore()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readCoreState(ctx, transaction)
	})
}

// DownCore removes only the production data boundary, leaving the immutable
// baseline installed for a subsequent exact release migration.
func (runner *Runner) DownCore(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil {
			return err
		}
		if !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readCoreState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionCore()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err := readState(ctx, transaction)
		if err != nil {
			return err
		}
		baseline := Baseline()
		if !state.Applied() || state.Version() != baseline.Version() || state.Name() != baseline.Name() || state.Checksum() != baseline.Checksum() {
			return ErrInvalidState
		}
		return nil
	})
}

func (runner *Runner) UpWorkflows(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := readCoreState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionWorkflows()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowState(ctx, transaction)
	})
}

func (runner *Runner) DownWorkflows(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readWorkflowState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionWorkflows()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readCoreState(ctx, transaction)
	})
}

func (runner *Runner) UpWorkflowReceipts(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := readWorkflowState(ctx, transaction); err != nil {
			return err
		}
		metadata := WorkflowReceipts()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowReceiptState(ctx, transaction)
	})
}

func (runner *Runner) DownWorkflowReceipts(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readWorkflowReceiptState(ctx, transaction); err != nil {
			return err
		}
		metadata := WorkflowReceipts()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowState(ctx, transaction)
	})
}

func (runner *Runner) UpWorkflowReceiptSafety(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := readWorkflowReceiptState(ctx, transaction); err != nil {
			return err
		}
		metadata := WorkflowReceiptSafety()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowReceiptSafetyState(ctx, transaction)
	})
}

func (runner *Runner) DownWorkflowReceiptSafety(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		// Every v5 workflow mutation takes a conflicting relation lock before
		// checking the installed release. Taking the same lock first here gives
		// the guard a stable view of all earlier writers and makes queued v5
		// writers re-check the release only after this transaction commits.
		if err := transaction.Exec(ctx, lockWorkflowMutationsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readWorkflowReceiptSafetyState(ctx, transaction); err != nil {
			return err
		}
		metadata := WorkflowReceiptSafety()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowReceiptState(ctx, transaction)
	})
}

func (runner *Runner) UpWorkflowReceiptProvenance(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		// Serializing with both current writers and rollback prevents an old v5
		// wrapper from committing a row outside the durable provenance backfill.
		if err := transaction.Exec(ctx, lockWorkflowMutationsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readWorkflowReceiptSafetyState(ctx, transaction); err != nil {
			return err
		}
		metadata := WorkflowReceiptProvenance()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowReceiptProvenanceState(ctx, transaction)
	})
}

func (runner *Runner) DownWorkflowReceiptProvenance(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		// The v6 wrapper takes ROW EXCLUSIVE before its post-lock release check.
		// ACCESS EXCLUSIVE makes the marker guard observe every earlier writer and
		// forces queued old wrappers to re-check only after this transaction ends.
		if err := transaction.Exec(ctx, lockWorkflowMutationsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readWorkflowReceiptProvenanceState(ctx, transaction); err != nil {
			return err
		}
		metadata := WorkflowReceiptProvenance()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowReceiptSafetyState(ctx, transaction)
	})
}

func (runner *Runner) UpProductionAdministration(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readWorkflowReceiptProvenanceState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionAdministration()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionAdministrationState(ctx, transaction)
	})
}

func (runner *Runner) DownProductionAdministration(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockAdministrationSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionAdministrationState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionAdministration()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowReceiptProvenanceState(ctx, transaction)
	})
}

func (runner *Runner) UpAPITokenRevealGrants(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := transaction.Exec(ctx, lockWorkflowMutationsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockAdministrationSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionAdministrationState(ctx, transaction); err != nil {
			return err
		}
		metadata := APITokenRevealGrants()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readAPITokenRevealGrantsState(ctx, transaction)
	})
}

func (runner *Runner) DownAPITokenRevealGrants(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockRevealGrantsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockWorkflowMutationsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockAdministrationSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readAPITokenRevealGrantsState(ctx, transaction); err != nil {
			return err
		}
		metadata := APITokenRevealGrants()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionAdministrationState(ctx, transaction)
	})
}

func (runner *Runner) UpProductionRiskProjection(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := transaction.Exec(ctx, lockRevealGrantsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockWorkflowMutationsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readAPITokenRevealGrantsState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRiskProjection()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionRiskProjectionState(ctx, transaction)
	})
}

func (runner *Runner) DownProductionRiskProjection(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockRiskProjectionSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockRevealGrantsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockAdministrationSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRiskProjectionState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRiskProjection()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readAPITokenRevealGrantsState(ctx, transaction)
	})
}

func (runner *Runner) UpProductionDiscovery(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := transaction.Exec(ctx, lockRiskProjectionSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRiskProjectionState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionDiscovery()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionDiscoveryState(ctx, transaction)
	})
}

func (runner *Runner) DownProductionDiscovery(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockWorkflowMutationsSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockDiscoverySQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionDiscoveryState(ctx, transaction); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, strings.TrimSpace(connectorV10RollbackNormalizationSQL)); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		metadata := ProductionDiscovery()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionRiskProjectionState(ctx, transaction)
	})
}

func (runner *Runner) UpConnectorAuthorization(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := transaction.Exec(ctx, lockDiscoverySQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionDiscoveryState(ctx, transaction); err != nil {
			return err
		}
		metadata := ConnectorAuthorization()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readConnectorAuthorizationState(ctx, transaction)
	})
}

func (runner *Runner) DownConnectorAuthorization(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockConnectorSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readConnectorAuthorizationState(ctx, transaction); err != nil {
			return err
		}
		metadata := ConnectorAuthorization()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionDiscoveryState(ctx, transaction)
	})
}

func (runner *Runner) UpReferenceAuthorization(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readConnectorAuthorizationState(ctx, transaction); err != nil {
			return err
		}
		metadata := ReferenceAuthorization()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readReferenceAuthorizationState(ctx, transaction)
	})
}

func (runner *Runner) DownReferenceAuthorization(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readReferenceAuthorizationState(ctx, transaction); err != nil {
			return err
		}
		metadata := ReferenceAuthorization()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readConnectorAuthorizationState(ctx, transaction)
	})
}

func (runner *Runner) UpProductionDiscoveryExecution(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readReferenceAuthorizationState(ctx, transaction); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, transaction, referenceAuthorizationReadinessSQL, ReferenceAuthorization().Checksum(), ReferenceAuthorizationSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionDiscoveryExecution()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionDiscoveryExecutionState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, discoveryExecutionReadinessSQL, metadata.Checksum(), ProductionDiscoveryExecutionSemanticFingerprint())
	})
}

func requireMigrationReadiness(ctx context.Context, queryer Queryer, statement, checksum, fingerprint string) error {
	var ready bool
	if err := scanRow(ctx, queryer, statement, []any{checksum, fingerprint}, &ready); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if !ready {
		return ErrInvalidState
	}
	return nil
}

func (runner *Runner) DownProductionDiscoveryExecution(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockExecutionSQL, lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionDiscoveryExecutionState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionDiscoveryExecution()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readReferenceAuthorizationState(ctx, transaction)
	})
}

func (runner *Runner) UpProductionTypedInventoryCutover(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockExecutionSQL, lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionDiscoveryExecutionState(ctx, transaction); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, transaction, discoveryExecutionReadinessSQL, ProductionDiscoveryExecution().Checksum(), ProductionDiscoveryExecutionSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionTypedInventoryCutover()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionTypedInventoryCutoverState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, typedInventoryReadinessSQL, metadata.Checksum(), ProductionTypedInventoryCutoverSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionTypedInventoryCutover(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockTypedInventorySQL, lockExecutionSQL, lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionTypedInventoryCutoverState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionTypedInventoryCutover()
		if err := requireMigrationReadiness(ctx, transaction, typedInventoryReadinessSQL, metadata.Checksum(), ProductionTypedInventoryCutoverSemanticFingerprint()); err != nil {
			return err
		}
		var rollbackAllowed bool
		if err := scanRow(ctx, transaction, typedInventoryRollbackAllowedSQL, nil, &rollbackAllowed); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !rollbackAllowed {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionDiscoveryExecutionState(ctx, transaction)
	})
}

func (runner *Runner) UpProductionRuntimeDataPlane(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockTypedInventorySQL, lockExecutionSQL, lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionTypedInventoryCutoverState(ctx, transaction); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, transaction, typedInventoryReadinessSQL, ProductionTypedInventoryCutover().Checksum(), ProductionTypedInventoryCutoverSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeDataPlane()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeDataPlaneState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, runtimeDataPlaneReadinessSQL, metadata.Checksum(), ProductionRuntimeDataPlaneSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeDataPlane(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockRuntimeDataPlaneSQL, lockTypedInventorySQL, lockExecutionSQL, lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeDataPlaneState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeDataPlane()
		if err := requireMigrationReadiness(ctx, transaction, runtimeDataPlaneReadinessSQL, metadata.Checksum(), ProductionRuntimeDataPlaneSemanticFingerprint()); err != nil {
			return err
		}
		var rollbackAllowed bool
		if err := scanRow(ctx, transaction, runtimeDataPlaneRollbackAllowedSQL, nil, &rollbackAllowed); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !rollbackAllowed {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readProductionTypedInventoryCutoverState(ctx, transaction)
	})
}

func (runner *Runner) UpProductionRuntimeGatewayReconciliation(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockRuntimeDataPlaneSQL, lockTypedInventorySQL, lockExecutionSQL, lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeDataPlaneState(ctx, transaction); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, transaction, runtimeDataPlaneReadinessSQL, ProductionRuntimeDataPlane().Checksum(), ProductionRuntimeDataPlaneSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeGatewayReconciliation()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeGatewayReconciliationState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, runtimeGatewayReconciliationReadinessSQL, metadata.Checksum(), ProductionRuntimeGatewayReconciliationSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeGatewayReconciliation(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockRuntimeGatewayReconciliationSQL, lockRuntimeDataPlaneSQL, lockTypedInventorySQL, lockExecutionSQL, lockDiscoverySQL, lockConnectorSQL, lockWorkflowMutationsSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeGatewayReconciliationState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeGatewayReconciliation()
		if err := requireMigrationReadiness(ctx, transaction, runtimeGatewayReconciliationReadinessSQL, metadata.Checksum(), ProductionRuntimeGatewayReconciliationSemanticFingerprint()); err != nil {
			return err
		}
		var rollbackAllowed bool
		if err := scanRow(ctx, transaction, runtimeGatewayReconciliationRollbackAllowedSQL, nil, &rollbackAllowed); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !rollbackAllowed {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeDataPlaneState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, runtimeDataPlaneReadinessSQL, ProductionRuntimeDataPlane().Checksum(), ProductionRuntimeDataPlaneSemanticFingerprint())
	})
}

func (runner *Runner) Down(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil {
			return err
		}
		if !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err := readPresentState(ctx, transaction)
		if err != nil {
			return err
		}
		if !state.Applied() {
			return ErrInvalidState
		}
		metadata := Baseline()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err = readState(ctx, transaction)
		if err != nil {
			return err
		}
		if state.Applied() {
			return ErrInvalidState
		}
		return nil
	})
}

func (runner *Runner) withTransaction(ctx context.Context, operation func(context.Context, Transaction) error) (resultErr error) {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	transaction, err := runner.database.Begin(ctx)
	if nilInterface(transaction) {
		if err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return ErrInvalidDatabase
	}
	if err != nil {
		if rollbackTransaction(ctx, transaction) != nil {
			return ErrDatabase
		}
		return fixedDatabaseError(ctx, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if err := rollbackTransaction(ctx, transaction); err != nil {
			resultErr = ErrDatabase
		}
	}()
	if err := operation(ctx, transaction); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := transaction.Commit(ctx); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	committed = true
	return nil
}

func rollbackTransaction(ctx context.Context, transaction Transaction) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	return transaction.Rollback(rollbackCtx)
}

func readState(ctx context.Context, queryer Queryer) (State, error) {
	present, err := tablePresent(ctx, queryer)
	if err != nil {
		return State{}, err
	}
	if !present {
		return State{}, nil
	}
	return readPresentState(ctx, queryer)
}

func tablePresent(ctx context.Context, queryer Queryer) (bool, error) {
	if nilInterface(queryer) {
		return false, ErrInvalidDatabase
	}
	var present bool
	if err := scanRow(ctx, queryer, tableExistsSQL, nil, &present); err != nil {
		return false, fixedDatabaseError(ctx, err)
	}
	return present, nil
}

func readPresentState(ctx context.Context, queryer Queryer) (State, error) {
	var count int64
	if err := scanRow(ctx, queryer, countRowsSQL, nil, &count); err != nil {
		return State{}, fixedDatabaseError(ctx, err)
	}
	if count != 1 {
		return State{}, ErrInvalidState
	}
	state := State{applied: true}
	if err := scanRow(ctx, queryer, readRowSQL, nil, &state.version, &state.name, &state.checksum); err != nil {
		return State{}, fixedDatabaseError(ctx, err)
	}
	metadata := Baseline()
	if state.version != metadata.Version() || state.name != metadata.Name() || state.checksum != metadata.Checksum() {
		return State{}, ErrInvalidState
	}
	return state, nil
}

func readCoreState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore()})
}

func readWorkflowState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows()})
}

func readWorkflowReceiptState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts()})
}

func readWorkflowReceiptSafetyState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety()})
}

func readWorkflowReceiptProvenanceState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance()})
}

func readProductionAdministrationState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration()})
}

func readAPITokenRevealGrantsState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants()})
}

func readProductionRiskProjectionState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection()})
}

func readProductionDiscoveryState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery()})
}

func readConnectorAuthorizationState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization()})
}

func readReferenceAuthorizationState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization()})
}

func readProductionDiscoveryExecutionState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution()})
}

func readProductionTypedInventoryCutoverState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover()})
}

func readProductionRuntimeDataPlaneState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane()})
}

func readProductionRuntimeGatewayReconciliationState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation()})
}

func readExactReleaseState(ctx context.Context, queryer Queryer, expected []Metadata) error {
	var count int64
	if err := scanRow(ctx, queryer, countRowsSQL, nil, &count); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if count != int64(len(expected)) {
		return ErrInvalidState
	}
	for _, metadata := range expected {
		state := State{applied: true}
		if err := scanRow(ctx, queryer, readVersionSQL, []any{metadata.Version()}, &state.version, &state.name, &state.checksum); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if state.version != metadata.Version() || state.name != metadata.Name() || state.checksum != metadata.Checksum() {
			return ErrInvalidState
		}
	}
	return nil
}

func scanRow(ctx context.Context, queryer Queryer, statement string, arguments []any, destinations ...any) error {
	row := queryer.QueryRow(ctx, statement, arguments...)
	if nilInterface(row) {
		return ErrInvalidDatabase
	}
	return row.Scan(destinations...)
}

func fixedDatabaseError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return ErrDatabase
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
