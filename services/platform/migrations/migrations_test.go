package migrations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fakeRow struct {
	values []any
	err    error
}

func (row fakeRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("scan arity")
	}
	for index, value := range row.values {
		switch destination := destinations[index].(type) {
		case *bool:
			converted, ok := value.(bool)
			if !ok {
				return errors.New("scan bool")
			}
			*destination = converted
		case *int64:
			converted, ok := value.(int64)
			if !ok {
				return errors.New("scan int64")
			}
			*destination = converted
		case *string:
			converted, ok := value.(string)
			if !ok {
				return errors.New("scan string")
			}
			*destination = converted
		default:
			return errors.New("scan destination")
		}
	}
	return nil
}

type fakeTransaction struct {
	events               *[]string
	rows                 []Row
	execErrorAt          int
	queryErrorAt         int
	commitError          error
	rollbackError        error
	rollbackContextError error
	execs                int
	queries              int
}

func (transaction *fakeTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	*transaction.events = append(*transaction.events, "exec:"+compactSQL(statement), argumentEvent(arguments))
	transaction.execs++
	if err := ctx.Err(); err != nil {
		return err
	}
	if transaction.execErrorAt == transaction.execs {
		return errors.New("database detail")
	}
	return nil
}

func (transaction *fakeTransaction) QueryRow(ctx context.Context, statement string, arguments ...any) Row {
	*transaction.events = append(*transaction.events, "query:"+compactSQL(statement), argumentEvent(arguments))
	transaction.queries++
	if err := ctx.Err(); err != nil {
		return fakeRow{err: err}
	}
	if transaction.queryErrorAt == transaction.queries {
		return fakeRow{err: errors.New("database detail")}
	}
	if len(transaction.rows) == 0 {
		return fakeRow{err: errors.New("missing scripted row")}
	}
	row := transaction.rows[0]
	transaction.rows = transaction.rows[1:]
	return row
}

func (transaction *fakeTransaction) Commit(ctx context.Context) error {
	*transaction.events = append(*transaction.events, "commit")
	if err := ctx.Err(); err != nil {
		return err
	}
	return transaction.commitError
}

func (transaction *fakeTransaction) Rollback(ctx context.Context) error {
	*transaction.events = append(*transaction.events, "rollback")
	transaction.rollbackContextError = ctx.Err()
	return transaction.rollbackError
}

type fakeDatabase struct {
	events      []string
	transaction *fakeTransaction
	rows        []Row
	beginError  error
	queries     int
}

type ambiguousBeginDatabase struct {
	events      []string
	transaction *fakeTransaction
}

func (database *ambiguousBeginDatabase) Begin(context.Context) (Transaction, error) {
	database.events = append(database.events, "begin")
	database.transaction.events = &database.events
	return database.transaction, errors.New("ambiguous begin detail")
}

func (database *ambiguousBeginDatabase) QueryRow(context.Context, string, ...any) Row {
	return fakeRow{err: errors.New("must not query")}
}

func (database *fakeDatabase) Begin(ctx context.Context) (Transaction, error) {
	database.events = append(database.events, "begin")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if database.beginError != nil {
		return nil, database.beginError
	}
	database.transaction.events = &database.events
	return database.transaction, nil
}

func (database *fakeDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) Row {
	database.events = append(database.events, "query:"+compactSQL(statement), argumentEvent(arguments))
	database.queries++
	if err := ctx.Err(); err != nil {
		return fakeRow{err: err}
	}
	if len(database.rows) == 0 {
		return fakeRow{err: errors.New("missing scripted row")}
	}
	row := database.rows[0]
	database.rows = database.rows[1:]
	return row
}

func compactSQL(value string) string { return strings.Join(strings.Fields(value), " ") }

func argumentEvent(values []any) string {
	if len(values) == 0 {
		return "args:none"
	}
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = fmt.Sprint(value)
	}
	return "args:" + strings.Join(parts, ",")
}

func exactRows() []Row {
	metadata := Baseline()
	return []Row{
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(1)}},
		fakeRow{values: []any{metadata.Version(), metadata.Name(), metadata.Checksum()}},
	}
}

func TestBaselineMetadataIsStableAndOpaque(t *testing.T) {
	metadata := Baseline()
	const expectedUp = `CREATE TABLE "public"."zasp_schema_versions" (
    "version" bigint PRIMARY KEY,
    "name" text NOT NULL UNIQUE CHECK (char_length("name") BETWEEN 1 AND 63),
    "checksum" text NOT NULL CHECK ("checksum" ~ '^[a-f0-9]{64}$'),
    "applied_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp()
);`
	const expectedDown = `DROP TABLE "public"."zasp_schema_versions";`
	const expectedChecksum = "feeec4a9f6da520b46d09ac4c9c6ea6d99b052e8f5e5d4408d0dfffd8e554670"
	if metadata.Version() != 1 || metadata.Name() != "schema_versions" {
		t.Fatalf("baseline identity = %d/%q", metadata.Version(), metadata.Name())
	}
	if len(metadata.Checksum()) != 64 || strings.Trim(metadata.Checksum(), "0123456789abcdef") != "" {
		t.Fatalf("baseline checksum = %q", metadata.Checksum())
	}
	if metadata.UpSQL() == "" || metadata.DownSQL() == "" || metadata.UpSQL() == metadata.DownSQL() {
		t.Fatal("embedded migration assets are missing")
	}
	if !strings.Contains(metadata.UpSQL(), `CREATE TABLE "public"."zasp_schema_versions"`) ||
		!strings.Contains(metadata.DownSQL(), `DROP TABLE "public"."zasp_schema_versions"`) {
		t.Fatal("baseline assets do not own only the schema-version table")
	}
	if Baseline() != metadata {
		t.Fatal("baseline metadata changed between reads")
	}
	if metadata.UpSQL() != expectedUp || metadata.DownSQL() != expectedDown || metadata.Checksum() != expectedChecksum {
		t.Fatalf("version-1 assets drifted: checksum=%q", metadata.Checksum())
	}
}

func TestProductionCoreMetadataOwnsOnlyMountedDurableSessionAndCoreSchema(t *testing.T) {
	metadata := ProductionCore()
	if metadata.Version() != 2 || metadata.Name() != "production_core" || len(metadata.Checksum()) != 64 {
		t.Fatalf("production core identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{"zasp_schema_metadata", "zasp_product_sessions", "zasp_product_api_tokens", "zasp_create_product_session", "zasp_core_payloads", "zasp_session_bootstrap", "zasp_core_read", "production-core-v1"} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("production core up migration missing %q", fragment)
		}
	}
	if strings.Contains(metadata.UpSQL(), "zasp_core_write") {
		t.Fatal("production core migration exposes an unmounted simulated mutation")
	}
	if metadata.UpSQL() == "" || metadata.DownSQL() == "" || ProductionCore() != metadata {
		t.Fatal("production core migration assets are missing or unstable")
	}
}

func TestProductionWorkflowsMetadataOwnsAtomicScopedWorkflowState(t *testing.T) {
	metadata := ProductionWorkflows()
	if metadata.Version() != 3 || metadata.Name() != "production_workflows" || len(metadata.Checksum()) != 64 {
		t.Fatalf("production workflows identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_workflow_records", "zasp_workflow_idempotency", "zasp_workflow_audit",
		"zasp_workflow_list", "zasp_workflow_page", "zasp_workflow_get", "zasp_workflow_replay", "zasp_workflow_mutate",
		"organization_id", "workspace_id", "environment_id", "expected_version",
		"requested_idempotency_key", "requested_intent", "pg_advisory_xact_lock", "requested_correlation_id", "production-workflows-v1",
		"SET \"authenticated_at\" = LEAST", "zasp_effective_scope_permissions",
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("production workflows migration missing %q", fragment)
		}
	}
	if strings.Contains(metadata.UpSQL(), "enrollment_token") || strings.Contains(metadata.UpSQL(), "provider_secret") {
		t.Fatal("workflow schema persists readable one-time or provider secrets")
	}
	if metadata.UpSQL() == "" || metadata.DownSQL() == "" || ProductionWorkflows() != metadata {
		t.Fatal("production workflows migration assets are missing or unstable")
	}
	if fingerprint := ProductionWorkflowsSemanticFingerprint(); len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) {
		t.Fatalf("production workflow semantic fingerprint = %q", fingerprint)
	}
}

func TestWorkflowReceiptsMetadataExtendsTheImmutableWorkflowRelease(t *testing.T) {
	metadata := WorkflowReceipts()
	if metadata.Version() != 4 || metadata.Name() != "workflow_receipts" || len(metadata.Checksum()) != 64 {
		t.Fatalf("workflow receipt identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_workflow_receipts", "zasp_workflow_receipt_list", "zasp_workflow_receipt_acknowledge",
		"acknowledged_at", "expires_at", "requested_receipt_id", "interval '7 days'",
		"production-workflow-receipts-v1", "production_workflow_receipts_fingerprint",
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("workflow receipt migration missing %q", fragment)
		}
	}
	if !strings.Contains(metadata.DownSQL(), "production-workflows-v1") || WorkflowReceipts() != metadata {
		t.Fatal("workflow receipt migration assets are missing or unstable")
	}
	if fingerprint := WorkflowReceiptsSemanticFingerprint(); len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) {
		t.Fatalf("workflow receipt semantic fingerprint = %q", fingerprint)
	}
}

func TestWorkflowReceiptSafetyMetadataSeparatesBrowserReceiptsAndBoundedCleanup(t *testing.T) {
	metadata := WorkflowReceiptSafety()
	if metadata.Version() != 5 || metadata.Name() != "workflow_receipt_safety" || len(metadata.Checksum()) != 64 {
		t.Fatalf("workflow receipt safety identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_workflow_receipt_cleanup", "requested_limit", "LIMIT requested_limit", "SKIP LOCKED",
		"requested_receipt_id IS NOT NULL", "requested_receipt_id <> ''", "production-workflow-receipt-safety-v2",
		"production_workflow_receipt_safety_fingerprint", `LOCK TABLE "public"."zasp_workflow_idempotency" IN ROW EXCLUSIVE MODE`,
		"workflow receipt safety release unavailable", `release."version" = 5`, `release."name" = 'workflow_receipt_safety'`,
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("workflow receipt safety migration missing %q", fragment)
		}
	}
	if !strings.Contains(metadata.DownSQL(), "production-workflow-receipts-v1") || WorkflowReceiptSafety() != metadata {
		t.Fatal("workflow receipt safety migration assets are missing or unstable")
	}
	for _, fragment := range []string{
		"workflow receipt safety rollback blocked", "zasp_schema_metadata", "applied_at",
		"zasp_workflow_idempotency", "response", "receipt_id", `LOCK TABLE "public"."zasp_workflow_idempotency" IN ACCESS EXCLUSIVE MODE`,
	} {
		if !strings.Contains(metadata.DownSQL(), fragment) {
			t.Fatalf("workflow receipt safety rollback guard missing %q", fragment)
		}
	}
	if fingerprint := WorkflowReceiptSafetySemanticFingerprint(); len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) {
		t.Fatalf("workflow receipt safety semantic fingerprint = %q", fingerprint)
	}
}

func TestWorkflowReceiptProvenanceMetadataUsesDurableMarkerAndSafeIntermediateDowngrade(t *testing.T) {
	metadata := WorkflowReceiptProvenance()
	if metadata.Version() != 6 || metadata.Name() != "workflow_receipt_provenance" || len(metadata.Checksum()) != 64 {
		t.Fatalf("workflow receipt provenance identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"receipt_semantics", "receiptless_incompatible", "receipt_backed",
		"production-workflow-receipt-provenance-v3", "production_workflow_receipt_provenance_fingerprint",
		`LOCK TABLE "public"."zasp_workflow_idempotency" IN ROW EXCLUSIVE MODE`,
		"workflow receipt provenance release unavailable", `release."version" = 6`, `release."name" = 'workflow_receipt_provenance'`,
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("workflow receipt provenance migration missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"workflow receipt provenance rollback blocked", "workflow mutations unavailable at intermediate receipt provenance downgrade",
		"zasp_workflow_idempotency_receipt_semantics_check", "receipt_semantics", "receipt_backed",
	} {
		if !strings.Contains(metadata.DownSQL(), fragment) {
			t.Fatalf("workflow receipt provenance rollback guard missing %q", fragment)
		}
	}
	if strings.Contains(metadata.DownSQL(), `"created_at"`) || strings.Contains(metadata.DownSQL(), `"applied_at" >=`) {
		t.Fatal("workflow receipt provenance rollback infers compatibility from timestamps")
	}
	fingerprint := WorkflowReceiptProvenanceSemanticFingerprint()
	if fingerprint == strings.Repeat("0", 64) || len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) {
		t.Fatalf("workflow receipt provenance semantic fingerprint = %q", fingerprint)
	}
	if WorkflowReceiptProvenance() != metadata {
		t.Fatal("workflow receipt provenance migration assets are unstable")
	}
}

func TestProductionAdministrationMetadataOwnsOnlyDurableLocalAdministration(t *testing.T) {
	metadata := ProductionAdministration()
	if metadata.Version() != 7 || metadata.Name() != "production_administration" || len(metadata.Checksum()) != 64 {
		t.Fatalf("production administration identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_organizations", "zasp_workspaces", "zasp_environments", "zasp_group_mappings", "zasp_admin_audit",
		"zasp_session_events", "zasp_compliance_controls", "zasp_compliance_evidence", "zasp_data_controls",
		"production_administration_fingerprint", "production-administration-v1",
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("production administration up migration missing %q", fragment)
		}
	}
	for _, prohibited := range []string{"sso_connection", "scim_connection", "compliance_export", "audit_export", "data_deletion"} {
		if strings.Contains(strings.ToLower(metadata.UpSQL()), prohibited) {
			t.Fatalf("production administration migration claims hidden boundary %q", prohibited)
		}
	}
	if ProductionAdministrationSemanticFingerprint() == "" {
		t.Fatal("production administration semantic fingerprint is missing")
	}
}

func TestAPITokenRevealGrantsMigrationOwnsEncryptedRecoverableSecrets(t *testing.T) {
	metadata := APITokenRevealGrants()
	if metadata.Version() != 8 || metadata.Name() != "api_token_reveal_grants" || len(metadata.Checksum()) != 64 {
		t.Fatalf("API token reveal migration identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_api_token_reveal_grants", "ciphertext", "nonce", "authentication_tag",
		"acknowledged_at", "api_token_reveal_grants_fingerprint", "api-token-reveal-grants-v1",
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("API token reveal migration missing %q", fragment)
		}
	}
	for _, prohibited := range []string{"raw_token", "plaintext", "token_secret"} {
		if strings.Contains(strings.ToLower(metadata.UpSQL()), prohibited) {
			t.Fatalf("API token reveal migration stores prohibited material %q", prohibited)
		}
	}
	fingerprint := APITokenRevealGrantsSemanticFingerprint()
	if len(fingerprint) != 64 || fingerprint == strings.Repeat("0", 64) {
		t.Fatalf("API token reveal semantic fingerprint = %q", fingerprint)
	}
	if !strings.Contains(APITokenRevealGrants().DownSQL(), "semantic schema drift blocks rollback") || !strings.Contains(ProductionAdministration().DownSQL(), "semantic schema drift blocks rollback") {
		t.Fatal("v7/v8 rollback must verify the live semantic fingerprint before destructive DDL")
	}
}

func TestProductionRiskProjectionMigrationOwnsTypedRiskAuthority(t *testing.T) {
	metadata := ProductionRiskProjection()
	if metadata.Version() != 9 || metadata.Name() != "production_risk_projection" || len(metadata.Checksum()) != 64 {
		t.Fatalf("risk projection migration identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_risk_findings", "zasp_risk_finding_evidence", "zasp_risk_finding_factors",
		"zasp_risk_attack_paths", "zasp_risk_attack_path_nodes", "zasp_risk_attack_path_evidence", "zasp_risk_break_options",
		"zasp_risk_finding_visible", "zasp_risk_finding_page", "zasp_risk_attack_path_valid", "zasp_risk_attack_path_page", "zasp_risk_mutate",
		"production_risk_projection_fingerprint", "production-risk-projection-v1",
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("risk projection migration missing %q", fragment)
		}
	}
	fingerprint := ProductionRiskProjectionSemanticFingerprint()
	if len(fingerprint) != 64 || fingerprint == strings.Repeat("0", 64) {
		t.Fatalf("risk projection semantic fingerprint = %q", fingerprint)
	}
	for _, fragment := range []string{"semantic schema drift blocks rollback", "risk projection data blocks rollback", "api-token-reveal-grants-v1"} {
		if !strings.Contains(metadata.DownSQL(), fragment) {
			t.Fatalf("risk projection down migration missing %q", fragment)
		}
	}
}

func TestProductionDiscoveryMigrationOwnsScopedRuntimeAuthority(t *testing.T) {
	metadata := ProductionDiscovery()
	if metadata.Version() != 10 || metadata.Name() != "production_discovery" || len(metadata.Checksum()) != 64 {
		t.Fatalf("production discovery migration identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_integrations", "zasp_discovery_syncs", "zasp_discovery_schedules", "zasp_discovery_cursors",
		"zasp_discovery_snapshots", "zasp_inventory_entities", "zasp_inventory_source_observations",
		"zasp_inventory_relationships", "zasp_inventory_evidence", "zasp_sensors", "zasp_sensor_tokens",
		"zasp_sensor_heartbeats", "zasp_runtime_batches", "zasp_runtime_stages", "zasp_discovery_jobs",
		"zasp_discovery_outbox", "zasp_projection_work", "zasp_gateway_devices", "zasp_gateway_enrollment_tokens",
		"zasp_gateway_credentials", "zasp_gateway_policy_subscriptions", "production_discovery_fingerprint",
		"zasp_discovery_apply_snapshot", "zasp_discovery_claim_jobs", "zasp_discovery_claim_schedules", "zasp_discovery_claim_projection_work",
		"zasp_discovery_complete_job", "zasp_discovery_retry_outbox", "zasp_discovery_complete_runtime_stage", "zasp_discovery_gateway_rotate",
		"production-discovery-v1",
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("production discovery migration missing %q", fragment)
		}
	}
	if fingerprint := ProductionDiscoverySemanticFingerprint(); len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) {
		t.Fatalf("production discovery semantic fingerprint = %q", fingerprint)
	}
	for _, fragment := range []string{"semantic schema drift blocks rollback", "production discovery data blocks rollback", "production-risk-projection-v1"} {
		if !strings.Contains(metadata.DownSQL(), fragment) {
			t.Fatalf("production discovery rollback missing %q", fragment)
		}
	}
}

func TestRunnerVersionDistinguishesEmptyBaselineCoreWorkflowsReceiptsAndDrift(t *testing.T) {
	baseline, core, workflows, receipts, safety, provenance, administration := Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration()
	reveal, risk, discovery := APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery()
	for _, test := range []struct {
		name    string
		rows    []Row
		want    int64
		wantErr error
	}{
		{name: "empty", rows: []Row{fakeRow{values: []any{false}}}, want: 0},
		{name: "baseline", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(1)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}}, want: 1},
		{name: "core", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(2)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}, fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}}}, want: 2},
		{name: "workflows", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(3)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}, fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}}, fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}}}, want: 3},
		{name: "receipts", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(4)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}, fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}}, fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}}, fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}}}, want: 4},
		{name: "safety", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(5)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}, fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}}, fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}}, fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}}, fakeRow{values: []any{safety.Version(), safety.Name(), safety.Checksum()}}}, want: 5},
		{name: "provenance", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(6)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}, fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}}, fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}}, fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}}, fakeRow{values: []any{safety.Version(), safety.Name(), safety.Checksum()}}, fakeRow{values: []any{provenance.Version(), provenance.Name(), provenance.Checksum()}}}, want: 6},
		{name: "administration", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(7)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}, fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}}, fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}}, fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}}, fakeRow{values: []any{safety.Version(), safety.Name(), safety.Checksum()}}, fakeRow{values: []any{provenance.Version(), provenance.Name(), provenance.Checksum()}}, fakeRow{values: []any{administration.Version(), administration.Name(), administration.Checksum()}}}, want: 7},
		{name: "discovery", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(10)}}, fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}}, fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}}, fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}}, fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}}, fakeRow{values: []any{safety.Version(), safety.Name(), safety.Checksum()}}, fakeRow{values: []any{provenance.Version(), provenance.Name(), provenance.Checksum()}}, fakeRow{values: []any{administration.Version(), administration.Name(), administration.Checksum()}}, fakeRow{values: []any{reveal.Version(), reveal.Name(), reveal.Checksum()}}, fakeRow{values: []any{risk.Version(), risk.Name(), risk.Checksum()}}, fakeRow{values: []any{discovery.Version(), discovery.Name(), discovery.Checksum()}}}, want: 10},
		{name: "drift", rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(11)}}}, wantErr: ErrInvalidState},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &fakeDatabase{rows: test.rows, transaction: &fakeTransaction{}}
			runner, _ := NewRunner(database)
			got, err := runner.Version(context.Background())
			if got != test.want || !errors.Is(err, test.wantErr) {
				t.Fatalf("Version = (%d, %v), want (%d, %v)", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestRunnerDownWorkflowReceiptProvenanceTakesMutationLockBeforeSchemaLock(t *testing.T) {
	baseline, core := Baseline(), ProductionCore()
	workflows, receipts := ProductionWorkflows(), WorkflowReceipts()
	safety, provenance := WorkflowReceiptSafety(), WorkflowReceiptProvenance()
	transaction := &fakeTransaction{rows: []Row{
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(6)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}},
		fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}},
		fakeRow{values: []any{safety.Version(), safety.Name(), safety.Checksum()}},
		fakeRow{values: []any{provenance.Version(), provenance.Name(), provenance.Checksum()}},
		fakeRow{values: []any{int64(5)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}},
		fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}},
		fakeRow{values: []any{safety.Version(), safety.Name(), safety.Checksum()}},
	}}
	database := &fakeDatabase{transaction: transaction}
	runner, _ := NewRunner(database)
	if err := runner.DownWorkflowReceiptProvenance(context.Background()); err != nil {
		t.Fatalf("DownWorkflowReceiptProvenance: %v", err)
	}
	wantPrefix := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`exec:LOCK TABLE "public"."zasp_workflow_idempotency" IN ACCESS EXCLUSIVE MODE`, "args:none",
		`exec:LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`, "args:none",
	}
	if len(database.events) < len(wantPrefix) || !reflect.DeepEqual(database.events[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("lock order = %#v, want prefix %#v", database.events, wantPrefix)
	}
	if !contains(database.events, "exec:"+compactSQL(provenance.DownSQL())) || !contains(database.events, "args:6,workflow_receipt_provenance,"+provenance.Checksum()) {
		t.Fatalf("workflow receipt provenance down events = %#v", database.events)
	}
}

func TestRunnerDownCoreRequiresExactCoreAndRestoresBaseline(t *testing.T) {
	baseline, core := Baseline(), ProductionCore()
	transaction := &fakeTransaction{rows: []Row{
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(2)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(1)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
	}}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.DownCore(context.Background()); err != nil {
		t.Fatalf("DownCore: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`exec:LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`, "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:1",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:2",
		`exec:DELETE FROM "public"."zasp_schema_versions" WHERE "version" = $1 AND "name" = $2 AND "checksum" = $3`, "args:2,production_core," + core.Checksum(),
		"exec:" + compactSQL(core.DownSQL()), "args:none",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`, "args:none",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
}

func TestRunnerUpCoreRequiresBaselineAndRecordsExactRelease(t *testing.T) {
	baseline, core := Baseline(), ProductionCore()
	transaction := &fakeTransaction{rows: append(exactRows(),
		fakeRow{values: []any{int64(2)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
	)}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.UpCore(context.Background()); err != nil {
		t.Fatalf("UpCore: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`, "args:none",
		"exec:" + compactSQL(core.UpSQL()), "args:none",
		`exec:INSERT INTO "public"."zasp_schema_versions" ("version", "name", "checksum") VALUES ($1, $2, $3)`,
		"args:2,production_core," + core.Checksum(),
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:1",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:2",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
}

func TestRunnerAppliesAndRemovesWorkflowReleaseOnlyFromExactAdjacentStates(t *testing.T) {
	baseline, core, workflows := Baseline(), ProductionCore(), ProductionWorkflows()
	upRows := []Row{
		fakeRow{values: []any{int64(2)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{int64(3)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}},
	}
	upDB := &fakeDatabase{transaction: &fakeTransaction{rows: upRows}}
	runner, _ := NewRunner(upDB)
	if err := runner.UpWorkflows(context.Background()); err != nil {
		t.Fatalf("UpWorkflows: %v", err)
	}
	if !contains(upDB.events, "args:3,production_workflows,"+workflows.Checksum()) || !contains(upDB.events, "exec:"+compactSQL(workflows.UpSQL())) {
		t.Fatalf("workflow up events = %#v", upDB.events)
	}

	downRows := []Row{
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(3)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}},
		fakeRow{values: []any{int64(2)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
	}
	downDB := &fakeDatabase{transaction: &fakeTransaction{rows: downRows}}
	runner, _ = NewRunner(downDB)
	if err := runner.DownWorkflows(context.Background()); err != nil {
		t.Fatalf("DownWorkflows: %v", err)
	}
	if !contains(downDB.events, "args:3,production_workflows,"+workflows.Checksum()) || !contains(downDB.events, "exec:"+compactSQL(workflows.DownSQL())) {
		t.Fatalf("workflow down events = %#v", downDB.events)
	}
}

func TestRunnerDownWorkflowReceiptSafetyTakesMutationLockBeforeSchemaLock(t *testing.T) {
	baseline, core := Baseline(), ProductionCore()
	workflows, receipts, safety := ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety()
	transaction := &fakeTransaction{rows: []Row{
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(5)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}},
		fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}},
		fakeRow{values: []any{safety.Version(), safety.Name(), safety.Checksum()}},
		fakeRow{values: []any{int64(4)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{workflows.Version(), workflows.Name(), workflows.Checksum()}},
		fakeRow{values: []any{receipts.Version(), receipts.Name(), receipts.Checksum()}},
	}}
	database := &fakeDatabase{transaction: transaction}
	runner, _ := NewRunner(database)
	if err := runner.DownWorkflowReceiptSafety(context.Background()); err != nil {
		t.Fatalf("DownWorkflowReceiptSafety: %v", err)
	}

	wantPrefix := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`exec:LOCK TABLE "public"."zasp_workflow_idempotency" IN ACCESS EXCLUSIVE MODE`, "args:none",
		`exec:LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`, "args:none",
	}
	if len(database.events) < len(wantPrefix) || !reflect.DeepEqual(database.events[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("lock order = %#v, want prefix %#v", database.events, wantPrefix)
	}
	if !contains(database.events, "exec:"+compactSQL(safety.DownSQL())) || !contains(database.events, "args:5,workflow_receipt_safety,"+safety.Checksum()) {
		t.Fatalf("workflow receipt safety down events = %#v", database.events)
	}
}

func TestRunnerUpCreatesAndRecordsExactBaselineInOneTransaction(t *testing.T) {
	metadata := Baseline()
	transaction := &fakeTransaction{rows: append([]Row{fakeRow{values: []any{false}}}, exactRows()...)}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	if err := runner.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		"exec:" + compactSQL(metadata.UpSQL()), "args:none",
		"exec:INSERT INTO \"public\".\"zasp_schema_versions\" (\"version\", \"name\", \"checksum\") VALUES ($1, $2, $3)",
		"args:1,schema_versions," + metadata.Checksum(),
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		"query:SELECT count(*) FROM \"public\".\"zasp_schema_versions\"", "args:none",
		"query:SELECT \"version\", \"name\", \"checksum\" FROM \"public\".\"zasp_schema_versions\" ORDER BY \"version\"", "args:none",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
	if transaction.execs != 2 || transaction.queries != 4 {
		t.Fatalf("calls = exec %d query %d", transaction.execs, transaction.queries)
	}
}

func TestRunnerDownRequiresExactStateAndRestoresAbsence(t *testing.T) {
	metadata := Baseline()
	transaction := &fakeTransaction{rows: append(exactRows(), fakeRow{values: []any{false}})}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.Down(context.Background()); err != nil {
		t.Fatalf("Down: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`exec:LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`, "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`, "args:none",
		`exec:DELETE FROM "public"."zasp_schema_versions" WHERE "version" = $1 AND "name" = $2 AND "checksum" = $3`,
		"args:1,schema_versions," + metadata.Checksum(),
		"exec:" + compactSQL(metadata.DownSQL()), "args:none",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
}

func TestRunnerStateReportsOnlyAbsentOrExactBaseline(t *testing.T) {
	metadata := Baseline()
	for name, rows := range map[string][]Row{
		"absent": {fakeRow{values: []any{false}}},
		"exact":  exactRows(),
	} {
		t.Run(name, func(t *testing.T) {
			database := &fakeDatabase{rows: rows}
			runner, err := NewRunner(database)
			if err != nil {
				t.Fatal(err)
			}
			state, err := runner.State(context.Background())
			if err != nil {
				t.Fatalf("State: %v", err)
			}
			if name == "absent" && state.Applied() {
				t.Fatal("absent state was applied")
			}
			if name == "exact" && (!state.Applied() || state.Version() != metadata.Version() || state.Name() != metadata.Name() || state.Checksum() != metadata.Checksum()) {
				t.Fatalf("exact state = %#v", state)
			}
		})
	}

	for name, rows := range map[string][]Row{
		"extra row":      {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(2)}}},
		"wrong version":  {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(1)}}, fakeRow{values: []any{int64(2), metadata.Name(), metadata.Checksum()}}},
		"wrong name":     {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(1)}}, fakeRow{values: []any{metadata.Version(), "other", metadata.Checksum()}}},
		"wrong checksum": {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(1)}}, fakeRow{values: []any{metadata.Version(), metadata.Name(), strings.Repeat("0", 64)}}},
	} {
		t.Run(name, func(t *testing.T) {
			runner, _ := NewRunner(&fakeDatabase{rows: rows})
			if _, err := runner.State(context.Background()); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("State error = %v", err)
			}
		})
	}
}

func TestRunnerRejectsExistingOrMissingStateWithoutMutation(t *testing.T) {
	for name, operation := range map[string]struct {
		rows []Row
		run  func(*Runner) error
	}{
		"up exact collision":   {rows: exactRows(), run: func(runner *Runner) error { return runner.Up(context.Background()) }},
		"up foreign collision": {rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(2)}}}, run: func(runner *Runner) error { return runner.Up(context.Background()) }},
		"down absent":          {rows: []Row{fakeRow{values: []any{false}}}, run: func(runner *Runner) error { return runner.Down(context.Background()) }},
	} {
		t.Run(name, func(t *testing.T) {
			transaction := &fakeTransaction{rows: operation.rows}
			database := &fakeDatabase{transaction: transaction}
			runner, _ := NewRunner(database)
			if err := operation.run(runner); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("error = %v", err)
			}
			if transaction.execs != 0 {
				t.Fatalf("collision executed %d mutations", transaction.execs)
			}
			if !contains(database.events, "rollback") {
				t.Fatalf("rollback missing: %#v", database.events)
			}
		})
	}
}

func TestRunnerRollsBackWithFixedErrorsAndCleanupPrecedence(t *testing.T) {
	for name, transaction := range map[string]*fakeTransaction{
		"query":               {rows: []Row{fakeRow{values: []any{false}}}, queryErrorAt: 2},
		"exec":                {rows: []Row{fakeRow{values: []any{false}}}, execErrorAt: 1},
		"commit":              {rows: append([]Row{fakeRow{values: []any{false}}}, exactRows()...), commitError: errors.New("commit detail")},
		"rollback precedence": {rows: []Row{fakeRow{values: []any{false}}}, execErrorAt: 1, rollbackError: errors.New("rollback detail")},
	} {
		t.Run(name, func(t *testing.T) {
			database := &fakeDatabase{transaction: transaction}
			runner, _ := NewRunner(database)
			if err := runner.Up(context.Background()); !errors.Is(err, ErrDatabase) {
				t.Fatalf("Up error = %v", err)
			}
			if !contains(database.events, "rollback") {
				t.Fatalf("rollback missing: %#v", database.events)
			}
		})
	}
}

func TestRunnerRollsBackTransactionReturnedWithBeginError(t *testing.T) {
	transaction := &fakeTransaction{}
	database := &ambiguousBeginDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.Up(context.Background()); !errors.Is(err, ErrDatabase) {
		t.Fatalf("Up error = %v", err)
	}
	if !reflect.DeepEqual(database.events, []string{"begin", "rollback"}) {
		t.Fatalf("events = %#v", database.events)
	}
	if transaction.rollbackContextError != nil {
		t.Fatalf("rollback inherited failed context: %v", transaction.rollbackContextError)
	}
}

func TestRunnerRejectsCancellationAndMalformedBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	database := &fakeDatabase{transaction: &fakeTransaction{}}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Up = %v", err)
	}
	if len(database.events) != 0 {
		t.Fatalf("canceled Up touched database: %#v", database.events)
	}
	if _, err := runner.State(nil); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("nil State = %v", err)
	}
	if err := runner.Down(nil); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("nil Down = %v", err)
	}

	var typedNil *fakeDatabase
	if _, err := NewRunner(typedNil); !errors.Is(err, ErrInvalidDatabase) {
		t.Fatalf("typed nil database = %v", err)
	}
	if _, err := NewRunner(nil); !errors.Is(err, ErrInvalidDatabase) {
		t.Fatalf("nil database = %v", err)
	}
	if _, err := (*Runner)(nil).State(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("nil runner = %v", err)
	}
	runner, _ = NewRunner(&fakeDatabase{rows: []Row{nil}})
	if _, err := runner.State(context.Background()); !errors.Is(err, ErrDatabase) {
		t.Fatalf("nil row = %v", err)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
