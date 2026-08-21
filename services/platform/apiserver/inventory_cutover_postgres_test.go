package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func migrateToTypedInventoryCutover(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := migrateToProductionDiscoveryExecution(t, ctx, connection)
	if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("typed inventory migration: %v", err)
	}
	return runner
}

func TestProductionTypedInventoryCutoverPostgresPreservesWorkflowAndRiskMutations(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	policy := json.RawMessage(`{"id":"policy-v14-compatibility","name":"V14 compatibility","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	workflow, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{
		Action: "create", Kind: "policy", ID: "policy-v14-compatibility", Operation: "createPolicy", IdempotencyKey: "aaaaaaaaaaaaaaaa",
		Intent: json.RawMessage(`{"body":` + string(policy) + `,"expected_version":0,"resource_id":""}`), Body: policy,
		AuditID: "pid_74000001-0000-4000-8000-000000000001", CorrelationID: "pid_74000002-0000-4000-8000-000000000002",
	})
	if err != nil || workflow.Version != 1 || workflow.Replayed {
		t.Fatalf("v14 workflow mutation=%#v err=%v", workflow, err)
	}
	findingID := "pid_74000003-0000-4000-8000-000000000003"
	seedConnectorRiskFinding(t, ctx, connection, identity, findingID)
	risk, err := repository.MutateRiskFinding(ctx, identity, RiskFindingMutation{
		Operation: "updateFinding", FindingID: findingID, IdempotencyKey: "bbbbbbbbbbbbbbbb", ExpectedVersion: 1, Status: "resolved",
		AuditID: "pid_74000004-0000-4000-8000-000000000004", CorrelationID: "pid_74000005-0000-4000-8000-000000000005",
	})
	if err != nil || risk.Version != 2 || risk.Body.Status != "resolved" {
		t.Fatalf("v14 risk mutation=%#v err=%v", risk, err)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("v14 down: %v", err)
	}
	repository, err = NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	secondPolicy := json.RawMessage(`{"id":"policy-v13-restored","name":"V13 restored","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	workflow, err = repository.MutateWorkflow(ctx, identity, WorkflowMutation{
		Action: "create", Kind: "policy", ID: "policy-v13-restored", Operation: "createPolicy", IdempotencyKey: "cccccccccccccccc",
		Intent: json.RawMessage(`{"body":` + string(secondPolicy) + `,"expected_version":0,"resource_id":""}`), Body: secondPolicy,
		AuditID: "pid_74000006-0000-4000-8000-000000000006", CorrelationID: "pid_74000007-0000-4000-8000-000000000007",
	})
	if err != nil || workflow.Version != 1 {
		t.Fatalf("restored v13 workflow mutation=%#v err=%v", workflow, err)
	}
	risk, err = repository.MutateRiskFinding(ctx, identity, RiskFindingMutation{
		Operation: "updateFinding", FindingID: findingID, IdempotencyKey: "dddddddddddddddd", ExpectedVersion: 2, Status: "open",
		AuditID: "pid_74000008-0000-4000-8000-000000000008", CorrelationID: "pid_74000009-0000-4000-8000-000000000009",
	})
	if err != nil || risk.Version != 3 || risk.Body.Status != "open" {
		t.Fatalf("restored v13 risk mutation=%#v err=%v", risk, err)
	}
}

func TestProductionTypedInventoryCutoverPostgresAppliesExactTypedSnapshot(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToProductionDiscoveryExecution(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("typed inventory migration: %v", err)
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	integrationID := "pid_75000001-0000-4000-8000-000000000001"
	if _, err := repository.CreateIntegration(ctx, identity, IntegrationCreate{ID: integrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "AWS typed", Configuration: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionIntegration(ctx, scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256([]byte("typed-inventory-sync"))
	request := SyncRequest{IntegrationID: integrationID, SyncID: "pid_75000002-0000-4000-8000-000000000002", JobID: "pid_75000003-0000-4000-8000-000000000003", OutboxID: "pid_75000004-0000-4000-8000-000000000004", IdempotencyKey: "typed-inventory-sync-0001", RequestDigest: requestDigest[:], TriggerKind: "manual", ParserVersion: "parser_v1", ToolVersion: "tool_v1"}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(
		organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version
	) VALUES($1,$2,$3,$4,$5,$6,$7,'manual',$8,'parser_v1','tool_v1')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), request.SyncID, integrationID, request.IdempotencyKey, requestDigest[:], identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	entityID, err := CanonicalDiscoveryID(scope, "aws_account", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	evidenceID := "pid_75000006-0000-4000-8000-000000000006"
	artifactID := "pid_75000007-0000-4000-8000-000000000007"
	findingEvidenceID := "pid_75000009-0000-4000-8000-000000000009"
	findingID := "pid_75000010-0000-4000-8000-000000000010"
	observed := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	entities := json.RawMessage(fmt.Sprintf(`[{
		"id":%q,"kind":"aws_account","source_native_id":"123456789012","display_name":"Production account",
		"stable_fields":{"account_id":"123456789012"},"attributes":{},"identity_namespace":"aws_account",
		"identity_rule_version":1,"identity_priority":100,"product_kind":"asset","confidence_basis_points":9000,
		"observed_at":%q,"fresh_until":%q,"evidence_id":%q,"source_projection_version":1
	}]`, entityID, observed.Format(time.RFC3339), observed.Add(24*time.Hour).Format(time.RFC3339), evidenceID))
	evidence := json.RawMessage(fmt.Sprintf(`[{
		"id":%q,"entity_id":%q,"object_reference":"s3://zasp-evidence/organizations/typed/page-1.json","artifact_reference":%q,
		"artifact_key":"organizations/typed/page-1.json","artifact_version_id":"version-1",
		"checksum_hex":"%s","size_bytes":128,"media_type":"application/json","schema_version":"raw_v1","parser_version":"parser_v1","tool_version":"tool_v1"
	},{
		"id":%q,"entity_id":%q,"finding_id":%q,"check_id":"iam_role_administratoraccess_policy","severity":"high","status":"FAIL","observed_at":%q,
		"object_reference":"s3://zasp-evidence/organizations/typed/page-1.json","artifact_reference":%q,
		"artifact_key":"organizations/typed/page-1.json","artifact_version_id":"version-1",
		"checksum_hex":"%s","size_bytes":128,"media_type":"application/json","schema_version":"raw_v1","parser_version":"parser_v1","tool_version":"tool_v1"
	}]`, evidenceID, entityID, artifactID, fmt.Sprintf("%064x", 1), findingEvidenceID, entityID, findingID, observed.Format(time.RFC3339), artifactID, fmt.Sprintf("%064x", 1)))
	candidate := CompleteSnapshot{
		IntegrationID: integrationID, SyncID: request.SyncID, SnapshotID: "pid_75000008-0000-4000-8000-000000000008",
		Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/typed/manifest.json", ManifestChecksum: bytes32(1),
		CollectedAt: observed, CursorProvider: "aws", CursorValue: "complete", Entities: entities, Relationships: json.RawMessage(`[]`), Evidence: evidence,
	}
	malformed := candidate
	malformed.Evidence = bytes.Replace(evidence, []byte(`"severity":"high"`), []byte(`"severity":"critical"`), 1)
	if _, err := repository.ApplyCompleteSnapshot(ctx, scope, malformed); err == nil {
		t.Fatal("malformed finding evidence applied")
	}
	var malformedResidue int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_discovery_snapshots WHERE id=$1)+(SELECT count(*) FROM zasp_inventory_evidence WHERE snapshot_id=$1)`, candidate.SnapshotID).Scan(&malformedResidue); err != nil || malformedResidue != 0 {
		t.Fatalf("malformed finding residue=%d err=%v", malformedResidue, err)
	}
	result, err := repository.ApplyCompleteSnapshot(ctx, scope, candidate)
	if err != nil {
		t.Fatalf("typed apply: %v", err)
	}
	if result.DiscoveredCount != 1 || result.ChangedCount != 0 || result.RemovedCount != 0 {
		t.Fatalf("typed apply result = %#v", result)
	}
	var storedEntityEvidence, storedFindingEvidence int
	if err := connection.QueryRow(ctx, `SELECT count(*) FILTER(WHERE id=$1),count(*) FILTER(WHERE id=$2) FROM zasp_inventory_evidence WHERE (organization_id,workspace_id,environment_id)=($3,$4,$5)`, evidenceID, findingEvidenceID, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&storedEntityEvidence, &storedFindingEvidence); err != nil || storedEntityEvidence != 1 || storedFindingEvidence != 0 {
		t.Fatalf("typed evidence storage = entity:%d finding:%d / %v", storedEntityEvidence, storedFindingEvidence, err)
	}
	var phase string
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_backfill_scope($1,$2,$3)->>'phase'`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&phase); err != nil || phase != "backfilled" {
		t.Fatalf("typed backfill = (%s, %v)", phase, err)
	}
	var kind, name, winnerEvidence, provider, namespace, nativeID string
	var confidence, bindingCount int
	var entityObserved, freshUntil time.Time
	if err := connection.QueryRow(ctx, `SELECT entity.product_kind,entity.display_name,entity.winning_evidence_id,entity.confidence_basis_points,entity.observed_at,entity.fresh_until,
		observation.provider,observation.identity_namespace,observation.source_native_id,
		(SELECT count(*) FROM zasp_inventory_identity_bindings binding WHERE (binding.organization_id,binding.workspace_id,binding.environment_id,binding.entity_id)=($1,$2,$3,$4))
	 FROM zasp_inventory_entities entity
	 JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.entity_id)=(entity.organization_id,entity.workspace_id,entity.environment_id,entity.id) AND observation.source_state='present'
	 WHERE (entity.organization_id,entity.workspace_id,entity.environment_id,entity.id)=($1,$2,$3,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), entityID).Scan(&kind, &name, &winnerEvidence, &confidence, &entityObserved, &freshUntil, &provider, &namespace, &nativeID, &bindingCount); err != nil {
		t.Fatal(err)
	}
	if kind != "asset" || name != "Production account" || winnerEvidence != evidenceID || confidence != 9000 || !entityObserved.Equal(observed) || !freshUntil.Equal(observed.Add(24*time.Hour)) || provider != "aws" || namespace != "aws_account" || nativeID != "123456789012" || bindingCount != 1 {
		t.Fatalf("typed projection = kind:%s name:%s evidence:%s confidence:%d observed:%s fresh:%s source:%s/%s/%s bindings:%d", kind, name, winnerEvidence, confidence, entityObserved, freshUntil, provider, namespace, nativeID, bindingCount)
	}
	legacyPayload := json.RawMessage(fmt.Sprintf(`{"id":%q,"name":"Production account","kind":"asset","owner":"","team":"","tags":[],"evidence_id":%q,"first_seen":%q,"last_seen":%q}`, entityID, evidenceID, observed.Format(time.RFC3339), observed.Format(time.RFC3339)))
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES($1,$2,$3,$4,$5::jsonb)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "asset:"+entityID, legacyPayload); err != nil {
		t.Fatalf("legacy equivalence payload: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_cutover_scope($1,$2,$3)->>'phase'`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&phase); err != nil || phase != "cutover" {
		t.Fatalf("typed cutover = (%s, %v)", phase, err)
	}
	inventoryRepository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatalf("typed repository: %v", err)
	}
	home, err := inventoryRepository.GetHomeSummary(ctx, scope)
	if err != nil || home.AgentCount != 0 || home.HighRiskPaths != 0 || !home.Healthy || home.AttentionRequired {
		t.Fatalf("typed home = %#v / %v", home, err)
	}
	page, err := inventoryRepository.ListInventoryPage(ctx, scope, InventoryKindAsset, "", 100)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != entityID || page.NextKey != "" || page.Items[0].EvidenceID != evidenceID || page.Items[0].ConfidenceBasisPoints != 9000 {
		t.Fatalf("typed page = %#v / %v", page, err)
	}
	parsedEntityID, _ := domain.ParseProductID(entityID)
	detail, err := inventoryRepository.GetInventory(ctx, scope, parsedEntityID, InventoryKindAsset)
	if err != nil || detail.Summary.ID != entityID || len(detail.Sources) != 1 || !detail.Sources[0].Winning || detail.Sources[0].SourceIdentifier == "123456789012" || len(detail.Evidence) != 1 || detail.Evidence[0].ID != evidenceID {
		t.Fatalf("typed detail = %#v / %v", detail, err)
	}
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	var apiPayload []byte
	apiErr := connection.QueryRow(ctx, `SELECT zasp_inventory_detail($1,$2,$3,$4,'asset')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), entityID).Scan(&apiPayload)
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if apiErr != nil || !json.Valid(apiPayload) || bytes.Contains(apiPayload, []byte("123456789012")) || bytes.Contains(apiPayload, []byte("s3://")) {
		t.Fatalf("api typed detail = %s / %v", apiPayload, apiErr)
	}
	var compatibility json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_core_read($1,$2,$3,$4)`, "asset:"+entityID, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&compatibility); err != nil || !json.Valid(compatibility) || !strings.Contains(string(compatibility), entityID) {
		t.Fatalf("typed compatibility = (%s, %v)", compatibility, err)
	}
	var legacyRows int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_core_payloads WHERE (organization_id,workspace_id,environment_id,operation)=($1,$2,$3,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "asset:"+entityID).Scan(&legacyRows); err != nil || legacyRows != 0 {
		t.Fatalf("legacy cutover rows = %d / %v", legacyRows, err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES($1,$2,$3,'agents','{"items":[]}'::jsonb)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err == nil {
		t.Fatal("targeted generic write passed cutover fence")
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES($1,$2,$3,'session_bootstrap:typed-test','{}'::jsonb)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatalf("unrelated compatibility write: %v", err)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("cutover rollback = %v", err)
	}
}

func TestProductionTypedInventoryCutoverPostgresInstallsExactRuleAndIdentityAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 14 {
		t.Fatalf("typed inventory version = (%d, %v)", version, versionErr)
	}
	var rules, bindings, annotations int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM zasp_inventory_identity_rules),
		(SELECT count(*) FROM zasp_inventory_identity_bindings),
		(SELECT count(*) FROM zasp_inventory_annotations)`).Scan(&rules, &bindings, &annotations); err != nil {
		t.Fatal(err)
	}
	if rules != len(inventoryprojection.RuleCatalog()) || bindings != 0 || annotations != 0 {
		t.Fatalf("typed inventory authority = rules:%d bindings:%d annotations:%d", rules, bindings, annotations)
	}
	rows, err := connection.Query(ctx, `SELECT provider,source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds FROM zasp_inventory_identity_rules ORDER BY provider,source_kind`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	databaseRules := make([]inventoryprojection.Rule, 0, rules)
	for rows.Next() {
		var rule inventoryprojection.Rule
		var productKind string
		var freshnessSeconds int64
		if err := rows.Scan(&rule.Provider, &rule.SourceKind, &rule.Namespace, &productKind, &rule.Version, &rule.Priority, &rule.ConfidenceBasisPoints, &freshnessSeconds); err != nil {
			t.Fatal(err)
		}
		rule.ProductKind = inventoryprojection.Kind(productKind)
		rule.Freshness = time.Duration(freshnessSeconds) * time.Second
		databaseRules = append(databaseRules, rule)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if expected := inventoryprojection.RuleCatalog(); !reflect.DeepEqual(databaseRules, expected) {
		t.Fatalf("database rule catalog = %#v, want %#v", databaseRules, expected)
	}
	var ruleDigest, liveFingerprint string
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT value FROM zasp_schema_metadata WHERE key='typed_inventory_rule_catalog_digest'),
		zasp_inventory_live_fingerprint(),
		zasp_inventory_readiness($1,$2)`, migrations.ProductionTypedInventoryCutover().Checksum(), migrations.ProductionTypedInventoryCutoverSemanticFingerprint()).Scan(&ruleDigest, &liveFingerprint, &ready); err != nil {
		t.Fatal(err)
	}
	expectedDigest := inventoryprojection.RuleCatalogDigest()
	if ruleDigest != hex.EncodeToString(expectedDigest[:]) || liveFingerprint != migrations.ProductionTypedInventoryCutoverSemanticFingerprint() || !ready {
		t.Fatalf("typed readiness digest=%s live=%s ready=%v", ruleDigest, liveFingerprint, ready)
	}
}

func TestInventoryRepositoryPostgresPaginatesOneThousandTwoTypedAgents(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	_ = runner
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	observed := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	seedAuthority := func(sequence int) {
		integrationID := fmt.Sprintf("pid_76%06x-0000-4000-8000-%012x", sequence, sequence)
		syncID := fmt.Sprintf("pid_77%06x-0000-4000-8000-%012x", sequence, sequence)
		snapshotID := fmt.Sprintf("pid_78%06x-0000-4000-8000-%012x", sequence, sequence)
		if _, err := discovery.CreateIntegration(ctx, identity, IntegrationCreate{ID: integrationID, Kind: "kubernetes", ConnectorVersion: "1.0.0", DisplayName: fmt.Sprintf("Kubernetes %d", sequence), Configuration: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
		if _, err := discovery.TransitionIntegration(ctx, scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
			t.Fatal(err)
		}
		requestDigest := sha256.Sum256([]byte(fmt.Sprintf("typed-inventory-page-%d", sequence)))
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,$6,$7,'manual',$8,'parser_v1','tool_v1')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), syncID, integrationID, fmt.Sprintf("typed-inventory-page-%04d", sequence), requestDigest[:], identity.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'kubernetes',$7,$8,'complete',$8,'{}'::jsonb,true,true,$9,$9)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), snapshotID, integrationID, syncID, fmt.Sprintf("s3://zasp-evidence/typed/manifest-%d.json", sequence), bytes32(byte(sequence)), observed); err != nil {
			t.Fatalf("snapshot %d: %v", sequence, err)
		}
	}
	seedAuthority(1)
	seedAuthority(2)
	organizationID := scope.OrganizationID().String()
	workspaceID := scope.WorkspaceID().String()
	environmentID := scope.EnvironmentID().String()
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_entities(
 organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,
 product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,
 winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection)
SELECT $1,$2,$3,
 format('pid_81%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 'agent',format('Agent %s',lpad(item::text,4,'0')),'{}'::jsonb,'active',$4,$4,1,
 'agent',9500,format('pid_91%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('pid_78%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),12,'0')),
 1,$4,$5,1,
 format('pid_76%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),12,'0')),
 'kubernetes','kubernetes',format('agent-%s',lpad(item::text,4,'0')),1,1
FROM generate_series(1,1002) item`, organizationID, workspaceID, environmentID, observed, observed.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_evidence(
 organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,
 source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
SELECT $1,$2,$3,
 format('pid_91%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('pid_76%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),12,'0')),
 format('pid_78%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),12,'0')),
 format('pid_81%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('s3://zasp-evidence/typed/pages/%s.json',lpad(item::text,4,'0')),digest(convert_to(item::text,'UTF8'),'sha256'),
 'application/json','raw_v1','parser_v1',$4,'kubernetes',1,'pid_79999999-0000-4000-8000-000000000999',
 format('typed/pages/%s.json',lpad(item::text,4,'0')),format('version-%s',lpad(item::text,4,'0')),128,'tool_v1'
FROM generate_series(1,1002) item`, organizationID, workspaceID, environmentID, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_source_observations(
 organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,
 provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,
 identity_rule_version,identity_priority,source_projection_version)
SELECT $1,$2,$3,
 format('pid_76%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),12,'0')),
 'kubernetes',format('pid_81%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 format('agent-%s',lpad(item::text,4,'0')),
 format('pid_78%s-0000-4000-8000-%s',lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),6,'0'),lpad(to_hex(CASE WHEN item<=1000 THEN 1 ELSE 2 END),12,'0')),
 'present','{}'::jsonb,$4,$4,'kubernetes','kubernetes_agent',format('Agent %s',lpad(item::text,4,'0')),'{}'::jsonb,'kubernetes_agent','agent',1,
 digest(convert_to(format('typed-agent-%s',item),'UTF8'),'sha256'),
 format('pid_91%s-0000-4000-8000-%s',lpad(to_hex(item),6,'0'),lpad(to_hex(item),12,'0')),
 9500,$4,$5,1,80,1
FROM generate_series(1,1002) item`, organizationID, workspaceID, environmentID, observed, observed.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'expanded',NULL,NULL)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'backfilled',NULL,NULL)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	digest := bytes32(99)
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'equivalent',$4,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), digest); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_advance_scope($1,$2,$3,'cutover',$4,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), digest); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	after, pages, total := "", 0, 0
	seen := map[string]struct{}{}
	for {
		page, pageErr := repository.ListInventoryPage(ctx, scope, InventoryKindAgent, after, 100)
		if pageErr != nil {
			t.Fatalf("page %d after=%q: %v", pages, after, pageErr)
		}
		pages++
		for _, item := range page.Items {
			if _, duplicate := seen[item.ID]; duplicate {
				t.Fatalf("duplicate %s", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
		total += len(page.Items)
		if page.NextKey == "" {
			break
		}
		after = page.NextKey
	}
	if total != 1002 || pages != 11 || len(seen) != 1002 {
		t.Fatalf("pagination total=%d pages=%d unique=%d", total, pages, len(seen))
	}
	agentID := "pid_81000001-0000-4000-8000-000000000001"
	auditID := "pid_82000001-0000-4000-8000-000000000001"
	correlationID := "pid_82000002-0000-4000-8000-000000000002"
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	var mutationPayload json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_update_agent($1,$2,$3,$4,$5,$6,1,$7,$8,$9::jsonb,$10,$11)`,
		organizationID, workspaceID, environmentID, identity.PrincipalID.String(), agentID, "typed-agent-owner-0001",
		"security", "platform", `["critical","production"]`, auditID, correlationID).Scan(&mutationPayload); err != nil {
		t.Fatalf("typed agent ownership mutation: %v", err)
	}
	var mutation struct {
		Agent         InventorySummary `json:"agent"`
		AuditID       string           `json:"audit_id"`
		CorrelationID string           `json:"correlation_id"`
		Replayed      bool             `json:"replayed"`
	}
	if decodeStrictInventory(mutationPayload, &mutation) != nil || mutation.Agent.ID != agentID || mutation.Agent.Owner != "security" || mutation.Agent.Team != "platform" || !reflect.DeepEqual(mutation.Agent.Tags, []string{"critical", "production"}) || mutation.Agent.Version != 2 || mutation.AuditID != auditID || mutation.CorrelationID != correlationID || mutation.Replayed {
		t.Fatalf("typed agent mutation = %s", mutationPayload)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_update_agent($1,$2,$3,$4,$5,$6,1,$7,$8,$9::jsonb,$10,$11)`,
		organizationID, workspaceID, environmentID, identity.PrincipalID.String(), agentID, "typed-agent-owner-0001",
		"security", "platform", `["critical","production"]`, auditID, correlationID).Scan(&mutationPayload); err != nil || decodeStrictInventory(mutationPayload, &mutation) != nil || !mutation.Replayed || mutation.Agent.Version != 2 {
		t.Fatalf("typed agent mutation replay = %s / %v", mutationPayload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_update_agent($1,$2,$3,$4,$5,$6,1,$7,$8,$9::jsonb,$10,$11)`,
		organizationID, workspaceID, environmentID, identity.PrincipalID.String(), agentID, "typed-agent-owner-0001",
		"other", "platform", `["critical","production"]`, auditID, correlationID).Scan(&mutationPayload); err == nil {
		t.Fatal("typed agent idempotency drift succeeded")
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_update_agent($1,$2,$3,$4,$5,$6,1,$7,$8,$9::jsonb,$10,$11)`,
		organizationID, workspaceID, environmentID, identity.PrincipalID.String(), agentID, "typed-agent-owner-0002",
		"other", "platform", `["critical","production"]`, "pid_82000003-0000-4000-8000-000000000003", "pid_82000004-0000-4000-8000-000000000004").Scan(&mutationPayload); err == nil {
		t.Fatal("stale typed agent ownership mutation succeeded")
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_update_agent($1,$2,$3,$4,$5,$6,1,$7,$8,$9::jsonb,$10,$11)`,
		"pid_83000001-0000-4000-8000-000000000001", workspaceID, environmentID, identity.PrincipalID.String(), agentID, "typed-agent-owner-0003",
		"other", "platform", `["critical","production"]`, "pid_82000005-0000-4000-8000-000000000005", "pid_82000006-0000-4000-8000-000000000006").Scan(&mutationPayload); err == nil {
		t.Fatal("foreign-scope typed agent ownership mutation succeeded")
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var entityVersion, annotationVersion, auditRows, genericRows int
	if err := connection.QueryRow(ctx, `SELECT entity.version,entity.annotation_version,
		(SELECT count(*) FROM zasp_workflow_audit audit WHERE (audit.organization_id,audit.workspace_id,audit.environment_id,audit.operation,audit.resource_kind,audit.resource_id) = ($1,$2,$3,'updateAgent','agent',$4)),
		(SELECT count(*) FROM zasp_core_payloads payload WHERE (payload.organization_id,payload.workspace_id,payload.environment_id) = ($1,$2,$3) AND payload.operation LIKE 'agent%')
		FROM zasp_inventory_entities entity WHERE (entity.organization_id,entity.workspace_id,entity.environment_id,entity.id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, agentID).Scan(&entityVersion, &annotationVersion, &auditRows, &genericRows); err != nil {
		t.Fatal(err)
	}
	if entityVersion != 1 || annotationVersion != 2 || auditRows != 1 || genericRows != 0 {
		t.Fatalf("typed agent mutation residue entity=%d annotation=%d audits=%d generic=%d", entityVersion, annotationVersion, auditRows, genericRows)
	}
	const (
		serviceAccountID = "pid_84000001-0000-4000-8000-000000000001"
		bindingID        = "pid_84000002-0000-4000-8000-000000000002"
		roleID           = "pid_84000003-0000-4000-8000-000000000003"
		integrationID    = "pid_76000001-0000-4000-8000-000000000001"
		snapshotID       = "pid_78000001-0000-4000-8000-000000000001"
	)
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_entities(
 organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,
 product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,
 winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection)
VALUES
 ($1,$2,$3,$4,'identity','agent-service-account','{}','active',$10,$10,1,'identity',9500,$7,$9,1,$10,$11,1,$8,'kubernetes','kubernetes','default/agent',1,1),
 ($1,$2,$3,$5,'asset','agent-role-binding','{}','active',$10,$10,1,'asset',9500,$12,$9,1,$10,$11,1,$8,'kubernetes','kubernetes','default/agent-binding',1,1),
 ($1,$2,$3,$6,'asset','agent-role','{}','active',$10,$10,1,'asset',9500,$13,$9,1,$10,$11,1,$8,'kubernetes','kubernetes','agent-role',1,1)`,
		organizationID, workspaceID, environmentID, serviceAccountID, bindingID, roleID,
		"pid_85000001-0000-4000-8000-000000000001", integrationID, snapshotID, observed, observed.Add(15*time.Minute),
		"pid_85000002-0000-4000-8000-000000000002", "pid_85000003-0000-4000-8000-000000000003"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_evidence(
 organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,
 source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
SELECT $1,$2,$3,item.evidence_id,$4,$5,item.entity_id,'s3://zasp-evidence/typed/capabilities/'||item.ordinal||'.json',digest(convert_to(item.ordinal,'UTF8'),'sha256'),
 'application/json','raw_v1','parser_v1',$6,'kubernetes',1,'pid_79999999-0000-4000-8000-000000000999','typed/capabilities/'||item.ordinal||'.json','version-'||item.ordinal,128,'tool_v1'
FROM (VALUES
 ('1',$7,$10),('2',$8,$11),('3',$9,$12)
) item(ordinal,entity_id,evidence_id)`, organizationID, workspaceID, environmentID, integrationID, snapshotID, observed,
		serviceAccountID, bindingID, roleID,
		"pid_85000001-0000-4000-8000-000000000001", "pid_85000002-0000-4000-8000-000000000002", "pid_85000003-0000-4000-8000-000000000003"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_source_observations(
 organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,
 provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,
 identity_rule_version,identity_priority,source_projection_version)
VALUES
 ($1,$2,$3,$4,'kubernetes',$6,'default/agent',$5,'present','{}',$12,$12,'kubernetes','kubernetes_service_account','agent-service-account','{}','kubernetes_service_account','identity',1,digest(convert_to('service-account','UTF8'),'sha256'),$9,9500,$12,$13,1,80,1),
 ($1,$2,$3,$4,'kubernetes',$7,'default/agent-binding',$5,'present','{}',$12,$12,'kubernetes','kubernetes_role_binding','agent-role-binding','{}','kubernetes_role_binding','asset',1,digest(convert_to('binding','UTF8'),'sha256'),$10,9500,$12,$13,1,80,1),
 ($1,$2,$3,$4,'kubernetes',$8,'agent-role',$5,'present',jsonb_build_object('namespaced',false,'rules',jsonb_build_array(jsonb_build_object('api_groups',jsonb_build_array(''),'non_resource_urls',jsonb_build_array('/metrics'),'resource_names','[]'::jsonb,'resources',jsonb_build_array('pods','pods/exec','services/proxy'),'verbs',jsonb_build_array('bind','create','get','impersonate','patch')))),$12,$12,'kubernetes','kubernetes_cluster_role','agent-role','{}','kubernetes_cluster_role','asset',1,digest(convert_to('role','UTF8'),'sha256'),$11,9500,$12,$13,1,80,1)`,
		organizationID, workspaceID, environmentID, integrationID, snapshotID, serviceAccountID, bindingID, roleID,
		"pid_85000001-0000-4000-8000-000000000001", "pid_85000002-0000-4000-8000-000000000002", "pid_85000003-0000-4000-8000-000000000003", observed, observed.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,state,attributes,first_seen_at,last_seen_at)
VALUES
 ($1,$2,$3,'pid_86000001-0000-4000-8000-000000000001',$4,'kubernetes',$5,$6,$7,'uses_identity','agent:uses_identity:service-account','present','{}',$10,$10),
 ($1,$2,$3,'pid_86000002-0000-4000-8000-000000000002',$4,'kubernetes',$5,$7,$8,'assigned_to','service-account:assigned_to:binding','present','{}',$10,$10),
 ($1,$2,$3,'pid_86000003-0000-4000-8000-000000000003',$4,'kubernetes',$5,$8,$9,'binds','binding:binds:role','present','{}',$10,$10)`,
		organizationID, workspaceID, environmentID, integrationID, snapshotID, agentID, serviceAccountID, bindingID, roleID, observed); err != nil {
		t.Fatal(err)
	}
	parsedAgentID, _ := domain.ParseProductID(agentID)
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	var rawCapabilityPage json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_agent_capabilities_page($1,$2,$3,$4,NULL,2)`, organizationID, workspaceID, environmentID, agentID).Scan(&rawCapabilityPage); err != nil {
		t.Fatalf("direct capability authority: %v", err)
	}
	if len(rawCapabilityPage) == 0 {
		t.Fatal("direct capability authority returned empty payload")
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_agent_capabilities_page($1,$2,$3,$4,NULL,2)`, "pid_83000001-0000-4000-8000-000000000001", workspaceID, environmentID, agentID).Scan(&rawCapabilityPage); err == nil {
		t.Fatal("foreign tenant capability authority returned data")
	}
	capabilityAfter, capabilityPages := "", 0
	capabilities := make([]Capability, 0, 6)
	for {
		page, pageErr := repository.ListAgentCapabilitiesPage(ctx, scope, parsedAgentID, capabilityAfter, 2)
		if pageErr != nil {
			t.Fatalf("capability page %d after=%q: %v", capabilityPages, capabilityAfter, pageErr)
		}
		capabilityPages++
		capabilities = append(capabilities, page.Items...)
		if page.NextKey == "" {
			break
		}
		capabilityAfter = page.NextKey
	}
	if capabilityPages != 3 || len(capabilities) != 6 {
		t.Fatalf("capability pages=%d values=%+v", capabilityPages, capabilities)
	}
	wantCategories := []string{"identity_assume", "action_execute", "administration", "data_read", "data_write", "network_egress"}
	for index, capability := range capabilities {
		if string(capability.Category) != wantCategories[index] || capability.AgentID != agentID || capability.State != "observed" || !capability.Reachable || len(capability.EvidenceIDs) < 2 {
			t.Fatalf("capability %d=%+v", index, capability)
		}
		for evidenceIndex := 1; evidenceIndex < len(capability.EvidenceIDs); evidenceIndex++ {
			if capability.EvidenceIDs[evidenceIndex] <= capability.EvidenceIDs[evidenceIndex-1] {
				t.Fatalf("capability evidence not canonical: %+v", capability)
			}
		}
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_source_observations SET attributes=jsonb_build_object('namespaced',false,'rules',jsonb_build_array(jsonb_build_object('api_groups',jsonb_build_array(''),'non_resource_urls','[]'::jsonb,'resource_names','[]'::jsonb,'resources',jsonb_build_array('*'),'verbs',jsonb_build_array('get')))) WHERE (organization_id,workspace_id,environment_id,entity_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	readOnlyCapabilities, err := repository.ListAgentCapabilitiesPage(ctx, scope, parsedAgentID, "", 100)
	if err != nil || readOnlyCapabilities.NextKey != "" || len(readOnlyCapabilities.Items) != 2 || readOnlyCapabilities.Items[0].Category != "identity_assume" || readOnlyCapabilities.Items[1].Category != "data_read" {
		t.Fatalf("read-only wildcard capability authority = (%+v, %v)", readOnlyCapabilities, err)
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_source_observations SET attributes='{"namespaced":false,"rules":[{"verbs":"get"}]}'::jsonb WHERE (organization_id,workspace_id,environment_id,entity_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_agent_capabilities_page($1,$2,$3,$4,NULL,2)`, organizationID, workspaceID, environmentID, agentID).Scan(&rawCapabilityPage); err == nil {
		t.Fatal("malformed RBAC capability authority returned data")
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
}

func TestProductionTypedInventoryCutoverPostgresHydratesStableObservationTime(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_79000001-0000-4000-8000-000000000001"
	connectionID := "pid_79000002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/typed-observation","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-typed-observation"}`)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", integrationID, connectionID, "ref:aws/external-id/typed-observation", configuration, "8")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatalf("production discovery execution migration: %v", err)
	}
	if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("typed inventory migration: %v", err)
	}
	syncID := "pid_79000003-0000-4000-8000-000000000003"
	jobID := "pid_79000004-0000-4000-8000-000000000004"
	outboxID := "pid_79000005-0000-4000-8000-000000000005"
	requestDigest := sha256.Sum256([]byte("typed-observation-time"))
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, syncID, jobID, outboxID, "typed-observation-time-0001", requestDigest[:], "manual", "parser_v1", "tool_v1").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	worker := "typed-observation-worker"
	leaseToken := "typed-observation-lease-0001"
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_jobs($1,$2,30,1)`, worker, leaseToken).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var first, replay ExecutionJobInput
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, leaseToken).Scan(&payload); err != nil || json.Unmarshal(payload, &first) != nil {
		t.Fatalf("first typed input = (%s, %v)", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, leaseToken).Scan(&payload); err != nil || json.Unmarshal(payload, &replay) != nil {
		t.Fatalf("replayed typed input = (%s, %v)", payload, err)
	}
	var reservedAt time.Time
	if err := connection.QueryRow(ctx, `SELECT reserved_at FROM zasp_discovery_generation_reservations WHERE (organization_id,workspace_id,environment_id,sync_id)=($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), syncID).Scan(&reservedAt); err != nil {
		t.Fatal(err)
	}
	expected := reservedAt.UTC().Truncate(time.Second)
	if first.ObservationTime.IsZero() || !first.ObservationTime.Equal(expected) || !replay.ObservationTime.Equal(first.ObservationTime) || first.ObservationTime.Location() != time.UTC || first.ObservationTime.Nanosecond() != 0 {
		t.Fatalf("observation authority first=%s replay=%s reserved=%s", first.ObservationTime, replay.ObservationTime, reservedAt)
	}
}

func TestProductionTypedInventoryCutoverPostgresRejectsDriftAndRemovesCompleteEmptySource(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToProductionDiscoveryExecution(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("typed inventory migration: %v", err)
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	integrationID := "pid_7a000001-0000-4000-8000-000000000001"
	if _, err := repository.CreateIntegration(ctx, identity, IntegrationCreate{ID: integrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "AWS drift", Configuration: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionIntegration(ctx, scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	insertSync := func(sequence int) string {
		t.Helper()
		syncID := fmt.Sprintf("pid_7a0000%02d-0000-4000-8000-%012d", sequence, sequence)
		digest := sha256.Sum256([]byte(fmt.Sprintf("typed-drift-%d", sequence)))
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(
			organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version
		) VALUES($1,$2,$3,$4,$5,$6,$7,'manual',$8,'parser_v1','tool_v1')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), syncID, integrationID, fmt.Sprintf("typed-inventory-drift-%04d", sequence), digest[:], identity.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
		return syncID
	}
	entityID := "pid_7a000020-0000-4000-8000-000000000020"
	evidenceID := "pid_7a000021-0000-4000-8000-000000000021"
	observed := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	entityPayload := func(id, evidence string, fresh time.Time) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`[{"id":%q,"kind":"aws_account","source_native_id":"123456789012","display_name":"Drift account","stable_fields":{"account_id":"123456789012"},"attributes":{},"identity_namespace":"aws_account","identity_rule_version":1,"identity_priority":100,"product_kind":"asset","confidence_basis_points":9000,"observed_at":%q,"fresh_until":%q,"evidence_id":%q,"source_projection_version":1}]`, id, observed.Format(time.RFC3339), fresh.Format(time.RFC3339), evidence))
	}
	evidencePayload := func(id, entity string, sequence int) json.RawMessage {
		key := fmt.Sprintf("organizations/typed/drift/page-%d.json", sequence)
		return json.RawMessage(fmt.Sprintf(`[{"id":%q,"entity_id":%q,"object_reference":%q,"artifact_reference":%q,"artifact_key":%q,"artifact_version_id":%q,"checksum_hex":%q,"size_bytes":128,"media_type":"application/json","schema_version":"raw_v1","parser_version":"parser_v1","tool_version":"tool_v1"}]`, id, entity, "s3://zasp-evidence/"+key, fmt.Sprintf("pid_7a0001%02d-0000-4000-8000-%012d", sequence, sequence), key, fmt.Sprintf("version-%d", sequence), fmt.Sprintf("%064x", sequence)))
	}
	apply := func(syncID, snapshotID string, generation int64, cursor string, entities, evidence json.RawMessage) (SnapshotApplyResult, error) {
		return repository.ApplyCompleteSnapshot(ctx, scope, CompleteSnapshot{IntegrationID: integrationID, SyncID: syncID, SnapshotID: snapshotID, Generation: generation, Source: "aws", ManifestReference: "s3://zasp-evidence/typed/drift/manifest.json", ManifestChecksum: bytes32(byte(generation)), CollectedAt: observed, CursorProvider: "aws", CursorValue: cursor, Entities: entities, Relationships: json.RawMessage(`[]`), Evidence: evidence})
	}
	firstSync := insertSync(1)
	firstSnapshot := "pid_7a000030-0000-4000-8000-000000000030"
	entities := entityPayload(entityID, evidenceID, observed.Add(24*time.Hour))
	evidence := evidencePayload(evidenceID, entityID, 1)
	first, err := apply(firstSync, firstSnapshot, 1, "complete-1", entities, evidence)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := apply(firstSync, firstSnapshot, 1, "complete-1", entities, evidence)
	if err != nil || replay.SnapshotID != first.SnapshotID || !replay.CommittedAt.Equal(first.CommittedAt) {
		t.Fatalf("exact replay = %#v / %v", replay, err)
	}
	staleSync := insertSync(2)
	staleSnapshot := "pid_7a000031-0000-4000-8000-000000000031"
	if _, err := apply(staleSync, staleSnapshot, 1, "complete-stale", entities, evidencePayload("pid_7a000022-0000-4000-8000-000000000022", entityID, 2)); err == nil {
		t.Fatal("same-generation drift applied")
	}
	driftSync := insertSync(3)
	driftEntity := "pid_7a000023-0000-4000-8000-000000000023"
	driftEvidence := "pid_7a000024-0000-4000-8000-000000000024"
	if _, err := apply(driftSync, "pid_7a000032-0000-4000-8000-000000000032", 2, "complete-drift", entityPayload(driftEntity, driftEvidence, observed.Add(24*time.Hour)), evidencePayload(driftEvidence, driftEntity, 3)); err == nil {
		t.Fatal("source identity rebound to a different entity")
	}
	malformedSync := insertSync(4)
	if _, err := apply(malformedSync, "pid_7a000033-0000-4000-8000-000000000033", 2, "complete-malformed", entityPayload(entityID, "pid_7a000025-0000-4000-8000-000000000025", observed.Add(24*time.Hour+time.Second)), evidencePayload("pid_7a000025-0000-4000-8000-000000000025", entityID, 4)); err == nil {
		t.Fatal("noncatalog freshness applied")
	}
	var imported bool
	annotations := json.RawMessage(fmt.Sprintf(`[{"id":%q,"owner":"security","team":"platform","tags":["critical"]}]`, entityID))
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_import_annotations($1,$2,$3,$4::jsonb)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), annotations).Scan(&imported); err != nil || !imported {
		t.Fatalf("annotation import = %v / %v", imported, err)
	}
	emptySync := insertSync(5)
	empty, err := apply(emptySync, "pid_7a000034-0000-4000-8000-000000000034", 2, "complete-empty", json.RawMessage(`[]`), json.RawMessage(`[]`))
	if err != nil || empty.RemovedCount != 1 {
		t.Fatalf("complete empty = %#v / %v", empty, err)
	}
	var entityState string
	var annotation json.RawMessage
	var rejectedResidue int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT state FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)),
		zasp_inventory_annotation_value($1,$2,$3,$4),
		(SELECT count(*) FROM zasp_discovery_snapshots WHERE id IN($5,$6,$7))`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), entityID, staleSnapshot, "pid_7a000032-0000-4000-8000-000000000032", "pid_7a000033-0000-4000-8000-000000000033").Scan(&entityState, &annotation, &rejectedResidue); err != nil {
		t.Fatal(err)
	}
	if entityState != "tombstoned" || rejectedResidue != 0 || !strings.Contains(string(annotation), `"owner": "security"`) || !strings.Contains(string(annotation), `"critical"`) {
		t.Fatalf("empty authority state=%s annotation=%s rejected=%d", entityState, annotation, rejectedResidue)
	}
}

func TestProductionTypedInventoryCutoverPostgresAbortsLegacySnapshotWithoutTypedAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToProductionDiscoveryExecution(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	integrationID := "pid_7b000001-0000-4000-8000-000000000001"
	if _, err := repository.CreateIntegration(ctx, identity, IntegrationCreate{ID: integrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "AWS legacy", Configuration: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionIntegration(ctx, scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	syncID := "pid_7b000002-0000-4000-8000-000000000002"
	requestDigest := sha256.Sum256([]byte("legacy-untyped-snapshot"))
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(
		organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version
	) VALUES($1,$2,$3,$4,$5,'legacy-untyped-snapshot-0001',$6,'manual',$7,'parser_v1','tool_v1')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), syncID, integrationID, requestDigest[:], identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	entityID, err := CanonicalDiscoveryID(scope, "aws_account", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ApplyCompleteSnapshot(ctx, scope, CompleteSnapshot{IntegrationID: integrationID, SyncID: syncID, SnapshotID: "pid_7b000004-0000-4000-8000-000000000004", Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/legacy/manifest.json", ManifestChecksum: bytes32(1), CollectedAt: time.Now().UTC(), CursorProvider: "aws", CursorValue: "complete", Entities: json.RawMessage(`[{"id":"` + entityID + `","kind":"aws_account","source_native_id":"123456789012","display_name":"Legacy account","stable_fields":{},"attributes":{}}]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`)}); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("typed inventory migration: %v", err)
	}
	var phase string
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_backfill_scope($1,$2,$3)->>'phase'`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&phase); err == nil {
		t.Fatalf("legacy untyped snapshot backfilled as %q", phase)
	}
	var state string
	var productKind *string
	var bindings int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT phase FROM zasp_inventory_cutover_state WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
		(SELECT product_kind FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)),
		(SELECT count(*) FROM zasp_inventory_identity_bindings WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3))`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), entityID).Scan(&state, &productKind, &bindings); err != nil {
		t.Fatal(err)
	}
	if state != "expanded" || productKind != nil || bindings != 0 {
		t.Fatalf("legacy abort residue phase=%s product=%v bindings=%d", state, productKind, bindings)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("uncutover rollback: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 13 {
		t.Fatalf("rollback version = %d / %v", version, err)
	}
}

func TestProductionTypedInventoryCutoverPostgresSelectsDeterministicWinnerAcrossSources(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToProductionDiscoveryExecution(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	awsIntegration := "pid_7c000001-0000-4000-8000-000000000001"
	githubIntegration := "pid_7c000002-0000-4000-8000-000000000002"
	for _, item := range []struct{ id, kind string }{{awsIntegration, "aws"}, {githubIntegration, "github"}} {
		if _, err := repository.CreateIntegration(ctx, identity, IntegrationCreate{ID: item.id, Kind: item.kind, ConnectorVersion: "1.0.0", DisplayName: item.kind + " winner", Configuration: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.TransitionIntegration(ctx, scope, IntegrationTransition{ID: item.id, ExpectedVersion: 1, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	insertSync := func(integrationID, syncID, key string) {
		t.Helper()
		digest := sha256.Sum256([]byte(key))
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,$6,$7,'manual',$8,'parser_v1','tool_v1')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), syncID, integrationID, key, digest[:], identity.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
	}
	entityID := "pid_7c000010-0000-4000-8000-000000000010"
	apply := func(integrationID, syncID, snapshotID, provider, cursor string, generation int64, observed time.Time, entities, evidence json.RawMessage) (SnapshotApplyResult, error) {
		return repository.ApplyCompleteSnapshot(ctx, scope, CompleteSnapshot{IntegrationID: integrationID, SyncID: syncID, SnapshotID: snapshotID, Generation: generation, Source: provider, ManifestReference: "s3://zasp-evidence/typed/winner/manifest.json", ManifestChecksum: bytes32(byte(generation + int64(len(provider)))), CollectedAt: observed, CursorProvider: provider, CursorValue: cursor, Entities: entities, Relationships: json.RawMessage(`[]`), Evidence: evidence})
	}
	typed := func(kind, nativeID, name, product string, priority int, observed time.Time, evidenceID, artifactID, key string) (json.RawMessage, json.RawMessage) {
		entities := json.RawMessage(fmt.Sprintf(`[{"id":%q,"kind":%q,"source_native_id":%q,"display_name":%q,"stable_fields":{},"attributes":{},"identity_namespace":%q,"identity_rule_version":1,"identity_priority":%d,"product_kind":%q,"confidence_basis_points":9000,"observed_at":%q,"fresh_until":%q,"evidence_id":%q,"source_projection_version":1}]`, entityID, kind, nativeID, name, kind, priority, product, observed.Format(time.RFC3339), observed.Add(24*time.Hour).Format(time.RFC3339), evidenceID))
		evidence := json.RawMessage(fmt.Sprintf(`[{"id":%q,"entity_id":%q,"object_reference":%q,"artifact_reference":%q,"artifact_key":%q,"artifact_version_id":"version-1","checksum_hex":%q,"size_bytes":128,"media_type":"application/json","schema_version":"raw_v1","parser_version":"parser_v1","tool_version":"tool_v1"}]`, evidenceID, entityID, "s3://zasp-evidence/"+key, artifactID, key, fmt.Sprintf("%064x", priority)))
		return entities, evidence
	}
	githubObserved := time.Date(2026, time.August, 20, 12, 1, 0, 0, time.UTC)
	githubEntities, githubEvidence := typed("github_repository", "zasp/security", "GitHub winner", "tool", 120, githubObserved, "pid_7c000011-0000-4000-8000-000000000011", "pid_7c000012-0000-4000-8000-000000000012", "typed/winner/github.json")
	githubSync := "pid_7c000013-0000-4000-8000-000000000013"
	insertSync(githubIntegration, githubSync, "typed-winner-github-0001")
	if _, err := apply(githubIntegration, githubSync, "pid_7c000014-0000-4000-8000-000000000014", "github", "github-complete", 1, githubObserved, githubEntities, githubEvidence); err != nil {
		t.Fatal(err)
	}
	awsObserved := time.Date(2026, time.August, 20, 12, 2, 0, 0, time.UTC)
	awsEntities, awsEvidence := typed("aws_account", "123456789012", "AWS winner", "asset", 100, awsObserved, "pid_7c000015-0000-4000-8000-000000000015", "pid_7c000016-0000-4000-8000-000000000016", "typed/winner/aws.json")
	awsSync := "pid_7c000017-0000-4000-8000-000000000017"
	insertSync(awsIntegration, awsSync, "typed-winner-aws-0001")
	if _, err := apply(awsIntegration, awsSync, "pid_7c000018-0000-4000-8000-000000000018", "aws", "aws-complete", 1, awsObserved, awsEntities, awsEvidence); err != nil {
		t.Fatal(err)
	}
	assertWinner := func(provider, product, name, evidence string) {
		t.Helper()
		var actualProvider, actualProduct, actualName, actualEvidence, state string
		var bindings int
		if err := connection.QueryRow(ctx, `SELECT winning_provider,product_kind,display_name,winning_evidence_id,state,(SELECT count(*) FROM zasp_inventory_identity_bindings binding WHERE (binding.organization_id,binding.workspace_id,binding.environment_id,binding.entity_id)=($1,$2,$3,$4)) FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), entityID).Scan(&actualProvider, &actualProduct, &actualName, &actualEvidence, &state, &bindings); err != nil {
			t.Fatal(err)
		}
		if actualProvider != provider || actualProduct != product || actualName != name || actualEvidence != evidence || state != "active" || bindings != 2 {
			t.Fatalf("winner=%s/%s/%s/%s state=%s bindings=%d", actualProvider, actualProduct, actualName, actualEvidence, state, bindings)
		}
	}
	assertWinner("aws", "asset", "AWS winner", "pid_7c000015-0000-4000-8000-000000000015")
	emptySync := "pid_7c000019-0000-4000-8000-000000000019"
	insertSync(awsIntegration, emptySync, "typed-winner-aws-empty-0002")
	if result, err := apply(awsIntegration, emptySync, "pid_7c000020-0000-4000-8000-000000000020", "aws", "aws-empty", 2, awsObserved.Add(time.Minute), json.RawMessage(`[]`), json.RawMessage(`[]`)); err != nil || result.RemovedCount != 1 {
		t.Fatalf("source removal = %#v / %v", result, err)
	}
	assertWinner("github", "tool", "GitHub winner", "pid_7c000011-0000-4000-8000-000000000011")
}
