package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionDiscoverySnapshotGenerationOrderingAndMeaningfulChanges(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	integrationID := "pid_51000001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "Primary")
	entityID, err := CanonicalDiscoveryID(fixture.scope, "aws_account", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	apply := func(sequence int, generation int64, displayName, cursor string) (SnapshotApplyResult, error) {
		t.Helper()
		request := fixture.requestSync(integrationID, sequence)
		return fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, CompleteSnapshot{
			IntegrationID: integrationID, SyncID: request.SyncID, SnapshotID: productID(52000000 + sequence),
			Generation: generation, Source: "aws", ManifestReference: "s3://zasp-evidence/fix/snapshot.json",
			ManifestChecksum: bytes32(byte(sequence)), CollectedAt: time.Date(2026, 8, 19, 12, sequence, 0, 0, time.UTC),
			CursorProvider: "aws", CursorValue: cursor,
			Entities:      json.RawMessage(`[{"id":"` + entityID + `","kind":"aws_account","source_native_id":"123456789012","display_name":"` + displayName + `","stable_fields":{"account":"123456789012"},"attributes":{"region":"us-west-2"}}]`),
			Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`),
		})
	}
	first, err := apply(1, 10, "Production", "cursor-10")
	if err != nil || first.DiscoveredCount != 1 || first.ChangedCount != 0 || first.RemovedCount != 0 {
		t.Fatalf("first apply=%#v err=%v", first, err)
	}
	identical, err := apply(2, 11, "Production", "cursor-11")
	if err != nil || identical.DiscoveredCount != 0 || identical.ChangedCount != 0 || identical.RemovedCount != 0 {
		t.Fatalf("identical successor=%#v err=%v", identical, err)
	}
	changed, err := apply(3, 12, "Renamed", "cursor-12")
	if err != nil || changed.DiscoveredCount != 0 || changed.ChangedCount != 1 || changed.RemovedCount != 0 {
		t.Fatalf("changed successor=%#v err=%v", changed, err)
	}
	staleRequest := fixture.requestSync(integrationID, 4)
	stale := CompleteSnapshot{
		IntegrationID: integrationID, SyncID: staleRequest.SyncID, SnapshotID: productID(52000004), Generation: 9,
		Source: "aws", ManifestReference: "s3://zasp-evidence/fix/stale.json", ManifestChecksum: bytes32(9),
		CollectedAt: time.Date(2026, 8, 19, 13, 0, 0, 0, time.UTC), CursorProvider: "aws", CursorValue: "cursor-stale",
		Entities: json.RawMessage(`[]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`),
	}
	if _, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, stale); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("stale generation error=%v", err)
	}
	var version int64
	var name, lastGood, cursor, staleState string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT e.version,e.display_name,s.id,c.cursor_value,stale.state
		FROM zasp_inventory_entities e
		JOIN zasp_discovery_snapshots s ON s.organization_id=e.organization_id AND s.workspace_id=e.workspace_id AND s.environment_id=e.environment_id AND s.integration_id=$4 AND s.is_last_good
		JOIN zasp_discovery_cursors c ON c.organization_id=e.organization_id AND c.workspace_id=e.workspace_id AND c.environment_id=e.environment_id AND c.integration_id=$4 AND c.provider='aws'
		JOIN zasp_discovery_syncs stale ON stale.organization_id=e.organization_id AND stale.workspace_id=e.workspace_id AND stale.environment_id=e.environment_id AND stale.id=$6
		WHERE e.organization_id=$1 AND e.workspace_id=$2 AND e.environment_id=$3 AND e.id=$5`, fixture.scopeArgs(integrationID, entityID, staleRequest.SyncID)...).Scan(&version, &name, &lastGood, &cursor, &staleState); err != nil {
		t.Fatal(err)
	}
	if version != 2 || name != "Renamed" || lastGood != productID(52000003) || cursor != "cursor-12" || staleState != "queued" {
		t.Fatalf("post-stale version=%d name=%q last_good=%q cursor=%q sync=%q", version, name, lastGood, cursor, staleState)
	}
	var staleRows int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FROM zasp_discovery_snapshots WHERE id=$1`, stale.SnapshotID).Scan(&staleRows); err != nil || staleRows != 0 {
		t.Fatalf("stale residue=%d err=%v", staleRows, err)
	}
}

func TestProductionDiscoverySerializesConcurrentGenerationsByIntegrationSource(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	integrationID := "pid_53000001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "Concurrent")
	highRequest := fixture.requestSync(integrationID, 11)
	lowRequest := fixture.requestSync(integrationID, 12)
	second := fixture.connectRepository()
	third := fixture.connectRepository()
	secondConnection := second.database.(*PostgresJSONDatabase).driver.(*integrationPostgresDriver).connection
	thirdConnection := third.database.(*PostgresJSONDatabase).driver.(*integrationPostgresDriver).connection
	secondPID := postgresConnectionPID(t, fixture.ctx, secondConnection)
	thirdPID := postgresConnectionPID(t, fixture.ctx, thirdConnection)
	blocker := fixture.connect()
	tx, err := blocker.Begin(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(fixture.ctx, `SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1::text,$2::text,$3::text,$4::text,$5::text),0))`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String(), integrationID, "aws"); err != nil {
		t.Fatal(err)
	}
	candidate := func(request SyncRequest, generation int64, cursor string) CompleteSnapshot {
		return CompleteSnapshot{IntegrationID: integrationID, SyncID: request.SyncID, SnapshotID: productID(53000000 + int(generation)), Generation: generation, Source: "aws", ManifestReference: "s3://zasp-evidence/fix/concurrent.json", ManifestChecksum: bytes32(byte(generation)), CollectedAt: time.Date(2026, 8, 19, 14, 0, 0, 0, time.UTC), CursorProvider: "aws", CursorValue: cursor, Entities: json.RawMessage(`[]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`)}
	}
	highDone := make(chan error, 1)
	go func() {
		_, applyErr := second.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, candidate(highRequest, 20, "cursor-20"))
		highDone <- applyErr
	}()
	waitForPostgresAdvisoryLock(t, fixture.ctx, fixture.connection, secondPID, highDone)
	lowDone := make(chan error, 1)
	go func() {
		_, applyErr := third.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, candidate(lowRequest, 19, "cursor-19"))
		lowDone <- applyErr
	}()
	waitForPostgresAdvisoryLock(t, fixture.ctx, fixture.connection, thirdPID, lowDone)
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-highDone; err != nil {
		t.Fatalf("newer generation=%v", err)
	}
	if err := <-lowDone; !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("queued stale generation=%v", err)
	}
	var generation int64
	var cursor string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT s.generation,c.cursor_value FROM zasp_discovery_snapshots s JOIN zasp_discovery_cursors c USING(organization_id,workspace_id,environment_id,integration_id) WHERE s.is_last_good AND s.integration_id=$1`, integrationID).Scan(&generation, &cursor); err != nil || generation != 20 || cursor != "cursor-20" {
		t.Fatalf("winner generation=%d cursor=%q err=%v", generation, cursor, err)
	}
}

func TestProductionDiscoveryRelationshipsAreSourceOwned(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	firstIntegration := "pid_54000001-0000-4000-8000-000000000001"
	secondIntegration := "pid_54000002-0000-4000-8000-000000000002"
	fixture.createActiveIntegration(firstIntegration, "First")
	fixture.createActiveIntegration(secondIntegration, "Second")
	fromID, _ := CanonicalDiscoveryID(fixture.scope, "account", "shared-from")
	toID, _ := CanonicalDiscoveryID(fixture.scope, "account", "shared-to")
	apply := func(integration string, sequence int, generation int64, includeRelationship bool) {
		t.Helper()
		request := fixture.requestSync(integration, sequence)
		relationships := `[]`
		if includeRelationship {
			relationshipID, idErr := CanonicalDiscoveryRelationshipID(fixture.scope, integration, "aws", "contains", "shared-edge")
			if idErr != nil {
				t.Fatal(idErr)
			}
			relationships = `[{"id":"` + relationshipID + `","kind":"contains","source_native_id":"shared-edge","from_entity_id":"` + fromID + `","to_entity_id":"` + toID + `","attributes":{}}]`
		}
		_, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, CompleteSnapshot{IntegrationID: integration, SyncID: request.SyncID, SnapshotID: productID(55000000 + sequence), Generation: generation, Source: "aws", ManifestReference: "s3://zasp-evidence/fix/relationships.json", ManifestChecksum: bytes32(byte(sequence)), CollectedAt: time.Date(2026, 8, 19, 15, sequence, 0, 0, time.UTC), CursorProvider: "aws", CursorValue: productID(sequence), Entities: json.RawMessage(`[{"id":"` + fromID + `","kind":"account","source_native_id":"shared-from","display_name":"From","stable_fields":{},"attributes":{}},{"id":"` + toID + `","kind":"account","source_native_id":"shared-to","display_name":"To","stable_fields":{},"attributes":{}}]`), Relationships: json.RawMessage(relationships), Evidence: json.RawMessage(`[]`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	apply(firstIntegration, 21, 1, true)
	apply(secondIntegration, 22, 1, true)
	apply(secondIntegration, 23, 2, false)
	var firstPresent, secondRemoved int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FILTER (WHERE integration_id=$1 AND state='present'),count(*) FILTER (WHERE integration_id=$2 AND state='removed') FROM zasp_inventory_relationships`, firstIntegration, secondIntegration).Scan(&firstPresent, &secondRemoved); err != nil || firstPresent != 1 || secondRemoved != 1 {
		t.Fatalf("source-owned relationships=%d/%d err=%v", firstPresent, secondRemoved, err)
	}
}

func TestProductionDiscoveryExactFindingAndEnrollmentParentsAndProjectionPlan(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	scope := []any{fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String()}
	integrationID := "pid_56000001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "Parents")
	request := fixture.requestSync(integrationID, 31)
	snapshotID := productID(56000002)
	if _, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, CompleteSnapshot{IntegrationID: integrationID, SyncID: request.SyncID, SnapshotID: snapshotID, Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/fix/parents.json", ManifestChecksum: bytes32(1), CollectedAt: time.Date(2026, 8, 19, 16, 0, 0, 0, time.UTC), CursorProvider: "aws", CursorValue: "parents", Entities: json.RawMessage(`[]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`)}); err != nil {
		t.Fatal(err)
	}
	findingID := "pid_56000003-0000-4000-8000-000000000003"
	evidenceID := "pid_56000004-0000-4000-8000-000000000004"
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,finding_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at) VALUES($1,$2,$3,$4,$5,$6,$7,'s3://zasp-evidence/fix/missing-finding.json',$8,'application/json','1','1',transaction_timestamp())`, append(scope, evidenceID, integrationID, snapshotID, findingID, make([]byte, 32))...); err == nil {
		t.Fatal("missing finding parent accepted")
	}
	deviceOne, deviceTwo := "pid_56000005-0000-4000-8000-000000000005", "pid_56000006-0000-4000-8000-000000000006"
	enrollmentID := "pid_56000007-0000-4000-8000-000000000007"
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name) VALUES($1,$2,$3,$4,'One'),($1,$2,$3,$5,'Two')`, append(scope, deviceOne, deviceTwo)...); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',$6,$7,transaction_timestamp()+interval '1 hour')`, append(scope, enrollmentID, deviceOne, make([]byte, 16), bytes32(7))...); err != nil {
		t.Fatal(err)
	}
	credentialID := "pid_56000008-0000-4000-8000-000000000008"
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,'runtime-gateway','ref:kms/gateway/parent',$8,transaction_timestamp()+interval '1 hour')`, append(scope, credentialID, deviceTwo, enrollmentID, bytes32(8), make([]byte, 32))...); err == nil {
		t.Fatal("cross-device enrollment parent accepted")
	}
	var evidenceRows, credentialRows int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT (SELECT count(*) FROM zasp_inventory_evidence WHERE id=$1),(SELECT count(*) FROM zasp_gateway_credentials WHERE id=$2)`, evidenceID, credentialID).Scan(&evidenceRows, &credentialRows); err != nil || evidenceRows != 0 || credentialRows != 0 {
		t.Fatalf("hostile parent residue=%d/%d err=%v", evidenceRows, credentialRows, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,candidate_digest,state,complete,collected_at,committed_at)
		SELECT $1,$2,$3,'pid_'||lpad(to_hex(i),8,'0')||'-0000-4000-8000-'||lpad(to_hex(i),12,'0'),$4,$5,1000+i,'aws','s3://zasp-evidence/fix/plan.json',$6,$6,'complete',true,transaction_timestamp(),transaction_timestamp() FROM generate_series(1,500) i`, append(scope, integrationID, request.SyncID, bytes32(1))...); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_projection_work(organization_id,workspace_id,environment_id,snapshot_id,kind,version,input_digest) SELECT organization_id,workspace_id,environment_id,id,'risk','plan-v1',$1 FROM zasp_discovery_snapshots WHERE integration_id=$2 ON CONFLICT DO NOTHING`, bytes32(1), integrationID); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.connection.Begin(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(fixture.ctx, `SET LOCAL enable_seqscan=off`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(fixture.ctx, `EXPLAIN (COSTS OFF) SELECT organization_id,min(snapshot_id) FROM zasp_projection_work WHERE state='pending' OR state='leased' AND lease_expires_at<=transaction_timestamp() GROUP BY organization_id ORDER BY min(snapshot_id),organization_id LIMIT 100`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if !strings.Contains(plan.String(), "zasp_projection_work_claim_idx") {
		t.Fatalf("projection claim plan:\n%s", plan.String())
	}
}

func TestProductionDiscoveryLeastPrivilegeRolesAndLiveReadiness(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	scope := fixture.scopeArgs()
	var forcedTables, totalTables int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FILTER (WHERE relforcerowsecurity),count(*) FROM pg_class JOIN pg_namespace n ON n.oid=relnamespace WHERE n.nspname='public' AND relkind='r' AND relname IN ('zasp_integrations','zasp_discovery_jobs','zasp_discovery_outbox','zasp_projection_work')`).Scan(&forcedTables, &totalTables); err != nil || forcedTables != totalTables || totalTables != 4 {
		t.Fatalf("forced RLS=%d/%d err=%v", forcedTables, totalTables, err)
	}
	var unsafeFunctions int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_discovery_%' AND (NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'])`).Scan(&unsafeFunctions); err != nil || unsafeFunctions != 0 {
		t.Fatalf("unsafe discovery functions=%d err=%v", unsafeFunctions, err)
	}
	integrationID := "pid_58000001-0000-4000-8000-000000000001"
	if _, err := fixture.connection.Exec(fixture.ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	var created []byte
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_create_integration($1,$2,$3,$4,'aws','1.0.0','Role-bound','{}'::jsonb,NULL)`, append(scope, integrationID)...).Scan(&created); err != nil || !strings.Contains(string(created), integrationID) {
		t.Fatalf("scoped API function=%s err=%v", created, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `SELECT count(*) FROM zasp_integrations`); err == nil {
		t.Fatal("API role received direct table access")
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `SELECT zasp_discovery_claim_jobs('api-worker','api-lease-token-0001',30,10,'discovery')`); err == nil {
		t.Fatal("API role received worker claim authority")
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_integrations SET state='active' WHERE id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	request := fixture.requestSync(integrationID, 41)
	if _, err := fixture.connection.Exec(fixture.ctx, `SET ROLE zasp_discovery_worker`); err != nil {
		t.Fatal(err)
	}
	var claimed []byte
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_claim_jobs('role-worker','role-lease-token-001',30,10,'discovery')`).Scan(&claimed); err != nil || !strings.Contains(string(claimed), request.JobID) {
		t.Fatalf("global worker claim=%s err=%v", claimed, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `SELECT count(*) FROM zasp_discovery_jobs`); err == nil {
		t.Fatal("worker role received direct table access")
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: fixture.connection})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiscoveryRepository(database); err != nil {
		t.Fatalf("constructor before drift=%v", err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `ALTER TABLE zasp_integrations ADD COLUMN live_drift text`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_readiness($1,$2)`, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatalf("readiness after live drift=%v err=%v", ready, err)
	}
	if _, err := NewDiscoveryRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("constructor after live drift=%v", err)
	}
}

type discoveryFixPostgresFixture struct {
	t          *testing.T
	ctx        context.Context
	dsn        string
	connection *pgx.Conn
	repository *DiscoveryRepository
	identity   RequestIdentity
	scope      domain.Scope
}

func newDiscoveryFixPostgresFixture(t *testing.T) *discoveryFixPostgresFixture {
	t.Helper()
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	migrateToProductionDiscovery(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewDiscoveryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	return &discoveryFixPostgresFixture{t: t, ctx: ctx, dsn: dsn, connection: connection, repository: repository, identity: identity, scope: identity.Scope}
}

func (fixture *discoveryFixPostgresFixture) createActiveIntegration(id, name string) {
	fixture.t.Helper()
	if _, err := fixture.repository.CreateIntegration(fixture.ctx, fixture.identity, IntegrationCreate{ID: id, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: name, Configuration: json.RawMessage(`{}`)}); err != nil {
		fixture.t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_integrations SET state='active' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, fixture.scopeArgs(id)...); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *discoveryFixPostgresFixture) requestSync(integrationID string, sequence int) SyncRequest {
	fixture.t.Helper()
	digest := sha256.Sum256([]byte(productID(sequence)))
	request := SyncRequest{IntegrationID: integrationID, SyncID: productID(57000000 + sequence*3), JobID: productID(57000001 + sequence*3), OutboxID: productID(57000002 + sequence*3), IdempotencyKey: "fix-sync-idempotency-" + productID(sequence), RequestDigest: digest[:], TriggerKind: "manual", ParserVersion: "1.0.0", ToolVersion: "1.0.0"}
	if _, err := fixture.repository.RequestDiscoverySync(fixture.ctx, fixture.identity, request); err != nil {
		fixture.t.Fatal(err)
	}
	return request
}

func (fixture *discoveryFixPostgresFixture) scopeArgs(extra ...any) []any {
	return append([]any{fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String()}, extra...)
}

func (fixture *discoveryFixPostgresFixture) connect() *pgx.Conn {
	fixture.t.Helper()
	connection, err := pgx.Connect(fixture.ctx, fixture.dsn)
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.t.Cleanup(func() { _ = connection.Close(context.Background()) })
	return connection
}

func (fixture *discoveryFixPostgresFixture) connectRepository() *DiscoveryRepository {
	fixture.t.Helper()
	connection := fixture.connect()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		fixture.t.Fatal(err)
	}
	repository, err := NewDiscoveryRepository(database)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return repository
}

func postgresConnectionPID(t *testing.T, ctx context.Context, connection *pgx.Conn) int32 {
	t.Helper()
	var pid int32
	if err := connection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func waitForPostgresAdvisoryLock(t *testing.T, ctx context.Context, observer *pgx.Conn, pid int32, completed <-chan error) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		select {
		case err := <-completed:
			t.Fatalf("snapshot completed before scope lock: %v", err)
		default:
		}
		var waiting bool
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event='advisory',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
	}
	t.Fatal("snapshot did not wait on the integration/source advisory lock")
}

func productID(value int) string {
	hex := "00000000" + strings.ToLower(strconv.FormatInt(int64(value), 16))
	hex = hex[len(hex)-8:]
	return "pid_" + hex + "-0000-4000-8000-000000000001"
}

func bytes32(value byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = value
	}
	return result
}
