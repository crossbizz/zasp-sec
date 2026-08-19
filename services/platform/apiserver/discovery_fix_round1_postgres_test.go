package apiserver

import (
	"bytes"
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
	changedToID, err := CanonicalDiscoveryID(fixture.scope, "account", "changed-to")
	if err != nil {
		t.Fatal(err)
	}
	changedRelationshipID, err := CanonicalDiscoveryRelationshipID(fixture.scope, firstIntegration, "aws", "owns", "shared-edge")
	if err != nil {
		t.Fatal(err)
	}
	changedRequest := fixture.requestSync(firstIntegration, 23)
	if _, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, CompleteSnapshot{
		IntegrationID: firstIntegration, SyncID: changedRequest.SyncID, SnapshotID: productID(55000023), Generation: 2,
		Source: "aws", ManifestReference: "s3://zasp-evidence/fix/relationship-evolution.json", ManifestChecksum: bytes32(23),
		CollectedAt: time.Date(2026, 8, 19, 15, 23, 0, 0, time.UTC), CursorProvider: "aws", CursorValue: "relationship-evolution",
		Entities:      json.RawMessage(`[{"id":"` + fromID + `","kind":"account","source_native_id":"shared-from","display_name":"From","stable_fields":{},"attributes":{}},{"id":"` + changedToID + `","kind":"account","source_native_id":"changed-to","display_name":"Changed To","stable_fields":{},"attributes":{}}]`),
		Relationships: json.RawMessage(`[{"id":"` + changedRelationshipID + `","kind":"owns","source_native_id":"shared-edge","from_entity_id":"` + fromID + `","to_entity_id":"` + changedToID + `","attributes":{"changed":true}}]`),
		Evidence:      json.RawMessage(`[]`),
	}); err != nil {
		t.Fatalf("relationship endpoint/kind successor: %v", err)
	}
	apply(secondIntegration, 24, 2, false)
	var firstPresent, secondRemoved int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FILTER (WHERE integration_id=$1 AND state='present'),count(*) FILTER (WHERE integration_id=$2 AND state='removed') FROM zasp_inventory_relationships`, firstIntegration, secondIntegration).Scan(&firstPresent, &secondRemoved); err != nil || firstPresent != 1 || secondRemoved != 1 {
		t.Fatalf("source-owned relationships=%d/%d err=%v", firstPresent, secondRemoved, err)
	}
	var evolvedID, evolvedKind, evolvedTo string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT id,kind,to_entity_id FROM zasp_inventory_relationships WHERE integration_id=$1 AND source='aws' AND source_native_id='shared-edge'`, firstIntegration).Scan(&evolvedID, &evolvedKind, &evolvedTo); err != nil || evolvedID != changedRelationshipID || evolvedKind != "owns" || evolvedTo != changedToID {
		t.Fatalf("evolved relationship id=%q kind=%q to=%q err=%v", evolvedID, evolvedKind, evolvedTo, err)
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
	fromID, toID := "pid_56000009-0000-4000-8000-000000000009", "pid_56000010-0000-4000-8000-000000000010"
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,'account','From',transaction_timestamp(),transaction_timestamp()),($1,$2,$3,$5,'account','To',transaction_timestamp(),transaction_timestamp())`, append(scope, fromID, toID)...); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,'azure',$5,'wrong-source-observation',$6,'present',transaction_timestamp(),transaction_timestamp())`, append(scope, integrationID, fromID, snapshotID)...); err == nil {
		t.Fatal("cross-source observation snapshot parent accepted")
	}
	wrongSourceRelationshipID, err := CanonicalDiscoveryRelationshipID(fixture.scope, integrationID, "azure", "contains", "wrong-source-relationship")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,'azure',$6,$7,$8,'contains','wrong-source-relationship',transaction_timestamp(),transaction_timestamp())`, append(scope, wrongSourceRelationshipID, integrationID, snapshotID, fromID, toID)...); err == nil {
		t.Fatal("cross-source relationship snapshot parent accepted")
	}
	findingID := "pid_56000003-0000-4000-8000-000000000003"
	evidenceID := "pid_56000004-0000-4000-8000-000000000004"
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,finding_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at) VALUES($1,$2,$3,$4,$5,$6,$7,'s3://zasp-evidence/fix/missing-finding.json',$8,'application/json','1','1',transaction_timestamp())`, append(scope, evidenceID, integrationID, snapshotID, findingID, make([]byte, 32))...); err == nil {
		t.Fatal("missing finding parent accepted")
	}
	deviceOne, deviceTwo := "pid_56000005-0000-4000-8000-000000000005", "pid_56000006-0000-4000-8000-000000000006"
	enrollmentID := "pid_56000007-0000-4000-8000-000000000007"
	if _, err := fixture.repository.CreateGatewayDevice(fixture.ctx, fixture.scope, GatewayDeviceCreate{ID: deviceOne, Name: "One"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.CreateGatewayDevice(fixture.ctx, fixture.scope, GatewayDeviceCreate{ID: deviceTwo, Name: "Two"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.IssueGatewayEnrollmentToken(fixture.ctx, fixture.scope, GatewayEnrollmentTokenIssue{ID: enrollmentID, DeviceID: deviceOne, Salt: make([]byte, 16), TokenHash: bytes32(7), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	credentialID := "pid_56000008-0000-4000-8000-000000000008"
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,'runtime-gateway','ref:kms/gateway/parent',$8,transaction_timestamp()+interval '1 hour')`, append(scope, credentialID, deviceTwo, enrollmentID, bytes32(8), make([]byte, 32))...); err == nil {
		t.Fatal("cross-device enrollment parent accepted")
	}
	var evidenceRows, credentialRows, observationRows, relationshipRows int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT (SELECT count(*) FROM zasp_inventory_evidence WHERE id=$1),(SELECT count(*) FROM zasp_gateway_credentials WHERE id=$2),(SELECT count(*) FROM zasp_inventory_source_observations WHERE source_native_id='wrong-source-observation'),(SELECT count(*) FROM zasp_inventory_relationships WHERE source_native_id='wrong-source-relationship')`, evidenceID, credentialID).Scan(&evidenceRows, &credentialRows, &observationRows, &relationshipRows); err != nil || evidenceRows != 0 || credentialRows != 0 || observationRows != 0 || relationshipRows != 0 {
		t.Fatalf("hostile parent residue=%d/%d/%d/%d err=%v", evidenceRows, credentialRows, observationRows, relationshipRows, err)
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
	if _, err := fixture.connection.Exec(fixture.ctx, `CREATE ROLE zasp_deployed_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; CREATE ROLE zasp_deployed_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; CREATE ROLE zasp_deployed_ingest LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; CREATE ROLE zasp_deployed_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; CREATE ROLE zasp_deployed_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; CREATE ROLE zasp_deployed_gateway LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; SELECT zasp_discovery_register_principals(session_user,'zasp_deployed_api','zasp_deployed_worker','zasp_deployed_ingest','zasp_deployed_runtime','zasp_deployed_outbox','zasp_deployed_gateway')`); err != nil {
		t.Fatal(err)
	}
	connectAs := func(role string) *pgx.Conn {
		t.Helper()
		configuration, parseErr := pgx.ParseConfig(fixture.dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		configuration.User = role
		connection, connectErr := pgx.ConnectConfig(fixture.ctx, configuration)
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		t.Cleanup(func() { _ = connection.Close(context.Background()) })
		return connection
	}
	apiLogin := connectAs("zasp_deployed_api")
	if _, err := apiLogin.Exec(fixture.ctx, `SELECT zasp_discovery_entity_page($1,$2,$3,NULL,1)`, scope...); err != nil {
		t.Fatalf("deployed API function authority=%v", err)
	}
	if _, err := apiLogin.Exec(fixture.ctx, `SELECT count(*) FROM zasp_integrations`); err == nil {
		t.Fatal("deployed API login retained direct table authority")
	}
	if _, err := apiLogin.Exec(fixture.ctx, `SELECT zasp_discovery_claim_jobs('api-worker','api-worker-token-0001',30,1,'discovery')`); err == nil {
		t.Fatal("deployed API login inherited worker authority")
	}
	workerLogin := connectAs("zasp_deployed_worker")
	if _, err := workerLogin.Exec(fixture.ctx, `SELECT zasp_discovery_claim_jobs('deployed-worker','deployed-worker-token-1',30,1,'discovery')`); err != nil {
		t.Fatalf("deployed worker function authority=%v", err)
	}
	if _, err := workerLogin.Exec(fixture.ctx, `SELECT count(*) FROM zasp_discovery_jobs`); err == nil {
		t.Fatal("deployed worker login retained direct table authority")
	}
	var inheritedAuthority bool
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT pg_has_role('zasp_deployed_api','zasp_discovery_authority','MEMBER') OR pg_has_role('zasp_deployed_worker','zasp_discovery_authority','MEMBER')`).Scan(&inheritedAuthority); err != nil || inheritedAuthority {
		t.Fatalf("deployed authority membership=%v err=%v", inheritedAuthority, err)
	}
	if _, err := fixture.repository.TransitionIntegration(fixture.ctx, fixture.scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
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
	if _, err := newDiscoveryRepositoryUnchecked(database); err != nil {
		t.Fatalf("constructor before drift=%v", err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `ALTER TABLE zasp_integrations ADD COLUMN live_drift text`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_readiness($1,$2)`, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatalf("readiness after live drift=%v err=%v", ready, err)
	}
	if _, err := newDiscoveryRepositoryUnchecked(database); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("constructor after live drift=%v", err)
	}
}

func TestProductionDiscoverySecurityDriftBlocksReadinessConstructorAndRollback(t *testing.T) {
	tests := []struct {
		name  string
		drift string
	}{
		{name: "policy", drift: `DROP POLICY zasp_integrations_authority ON zasp_integrations`},
		{name: "table ACL", drift: `GRANT SELECT ON zasp_integrations TO zasp_discovery_api`},
		{name: "function owner", drift: `ALTER FUNCTION zasp_discovery_claim_jobs(text,text,integer,integer,text) OWNER TO CURRENT_USER`},
		{name: "function execute ACL", drift: `GRANT EXECUTE ON FUNCTION zasp_discovery_claim_jobs(text,text,integer,integer,text) TO zasp_discovery_api`},
		{name: "role attribute", drift: `ALTER ROLE zasp_discovery_api BYPASSRLS`},
		{name: "role membership", drift: `CREATE ROLE zasp_test_drift_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; GRANT zasp_discovery_api TO zasp_test_drift_login`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixPostgresFixture(t)
			if _, err := fixture.connection.Exec(fixture.ctx, test.drift); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_readiness($1,$2)`, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatalf("security readiness=%v err=%v", ready, err)
			}
			database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: fixture.connection})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newDiscoveryRepositoryUnchecked(database); !errors.Is(err, ErrRepositoryConfiguration) {
				t.Fatalf("security constructor=%v", err)
			}
			if err := fixture.runner.DownProductionDiscovery(fixture.ctx); err == nil {
				t.Fatal("security drift did not block rollback")
			}
		})
	}
}

func TestProductionDiscoveryRolesAreSafeAcrossDatabasesInOneCluster(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	first, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())
	firstRunner := migrateToProductionDiscovery(t, ctx, first)
	if _, err := first.Exec(ctx, `CREATE DATABASE zasp_discovery_second`); err != nil {
		t.Fatal(err)
	}
	configuration, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Database = "zasp_discovery_second"
	second, err := pgx.ConnectConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	migrateToProductionDiscovery(t, ctx, second)
	if err := firstRunner.DownProductionDiscovery(ctx); err != nil {
		t.Fatalf("down first database with shared roles: %v", err)
	}
	var roles int
	if err := second.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('zasp_discovery_authority','zasp_discovery_api','zasp_discovery_worker','zasp_runtime_ingest','zasp_runtime_worker','zasp_outbox_worker','zasp_runtime_gateway')`).Scan(&roles); err != nil || roles != 7 {
		t.Fatalf("shared roles after one database down=%d err=%v", roles, err)
	}
	if _, err := second.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatalf("second database role unusable: %v", err)
	}
	var ready bool
	if err := second.QueryRow(ctx, `SELECT zasp_discovery_readiness($1,$2)`, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("second database readiness=%v err=%v", ready, err)
	}
}

func TestProductionDiscoveryTypedLifecyclesAndBoundedWorkerRecovery(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	integrationID := "pid_62000001-0000-4000-8000-000000000001"
	created, err := fixture.repository.CreateIntegration(fixture.ctx, fixture.identity, IntegrationCreate{ID: integrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "Typed", Configuration: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.repository.CreateIntegration(fixture.ctx, fixture.identity, IntegrationCreate{ID: integrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "Typed", Configuration: json.RawMessage(`{}`)})
	if err != nil || replayed.CreatedAt != created.CreatedAt {
		t.Fatalf("integration replay=%#v err=%v", replayed, err)
	}
	if _, err := fixture.repository.CreateIntegration(fixture.ctx, fixture.identity, IntegrationCreate{ID: integrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "Changed", Configuration: json.RawMessage(`{}`)}); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("integration conflict=%v", err)
	}
	if _, err := fixture.repository.TransitionIntegration(fixture.ctx, fixture.scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionIntegration(fixture.ctx, fixture.scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatalf("integration transition replay=%v", err)
	}
	connection := IntegrationConnectionPut{ID: "pid_62000002-0000-4000-8000-000000000002", IntegrationID: integrationID, Provider: "aws", ConnectionReference: "ref:aws/connection-0002"}
	if _, err := fixture.repository.PutIntegrationConnection(fixture.ctx, fixture.scope, connection); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.PutIntegrationConnection(fixture.ctx, fixture.scope, connection); err != nil {
		t.Fatalf("connection replay=%v", err)
	}
	connectionConflict := connection
	connectionConflict.ConnectionReference = "ref:aws/connection-conflict"
	if _, err := fixture.repository.PutIntegrationConnection(fixture.ctx, fixture.scope, connectionConflict); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("connection conflict=%v", err)
	}
	if _, err := fixture.repository.TransitionIntegrationConnection(fixture.ctx, fixture.scope, integrationID, IntegrationTransition{ID: connection.ID, ExpectedVersion: 1, State: "verified"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionIntegrationConnection(fixture.ctx, fixture.scope, integrationID, IntegrationTransition{ID: connection.ID, ExpectedVersion: 1, State: "verified"}); err != nil {
		t.Fatalf("connection transition replay=%v", err)
	}
	next := time.Now().UTC().Add(-time.Minute)
	schedule := DiscoverySchedulePut{ID: "pid_62000003-0000-4000-8000-000000000003", IntegrationID: integrationID, CadenceSeconds: 300, NextRunAt: next}
	if _, err := fixture.repository.PutDiscoverySchedule(fixture.ctx, fixture.scope, schedule); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.PutDiscoverySchedule(fixture.ctx, fixture.scope, schedule); err != nil {
		t.Fatalf("schedule replay=%v", err)
	}
	scheduleConflict := schedule
	scheduleConflict.CadenceSeconds++
	if _, err := fixture.repository.PutDiscoverySchedule(fixture.ctx, fixture.scope, scheduleConflict); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("schedule conflict=%v", err)
	}
	leases, err := fixture.repository.ClaimDiscoverySchedules(fixture.ctx, "schedule-worker", "schedule-lease-token-1", 30, 1)
	if err != nil || len(leases) != 1 {
		t.Fatalf("schedule claim=%#v err=%v", leases, err)
	}
	completion := DiscoveryScheduleCompletion{ID: schedule.ID, Worker: "schedule-worker", LeaseToken: "schedule-lease-token-1", Outcome: "advanced", NextRunAt: time.Now().UTC().Add(5 * time.Minute)}
	firstCompletion, err := fixture.repository.CompleteDiscoverySchedule(fixture.ctx, fixture.scope, completion)
	if err != nil {
		t.Fatal(err)
	}
	secondCompletion, err := fixture.repository.CompleteDiscoverySchedule(fixture.ctx, fixture.scope, completion)
	if err != nil || secondCompletion != firstCompletion {
		t.Fatalf("schedule completion replay=%#v/%#v err=%v", firstCompletion, secondCompletion, err)
	}
	schedule.ExpectedVersion = firstCompletion.Version
	schedule.NextRunAt = time.Now().UTC().Add(-time.Minute)
	if _, err := fixture.repository.PutDiscoverySchedule(fixture.ctx, fixture.scope, schedule); err != nil {
		t.Fatalf("schedule release setup=%v", err)
	}
	if claimed, err := fixture.repository.ClaimDiscoverySchedules(fixture.ctx, "schedule-worker", "schedule-lease-token-2", 30, 1); err != nil || len(claimed) != 1 {
		t.Fatalf("schedule release claim=%#v err=%v", claimed, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_discovery_schedules SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE id=$1`, schedule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.CompleteDiscoverySchedule(fixture.ctx, fixture.scope, DiscoveryScheduleCompletion{ID: schedule.ID, Worker: "schedule-worker", LeaseToken: "schedule-lease-token-2", Outcome: "released", NextRunAt: time.Now().UTC().Add(time.Minute)}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("expired-owner schedule completion=%v", err)
	}
	if claimed, err := fixture.repository.ClaimDiscoverySchedules(fixture.ctx, "schedule-worker", "schedule-lease-token-2b", 30, 1); err != nil || len(claimed) != 1 {
		t.Fatalf("schedule release reclaim=%#v err=%v", claimed, err)
	}
	released, err := fixture.repository.CompleteDiscoverySchedule(fixture.ctx, fixture.scope, DiscoveryScheduleCompletion{ID: schedule.ID, Worker: "schedule-worker", LeaseToken: "schedule-lease-token-2b", Outcome: "released", NextRunAt: time.Now().UTC().Add(time.Minute)})
	if err != nil || released.State != "enabled" {
		t.Fatalf("schedule release=%#v err=%v", released, err)
	}
	schedule.ExpectedVersion = released.Version
	schedule.NextRunAt = time.Now().UTC().Add(-time.Minute)
	if _, err := fixture.repository.PutDiscoverySchedule(fixture.ctx, fixture.scope, schedule); err != nil {
		t.Fatalf("schedule disable setup=%v", err)
	}
	if claimed, err := fixture.repository.ClaimDiscoverySchedules(fixture.ctx, "schedule-worker", "schedule-lease-token-3", 30, 1); err != nil || len(claimed) != 1 {
		t.Fatalf("schedule disable claim=%#v err=%v", claimed, err)
	}
	disabled, err := fixture.repository.CompleteDiscoverySchedule(fixture.ctx, fixture.scope, DiscoveryScheduleCompletion{ID: schedule.ID, Worker: "schedule-worker", LeaseToken: "schedule-lease-token-3", Outcome: "disabled", NextRunAt: time.Now().UTC().Add(time.Minute)})
	if err != nil || disabled.State != "disabled" {
		t.Fatalf("schedule disable=%#v err=%v", disabled, err)
	}
	sensor := SensorCreate{ID: "pid_62000004-0000-4000-8000-000000000004", Name: "Typed sensor", Kind: "otlp"}
	if _, err := fixture.repository.CreateSensor(fixture.ctx, fixture.scope, sensor); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.CreateSensor(fixture.ctx, fixture.scope, sensor); err != nil {
		t.Fatalf("sensor replay=%v", err)
	}
	sensorConflict := sensor
	sensorConflict.Name = "Changed sensor"
	if _, err := fixture.repository.CreateSensor(fixture.ctx, fixture.scope, sensorConflict); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("sensor conflict=%v", err)
	}
	if _, err := fixture.repository.TransitionSensor(fixture.ctx, fixture.scope, IntegrationTransition{ID: sensor.ID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionSensor(fixture.ctx, fixture.scope, IntegrationTransition{ID: sensor.ID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatalf("sensor transition replay=%v", err)
	}
	device := GatewayDeviceCreate{ID: "pid_62000005-0000-4000-8000-000000000005", Name: "Typed gateway"}
	if _, err := fixture.repository.CreateGatewayDevice(fixture.ctx, fixture.scope, device); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.CreateGatewayDevice(fixture.ctx, fixture.scope, device); err != nil {
		t.Fatalf("device replay=%v", err)
	}
	deviceConflict := device
	deviceConflict.Name = "Changed gateway"
	if _, err := fixture.repository.CreateGatewayDevice(fixture.ctx, fixture.scope, deviceConflict); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("device conflict=%v", err)
	}
	if _, err := fixture.repository.TransitionGatewayDevice(fixture.ctx, fixture.scope, IntegrationTransition{ID: device.ID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionGatewayDevice(fixture.ctx, fixture.scope, IntegrationTransition{ID: device.ID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatalf("device transition replay=%v", err)
	}
	enrollment := GatewayEnrollmentTokenIssue{ID: "pid_62000006-0000-4000-8000-000000000006", DeviceID: device.ID, Salt: bytes.Repeat([]byte{6}, 16), TokenHash: bytes.Repeat([]byte{7}, 32), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if _, err := fixture.repository.IssueGatewayEnrollmentToken(fixture.ctx, fixture.scope, enrollment); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.IssueGatewayEnrollmentToken(fixture.ctx, fixture.scope, enrollment); err != nil {
		t.Fatalf("enrollment replay=%v", err)
	}
	conflict := enrollment
	conflict.ExpiresAt = conflict.ExpiresAt.Add(time.Minute)
	if _, err := fixture.repository.IssueGatewayEnrollmentToken(fixture.ctx, fixture.scope, conflict); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("enrollment conflict=%v", err)
	}
	if err := fixture.repository.RevokeGatewayEnrollmentToken(fixture.ctx, fixture.scope, enrollment.DeviceID, enrollment.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repository.RevokeGatewayEnrollmentToken(fixture.ctx, fixture.scope, enrollment.DeviceID, enrollment.ID); err != nil {
		t.Fatalf("enrollment revoke replay=%v", err)
	}
	request := fixture.requestSync(integrationID, 51)
	claims, err := fixture.repository.ClaimDiscoveryJobs(fixture.ctx, "job-worker", "job-lease-token-00001", "discovery", 30, 1)
	if err != nil || len(claims) != 1 || claims[0].ID != request.JobID {
		t.Fatalf("job claim=%#v err=%v", claims, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_discovery_jobs SET updated_at=created_at,lease_expires_at=created_at+interval '1 microsecond' WHERE id=$1`, request.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.FinishDiscoveryJob(fixture.ctx, fixture.scope, DiscoveryJobCompletion{ID: request.JobID, Worker: "job-worker", LeaseToken: "job-lease-token-00001", Outcome: "failed", LastError: "expired owner"}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("expired-owner typed job=%v", err)
	}
	claims, err = fixture.repository.ClaimDiscoveryJobs(fixture.ctx, "job-worker", "job-lease-token-00002", "discovery", 30, 1)
	if err != nil || len(claims) != 1 || claims[0].ID != request.JobID {
		t.Fatalf("job reclaim=%#v err=%v", claims, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_discovery_jobs SET attempt=5 WHERE id=$1`, request.JobID); err != nil {
		t.Fatal(err)
	}
	jobCompletion := DiscoveryJobCompletion{ID: request.JobID, Worker: "job-worker", LeaseToken: "job-lease-token-00002", Outcome: "retryable", LastError: "failed", RetryAfterSeconds: 5}
	jobResult, err := fixture.repository.FinishDiscoveryJob(fixture.ctx, fixture.scope, jobCompletion)
	if err != nil || jobResult.State != "failed" || jobResult.Attempt != 5 {
		t.Fatalf("job exhaustion=%#v err=%v", jobResult, err)
	}
	replayResult, err := fixture.repository.FinishDiscoveryJob(fixture.ctx, fixture.scope, jobCompletion)
	if err != nil || replayResult.State != "failed" {
		t.Fatalf("job replay=%#v err=%v", replayResult, err)
	}
	cancelRequest := fixture.requestSync(integrationID, 53)
	cancelClaims, err := fixture.repository.ClaimDiscoveryJobs(fixture.ctx, "job-worker", "job-cancel-token-00001", "discovery", 30, 1)
	if err != nil || len(cancelClaims) != 1 || cancelClaims[0].ID != cancelRequest.JobID {
		t.Fatalf("job cancel claim=%#v err=%v", cancelClaims, err)
	}
	cancelledJob, err := fixture.repository.FinishDiscoveryJob(fixture.ctx, fixture.scope, DiscoveryJobCompletion{ID: cancelRequest.JobID, Worker: "job-worker", LeaseToken: "job-cancel-token-00001", Outcome: "cancelled", LastError: "cancelled by authority"})
	if err != nil || cancelledJob.State != "cancelled" {
		t.Fatalf("job cancel=%#v err=%v", cancelledJob, err)
	}
	projectionRequest := fixture.requestSync(integrationID, 52)
	projectionSnapshotID := "pid_62000010-0000-4000-8000-000000000010"
	if _, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, CompleteSnapshot{IntegrationID: integrationID, SyncID: projectionRequest.SyncID, SnapshotID: projectionSnapshotID, Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/typed/projection.json", ManifestChecksum: bytes32(10), CollectedAt: time.Now().UTC(), CursorProvider: "aws", CursorValue: "projection", Entities: json.RawMessage(`[]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`)}); err != nil {
		t.Fatalf("projection setup=%v", err)
	}
	targetKind := ""
	targetAttempts := 0
	for claimNumber := 1; claimNumber <= 8 && targetAttempts < 5; claimNumber++ {
		token := "projection-lease-token-" + strconv.Itoa(claimNumber)
		claimed, claimErr := fixture.repository.ClaimProjectionWork(fixture.ctx, "projection-worker", token, 30, 1)
		if claimErr != nil || len(claimed) != 1 {
			t.Fatalf("projection claim %d=%#v err=%v", claimNumber, claimed, claimErr)
		}
		if targetKind == "" {
			targetKind = claimed[0].Kind
		}
		if claimNumber == 1 {
			for other := 1; other <= 2; other++ {
				cancelToken := "projection-cancel-token-" + strconv.Itoa(other)
				otherClaims, otherErr := fixture.repository.ClaimProjectionWork(fixture.ctx, "projection-worker", cancelToken, 30, 1)
				if otherErr != nil || len(otherClaims) != 1 || otherClaims[0].Kind == targetKind {
					t.Fatalf("projection cancel claim %d=%#v err=%v", other, otherClaims, otherErr)
				}
				cancelled, cancelErr := fixture.repository.FinishProjectionWork(fixture.ctx, fixture.scope, ProjectionWorkCompletion{SnapshotID: otherClaims[0].SnapshotID, Kind: otherClaims[0].Kind, Version: otherClaims[0].Version, Worker: "projection-worker", LeaseToken: cancelToken, Outcome: "cancelled", LastError: "cancelled by authority"})
				if cancelErr != nil || cancelled.State != "cancelled" {
					t.Fatalf("projection cancel %d=%#v err=%v", other, cancelled, cancelErr)
				}
			}
			if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_projection_work SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE snapshot_id=$1 AND kind=$2`, claimed[0].SnapshotID, claimed[0].Kind); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.repository.FinishProjectionWork(fixture.ctx, fixture.scope, ProjectionWorkCompletion{SnapshotID: claimed[0].SnapshotID, Kind: claimed[0].Kind, Version: claimed[0].Version, Worker: "projection-worker", LeaseToken: token, Outcome: "failed", LastError: "expired owner"}); !errors.Is(err, ErrRepositoryNotFound) {
				t.Fatalf("expired-owner projection=%v", err)
			}
			token = "projection-lease-token-reclaimed"
			claimed, claimErr = fixture.repository.ClaimProjectionWork(fixture.ctx, "projection-worker", token, 30, 1)
			if claimErr != nil || len(claimed) != 1 || claimed[0].Attempt != 2 {
				t.Fatalf("projection reclaim=%#v err=%v", claimed, claimErr)
			}
		}
		targetAttempts = claimed[0].Attempt
		finished, finishErr := fixture.repository.FinishProjectionWork(fixture.ctx, fixture.scope, ProjectionWorkCompletion{SnapshotID: claimed[0].SnapshotID, Kind: claimed[0].Kind, Version: claimed[0].Version, Worker: "projection-worker", LeaseToken: token, Outcome: "retryable", LastError: "retry", RetryAfterSeconds: 0})
		if finishErr != nil {
			t.Fatalf("projection finish %d=%#v err=%v", claimNumber, finished, finishErr)
		}
		if claimed[0].Kind == targetKind && claimed[0].Attempt == 5 && finished.State != "failed" {
			t.Fatalf("projection exhaustion=%#v", finished)
		}
	}
	if targetAttempts != 5 {
		t.Fatalf("projection attempts=%d", targetAttempts)
	}
	runtime := RuntimeBatchCreate{SensorID: sensor.ID, BatchID: "pid_62000007-0000-4000-8000-000000000007", JobID: "pid_62000008-0000-4000-8000-000000000008", OutboxID: "pid_62000009-0000-4000-8000-000000000009", IdempotencyKey: "typed-runtime-batch-0001", PayloadDigest: bytes32(8), EventCount: 1, ObjectReference: "s3://zasp-runtime/typed/batch.jsonl", PayloadBytes: 128, MediaType: "application/x-ndjson", SchemaVersion: "runtime-event-v1"}
	if _, err := fixture.repository.CreateRuntimeBatch(fixture.ctx, fixture.scope, runtime); err != nil {
		t.Fatal(err)
	}
	failedStage := RuntimeStageCompletion{BatchID: runtime.BatchID, Stage: "archive", InputDigest: runtime.PayloadDigest, Succeeded: false, ResultReference: "s3://zasp-runtime/typed/failure.json"}
	if err := fixture.repository.CompleteRuntimeStage(fixture.ctx, fixture.scope, failedStage); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repository.CompleteRuntimeStage(fixture.ctx, fixture.scope, failedStage); err != nil {
		t.Fatalf("failed stage replay=%v", err)
	}
	recovered := failedStage
	recovered.Succeeded = true
	recovered.ResultReference = "s3://zasp-runtime/typed/success.json"
	if err := fixture.repository.CompleteRuntimeStage(fixture.ctx, fixture.scope, recovered); err != nil {
		t.Fatalf("stage recovery=%v", err)
	}
}

type discoveryFixPostgresFixture struct {
	t          *testing.T
	ctx        context.Context
	dsn        string
	connection *pgx.Conn
	repository *DiscoveryRepository
	runner     *migrations.Runner
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
	runner := migrateToProductionDiscovery(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	return &discoveryFixPostgresFixture{t: t, ctx: ctx, dsn: dsn, connection: connection, repository: repository, runner: runner, identity: identity, scope: identity.Scope}
}

func (fixture *discoveryFixPostgresFixture) createActiveIntegration(id, name string) {
	fixture.t.Helper()
	if _, err := fixture.repository.CreateIntegration(fixture.ctx, fixture.identity, IntegrationCreate{ID: id, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: name, Configuration: json.RawMessage(`{}`)}); err != nil {
		fixture.t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionIntegration(fixture.ctx, fixture.scope, IntegrationTransition{ID: id, ExpectedVersion: 1, State: "active"}); err != nil {
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
	repository, err := newDiscoveryRepositoryUnchecked(database)
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
