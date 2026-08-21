package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProductionGlobalSearchPostgresIsIndexedScopedAndAPIOnly(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 migration: %v", err)
	}
	if err := runner.UpProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatalf("v16 migration: %v", err)
	}

	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	foreignOrganization := "pid_4f000001-0000-4000-8000-000000000001"
	agentID := "pid_4f000002-0000-4000-8000-000000000002"
	foreignAgentID := "pid_4f000003-0000-4000-8000-000000000003"
	findingID := "pid_4f000004-0000-4000-8000-000000000004"
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest,legacy_digest,typed_digest,backfilled_at,equivalent_at,cutover_at)
VALUES($1,$2,$3,'cutover','44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30',digest(convert_to('search-fixture','UTF8'),'sha256'),digest(convert_to('search-fixture','UTF8'),'sha256'),transaction_timestamp(),transaction_timestamp(),transaction_timestamp())
ON CONFLICT(organization_id,workspace_id,environment_id) DO UPDATE SET
 phase='cutover',legacy_digest=digest(convert_to('search-fixture','UTF8'),'sha256'),typed_digest=digest(convert_to('search-fixture','UTF8'),'sha256'),
 backfilled_at=transaction_timestamp(),equivalent_at=transaction_timestamp(),cutover_at=transaction_timestamp()`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind)
VALUES($1,$2,$3,$4,'agent','Production payment agent','active',transaction_timestamp(),transaction_timestamp(),'agent'),
      ($5,$2,$3,$6,'agent','Production foreign agent','active',transaction_timestamp(),transaction_timestamp(),'agent')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), agentID, foreignOrganization, foreignAgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status)
VALUES($1,$2,$3,$4,'prowler','Production credential exposed','critical','open')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), findingID); err != nil {
		t.Fatal(err)
	}

	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	page, err := repository.SearchGlobal(ctx, scope, "Production", 20)
	if err != nil || len(page.Items) != 2 || page.Items[0].ID != agentID || page.Items[1].ID != findingID {
		t.Fatalf("scoped search=%#v err=%v", page, err)
	}
	var raw json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_global_search($1,$2,$3,$4,$5)`, foreignOrganization, scope.WorkspaceID().String(), scope.EnvironmentID().String(), "Production", 20).Scan(&raw); err == nil {
		t.Fatalf("foreign uncutover scope search unexpectedly succeeded: %s", raw)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_global_search($1,$2,$3,$4,$5)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "MATCH (n)", 20).Scan(&raw); err == nil {
		t.Fatalf("raw graph query unexpectedly succeeded: %s", raw)
	}

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	if err := transaction.QueryRow(ctx, `SELECT zasp_global_search($1,$2,$3,$4,$5)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "Production", 20).Scan(&raw); err != nil {
		t.Fatalf("API search authority: %v", err)
	}
	var apiPage GlobalSearchPage
	if json.Unmarshal(raw, &apiPage) != nil || len(apiPage.Items) != 2 {
		t.Fatalf("API search payload=%s", raw)
	}
	if _, err := transaction.Exec(ctx, `SELECT count(*) FROM zasp_inventory_entities`); err == nil {
		t.Fatal("API principal gained direct inventory table access")
	}
	if rollbackErr := transaction.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
		t.Fatal(rollbackErr)
	}
}
