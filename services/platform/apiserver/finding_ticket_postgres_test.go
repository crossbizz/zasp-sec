package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProductionFindingTicketPostgresFencesTenantReplayAndAPIAuthority(t *testing.T) {
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
	organization := identity.Scope.OrganizationID().String()
	workspace := identity.Scope.WorkspaceID().String()
	environment := identity.Scope.EnvironmentID().String()
	integrationID := "pid_41000002-0000-4000-8000-000000000002"
	deliveryID := "pid_41000003-0000-4000-8000-000000000003"
	secondDeliveryID := "pid_41000004-0000-4000-8000-000000000004"
	correlationID := "pid_41000005-0000-4000-8000-000000000005"
	replayCorrelationID := "pid_41000006-0000-4000-8000-000000000006"
	requestCorrelationID := correlationID
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$4,'posture','Production credential exposed','critical','open')`, organization, workspace, environment, riskFindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'connector_key','generic-webhook','name','Ticket webhook','configuration',jsonb_build_object('destination_url','https://tickets.example.test/zasp','signing_secret_reference','secret_ref_ticket_prod'),'status','configured','created_at','2026-08-21T00:00:00Z','updated_at','2026-08-21T00:00:00Z'))`, organization, workspace, environment, integrationID); err != nil {
		t.Fatal(err)
	}

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	reserve := func(delivery, token, key string, expected int64) (json.RawMessage, error) {
		var value json.RawMessage
		err := transaction.QueryRow(ctx, `SELECT zasp_finding_ticket_reserve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,15)`, organization, workspace, environment, identity.PrincipalID.String(), riskFindingID, expected, key, requestCorrelationID, delivery, token).Scan(&value)
		return value, err
	}
	first, err := reserve(deliveryID, strings.Repeat("a", 64), "finding-ticket-pg-0001", 1)
	if err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	var dispatch struct {
		State           string  `json:"state"`
		DeliveryID      string  `json:"delivery_id"`
		Payload         string  `json:"payload"`
		PayloadDigest   string  `json:"payload_digest"`
		DestinationURL  string  `json:"destination_url"`
		SecretReference string  `json:"secret_reference"`
		TicketID        *string `json:"ticket_id"`
	}
	if json.Unmarshal(first, &dispatch) != nil || dispatch.State != "dispatch" || dispatch.DeliveryID != deliveryID || dispatch.DestinationURL != "https://tickets.example.test/zasp" || dispatch.SecretReference != "secret_ref_ticket_prod" || dispatch.TicketID != nil || !strings.HasPrefix(dispatch.PayloadDigest, "sha256:") || strings.Contains(dispatch.Payload, "evidence") || strings.Contains(dispatch.Payload, "secret_ref") {
		t.Fatalf("dispatch=%s", first)
	}
	requestCorrelationID = replayCorrelationID
	busy, err := reserve(secondDeliveryID, strings.Repeat("b", 64), "finding-ticket-pg-0001", 1)
	var busyValue map[string]any
	if err != nil || json.Unmarshal(busy, &busyValue) != nil || busyValue["state"] != "busy" || busyValue["delivery_id"] != deliveryID || busyValue["destination_url"] != nil {
		t.Fatalf("busy=%s err=%v", busy, err)
	}
	var completed json.RawMessage
	var completedValue FindingTicket
	if err := transaction.QueryRow(ctx, `SELECT zasp_finding_ticket_complete($1,$2,$3,$4,$5,$6,$7)`, organization, workspace, environment, deliveryID, strings.Repeat("a", 64), dispatch.PayloadDigest, "SEC-1234").Scan(&completed); err != nil || json.Unmarshal(completed, &completedValue) != nil || completedValue.TicketID != "SEC-1234" {
		t.Fatalf("complete=%s err=%v", completed, err)
	}
	replay, err := reserve(secondDeliveryID, strings.Repeat("c", 64), "finding-ticket-pg-0001", 1)
	var replayValue map[string]any
	if err != nil || json.Unmarshal(replay, &replayValue) != nil || replayValue["state"] != "completed" || replayValue["ticket_id"] != "SEC-1234" || replayValue["destination_url"] != nil || replayValue["payload_digest"] != nil {
		t.Fatalf("completed replay=%s err=%v", replay, err)
	}
	if _, err := reserve(secondDeliveryID, strings.Repeat("d", 64), "finding-ticket-pg-stale", 2); err == nil {
		t.Fatal("stale finding version was accepted")
	}
	if _, err := transaction.Exec(ctx, `SELECT count(*) FROM zasp_finding_ticket_deliveries`); err == nil {
		t.Fatal("API role gained direct ticket table access")
	}
	if rollbackErr := transaction.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
		t.Fatal(rollbackErr)
	}
}
