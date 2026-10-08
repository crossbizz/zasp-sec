package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Current authorization cannot obtain background authority by reusing a bare
// API session. These are the original dispatch entry points used by the API
// lifecycle workers; native registration and captured provenance remain needed.
func TestCurrentAuthorizationRefusesLegacyBackgroundDispatch(t *testing.T) {
	driver := &guardedReadinessDriver{t: t}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	owner, token := "owned-background-boundary", strings.Repeat("a", 64)
	for _, request := range []struct {
		statement string
		arguments []any
	}{
		{postgresConnectorRecoverFinalAttemptsSQL, []any{owner, 30, 25}},
		{postgresConnectorClaimReconciliationSQL, []any{owner, 30, 25}},
		{postgresApprovalNotificationClaimSQL, []any{owner, token, 30}},
	} {
		if _, err := database.QueryJSON(ctx, request.statement, request.arguments...); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatal("bare background statement acquired authority", err)
		}
	}
	connector := &ConnectorRepository{database: database}
	if _, err := connector.RecoverExpiredFinalAttempts(ctx, owner, 30, 25); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatal("connector recovery lost authorization refusal", err)
	}
	if _, err := connector.ClaimReconciliation(ctx, owner, 30, 25); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatal("connector claim lost authorization refusal", err)
	}
	approval := &PostgresRepository{database: database, schema: ProductionApprovalNotificationSchemaVersion, securityAgentExecution: true}
	if _, err := approval.ClaimApprovalNotification(ctx, owner, token, 30); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatal("approval claim lost authorization refusal", err)
	}
	if driver.calls != 0 {
		t.Fatalf("bare background dispatch reached QueryRow: calls=%d", driver.calls)
	}
}
