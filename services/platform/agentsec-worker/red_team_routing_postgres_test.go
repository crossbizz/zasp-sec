package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Called only by the owned offline PostgreSQL fixture. No host database startup.
func TestRedTeamRoutedOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_ROUTING_WORKER_DSN")
	if dsn == "" {
		t.Skip("requires owned routing fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// ConnString retains the owner's original DSN even when the fixture
	// changes ConnConfig.User. Connect directly as the registered login.
	config.ConnConfig.User = "existing_test_red_worker"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var sessionUser string
	if err := pool.QueryRow(ctx, "SELECT session_user::text").Scan(&sessionUser); err != nil {
		t.Fatal(err)
	}
	if sessionUser != "existing_test_red_worker" {
		t.Fatalf("fixture connected as %q, expected registered worker", sessionUser)
	}
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRoutedRedTeamAuthority(db)
	if err != nil {
		// Read-only diagnostics preserve the failing constructor's boundary.
		// Never log the connection string or session credentials.
		for _, check := range []struct {
			name, query, checksum, fingerprint string
		}{
			{"recovery", "SELECT to_jsonb(zasp_recovery_execution_readiness($1,$2))", migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()},
			{"execution", "SELECT to_jsonb(zasp_red_team_execution_readiness($1,$2))", migrations.ProductionRedTeamExecution().Checksum(), migrations.ProductionRedTeamExecutionSemanticFingerprint()},
		} {
			payload, queryErr := db.QueryJSON(ctx, check.query, check.checksum, check.fingerprint)
			t.Logf("%s readiness: %s error=%v", check.name, payload, queryErr)
		}
		_, legacyErr := apiserver.NewRedTeamExecutionRepository(db, apiserver.RedTeamExecutionAuthorityWorker)
		_, linkedErr := apiserver.NewLinkedRedTeamExecutionRepository(db)
		t.Fatalf("router construction: %v; legacy=%v; linked=%v", err, legacyErr, linkedErr)
	}
	if err := router.ReadyArtifacts(ctx); err != nil {
		t.Fatalf("registered composed readiness: %v", err)
	}
	o, _ := domain.ParseProductID(os.Getenv("ZASP_ROUTING_ORG"))
	w, _ := domain.ParseProductID(os.Getenv("ZASP_ROUTING_WORKSPACE"))
	e, _ := domain.ParseProductID(os.Getenv("ZASP_ROUTING_ENVIRONMENT"))
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"linked", "legacy"} {
		name := "ZASP_ROUTING_LINKED"
		if protocol == "legacy" {
			name = "ZASP_ROUTING_LEGACY"
		}
		if got, err := router.protocol(ctx, scope, os.Getenv(name)); err != nil || got != protocol {
			t.Fatalf("registered protocol: %q %v", got, err)
		}
	}
}
