package main

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// The parent mounted PostgreSQL fixture supplies its registered API DSN. No
// owner SQL or fake transaction/decorator is used for this production path.
func TestConnectorRejectionRuntimePostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_CONNECTOR_REJECTION_RUNTIME_DSN")
	if dsn == "" {
		t.Skip("requires the owned mounted connector-rejection fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, pool, err := openRuntimePostgres(ctx, dsn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var current string
	var superuser, bypass bool
	if err = pool.QueryRow(ctx, `SELECT current_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&current, &superuser, &bypass); err != nil || current != "security_agent_v33_discovery_api_login" || superuser || bypass {
		t.Fatalf("actual runtime role=%s super=%t bypass=%t err=%v", current, superuser, bypass, err)
	}
	traced := &tracedJSONDatabase{next: db, metrics: newOperationalMetrics(), exporter: &captureSpanExporter{}}
	repository, err := apiserver.NewPostgresRepository(traced)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := repository.Authenticate(ctx, apiserver.Credential{Kind: apiserver.CredentialBrowserSession, Value: "connector-rejection-session"})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("connector-rejection-session"))
	command := apiserver.IntegrationRejection{CredentialDigest: digest[:], Operation: "createIntegration", TargetID: identity.Scope.EnvironmentID().String(), AuditID: "pid_8b000022-0000-4000-8000-000000000022", CorrelationID: "pid_8b000023-0000-4000-8000-000000000023"}
	if err = repository.AuditIntegrationRejection(ctx, identity, command); err != nil {
		t.Fatal(err)
	}
	var action, outcome string
	if err = pool.QueryRow(ctx, `SELECT action,outcome FROM zasp_admin_audit WHERE id=$1`, command.AuditID).Scan(&action, &outcome); err != nil || action != "integration.setup.rejected" || outcome != "rejected" {
		t.Fatalf("actual pgx/traced durable event: %s %s %v", action, outcome, err)
	}
	legacy := &tracedJSONDatabase{next: boundaryDatabase{}}
	if err = legacy.AuditIntegrationRejection(ctx, identity, command); err != apiserver.ErrRepositoryUnavailable {
		t.Fatalf("missing decorator capability error=%v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	command.AuditID = "pid_8b000024-0000-4000-8000-000000000024"
	if err = traced.AuditIntegrationRejection(ctx, identity, command); err != apiserver.ErrRepositoryUnavailable {
		t.Fatalf("closed runtime DB error=%v", err)
	}
	t.Log("actual pgxpool READ COMMITTED driver + production tracing + repository committed one safe audit; missing/closed capabilities fail unavailable")
}
