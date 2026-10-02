package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are real constructors on the registered API principals, not repository
// struct literals or a readiness fixture. Full HTTP/services composition is a
// separate gate; this group protects its database-backed constructor seams.
func TestP7AuthorizationRepositoryCompositionPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	if _, err = owner.Exec(ctx, `CREATE ROLE auth80_agent_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE auth80_agent_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; SELECT zasp_security_agent_register_principals(session_user,'auth80_agent_api','auth80_agent_worker')`); err != nil {
		t.Fatal(err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	agentAPI := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_agent_api")
	defer agentAPI.Close(context.Background())
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	agentDatabase, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: agentAPI})
	for _, db := range []*PostgresJSONDatabase{database, agentDatabase} {
		if err = db.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name      string
		construct func() error
	}{
		{"core", func() error {
			r, e := NewPostgresRepository(database)
			if e == nil && !r.currentAuthorization {
				t.Fatal("core constructor lost enforced mode")
			}
			return e
		}},
		{"inventory", func() error { _, e := NewPostgresInventoryRepository(database); return e }},
		{"connector", func() error { _, e := NewConnectorRepository(database); return e }},
		{"reference", func() error { _, e := NewReferenceAuthorizationRepository(database); return e }},
		{"discovery", func() error {
			_, e := NewDiscoveryRepositoryForAuthority(database, DiscoveryDatabaseAuthorityAPI)
			return e
		}},
		{"sensor", func() error { _, e := NewSensorPublicRepository(database); return e }},
		{"recovery", func() error { _, e := NewRecoveryPublicRepository(database); return e }},
		{"policy", func() error { _, e := NewPolicyDecisionRepository(database); return e }},
		{"audit page", func() error { _, e := NewAuditPublicPageRepository(ctx, database); return e }},
		{"audit export", func() error { _, e := NewAuditExportRepository(database); return e }},
		{"compliance", func() error { _, e := NewComplianceRepository(database); return e }},
		{"compliance export", func() error { _, e := NewComplianceExportsRepository(database); return e }},
		{"security agent", func() error { _, e := NewSecurityAgentPostgresRepository(agentDatabase); return e }},
		{"approval notification", func() error { _, e := NewApprovalNotificationPostgresRepository(agentDatabase); return e }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.construct(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err = database.QueryJSON(ctx, postgresProductionRecoveryReadinessSQL, strings.Repeat("0", 64), migrations.ProductionRecoverySemanticFingerprint()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("foreign compiled pin accepted: %v", err)
	}
	if _, err = agentDatabase.QueryJSON(ctx, postgresProductionRecoveryReadinessSQL, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("wrong API principal accepted: %v", err)
	}
	if _, err = database.QueryJSON(ctx, `SELECT '{"unfenced":true}'::jsonb`); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("arbitrary proofless query accepted: %v", err)
	}
	// A present but malformed optional extension is not an absent predecessor.
	// This empty schema is created only in this owned disposable PostgreSQL.
	if _, err = owner.Exec(ctx, `CREATE SCHEMA zasp_temporal74`); err != nil {
		t.Fatal(err)
	}
	if _, err = NewAuditExportRepository(database); err == nil {
		t.Fatal("invalid present Temporal74 fell back to canonical61")
	}
}
