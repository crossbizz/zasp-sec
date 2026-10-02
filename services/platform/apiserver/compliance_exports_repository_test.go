package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

// Missing scope binding, public token leakage, or conflating idempotency with a
// source_changed conflict must break the API's durable-job contract.
func TestComplianceExportsRepository(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "view_compliance"}
	identity.FreshAuthenticated = true
	digest := sha256.Sum256([]byte("session"))
	raw := json.RawMessage(`{"export_id":"pid_10000004-0000-4000-8000-000000000004","organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","state":"pending","phase":"queued","failure_code":null,"created_at":"2026-09-18T01:00:00Z","retrieval_expires_at":"2026-09-19T01:00:00Z","mapping_revision":"product-evidence-v1"}`)
	db := &discoveryCallDatabase{schema: ProductionRecoverySchemaVersion, responses: map[string]json.RawMessage{postgresComplianceReadySQL: json.RawMessage(`true`), postgresComplianceExportCreateSQL: raw}}
	r, err := NewComplianceExportsRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	job, err := r.Create(context.Background(), identity, digest[:], "idempotent", ComplianceExportRequest{Framework: "soc2_security"})
	if err != nil || job.State != "pending" {
		t.Fatalf("create: %+v %v", job, err)
	}
	if len(db.args) != 9 || db.args[0] != identity.Scope.OrganizationID().String() || db.args[3] != identity.PrincipalID.String() || db.args[5] != "idempotent" {
		t.Fatalf("scope/request binding: %#v", db.args)
	}
	db.errors = map[string]error{postgresComplianceExportCreateSQL: classifyPostgresError(&pgconn.PgError{Code: "40001"})}
	if _, err := r.Create(context.Background(), identity, digest[:], "idempotent", ComplianceExportRequest{}); !errors.Is(err, ErrRepositoryConflict) || errors.Is(err, ErrComplianceSourceChanged) {
		t.Fatalf("job conflict classification: %v", err)
	}
	db.errors = nil
	identity.FreshAuthenticated = false
	if _, err := r.Create(context.Background(), identity, digest[:], "idempotent", ComplianceExportRequest{}); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("create accepted stale authentication: %v", err)
	}
	identity.FreshAuthenticated = true
	db.responses[postgresComplianceExportCreateSQL] = append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"lease_token":"secret"}`)...)
	if _, err := r.Create(context.Background(), identity, digest[:], "idempotent", ComplianceExportRequest{}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("public secret accepted: %v", err)
	}
	if _, err := r.Create(context.Background(), identity, digest[:], "idempotent", ComplianceExportRequest{Framework: "other"}); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("unknown framework: %v", err)
	}
}
